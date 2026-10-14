"""Polls the public GitHub repo for PRs and CI runs, runs the detection backtest and playbook UAT on each PR head,
and queues cards for #detection-ci, #playbook-uat and #coverage. Read-only against GitHub (public API, no token)."""
import io
import json
import os
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

from core import ci as cilib
from core import packs as pk
from core.console import coverage as cov
from core.console import outbox as ob
from core.console import paths

GREEN, RED, BLUE, GREY = 3066993, 15158332, 3447003, 9807270


def gh(path):
    req = urllib.request.Request('https://api.github.com' + path, headers={'User-Agent': 'lab-console', 'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def checkout(repo, sha, base):
    dest = Path(base) / sha[:12]
    if (dest / 'core').is_dir():
        return dest
    dest.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(urllib.request.Request('https://codeload.github.com/%s/tar.gz/%s' % (repo, sha), headers={'User-Agent': 'lab-console'}), timeout=120) as r:
        data = r.read()
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tf:
        for m in tf.getmembers():
            parts = Path(m.name).parts[1:]
            if not parts or '..' in parts or m.name.startswith('/'):
                continue
            m.name = str(Path(*parts))
            tf.extract(m, dest)
    return dest


def full_report(ctx, repo, sha, base=None):
    cached = ctx.store.get('ci_report', sha)
    if cached:
        return cached['report']
    root = checkout(repo, sha, base or paths.ci_dir())
    if not (root / 'core' / 'ci.py').is_file() or not (root / 'packs').is_dir():
        rep = {'legacy': True, 'error': 'this commit predates the pack structure, so there is nothing to backtest'}
        ctx.store.put('ci_report', sha, {'report': rep})
        return rep
    env = dict(os.environ, PYTHONPATH=str(root))
    proc = subprocess.run([sys.executable, '-m', 'core.ci', '--root', str(root), '--sha', sha], cwd=str(root), env=env, capture_output=True, text=True, timeout=300)
    rep = json.loads(proc.stdout) if proc.stdout.strip().startswith('{') else {'error': (proc.stderr or proc.stdout)[-300:]}
    if 'error' not in rep:
        bl = Path(ctx.env.get('LAB_BACKTEST_BASELINE', str(paths.state_dir() / 'backtest-baseline.json')))
        baseline = json.loads(bl.read_text()) if bl.is_file() else []
        rep['backtest_real'] = cilib.backtest_real(ctx.es, root, baseline) if baseline else None
        rep['snapshot'] = cov.snapshot(root)
    ctx.store.put('ci_report', sha, {'report': rep})
    return rep


def ci_embed(pr, run, rep):
    ok = run['conclusion'] == 'success' and 'error' not in rep and not rep['detections']['failed'] and not rep['playbooks']['failed'] and not rep['platform']['failed']
    f = [{'name': 'CI', 'value': ('\u2705 ' if run['conclusion'] == 'success' else '\u274C ') + run['conclusion'] + ' \u00b7 [run](%s)' % run['html_url'], 'inline': True}]
    if rep.get('legacy'):
        f.append({'name': 'Backtest', 'value': 'n/a: ' + rep['error'], 'inline': False})
    elif 'error' in rep:
        f.append({'name': 'Backtest', 'value': 'could not run: ' + rep['error'][:200], 'inline': False})
    else:
        d, p, pl = rep['detections'], rep['playbooks'], rep['platform']
        f += [{'name': 'Detection backtest (fixtures)', 'value': '%d/%d pass' % (d['passed'], d['total']) + ((' \u00b7 FAIL: ' + ', '.join(d['failed'][:3])) if d['failed'] else ''), 'inline': True},
              {'name': 'Playbook tests', 'value': '%d/%d pass' % (p['passed'], p['total']), 'inline': True},
              {'name': 'Platform tests', 'value': '%d/%d pass' % (pl['passed'], pl['total']), 'inline': True}]
        br = rep.get('backtest_real')
        f.append({'name': 'Backtest (real events)', 'value': ('%d/%d still fire' % (br['passed'], br['total']) + ((' \u00b7 FAIL: ' + ', '.join(br['failed'])) if br['failed'] else '')) if br else 'n/a (no baseline recorded)', 'inline': True})
        snap = rep.get('snapshot')
        if snap:
            f.append({'name': 'Pack content', 'value': '%d rules \u00b7 %d playbooks \u00b7 %d techniques' % (len(snap['rules']), len(snap['playbooks']), len(snap['techniques'])), 'inline': True})
    f.append({'name': 'Head', 'value': pr['head']['sha'][:7], 'inline': True})
    return {'title': ('PR #%d \u00b7 %s' % (pr['number'], pr['title']))[:250], 'url': pr['html_url'], 'color': GREEN if ok else RED, 'fields': f,
            'footer': {'text': 'detection-ci \u00b7 ' + (run.get('updated_at') or '')[:19] + 'Z'}}


def uat_embed(pr, rep):
    rows = rep.get('matrix', [])
    lines = ['%-26s %-40s %-5s %5s' % ('playbook', 'case', 'result', 'ms')]
    for r in rows:
        lines.append('%-26s %-40s %-5s %5d' % (r['playbook'][:26], r['case'][:40], r['status'].upper(), r['ms']))
    ok = rows and all(r['status'] == 'pass' for r in rows)
    body = '```\n' + '\n'.join(lines)[:3700] + '\n```'
    return {'title': 'Playbook UAT \u00b7 PR #%d \u00b7 %s' % (pr['number'], 'PASS' if ok else 'FAIL'), 'url': pr['html_url'], 'color': GREEN if ok else RED,
            'description': body, 'footer': {'text': '%d/%d cases pass \u00b7 head %s \u00b7 response lane sign-off' % (sum(1 for r in rows if r['status'] == 'pass'), len(rows), pr['head']['sha'][:7])}}


def poll(ctx, repo):
    made = []
    for pr in gh('/repos/%s/pulls?state=all&sort=updated&direction=desc&per_page=3' % repo):
        n, sha = pr['number'], pr['head']['sha']
        if ob.enqueue(ctx.store, 'pr-opened:%d' % n, {'channel': 'detection-ci', 'kind': 'embed', 'message': 'PR #%d opened' % n,
                      'embed': {'title': 'PR #%d opened \u00b7 %s' % (n, pr['title'])[:250], 'url': pr['html_url'], 'color': BLUE, 'description': 'Branch `%s` into `%s`.' % (pr['head']['ref'], pr['base']['ref'])}}):
            made.append('pr-opened:%d' % n)
        if pr.get('merged_at') and ob.enqueue(ctx.store, 'pr-merged:%d' % n, {'channel': 'detection-ci', 'kind': 'embed', 'message': 'PR #%d merged' % n,
                      'embed': {'title': 'PR #%d merged \u00b7 %s' % (n, pr['title'])[:250], 'url': pr['html_url'], 'color': GREEN}}):
            made.append('pr-merged:%d' % n)
        runs = gh('/repos/%s/actions/runs?head_sha=%s&per_page=5' % (repo, sha)).get('workflow_runs', [])
        run = next((r for r in runs if r['name'] == 'Offline lab CI' and r['status'] == 'completed'), None)
        key = 'ci:%d:%s' % (n, sha)
        if not run or ctx.store.exists('outbox', key):
            continue
        rep = full_report(ctx, repo, sha)
        files = gh('/repos/%s/pulls/%d/files?per_page=100' % (repo, n))
        names = [f['filename'] for f in files]
        ob.enqueue(ctx.store, key, {'channel': 'detection-ci', 'kind': 'embed', 'message': 'PR #%d CI %s' % (n, run['conclusion']), 'embed': ci_embed(pr, run, rep)})
        made.append(key)
        if any(x.startswith('packs/') and '/playbooks/' in x for x in names) and 'error' not in rep:
            ob.enqueue(ctx.store, 'uat:%d:%s' % (n, sha), {'channel': 'playbook-uat', 'kind': 'embed', 'message': 'Playbook UAT for PR #%d' % n, 'embed': uat_embed(pr, rep)})
            made.append('uat:%d:%s' % (n, sha))
        if any(x.startswith('packs/') for x in names) and 'error' not in rep and rep.get('snapshot'):
            old = ctx.store.get('coverage_snapshot', 'latest')
            d = cov.diff(old['snapshot'] if old else None, rep['snapshot'])
            ob.enqueue(ctx.store, 'coverage:%d:%s' % (n, sha), {'channel': 'coverage', 'kind': 'coverage', 'message': 'ATT&CK coverage for PR #%d' % n, 'snapshot': rep['snapshot'], 'diff': d,
                                                              'title': 'Coverage map \u00b7 PR #%d head %s' % (n, sha[:7])})
            made.append('coverage:%d:%s' % (n, sha))
    return made
