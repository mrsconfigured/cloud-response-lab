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
from core.console import plain as pl
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


def _n(x):
    return '%d of %d' % (x['passed'], x['total'])


def ci_embed(pr, run, rep):
    n = pr['number']
    ok_run = run['conclusion'] == 'success'
    if rep.get('legacy') or 'error' in rep:
        why = rep.get('error', 'unknown problem')[:200]
        head = '\u26AA Automatic checks ran for code change #%d, but the deeper tests could not run' % n
        desc = '**Change:** %s\n**What this means:** the basic check %s, but the detection and response tests did not run (%s).' % (pr['title'], 'passed' if ok_run else 'failed', why)
        return {'title': head[:250], 'url': pr['html_url'], 'color': GREY, 'description': desc, 'footer': {'text': 'Version %s' % pr['head']['sha'][:7]}}
    d, p, pl_, br, snap = rep['detections'], rep['playbooks'], rep['platform'], rep.get('backtest_real'), rep.get('snapshot')
    bad = [x for x in ('detection', 'response', 'platform') if {'detection': d, 'response': p, 'platform': pl_}[x]['failed']] + ([] if (br is None or not br['failed']) else ['replay of past attacks'])
    ok = ok_run and not bad
    if ok:
        head = '\u2705 All automatic checks passed for code change #%d' % n
        what = 'Every test passed, so this change is ready for a person to review. It has **not** been merged.'
    else:
        head = '\u274C Automatic checks failed for code change #%d' % n
        what = 'Something failed (%s). Do not merge until it is fixed.' % (', '.join(bad) or 'the basic check')
    facts = ['Detection tests: %s passed' % _n(d), 'Response tests: %s passed' % _n(p), 'Platform tests: %s passed' % _n(pl_)]
    facts.append('Replay of past real attacks: ' + (('%s still caught' % _n(br)) if br else 'not available yet'))
    desc = '**Change:** %s\n**What this means:** %s\n\n%s' % (pr['title'], what, ' \u00b7 '.join(facts))
    if snap:
        desc += '\n**This change contains:** %d detection rules and %d response playbooks, covering %d attack types.' % (len(snap['rules']), len(snap['playbooks']), len(snap['techniques']))
    return {'title': head[:250], 'url': pr['html_url'], 'color': GREEN if ok else RED, 'description': desc,
            'footer': {'text': 'Version %s \u00b7 checked %s UTC \u00b7 Show details has the full result' % (pr['head']['sha'][:7], (run.get('updated_at') or '')[11:16])}}


def ci_details(pr, run, rep):
    slim = {k: v for k, v in rep.items() if k != 'snapshot'}
    return 'Code change: %s\nAutomatic check run: %s\nConclusion: %s\n\n%s' % (pr['html_url'], run['html_url'], run['conclusion'], pl.as_json(slim))


def uat_embed(pr, rep):
    rows = rep.get('matrix', [])
    n = pr['number']
    fails = [r for r in rows if r['status'] != 'pass']
    if rows and not fails:
        head = '\u2705 All %d response tests passed (code change #%d)' % (len(rows), n)
    else:
        head = '\u274C %d of %d response tests failed (code change #%d)' % (len(fails), len(rows), n)
    per = {}
    for r in rows:
        g = per.setdefault(r['playbook'], [0, 0])
        g[1] += 1
        g[0] += r['status'] == 'pass'
    lines = ['\u2022 %s \u2014 %d of %d passed' % (pl.PB_TITLE.get(k, k), g[0], g[1]) for k, g in sorted(per.items())]
    desc = 'These tests prove each practice lockdown only acts on the right alerts, always waits for approval, does nothing on harmless events, and leaves an audit record.\n\n' + '\n'.join(lines)
    if fails:
        desc += '\n\n**Failing:** ' + ', '.join('%s / %s' % (pl.PB_TITLE.get(r['playbook'], r['playbook']), r['case'].replace('_', ' ')) for r in fails[:5])
    return {'title': head, 'url': pr['html_url'], 'color': GREEN if rows and not fails else RED, 'description': desc[:4000],
            'footer': {'text': 'Version %s \u00b7 for the response team to sign off \u00b7 Show details has every test' % pr['head']['sha'][:7]}}


def uat_details(rep):
    rows = rep.get('matrix', [])
    lines = ['%-26s %-40s %-5s %5s' % ('playbook', 'case', 'result', 'ms')] + ['%-26s %-40s %-5s %5d' % (r['playbook'][:26], r['case'][:40], r['status'].upper(), r['ms']) for r in rows]
    return '\n'.join(lines)


def pr_files(repo, n, pages=10):
    # GitHub returns at most 100 files per page; a big PR spans several pages
    names = []
    for page in range(1, pages + 1):
        chunk = gh('/repos/%s/pulls/%d/files?per_page=100&page=%d' % (repo, n, page))
        names += [f['filename'] for f in chunk]
        if len(chunk) < 100:
            break
    return names


def _queue(ctx, key, channel, embed, title, body, **extra):
    if ctx.store.exists('outbox', key):
        return False
    return ob.enqueue(ctx.store, key, pl.post_with_details(ctx.store, key, channel, embed, title, body, **extra))


def poll(ctx, repo):
    made = []
    for pr in gh('/repos/%s/pulls?state=all&sort=updated&direction=desc&per_page=3' % repo):
        n, sha = pr['number'], pr['head']['sha']
        if _queue(ctx, 'pr-opened:%d' % n, 'detection-ci', {'title': '\U0001F4EC Code change #%d proposed: %s' % (n, pr['title'])[:250], 'url': pr['html_url'], 'color': BLUE,
                  'description': 'Someone proposed a change to the lab\u2019s code (from branch `%s` into `%s`). Automatic checks will post here when they finish. Nothing is merged until a person decides.' % (pr['head']['ref'], pr['base']['ref'])},
                  'Code change #%d' % n, 'Link: %s\nBranch: %s into %s' % (pr['html_url'], pr['head']['ref'], pr['base']['ref'])):
            made.append('pr-opened:%d' % n)
        if pr.get('merged_at') and _queue(ctx, 'pr-merged:%d' % n, 'detection-ci', {'title': '\U0001F500 Code change #%d was merged: %s' % (n, pr['title'])[:250], 'url': pr['html_url'], 'color': GREEN,
                  'description': 'A person approved this change and it is now part of the lab\u2019s main code.'}, 'Code change #%d merged' % n, 'Link: %s' % pr['html_url']):
            made.append('pr-merged:%d' % n)
        done_key = '%d:%s' % (n, sha)
        if ctx.store.exists('ci_done', done_key):
            continue   # this head is fully handled; an unauthenticated API allows only 60 calls an hour
        runs = gh('/repos/%s/actions/runs?head_sha=%s&per_page=5' % (repo, sha)).get('workflow_runs', [])
        run = next((r for r in runs if r['name'] == 'Offline lab CI' and r['status'] == 'completed'), None)
        key = 'ci:%d:%s' % (n, sha)
        if not run:
            continue
        rep = full_report(ctx, repo, sha)
        names = pr_files(repo, n)
        if _queue(ctx, key, 'detection-ci', ci_embed(pr, run, rep), 'Automatic check result for code change #%d' % n, ci_details(pr, run, rep)):
            made.append(key)
        if any(x.startswith('packs/') and '/playbooks/' in x for x in names) and 'error' not in rep:
            if _queue(ctx, 'uat:%d:%s' % (n, sha), 'playbook-uat', uat_embed(pr, rep), 'Every response test for code change #%d' % n, uat_details(rep)):
                made.append('uat:%d:%s' % (n, sha))
        if any(x.startswith('packs/') for x in names) and 'error' not in rep and rep.get('snapshot') and not ctx.store.exists('outbox', 'coverage:%d:%s' % (n, sha)):
            old = ctx.store.get('coverage_snapshot', 'latest')
            png = cov.render_png(rep['snapshot'], str(paths.state_dir() / ('coverage-%s.png' % sha[:7])))
            emb, _ = cov.embed(rep['snapshot'], old['snapshot'] if old else None, 'This map is for code change #%d (version %s).' % (n, sha[:7]))
            if _queue(ctx, 'coverage:%d:%s' % (n, sha), 'coverage', emb, 'Every attack type and its rules', cov.details_text(rep['snapshot']), kind='coverage', image=png):
                made.append('coverage:%d:%s' % (n, sha))
        ctx.store.put('ci_done', done_key, {'status': 'done'})
    return made
