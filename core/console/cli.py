"""python -m core.console <command>. Prints JSON so the gateway-side poster/agent can ship it."""
import argparse
import json
import subprocess
import sys
import uuid
from pathlib import Path

from core import deploy as deploy_mod
from core import packs as pk
from core.console import alerts as al
from core.console import cipoll, coverage as cov, enrich as en, hunt as hu, metrics as me, outbox as ob, plain as pl, service as sv, status as stt
from core.console.queries import rel
from core.console import audit as au
from core.console import learncli, paths
from core.console.es import Http, load_env
from core.console.shuffle import ShuffleExecutor
from core.console.store import now_iso

STATE_MAPPING = {'mappings': {'properties': {'kind': {'type': 'keyword'}, 'key': {'type': 'keyword'}, 'status': {'type': 'keyword'}, 'created_at': {'type': 'date'},
                                           'payload': {'type': 'object', 'enabled': False}, 'event': {'type': 'object', 'enabled': False}, 'report': {'type': 'object', 'enabled': False},
                                           'snapshot': {'type': 'object', 'enabled': False}, 'plan': {'type': 'object', 'enabled': False}}}}
AUDIT_MAPPING = {'mappings': {'properties': {'@timestamp': {'type': 'date'}, 'actor': {'type': 'keyword'}, 'approver': {'type': 'keyword'}, 'action': {'type': 'keyword'},
                                            'playbook': {'type': 'keyword'}, 'playbook_version': {'type': 'keyword'}, 'run_id': {'type': 'keyword'}, 'alert_id': {'type': 'keyword'},
                                            'rule_id': {'type': 'keyword'}, 'result': {'type': 'text'}, 'mode': {'type': 'keyword'}, 'execution_id': {'type': 'keyword'}}}}


def out(obj):
    print(json.dumps(obj, indent=1, default=str))


def cmd_init(a):
    env = load_env()
    admin = Http(env['LAB_ES_URL'], env['LAB_ADMIN_USER'], env['LAB_ADMIN_PASSWORD'], env.get('LAB_ES_CA'))
    cfg = pk.config()
    res = {}
    for name, mapping in ((cfg['indices']['state'], STATE_MAPPING), (cfg['indices']['audit'], AUDIT_MAPPING)):
        exists = admin.request('HEAD', '/' + name, allow=(404,)) if False else None
        try:
            admin.request('PUT', '/' + name, dict(mapping, settings={'number_of_shards': 1, 'number_of_replicas': 0}))
            res[name] = 'created'
        except RuntimeError as e:
            res[name] = 'exists' if 'resource_already_exists' in str(e) else 'error: ' + str(e)[:120]
    out(res)


def cmd_alerts_poll(a, ctx):
    made = sv.poll_alerts(ctx, a.limit)
    out({'queued': made})


def cmd_outbox_next(a, ctx):
    out(ob.next_batch(ctx.store, a.limit))


def cmd_outbox_ack(a, ctx):
    ob.ack(ctx.store, a.key, a.ids.split(',') if a.ids else [])
    out({'ok': True})


def cmd_outbox_fail(a, ctx):
    out({'status': ob.fail(ctx.store, a.key, a.error)})


def cmd_action(a, ctx):
    out(sv.action(ctx, a.alert, a.action, a.by))


def cmd_details(a, ctx):
    out(sv.details(ctx, a.id, a.by))


def cmd_confirm(a, ctx):
    out(sv.confirm(ctx, a.approval, a.by))


def cmd_cancel(a, ctx):
    out(sv.cancel(ctx, a.approval, a.by))


def cmd_verdict(a, ctx):
    out(sv.verdict(ctx, a.alert, a.kind, a.by))


def cmd_enrich(a, ctx):
    principal = sys.stdin.read().strip() if a.stdin else a.principal
    r = en.enrich(ctx.es, principal, a.window)
    rid = pl.stash(ctx.store, 'enrich:' + uuid.uuid4().hex, 'Raw activity record', pl.as_json(r))
    out({'text': en.render_plain(r), 'card': pl.details_card(rid, label='Show raw') if r['events'] else None})


def cmd_hunt(a, ctx):
    query = sys.stdin.read().strip() if a.stdin else a.query
    r = hu.hunt(ctx.es, ctx.store, query, a.window)
    card = None
    if r['total']:
        raw = pl.stash(ctx.store, 'hunt:' + str(r.get('hunt_id')), 'Raw search and results', pl.as_json({'search': r['query'], 'window': r['window'], 'total': r['total'], 'rows': r['rows'], 'covered_by': r.get('covered')}))
        buttons = [{'label': '\U0001F50E Show raw \u00b7 %s' % raw, 'style': 'secondary'}]
        text = '**Show raw** sends you the exact search and raw results privately.'
        if r.get('hunt_id'):
            buttons.insert(0, {'label': '\U0001F4BE Turn into a draft detection \u00b7 %s' % r['hunt_id'], 'style': 'primary', 'allowedUsers': list(ctx.approvers)})
            text = '**Turn into a draft detection** opens a draft pull request for the team to review; nothing goes live. ' + text
        card = {'reusable': True, 'text': text, 'blocks': [{'type': 'actions', 'buttons': buttons}]}
    out({'text': hu.render_plain(r), 'hunt_id': r.get('hunt_id'), 'total': r['total'], 'card': card})


def cmd_hunt_stub(a, ctx):
    h = ctx.store.get('hunt', a.hunt)
    if not h:
        out({'ok': False, 'text': 'Unknown hunt.'})
        return
    out(dict(hu.candidate_stub(h), ok=True, hunt=h))


def cmd_status(a, ctx):
    s = stt.status(ctx.es, ctx.kb, ctx.shuffle, ctx.store)
    rid = pl.stash(ctx.store, 'status:' + uuid.uuid4().hex, 'Raw status record', pl.as_json(s))
    out({'text': stt.render_plain(s), 'card': pl.details_card(rid, label='Show raw')})


def metrics_embed(s):
    return pl.metrics_embed(s, rel)


def cmd_metrics(a, ctx):
    s = me.scorecard(ctx.es, ctx.store, ctx.cfg['indices']['audit'])
    emb = metrics_embed(s)
    if a.post:
        key = 'metrics:' + s['at'][:10]
        ob.enqueue(ctx.store, key, pl.post_with_details(ctx.store, key, 'metrics', emb, 'Raw scorecard numbers', pl.as_json(s)))
    out({'embed': emb, 'raw': s, 'queued': bool(a.post)})


def cmd_uat_run(a, ctx):
    from core import ci
    rep = ci.report(a.root or pk.ROOT)
    p, d = rep['playbooks'], rep['detections']
    passed, total = p['passed'] + d['passed'], p['total'] + d['total']
    ctx.store.put('uat_last', 'latest', {'passed': p['passed'], 'total': p['total'], 'detection_passed': d['passed'], 'detection_total': d['total'], 'at': now_iso()})
    out({'detections': d, 'playbooks': p, 'platform': rep['platform'], 'stored': True})


def cmd_ci_poll(a, ctx):
    if not ctx.env.get('LAB_GITHUB_REPO'):
        raise SystemExit('LAB_GITHUB_REPO is not set (owner/repo)')
    out({'queued': cipoll.poll(ctx, ctx.env['LAB_GITHUB_REPO'])})


def cmd_coverage_post(a, ctx):
    snap = cov.snapshot(a.root or pk.ROOT)
    old = ctx.store.get('coverage_snapshot', 'latest')
    day = now_iso()[:10]
    key = ('coverage-weekly:' if a.digest else 'coverage-map:') + (day if a.digest else uuid.uuid4().hex[:6])
    png = cov.render_png(snap, str(paths.state_dir() / ('coverage-%s.png' % day)))
    emb, d = cov.embed(snap, old['snapshot'] if old else None, digest=a.digest)
    ob.enqueue(ctx.store, key, pl.post_with_details(ctx.store, key, 'coverage', emb, 'Every attack type and its rules', cov.details_text(snap), kind='coverage', image=png))
    if a.digest or not old:
        ctx.store.put('coverage_snapshot', 'latest', {'snapshot': snap, 'at': now_iso()})
    out({'queued': key, 'diff': d, 'png': png})


def cmd_deploy(a, ctx):
    if a.apply:
        changed = deploy_mod.apply(ctx.kb)
        res = deploy_mod.verify(ctx.kb)
        if changed:
            k = 'rules-deployed:' + now_iso()
            emb = {'title': ('\U0001F680 %d detection rule%s updated in Kibana' % (len(changed), '' if len(changed) == 1 else 's')) if res['match'] else '\u26A0\uFE0F Rules were updated but Kibana does not fully match the code',
                   'color': 3066993 if res['match'] else 15158332,
                   'description': ('The live rules now match the code exactly. %d are switched on.' % res['enabled_in_kibana']) if res['match'] else '%d difference(s) remain between the code and the live rules.' % len(res['diffs'])}
            ob.enqueue(ctx.store, k, pl.post_with_details(ctx.store, k, 'detection-ci', emb, 'Which rules changed', pl.as_json({'changed': changed, 'verify': res})))
        out({'changed': changed, 'verify': res})
    else:
        res = deploy_mod.verify(ctx.kb)
        if a.alert and not res['match']:
            import hashlib
            sig = hashlib.sha256(json.dumps(res['diffs'], sort_keys=True, default=str).encode()).hexdigest()[:10]
            k = 'rule-drift:' + sig
            emb = {'title': '\u26A0\uFE0F The live detection rules no longer match the code', 'color': 15158332,
                   'description': '%d rule setting%s differ between the code and Kibana, so what is running may not be what was reviewed.\n**Suggested next step:** re-apply the code\u2019s rules to Kibana, or fix the code if Kibana is right.' % (len(res['diffs']), '' if len(res['diffs']) == 1 else 's')}
            ob.enqueue(ctx.store, k, pl.post_with_details(ctx.store, k, 'detection-ci', emb, 'What differs', pl.as_json(res['diffs'])))
        out(res)


def cmd_playbooks_deploy(a, ctx):
    ex = ShuffleExecutor(ctx.shuffle)
    res = []
    for p in pk.packs():
        for path in p['playbooks']:
            pb = json.loads(path.read_text())
            wid, how = ex.ensure(pb)
            res.append({'playbook': pb['id'], 'workflow': wid[:8], 'result': how})
    out(res)


def cmd_ingest_record(a, ctx):
    ctx.store.put('ingest_run', '%s:%s' % (a.source, now_iso()), {'source': a.source, 'docs': a.docs, 'errors': a.errors, 'at': now_iso()})
    out({'ok': True})


def main(argv=None):
    p = argparse.ArgumentParser(prog='core.console')
    sub = p.add_subparsers(dest='cmd', required=True)
    sub.add_parser('init')
    s = sub.add_parser('alerts-poll'); s.add_argument('--limit', type=int, default=25)
    s = sub.add_parser('outbox-next'); s.add_argument('--limit', type=int, default=5)
    s = sub.add_parser('outbox-ack'); s.add_argument('key'); s.add_argument('--ids', default='')
    s = sub.add_parser('outbox-fail'); s.add_argument('key'); s.add_argument('--error', default='')
    s = sub.add_parser('action'); s.add_argument('alert'); s.add_argument('action'); s.add_argument('--by', required=True)
    s = sub.add_parser('approval-confirm'); s.add_argument('approval'); s.add_argument('--by', required=True)
    s = sub.add_parser('approval-cancel'); s.add_argument('approval'); s.add_argument('--by', required=True)
    s = sub.add_parser('details'); s.add_argument('id'); s.add_argument('--by', default=None)
    s = sub.add_parser('verdict'); s.add_argument('alert'); s.add_argument('kind'); s.add_argument('--by', required=True)
    s = sub.add_parser('enrich'); s.add_argument('principal', nargs='?'); s.add_argument('--window', default='1h'); s.add_argument('--stdin', action='store_true')
    s = sub.add_parser('hunt'); s.add_argument('query', nargs='?'); s.add_argument('--window', default='7d'); s.add_argument('--stdin', action='store_true')
    s = sub.add_parser('hunt-stub'); s.add_argument('hunt')
    sub.add_parser('lab-status')
    s = sub.add_parser('metrics'); s.add_argument('--post', action='store_true')
    s = sub.add_parser('uat-run'); s.add_argument('--root')
    sub.add_parser('ci-poll')
    s = sub.add_parser('coverage-post'); s.add_argument('--root'); s.add_argument('--digest', action='store_true')
    s = sub.add_parser('deploy-rules'); s.add_argument('--apply', action='store_true'); s.add_argument('--alert', action='store_true')
    sub.add_parser('playbooks-deploy')
    s = sub.add_parser('ingest-record'); s.add_argument('--source', required=True); s.add_argument('--docs', type=int, default=0); s.add_argument('--errors', type=int, default=0)
    learn = learncli.register(sub)
    a = p.parse_args(argv)
    if a.cmd == 'init':
        return cmd_init(a)
    if a.cmd in learn:
        return learn[a.cmd](a)
    ctx = sv.Ctx()
    fn = {'alerts-poll': cmd_alerts_poll, 'outbox-next': cmd_outbox_next, 'outbox-ack': cmd_outbox_ack, 'outbox-fail': cmd_outbox_fail, 'action': cmd_action,
          'approval-confirm': cmd_confirm, 'approval-cancel': cmd_cancel, 'verdict': cmd_verdict, 'details': cmd_details, 'enrich': cmd_enrich, 'hunt': cmd_hunt, 'hunt-stub': cmd_hunt_stub,
          'lab-status': cmd_status, 'metrics': cmd_metrics, 'uat-run': cmd_uat_run, 'ci-poll': cmd_ci_poll, 'coverage-post': cmd_coverage_post,
          'deploy-rules': cmd_deploy, 'playbooks-deploy': cmd_playbooks_deploy, 'ingest-record': cmd_ingest_record}[a.cmd]
    fn(a, ctx)
    return 0
