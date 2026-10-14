"""Console behaviours. Each function returns plain data; the CLI prints it and the gateway-side poster/agent ships it to Discord."""
import datetime as dt
import json
import uuid

from core import packs as pk
from core.console import alerts as al
from core.console import audit as au
from core.console import enrich as en
from core.console import es as eslib
from core.console import outbox as ob
from core.console import playbooks as pbk
from core.console.fields import first, getf
from core.console.shuffle import ShuffleExecutor
from core.console.store import ElasticStore, now_iso


class Ctx:
    def __init__(self, env=None):
        self.env = env or eslib.load_env()
        self.cfg = pk.config()
        self.packs = pk.packs()
        self.attack = pk.attack_names()
        self.es = eslib.elastic(self.env)
        self._kb = self._admin = self._sh = None
        self.store = ElasticStore(self.es, self.cfg['indices']['state'])
        self.audit = au.ElasticAudit(self.es, self.cfg['indices']['audit'])
        self.approvers = {}
        for part in (self.env.get('LAB_APPROVERS') or '').split(','):
            if ':' in part:
                uid, _, role = part.strip().partition(':')
                self.approvers[uid] = role
        self.protected = tuple(x for x in (self.env.get('LAB_PROTECTED_TARGETS') or '').split(',') if x)

    @property
    def kb(self):
        if self._kb is None:
            self._kb = eslib.kibana(self.env, admin=True)
        return self._kb

    @property
    def shuffle(self):
        if self._sh is None:
            self._sh = eslib.shuffle(self.env)
        return self._sh

    def gate(self):
        return pbk.Gate(self.store, self.audit, ShuffleExecutor(self.shuffle), self.approvers, self.protected)

    def who(self, user_id):
        return self.approvers.get(str(user_id))


def poll_alerts(ctx, limit=25):
    """New detection-engine alerts -> alert state + outbox entries. Idempotent."""
    r = ctx.es.request('POST', '/.alerts-security.alerts-default/_search', {'size': 200, 'sort': [{'@timestamp': 'asc'}], 'query': {'match_all': {}}})
    made = []
    for h in r['hits']['hits']:
        a = h['_source']
        uuid_ = getf(a, 'kibana.alert.uuid') or h['_id']
        sid = al.short(uuid_)
        if ctx.store.exists('alert', sid):
            continue
        anc = (getf(a, 'kibana.alert.ancestors') or [{}])[0]
        index, doc_id = anc.get('index'), anc.get('id')
        pack = al.pack_for_index(index, ctx.packs)
        source = {}
        if pack and doc_id:
            try:
                source = ctx.es.request('GET', '/%s/_doc/%s' % (index, doc_id)).get('_source', {})
            except RuntimeError:
                source = {}
        if not source:
            source = a
        if not pack:
            continue
        post = al.build_post(dict(a, _id=h['_id']), source, pack, ctx.attack, ctx.cfg, ctx.env.get('LAB_KIBANA_PUBLIC', ctx.env['LAB_KIBANA_URL']), list(ctx.approvers))
        d = post['summary']
        ctx.store.put('alert', sid, {'status': 'open', 'alert_uuid': uuid_, 'alert_doc_id': h['_id'], 'pack': pack['name'], 'rule_id': d['rule_id'],
                                     'rule_name': d['rule_name'], 'severity': d['severity'], 'event': source, 'alert_time': a.get('@timestamp'), 'technique': d['technique']})
        ob.enqueue(ctx.store, 'alert:' + sid, post)
        made.append(sid)
        if len(made) >= limit:
            break
    return made


def _label(ctx, user_id):
    role = ctx.who(user_id)
    return role


def _card(text, blocks):
    return {'reusable': True, 'text': text, 'blocks': blocks}


def action(ctx, sid, action_id, user_id):
    doc = ctx.store.get('alert', sid)
    if doc is None:
        return {'ok': False, 'text': 'Unknown alert `%s`.' % sid}
    role = _label(ctx, user_id)
    if not role:
        return {'ok': False, 'text': 'You are not an approver for this lab.'}
    pack = pk.by_name(doc['pack'])
    act = next((a for a in pack['actions'] if a['id'] == action_id), None)
    if not act:
        return {'ok': False, 'text': 'That action is not available for %s alerts.' % pack['name']}
    run_id = uuid.uuid4().hex
    if action_id == 'acknowledge':
        try:
            ctx.kb.request('POST', '/api/detection_engine/signals/status', {'signal_ids': [doc['alert_doc_id']], 'status': 'acknowledged'})
            kb_note = 'Kibana status set to acknowledged.'
        except RuntimeError as e:
            kb_note = 'Kibana status not changed (%s).' % str(e)[:60]
        rec = ctx.audit.write(actor=role, action='acknowledge', playbook='acknowledge', run_id=run_id, alert_id=sid, rule_id=doc['rule_id'], result='acknowledged')
        ctx.store.update('alert', sid, status='acknowledged')
        return {'ok': True, 'text': '\u2705 Alert `%s` acknowledged by **%s**. %s\n%s' % (sid, role, kb_note, au.line(rec))}
    if action_id == 'investigate':
        d = al.describe({'kibana.alert.rule.name': doc['rule_name'], 'kibana.alert.severity': doc['severity']}, doc['event'], pack, ctx.attack, ctx.cfg, ctx.env.get('LAB_KIBANA_PUBLIC', ''))
        principal = d['actor'] if pack['provider'] == 'aws' else (first(doc['event'], pack['fields']['actor']) or d['actor'])
        summary = en.render(en.enrich(ctx.es, str(principal), '6h'))
        ctx.audit.write(actor=role, action='investigate', playbook='investigate', run_id=run_id, alert_id=sid, rule_id=doc['rule_id'], result='triage thread requested')
        starter = '**Triage \u00b7 `%s`** \u2014 %s \u00b7 %s \u00b7 ATT&CK %s\nOpened by %s.\n\n%s' % (sid, doc['rule_name'], doc['severity'].upper(), doc['technique'] or 'n/a', role, summary)
        buttons = _card('**Verdict** for alert `%s` \u2014 this feeds the false-positive rate.' % sid, [{'type': 'actions', 'buttons': [
            {'label': '\u2714 Benign \u00b7 %s' % sid, 'style': 'success', 'allowedUsers': list(ctx.approvers)},
            {'label': '\u26A0 True positive \u00b7 %s' % sid, 'style': 'danger', 'allowedUsers': list(ctx.approvers)}]}])
        return {'ok': True, 'thread': {'channel': 'lab-shared', 'name': ('triage-%s-%s' % (sid, doc['rule_name'].lower().replace(' ', '-')))[:90], 'starter': starter, 'buttons': buttons},
                'text': '\U0001F50D Triage thread opened in #lab-shared for `%s`.' % sid}
    pb_id = act.get('playbook')
    _, pb = pk.find_playbook(pb_id)
    r = ctx.gate().request(pb, {'alert_id': sid, 'rule_id': doc['rule_id'], 'event': doc['event']}, role)
    if r['status'] == 'no_op':
        return {'ok': True, 'text': 'No action taken: %s. (audit recorded, dry-run \u00b7 lab)' % r['reason']}
    steps = '\n'.join('\u2022 `%s` \u2014 %s' % (s['action'], ', '.join('%s=%s' % kv for kv in s['params'].items())) for s in r['plan'])
    card = _card('**\u26A0 Approval required** \u00b7 `%s` \u00b7 playbook `%s@%s`\n%s\n\n**Exactly what will change** (simulated, **dry-run \u00b7 lab**):\n%s\n\nRequested by %s. Expires in 30 minutes. Nothing has changed yet.' % (
        sid, pb['id'], pb['version'], r['prompt'], steps, role), [{'type': 'actions', 'buttons': [
            {'label': '\u2705 Confirm \u00b7 %s' % r['approval_id'], 'style': 'success', 'allowedUsers': list(ctx.approvers)},
            {'label': '\u2716 Cancel \u00b7 %s' % r['approval_id'], 'style': 'secondary', 'allowedUsers': list(ctx.approvers)}]}])
    return {'ok': True, 'approval_id': r['approval_id'], 'card': card, 'text': 'Approval required for %s (dry-run).' % pb['id']}


def confirm(ctx, approval_id, user_id):
    role = _label(ctx, user_id)
    doc = ctx.store.get('approval', approval_id)
    if not doc:
        return {'ok': False, 'text': 'Unknown approval `%s`.' % approval_id}
    _, pb = pk.find_playbook(doc['playbook'])
    r = ctx.gate().confirm(approval_id, str(user_id), pb)
    if r['status'] != 'executed':
        return {'ok': False, 'text': 'Not run: %s.' % r.get('reason', r['status'])}
    steps = ' \u2192 '.join('%s %s' % (x.get('label'), (x.get('status') or '').lower()) for x in r['results']) or 'no step results returned'
    rec = r['audit']
    return {'ok': True, 'text': '\U0001F6E1\uFE0F **Executed (dry-run \u00b7 lab)** `%s` on %s. Approved by **%s**. Shuffle steps: %s.\n%s' % (doc['playbook'], doc['target'], role, steps, au.line(rec))}


def cancel(ctx, approval_id, user_id):
    role = _label(ctx, user_id)
    doc = ctx.store.get('approval', approval_id)
    if not doc or not role:
        return {'ok': False, 'text': 'Cannot cancel that approval.'}
    _, pb = pk.find_playbook(doc['playbook'])
    r = ctx.gate().cancel(approval_id, role, pb)
    if r['status'] != 'cancelled':
        return {'ok': False, 'text': 'Not cancelled: %s.' % r.get('reason')}
    return {'ok': True, 'text': '\u2716 Cancelled by **%s**. Nothing changed.\n%s' % (role, au.line(r['audit']))}


def verdict(ctx, sid, kind, user_id):
    role = _label(ctx, user_id)
    doc = ctx.store.get('alert', sid)
    if not role or not doc or kind not in ('benign', 'true_positive'):
        return {'ok': False, 'text': 'Cannot record that verdict.'}
    rec = ctx.audit.write(actor=role, action='verdict_' + kind, playbook='triage', run_id=uuid.uuid4().hex, alert_id=sid, rule_id=doc['rule_id'], result=kind.replace('_', ' '))
    ctx.store.update('alert', sid, status=kind)
    return {'ok': True, 'text': 'Verdict recorded for `%s`: **%s** (by %s).\n%s' % (sid, kind.replace('_', ' '), role, au.line(rec))}
