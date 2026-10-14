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
from core.console import plain as pl
from core.console import playbooks as pbk
from core.console.fields import first, getf
from core.console.redact import scrub, scrub_keep
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


def safe(res):
    # Everything bound for Discord is masked. The real target stays in state and still drives the plan.
    # Button labels are left alone: they carry ids that must round-trip exactly.
    for k in ('text', 'dm'):
        if k in res:
            res[k] = scrub(res[k])
    if res.get('card'):
        res['card']['text'] = scrub(res['card']['text'])
    if res.get('thread'):
        res['thread']['starter'] = scrub(res['thread']['starter'])
        res['thread']['buttons']['text'] = scrub(res['thread']['buttons']['text'])
    return res


def _label(ctx, user_id):
    return ctx.who(user_id)


def _card(text, blocks):
    return {'reusable': True, 'text': text, 'blocks': blocks}


NOOP = {'rule is not in this playbook trigger': 'this kind of alert is not handled by that lockdown',
        'no target to act on': 'the event does not name an account to act on',
        'protected target is never contained automatically': 'that account is protected and is never locked down automatically'}


def _noop(reason):
    if reason.startswith('benign'):
        return 'the activity looks routine (%s)' % reason.partition(': ')[2]
    if reason.startswith('trigger condition not met') or reason.startswith('excluded by condition'):
        return 'the event does not match what that lockdown is built for'
    return NOOP.get(reason, 'the safety checks said no (%s)' % reason)


def _done(ctx, text, key, title, body):
    i = pl.stash(ctx.store, key, title, body)
    return {'ok': True, 'text': text, 'card': pl.details_card(i, text)}


def _headline(doc):
    return pl.alert_headline({'rule_id': doc.get('rule_id'), 'rule_name': doc.get('rule_name', 'a detection rule'), 'target': None})[0]


def _action(ctx, sid, action_id, user_id):
    doc = ctx.store.get('alert', sid)
    if doc is None:
        return {'ok': False, 'text': 'I do not recognise alert `%s` \u2014 it may be too old.' % sid}
    role = _label(ctx, user_id)
    if not role:
        return {'ok': False, 'text': 'Only approved people can use these buttons, and you are not on the approver list yet.'}
    pack = pk.by_name(doc['pack'])
    act = next((a for a in pack['actions'] if a['id'] == action_id), None)
    if not act:
        return {'ok': False, 'text': 'That step is not available for %s alerts.' % pack['name']}
    run_id = uuid.uuid4().hex
    if action_id == 'acknowledge':
        try:
            ctx.kb.request('POST', '/api/detection_engine/signals/status', {'signal_ids': [doc['alert_doc_id']], 'status': 'acknowledged'})
            kb_note = 'It is now shown as acknowledged in Kibana too.'
        except RuntimeError as e:
            kb_note = 'Kibana could not be updated, so only our own record changed.'
        rec = ctx.audit.write(actor=role, action='acknowledge', playbook='acknowledge', run_id=run_id, alert_id=sid, rule_id=doc['rule_id'], result='acknowledged')
        ctx.store.update('alert', sid, status='acknowledged')
        text = '\u2705 **Marked as seen** by %s: %s\nThis only records that someone looked; nothing in your cloud changed. %s' % (role, _headline(doc), kb_note)
        return _done(ctx, text, 'ack:' + run_id, 'Audit record: marked as seen', pl.as_json(rec))
    if action_id == 'investigate':
        d = al.describe({'kibana.alert.rule.name': doc['rule_name'], 'kibana.alert.severity': doc['severity']}, doc['event'], pack, ctx.attack, ctx.cfg, ctx.env.get('LAB_KIBANA_PUBLIC', ''))
        principal = d['actor'] if pack['provider'] == 'aws' else (first(doc['event'], pack['fields']['actor']) or d['actor'])
        raw = en.enrich(ctx.es, str(principal), '6h')
        raw_id = pl.stash(ctx.store, 'enrich:' + run_id, 'Raw activity record', pl.as_json(raw))
        ctx.audit.write(actor=role, action='investigate', playbook='investigate', run_id=run_id, alert_id=sid, rule_id=doc['rule_id'], result='triage thread requested')
        starter = '**Investigation** \u00b7 alert `%s` \u2014 %s\nOpened by %s. Here is what this account did in the last 6 hours.\n\n%s' % (sid, _headline(doc), role, en.render_plain(raw))
        buttons = _card('**Was this a real problem?** Pick one \u2014 it feeds the false-alarm rate on the scorecard.\n\u2022 **Harmless** \u2014 normal activity, not an attack.\n\u2022 **Real problem** \u2014 an attack or mistake worth following up.\n\u2022 **Show raw** \u2014 sends you the raw activity privately.', [{'type': 'actions', 'buttons': [
            {'label': '\u2714 Harmless \u00b7 %s' % sid, 'style': 'success', 'allowedUsers': list(ctx.approvers)},
            {'label': '\u26A0 Real problem \u00b7 %s' % sid, 'style': 'danger', 'allowedUsers': list(ctx.approvers)},
            {'label': '\U0001F50E Show raw \u00b7 %s' % raw_id, 'style': 'secondary'}]}])
        return {'ok': True, 'thread': {'channel': 'lab-shared', 'name': ('look-into-%s-%s' % (sid, doc['rule_name'].lower().replace(' ', '-')))[:90], 'starter': starter, 'buttons': buttons},
                'text': '\U0001F50D Investigation thread opened in #lab-shared for alert `%s`.' % sid}
    pb_id = act.get('playbook')
    _, pb = pk.find_playbook(pb_id)
    r = ctx.gate().request(pb, {'alert_id': sid, 'rule_id': doc['rule_id'], 'event': doc['event']}, role)
    if r['status'] == 'no_op':
        return {'ok': True, 'text': 'Nothing was changed: %s. (Practice run; a record of the request was saved.)' % _noop(r['reason'])}
    will = pl.playbook_will(pb['id'], r['target'])
    card = _card('**\u26A0 Waiting for your approval \u2014 nothing has changed yet.**\n**If you click Confirm, the lab will** %s.\nThis is a **practice run (dry-run)**: the change is only simulated, so the real account is not touched.\n\n**Why:** %s (alert `%s`)\n**Requested by:** %s \u00b7 **Expires:** in 30 minutes\n\u2022 **Confirm** \u2014 runs the practice step.\n\u2022 **Cancel** \u2014 drops the request.\n\u2022 **Show details** \u2014 sends you the exact steps privately.' % (
        will, _headline(doc), sid, role), [{'type': 'actions', 'buttons': [
            {'label': '\u2705 Confirm (practice run) \u00b7 %s' % r['approval_id'], 'style': 'success', 'allowedUsers': list(ctx.approvers)},
            {'label': '\u2716 Cancel \u00b7 %s' % r['approval_id'], 'style': 'secondary', 'allowedUsers': list(ctx.approvers)},
            {'label': '\U0001F50E Show details \u00b7 %s' % r['approval_id'], 'style': 'secondary'}]}])
    return {'ok': True, 'approval_id': r['approval_id'], 'card': card, 'text': 'Waiting for approval: %s (practice run).' % will}


def _confirm(ctx, approval_id, user_id):
    role = _label(ctx, user_id)
    doc = ctx.store.get('approval', approval_id)
    if not doc:
        return {'ok': False, 'text': 'I do not recognise approval `%s`.' % approval_id}
    _, pb = pk.find_playbook(doc['playbook'])
    r = ctx.gate().confirm(approval_id, str(user_id), pb)
    if r['status'] != 'executed':
        return {'ok': False, 'text': 'Nothing was run: %s.' % r.get('reason', r['status'])}
    ok = bool(r['results']) and all('success' in str(x.get('status') or '').lower() for x in r['results'])
    steps = ('All %d automation steps reported success.' % len(r['results'])) if ok else 'Some automation steps did not report success \u2014 click Show details.'
    text = '\U0001F6E1\uFE0F **Done \u2014 practice run only.** %s.\nApproved by **%s**. This lab only simulates the change, so nothing in the real account was touched. %s' % (pl.playbook_done(doc['playbook'], doc['target']), role, steps)
    return {'ok': True, 'text': text, 'card': pl.details_card(approval_id, text)}


def _cancel(ctx, approval_id, user_id):
    role = _label(ctx, user_id)
    doc = ctx.store.get('approval', approval_id)
    if not doc or not role:
        return {'ok': False, 'text': 'That request could not be cancelled.'}
    _, pb = pk.find_playbook(doc['playbook'])
    r = ctx.gate().cancel(approval_id, role, pb)
    if r['status'] != 'cancelled':
        return {'ok': False, 'text': 'Not cancelled: %s.' % r.get('reason')}
    text = '\u2716 **Cancelled** by %s. The request to %s was dropped; nothing changed.' % (role, pl.playbook_will(doc['playbook'], doc['target']))
    return {'ok': True, 'text': text, 'card': pl.details_card(approval_id, text)}


def _verdict(ctx, sid, kind, user_id):
    role = _label(ctx, user_id)
    doc = ctx.store.get('alert', sid)
    if not role or not doc or kind not in ('benign', 'true_positive'):
        return {'ok': False, 'text': 'That answer could not be recorded.'}
    rec = ctx.audit.write(actor=role, action='verdict_' + kind, playbook='triage', run_id=uuid.uuid4().hex, alert_id=sid, rule_id=doc['rule_id'], result=kind.replace('_', ' '))
    ctx.store.update('alert', sid, status=kind)
    word = 'harmless (a false alarm)' if kind == 'benign' else 'a real problem'
    text = 'Recorded: alert `%s` was judged **%s** by %s. This feeds the false-alarm rate on the scorecard.' % (sid, word, role)
    return _done(ctx, text, 'verdict:' + rec['run_id'], 'Audit record: verdict', pl.as_json(rec))


def details(ctx, id_, user_id=None):
    """The technical record behind a message. Returned as a private message for the clicker, never posted in the channel."""
    d = ctx.store.get('detail', id_)
    if d:
        title, body = d['title'], d['body']
    elif ctx.store.get('alert', id_):
        a = ctx.store.get('alert', id_)
        pack = pk.by_name(a['pack'])
        public = ctx.env.get('LAB_KIBANA_PUBLIC', '')
        ev = a['event']
        link = None
        try:
            link = al.kibana_link(public, pack, first(ev, pack['id_field']), first(ev, pack['time_field']))
        except Exception:
            pass
        title = 'Technical record for alert ' + id_
        body = scrub_keep('Rule: %s (%s)\nSeverity: %s\nAttack technique: %s\nStatus: %s\nKibana: %s\n\nRaw event:\n%s' % (
            a['rule_name'], a['rule_id'], a['severity'], pl.tech_plain(a.get('technique'), ctx.attack), a['status'], link or 'n/a', pl.as_json(ev)), [public.rstrip('/')] if public else [])
    elif ctx.store.get('approval', id_):
        a = ctx.store.get('approval', id_)
        try:
            recs = [h['_source'] for h in ctx.es.request('POST', '/%s/_search' % ctx.cfg['indices']['audit'], {'size': 20, 'sort': [{'@timestamp': 'asc'}], 'query': {'term': {'run_id': a['run_id']}}})['hits']['hits']]
        except Exception:
            recs = [x for x in getattr(ctx.audit, 'records', []) if x.get('run_id') == a['run_id']]
        title = 'Technical record for approval ' + id_
        body = scrub('Status: %s\nPlaybook: %s@%s\nTarget: %s\nSteps (simulated):\n%s\n\nAudit records:\n%s' % (
            a['status'], a['playbook'], a['playbook_version'], a['target'], pl.as_json(a['plan']), pl.as_json(recs)))
    else:
        return {'ok': False, 'text': 'That record has expired or does not exist.'}
    return {'ok': True, 'dm': pl.dm_text(title, body), 'text': 'Sent to you privately.', 'title': title}


def action(ctx, sid, action_id, user_id):
    return safe(_action(ctx, sid, action_id, user_id))


def confirm(ctx, approval_id, user_id):
    return safe(_confirm(ctx, approval_id, user_id))


def cancel(ctx, approval_id, user_id):
    return safe(_cancel(ctx, approval_id, user_id))


def verdict(ctx, sid, kind, user_id):
    return safe(_verdict(ctx, sid, kind, user_id))
