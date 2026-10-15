"""Response-as-code runner.

A playbook is a versioned JSON file in packs/<pack>/playbooks/. This module is the only code that decides
whether it applies to an alert, asks for approval, and runs it. Properties enforced here and asserted by tests:
  1. it acts only on events that match its trigger,
  2. it halts for approval before any change (the executor is never called before confirm),
  3. it no-ops on benign or non-matching events,
  4. every outcome writes an audit record.
Everything runs in dry-run mode. live.supported is false in every shipped playbook."""
import datetime as dt
import uuid

from core.console.fields import getf
from core.console.store import now_iso

APPROVAL_TTL_SECONDS = 1800
SCHEMA_KEYS = ('schema_version', 'id', 'version', 'pack', 'title', 'trigger', 'target', 'approval', 'steps', 'mode', 'live')


class PlaybookError(ValueError):
    pass


def validate(pb):
    missing = [k for k in SCHEMA_KEYS if k not in pb]
    if missing:
        raise PlaybookError('playbook %s missing %s' % (pb.get('id'), missing))
    if pb['mode'] != 'dry_run':
        raise PlaybookError('only dry_run is allowed')
    if pb['live'].get('supported') is not False:
        raise PlaybookError('live execution must be explicitly unsupported')
    if pb['approval'].get('required') is not True:
        raise PlaybookError('approval must be required')
    if not pb['steps'] or any('id' not in s or 'action' not in s for s in pb['steps']):
        raise PlaybookError('steps need id and action')
    if not pb['trigger'].get('rule_ids'):
        raise PlaybookError('trigger.rule_ids is required so a playbook never acts on an arbitrary event')
    if 'path' not in pb['target']:
        raise PlaybookError('target.path is required')
    return True


def _cond(event, c):
    v = getf(event, c['path'])
    if 'equals' in c:
        return v == c['equals']
    if 'in' in c:
        return v in c['in']
    if 'contains' in c:
        return isinstance(v, str) and c['contains'] in v
    if 'startswith' in c:
        return isinstance(v, str) and v.startswith(c['startswith'])
    if 'exists' in c:
        return (v not in (None, '')) == bool(c['exists'])
    raise PlaybookError('unknown condition %s' % c)


def evaluate(pb, alert, protected=()):
    """Return {'match': bool, 'reason': str, 'target': str|None}. Pure; never touches anything."""
    event = alert.get('event') if isinstance(alert, dict) else None
    if not isinstance(event, dict):
        return {'match': False, 'reason': 'no event', 'target': None}
    trig = pb['trigger']
    if alert.get('rule_id') not in trig['rule_ids']:
        return {'match': False, 'reason': 'rule is not in this playbook trigger', 'target': None}
    ev = trig.get('event', {})
    for c in ev.get('all_of', []):
        if not _cond(event, c):
            return {'match': False, 'reason': 'trigger condition not met: %s' % c['path'], 'target': None}
    for c in ev.get('none_of', []):
        if _cond(event, c):
            return {'match': False, 'reason': 'excluded by condition: %s' % c['path'], 'target': None}
    target = getf(event, pb['target']['path'])
    if not isinstance(target, str) or not target.strip():
        return {'match': False, 'reason': 'no target to act on', 'target': None}
    for c in pb.get('benign', {}).get('any_of', []):
        if _cond(event, c):
            return {'match': False, 'reason': 'benign: %s' % c.get('why', c['path']), 'target': target}
    if target in set(protected) | set(pb.get('protected_targets', [])):
        return {'match': False, 'reason': 'protected target is never contained automatically', 'target': target}
    return {'match': True, 'reason': 'matches trigger', 'target': target}


def _render(text, target):
    return text.replace('{target}', target)


def plan(pb, target):
    return [{'id': s['id'], 'action': s['action'], 'params': {k: _render(str(v), target) for k, v in s.get('params', {}).items()}}
            for s in pb['steps']]


class Gate:
    """Approval gate. store/audit/executor are injected so tests use fakes and production uses Elastic + Shuffle."""

    def __init__(self, store, audit, executor, approvers, protected=(), clock=None):
        self.store, self.audit, self.executor = store, audit, executor
        self.approvers = dict(approvers)            # approver id -> role label
        self.protected = tuple(protected)
        self.clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))

    def _rec(self, pb, run_id, action, result, **kw):
        return self.audit.write(playbook=pb['id'], playbook_version=pb['version'], run_id=run_id, action=action, result=result, **kw)

    def request(self, pb, alert, requested_by):
        validate(pb)
        run_id = uuid.uuid4().hex
        ev = evaluate(pb, alert, self.protected)
        base = dict(actor=requested_by, alert_id=alert.get('alert_id'), rule_id=alert.get('rule_id'))
        if not ev['match']:
            self._rec(pb, run_id, 'no_op', 'no action taken: ' + ev['reason'], **base)
            return {'status': 'no_op', 'run_id': run_id, 'reason': ev['reason']}
        approval_id = uuid.uuid4().hex[:12]
        now = self.clock()
        prompt = _render(pb['approval']['prompt'], ev['target'])
        doc = {'approval_id': approval_id, 'run_id': run_id, 'status': 'pending', 'playbook': pb['id'], 'playbook_version': pb['version'],
               'pack': pb['pack'], 'alert_id': alert.get('alert_id'), 'rule_id': alert.get('rule_id'), 'target': ev['target'],
               'prompt': prompt, 'plan': plan(pb, ev['target']), 'requested_by': requested_by,
               'expires_at': (now + dt.timedelta(seconds=APPROVAL_TTL_SECONDS)).strftime('%Y-%m-%dT%H:%M:%SZ'),
               'created_at': now.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'}
        self.store.put('approval', approval_id, doc)
        self._rec(pb, run_id, 'approval_requested', 'awaiting approval; nothing has changed', **base)
        return {'status': 'awaiting_approval', 'approval_id': approval_id, 'run_id': run_id, 'prompt': prompt, 'plan': doc['plan'], 'target': ev['target']}

    def confirm(self, approval_id, approver, pb):
        doc = self.store.get('approval', approval_id)
        if doc is None:
            raise PlaybookError('unknown approval')
        label = self.approvers.get(approver, 'unauthorised')
        base = dict(actor=doc['requested_by'], approver=label, approver_id=approver, alert_id=doc['alert_id'], rule_id=doc['rule_id'])
        if doc['status'] != 'pending':
            self._rec(pb, doc['run_id'], 'confirm_refused', 'refused: approval already %s' % doc['status'], **base)
            return {'status': 'refused', 'reason': 'approval already %s' % doc['status'], 'run_id': doc['run_id']}
        if approver not in self.approvers:
            self._rec(pb, doc['run_id'], 'confirm_refused', 'refused: approver not authorised', **base)
            return {'status': 'refused', 'reason': 'approver not authorised', 'run_id': doc['run_id']}
        if self.clock().strftime('%Y-%m-%dT%H:%M:%SZ') > doc['expires_at']:
            self.store.update('approval', approval_id, status='expired')
            self._rec(pb, doc['run_id'], 'confirm_refused', 'refused: approval expired', **base)
            return {'status': 'refused', 'reason': 'approval expired', 'run_id': doc['run_id']}
        self.store.update('approval', approval_id, status='executing')
        result = self.executor.run(pb, doc['run_id'], {'target': doc['target'], 'plan': doc['plan'], 'mode': 'dry_run', 'approved_by': self.approvers[approver]})
        self.store.update('approval', approval_id, status='executed', approver=label, executed_at=now_iso(), execution_id=result.get('execution_id'))
        rec = self._rec(pb, doc['run_id'], 'executed', 'simulated: %d step(s)' % len(doc['plan']), execution_id=result.get('execution_id'), **base)
        return {'status': 'executed', 'run_id': doc['run_id'], 'execution_id': result.get('execution_id'), 'results': result.get('results', []), 'audit': rec, 'plan': doc['plan']}

    def cancel(self, approval_id, who, pb):
        doc = self.store.get('approval', approval_id)
        if doc is None:
            raise PlaybookError('unknown approval')
        base = dict(actor=doc['requested_by'], approver=who, alert_id=doc['alert_id'], rule_id=doc['rule_id'])
        if doc['status'] != 'pending':
            return {'status': 'refused', 'reason': 'approval already %s' % doc['status'], 'run_id': doc['run_id']}
        self.store.update('approval', approval_id, status='cancelled')
        rec = self._rec(pb, doc['run_id'], 'cancelled', 'cancelled; nothing changed', **base)
        return {'status': 'cancelled', 'run_id': doc['run_id'], 'audit': rec}


class FakeExecutor:
    """Test double: records calls, never touches anything."""

    def __init__(self):
        self.calls = []

    def run(self, pb, run_id, payload):
        self.calls.append({'playbook': pb['id'], 'run_id': run_id, 'payload': payload})
        return {'status': 'FINISHED', 'execution_id': 'fake-' + run_id[:8], 'results': [{'label': s['id'], 'status': 'SUCCESS'} for s in payload['plan']]}
