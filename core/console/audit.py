"""Audit trail. Every playbook outcome writes one record, including no-ops and refusals."""
from core.console.store import now_iso

REQUIRED = ('@timestamp', 'actor', 'action', 'approver', 'playbook', 'run_id', 'result')


class MemoryAudit:
    def __init__(self):
        self.records = []

    def write(self, **rec):
        rec.setdefault('@timestamp', now_iso())
        rec.setdefault('approver', None)
        rec.setdefault('mode', 'dry-run')
        missing = [k for k in REQUIRED if k not in rec]
        if missing:
            raise ValueError('audit record missing %s' % missing)
        self.records.append(rec)
        return rec


class ElasticAudit(MemoryAudit):
    def __init__(self, es, index):
        super().__init__()
        self.es, self.index = es, index

    def write(self, **rec):
        rec = super().write(**rec)
        self.es.request('POST', '/%s/_doc?refresh=wait_for' % self.index, rec)
        return rec


def line(rec):
    who = 'approver=%s' % rec['approver'] if rec.get('approver') else 'actor=%s' % rec['actor']
    tag = '(dry-run \u00b7 lab)' if rec.get('mode', 'dry-run') == 'dry-run' else '(LIVE)'
    pb = '%s@%s' % (rec['playbook'], rec['playbook_version']) if rec.get('playbook_version') else rec['playbook']
    extra = ' \u00b7 shuffle %s' % rec['execution_id'][:8] if rec.get('execution_id') else ''
    return 'AUDIT %s \u00b7 %s \u00b7 run %s \u00b7 %s \u00b7 %s \u00b7 %s %s%s' % (
        rec['@timestamp'], pb, str(rec['run_id'])[:8], who, rec['action'], rec['result'], tag, extra)
