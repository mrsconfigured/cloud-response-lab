"""Runs a playbook's dry-run workflow in Shuffle and reads the result back. Real execution, no side effects."""
import json
import time

from core import shuffle_export


class ShuffleExecutor:
    def __init__(self, http, timeout=120, poll=3):
        self.http, self.timeout, self.poll = http, timeout, poll

    def workflow_id(self, pb):
        name = shuffle_export.workflow_name(pb)
        for w in self.http.request('GET', '/api/v1/workflows'):
            if w.get('name') == name:
                return w['id']
        return None

    def ensure(self, pb):
        wid = self.workflow_id(pb)
        wf = shuffle_export.export(pb)
        if wid:
            wf['id'] = wid
            self.http.request('PUT', '/api/v1/workflows/' + wid, wf)
            return wid, 'updated'
        created = self.http.request('POST', '/api/v1/workflows', wf)
        wid = created.get('id') or wf['id']
        self.http.request('PUT', '/api/v1/workflows/' + wid, dict(wf, id=wid))
        return wid, 'created'

    def run(self, pb, run_id, payload):
        wid = self.workflow_id(pb) or self.ensure(pb)[0]
        arg = json.dumps(dict(payload, playbook=pb['id'], run_id=run_id))
        started = self.http.request('POST', '/api/v1/workflows/%s/execute' % wid, {'execution_argument': arg})
        eid = started.get('execution_id')
        if not eid:
            raise RuntimeError('shuffle did not start an execution: %s' % started)
        deadline = time.time() + self.timeout
        last = {}
        while time.time() < deadline:
            time.sleep(self.poll)
            for e in self.http.request('GET', '/api/v1/workflows/%s/executions' % wid):
                if e.get('execution_id') == eid:
                    last = e
            if last.get('status') in ('FINISHED', 'ABORTED', 'FAILURE', 'ERROR'):
                break
        results = [{'label': (r.get('action') or {}).get('label'), 'status': r.get('status'), 'result': (r.get('result') or '')[:300]} for r in last.get('results', [])]
        return {'status': last.get('status', 'UNKNOWN'), 'execution_id': eid, 'results': results}
