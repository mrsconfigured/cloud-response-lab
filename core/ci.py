"""CI-side reporting: per-test results with timings (the playbook UAT matrix) and the detection backtest."""
import contextlib
import datetime as dt
import json
import sys
import time
import unittest
from pathlib import Path

from core import packs as pk


class TimedResult(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.rows, self._t0 = [], {}

    def startTest(self, test):
        super().startTest(test)
        self._t0[test.id()] = time.perf_counter()

    def _row(self, test, status, detail=None):
        ms = round((time.perf_counter() - self._t0.get(test.id(), time.perf_counter())) * 1000)
        self.rows.append({'id': test.id(), 'status': status, 'ms': ms, 'detail': (detail or '')[:300]})

    def addSuccess(self, test):
        super().addSuccess(test)
        self._row(test, 'pass')

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self._row(test, 'fail', str(err[1]))

    def addError(self, test, err):
        super().addError(test, err)
        self._row(test, 'error', str(err[1]))

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self._row(test, 'fail', str(err[1]))


def run_suite(root, start, pattern='test_*.py'):
    root = Path(root)
    sys.path.insert(0, str(root))
    # tests/ is a plain directory of modules; packs/ and core/tests are packages rooted at the repo
    top = root if (root / start / '__init__.py').is_file() else root / start
    suite = unittest.TestLoader().discover(str(root / start), pattern=pattern, top_level_dir=str(top))
    res = TimedResult()
    with contextlib.redirect_stdout(sys.stderr):   # some legacy tests print progress; stdout must stay clean JSON
        suite.run(res)
    # a test that failed in a subtest was recorded as fail already; keep one row per test id, worst status wins
    rank = {'pass': 0, 'fail': 1, 'error': 2}
    best = {}
    for r in res.rows:
        cur = best.get(r['id'])
        if cur is None or rank[r['status']] > rank[cur['status']]:
            best[r['id']] = r
    return list(best.values())


def playbook_matrix(rows):
    out = []
    for r in rows:
        tail = r['id'].split('.')[-1]
        if '__' not in tail:
            continue
        key, case = tail[len('test_'):].split('__', 1)
        out.append({'playbook': key.replace('_', '-'), 'case': case, 'status': r['status'], 'ms': r['ms']})
    return sorted(out, key=lambda x: (x['playbook'], x['case']))


def report(root, sha=None):
    root = Path(root)
    det = run_suite(root, 'packs', 'test_detections.py')
    pbs = run_suite(root, 'packs', 'test_playbooks.py')
    plat = run_suite(root, 'tests') + run_suite(root, 'core/tests') if (root / 'core/tests').is_dir() else run_suite(root, 'tests')
    summ = lambda rows: {'passed': sum(1 for r in rows if r['status'] == 'pass'), 'total': len(rows), 'failed': [r['id'].split('.')[-1] for r in rows if r['status'] != 'pass']}
    return {'sha': sha, 'at': dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'detections': summ(det), 'playbooks': summ(pbs),
            'platform': summ(plat), 'matrix': playbook_matrix(pbs)}


def backtest_real(es, root, baseline):
    """Each baseline entry names a rule and a real event id that the rule must still match. Baseline lives on the lab host, not in the repo."""
    gen = Path(root) / 'library/generated'
    matrix = {m['slug']: m for m in json.loads((gen / 'matrix.json').read_text())}
    rules = {r['rule_id']: r for r in json.loads((gen / 'rules.json').read_text())}
    results = []
    for entry in baseline:
        m = matrix.get(entry['rule'])
        if not m:
            results.append({'rule': entry['rule'], 'ok': False, 'why': 'rule no longer exists'})
            continue
        rule = rules[m['id']]
        pack = next(p for p in pk.packs(root) if p['provider'] == m['provider'])
        q = '(%s) AND %s:"%s"' % (rule['query'], pack['id_field'], entry['event_id'])
        r = es.request('POST', '/%s/_search' % rule['index'][0], {'size': 0, 'track_total_hits': True, 'query': {'query_string': {'query': q, 'default_operator': 'AND', 'analyze_wildcard': True, 'lenient': True}}})
        results.append({'rule': entry['rule'], 'ok': r['hits']['total']['value'] >= 1})
    return {'passed': sum(1 for x in results if x['ok']), 'total': len(results), 'failed': [x['rule'] for x in results if not x['ok']]}


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(prog='core.ci')
    p.add_argument('--root', default=str(pk.ROOT))
    p.add_argument('--sha')
    p.add_argument('--out')
    a = p.parse_args(argv)
    rep = report(a.root, a.sha)
    text = json.dumps(rep, indent=1)
    if a.out:
        Path(a.out).write_text(text)
    print(text)
    return 0 if not (rep['detections']['failed'] or rep['playbooks']['failed'] or rep['platform']['failed']) else 1


if __name__ == '__main__':
    sys.exit(main())
