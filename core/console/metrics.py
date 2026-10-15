"""Daily SOC scorecard from real data only. A value that cannot be computed is reported as n/a, never a placeholder."""
import datetime as dt
import json
import statistics
from pathlib import Path

from core import packs as pk
from core.console.fields import getf
from core.console.queries import rel


def _t(s):
    return dt.datetime.fromisoformat(s.replace('Z', '+00:00'))


def _summ(xs):
    if not xs:
        return None
    xs = sorted(xs)
    return {'n': len(xs), 'median': statistics.median(xs), 'p90': xs[min(len(xs) - 1, int(0.9 * len(xs)))]}


def scorecard(es, store, audit_index, now=None, root=pk.ROOT):
    now = now or dt.datetime.now(dt.timezone.utc)
    res = {'at': now.strftime('%Y-%m-%dT%H:%M:%SZ')}
    ar = es.request('POST', '/.alerts-security.alerts-default/_search', {'size': 500, 'sort': [{'@timestamp': 'asc'}],
            'query': {'range': {'@timestamp': {'gte': 'now-7d'}}}, '_source': ['@timestamp', 'kibana.alert.original_time', 'kibana.alert.uuid', 'kibana.alert.rule.name', 'kibana.alert.severity']})
    alerts = [h['_source'] for h in ar['hits']['hits']]
    day = [a for a in alerts if _t(a['@timestamp']) >= now - dt.timedelta(hours=24)]
    res['alerts_24h'] = len(day)
    res['alerts_by_severity_24h'] = {}
    for a in day:
        s = getf(a, 'kibana.alert.severity') or '?'
        res['alerts_by_severity_24h'][s] = res['alerts_by_severity_24h'].get(s, 0) + 1
    lags = []
    for a in alerts:
        o = getf(a, 'kibana.alert.original_time')
        if o:
            lags.append(max(0.0, (_t(a['@timestamp']) - _t(o)).total_seconds()))
    res['mttd'] = _summ(lags)
    # response times and verdicts come from the audit index
    ra = es.request('POST', '/%s/_search' % audit_index, {'size': 1000, 'sort': [{'@timestamp': 'asc'}], 'query': {'range': {'@timestamp': {'gte': 'now-30d'}}}})
    recs = [h['_source'] for h in ra['hits']['hits']]
    alert_docs = {d['key']: d for d in store.list('alert', limit=1000)}
    ttr, tta, verdicts = [], [], {'benign': 0, 'true_positive': 0}
    seen_r, seen_a = set(), set()
    for r in recs:
        aid = r.get('alert_id')
        doc = alert_docs.get(aid)
        if r['action'] == 'executed' and aid and doc and aid not in seen_r:
            seen_r.add(aid)
            ttr.append(max(0.0, (_t(r['@timestamp']) - _t(doc['alert_time'])).total_seconds()))
        if r['action'] == 'acknowledge' and aid and doc and aid not in seen_a:
            seen_a.add(aid)
            tta.append(max(0.0, (_t(r['@timestamp']) - _t(doc['alert_time'])).total_seconds()))
        if r['action'] in ('verdict_benign', 'verdict_true_positive'):
            verdicts['benign' if r['action'] == 'verdict_benign' else 'true_positive'] += 1
    res['mttr'] = _summ(ttr)
    res['mtta'] = _summ(tta)
    tot = sum(verdicts.values())
    res['false_positive_rate'] = {'benign': verdicts['benign'], 'triaged': tot, 'rate': (verdicts['benign'] / tot) if tot else None}
    uat = store.get('uat_last', 'latest')
    res['playbooks'] = {'passed': uat.get('passed'), 'total': uat.get('total'), 'at': uat.get('at')} if uat else None
    cov = {}
    for p in pk.packs(root):
        layer = json.loads((Path(root) / 'packs' / p['name'] / 'attack-layer.json').read_text())
        for t in layer['techniques']:
            cov.setdefault(t['techniqueID'], 0)
            cov[t['techniqueID']] += t['score']
    res['techniques'] = {'mapped': len(cov), 'enabled': sum(1 for v in cov.values() if v > 0)}
    return res


def render(s, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    def d(x):
        return ('%s (median of %d, p90 %s)' % (rel(x['median'], now), x['n'], rel(x['p90'], now))) if x else 'n/a (nothing to measure yet)'
    fp = s['false_positive_rate']
    pb = s['playbooks']
    return {'MTTD (event to alert, includes CloudTrail delivery)': d(s['mttd']), 'MTTR (alert to first dry-run containment)': d(s['mttr']), 'MTTA (alert to acknowledge)': d(s['mtta']),
            'Alerts, last 24h': '%d%s' % (s['alerts_24h'], (' (' + ', '.join('%s %d' % kv for kv in sorted(s['alerts_by_severity_24h'].items())) + ')') if s['alerts_24h'] else ''),
            'False-positive rate': ('%d%% (%d benign of %d triaged)' % (round(100 * fp['rate']), fp['benign'], fp['triaged'])) if fp['triaged'] else 'n/a (no triaged verdicts yet)',
            'Playbooks passing': ('%s/%s (UAT run %s)' % (pb['passed'], pb['total'], (pb['at'] or '')[:16])) if pb else 'n/a (no UAT run recorded)',
            'ATT&CK techniques with an enabled rule': '%d of %d mapped' % (s['techniques']['enabled'], s['techniques']['mapped'])}
