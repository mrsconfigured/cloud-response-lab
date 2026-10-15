"""/lab_status: stack health from real services."""
import datetime as dt

from core import packs as pk
from core.console import plain as pl
from core.console.fields import getf
from core.console.queries import rel


def _lag(es, index, field='@timestamp'):
    r = es.request('POST', '/%s/_search' % index, {'size': 0, 'aggs': {'mx': {'max': {'field': field}}}, 'track_total_hits': True})
    mx = r['aggregations']['mx'].get('value_as_string')
    return r['hits']['total']['value'], mx


def status(es, kb, shuffle, store, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    out = {'at': now.strftime('%Y-%m-%dT%H:%M:%SZ')}
    h = es.request('GET', '/_cluster/health')
    out['elastic'] = {'status': h['status'], 'nodes': h['number_of_nodes']}
    out['sources'] = []
    for p in pk.packs():
        try:
            n, mx = _lag(es, p['index'])
        except RuntimeError as e:
            out['sources'].append({'pack': p['name'], 'error': str(e)[:80]})
            continue
        lag = (now - dt.datetime.fromisoformat(mx.replace('Z', '+00:00'))).total_seconds() if mx else None
        runs = [d for d in store.list('ingest_run', limit=500) if d.get('source') == p['name']]
        last = max(runs, key=lambda d: d.get('at', '')) if runs else None
        out['sources'].append({'pack': p['name'], 'log_source': p['log_source'], 'docs': n, 'newest_event': mx, 'lag': rel(lag, now),
                               'last_pull': last['at'] if last else None, 'last_pull_docs': last.get('docs') if last else None})
    try:
        rules = kb.request('GET', '/api/detection_engine/rules/_find?per_page=100')['data']
        ok = sum(1 for r in rules if (getf(r, 'execution_summary.last_execution.status') or '') == 'succeeded')
        out['rules'] = {'total': len(rules), 'enabled': sum(1 for r in rules if r['enabled']), 'last_run_ok': ok,
                        'failing': [r['name'] for r in rules if r['enabled'] and (getf(r, 'execution_summary.last_execution.status') or '') == 'failed']}
    except RuntimeError as e:
        out['rules'] = {'error': str(e)[:80]}
    a = es.request('POST', '/.alerts-security.alerts-default/_search', {'size': 0, 'track_total_hits': True, 'query': {'range': {'@timestamp': {'gte': 'now-24h'}}}})
    out['alerts_24h'] = a['hits']['total']['value']
    try:
        sh = shuffle.request('GET', '/api/v1/health')
        out['shuffle'] = 'up' if sh.get('success') else 'degraded'
    except Exception as e:
        out['shuffle'] = 'down (%s)' % str(e)[:40]
    box = store.list('outbox', limit=500)
    out['outbox'] = {'pending': sum(1 for d in box if d['status'] in ('pending', 'posting')), 'failed': sum(1 for d in box if d['status'] == 'failed')}
    uat = store.get('uat_last', 'latest')
    out['playbooks'] = {'passing': uat.get('passed'), 'total': uat.get('total'), 'at': uat.get('at')} if uat else None
    return out


def render(s):
    L = ['**Lab status** \u00b7 ' + s['at']]
    L.append('Elastic: **%s** (%d node)' % (s['elastic']['status'], s['elastic']['nodes']))
    for x in s['sources']:
        if 'error' in x:
            L.append('\u2022 %s: error %s' % (x['pack'], x['error']))
        else:
            L.append('\u2022 %s: %d docs, newest event %s (lag %s), last pull %s' % (x['log_source'], x['docs'], (x['newest_event'] or 'n/a')[:19], x['lag'], (x['last_pull'] or 'never')[:19]))
    r = s['rules']
    L.append('Rules: ' + ('%d enabled of %d, %d ran ok%s' % (r['enabled'], r['total'], r['last_run_ok'], (', FAILING: ' + ', '.join(r['failing'])) if r['failing'] else '') if 'total' in r else 'error ' + r['error']))
    L.append('Alerts (24h): %d \u00b7 Shuffle: %s \u00b7 Discord outbox: %d pending, %d failed' % (s['alerts_24h'], s['shuffle'], s['outbox']['pending'], s['outbox']['failed']))
    L.append('Playbooks passing: ' + ('%s/%s (run %s)' % (s['playbooks']['passing'], s['playbooks']['total'], (s['playbooks']['at'] or '')[:16]) if s['playbooks'] else 'n/a (no UAT run recorded)'))
    return '\n'.join(L)


def render_plain(s):
    problems = []
    if s['elastic']['status'] != 'green':
        problems.append('the search database is ' + s['elastic']['status'])
    if s['shuffle'] != 'up':
        problems.append('the response automation (Shuffle) is ' + s['shuffle'])
    r = s['rules']
    if 'error' in r:
        problems.append('the rule list could not be read')
    elif r['failing']:
        problems.append('rules failing: ' + ', '.join(r['failing']))
    if s['outbox']['failed']:
        problems.append('%d Discord post(s) failed to send' % s['outbox']['failed'])
    for x in s['sources']:
        if 'error' in x:
            problems.append('%s could not be read' % x['pack'])
    L = [('\u2705 **Everything is healthy.**' if not problems else '\u26A0\uFE0F **Needs attention:** ' + '; '.join(problems) + '.')]
    L.append('\u2022 **Search database:** ' + s['elastic']['status'])
    for x in s['sources']:
        if 'error' not in x:
            L.append('\u2022 **%s:** %d records, newest event %s ago' % (x['log_source'], x['docs'], x['lag']))
    L.append('\u2022 **Detection rules:** ' + ('%d of %d switched on, %d ran fine at their last check' % (r['enabled'], r['total'], r['last_run_ok']) if 'total' in r else 'unknown'))
    L.append('\u2022 **Alerts in the last 24 hours:** %d' % s['alerts_24h'])
    L.append('\u2022 **Response automation (Shuffle):** ' + s['shuffle'])
    L.append('\u2022 **Discord posts waiting to send:** %d' % s['outbox']['pending'])
    pb = s['playbooks']
    L.append('\u2022 **Response tests:** ' + ('%s of %s passing' % (pb['passing'], pb['total']) if pb else 'no run recorded yet'))
    return pl.say('\n'.join(L))
