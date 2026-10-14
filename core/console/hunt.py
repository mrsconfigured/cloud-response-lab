"""/hunt <lucene query or technique id>: ad-hoc hunt on real indices, a one-line verdict, and a detection-candidate stub."""
import datetime as dt
import json
import re
import uuid
from pathlib import Path

from core import packs as pk
from core.console.fields import first, getf
from core.console import plain as pl
from core.console.queries import TECH, esc, index_pattern, parse_window, rel
from core.console.redact import clean, mask_ip, scrub
from core.console.store import now_iso

BT = chr(96)


def _rules_for_technique(tech, root=pk.ROOT):
    gen = Path(root) / 'library/generated'
    matrix = json.loads((gen / 'matrix.json').read_text())
    rules = {r['rule_id']: r for r in json.loads((gen / 'rules.json').read_text())}
    return [(m['slug'], rules[m['id']]['query']) for m in matrix if m['technique'].upper() == tech.upper() and m['id'] in rules]


def hunt(es, store, query, window='7d', size=10, now=None, root=pk.ROOT):
    window, secs = parse_window(window, '7d')
    now = now or dt.datetime.now(dt.timezone.utc)
    query = (query or '').strip()
    if not query:
        raise ValueError('give a Lucene query (eventName:CreateAccessKey) or a technique id (T1098.001)')
    label, lucene, techs = query, query, []
    if TECH.match(query):
        rules = _rules_for_technique(query, root)
        if not rules:
            return {'hunt_id': None, 'query': query, 'window': window, 'total': 0, 'verdict': 'No rule maps to %s yet. Try a Lucene query such as eventName:CreateAccessKey.' % query.upper(), 'rows': []}
        lucene = ' OR '.join('(%s)' % q for _, q in rules)
        label = '%s via %d rule(s): %s' % (query.upper(), len(rules), ', '.join(s for s, _ in rules))
        techs = [query.upper()]
    body = {'size': size, 'track_total_hits': True, 'sort': [{'@timestamp': 'desc'}],
            'query': {'bool': {'filter': [{'range': {'@timestamp': {'gte': 'now-' + window}}},
                                          {'query_string': {'query': lucene, 'default_operator': 'AND', 'analyze_wildcard': True, 'lenient': True}}]}},
            'aggs': {'ops': {'terms': {'field': 'eventName', 'size': 5}}, 'aops': {'terms': {'field': 'activityDisplayName', 'size': 5}},
                     'users': {'terms': {'field': 'userIdentity.userName.keyword', 'size': 5}}, 'roles': {'terms': {'field': 'userIdentity.sessionContext.sessionIssuer.userName.keyword', 'size': 5}},
                     'upn': {'terms': {'field': 'initiatedBy.user.userPrincipalName.keyword', 'size': 5}},
                     'idx': {'terms': {'field': '_index', 'size': 5}}, 'mn': {'min': {'field': '@timestamp'}}, 'mx': {'max': {'field': '@timestamp'}}}}
    r = es.request('POST', '/%s/_search' % index_pattern(), body)
    total = r['hits']['total']['value']
    hunt_id = uuid.uuid4().hex[:8]
    packs = pk.packs(root)
    rows = []
    for h in r['hits']['hits']:
        pack = next((p for p in packs if h['_index'].startswith(p['index'])), None)
        s = h['_source']
        f = pack['fields'] if pack else {}
        rows.append({'time': (first(s, pack['time_field']) if pack else s.get('@timestamp')) or '', 'pack': pack['name'] if pack else '?',
                     'op': str(first(s, f.get('operation')) or '?'), 'actor': scrub(str(first(s, f.get('actor')) or '?')),
                     'src': mask_ip(first(s, f.get('source_ip')) or '') or '', 'id': first(s, pack['id_field']) if pack else None, 'doc': h['_id']})
    ag = r.get('aggregations', {})
    top = lambda k: [(b['key'], b['doc_count']) for b in ag.get(k, {}).get('buckets', [])]
    actors = {}
    for k in ('users', 'roles', 'upn'):
        for key, n in top(k):
            actors[scrub(str(key))] = actors.get(scrub(str(key)), 0) + n
    ops = top('ops') + top('aops')
    covered = []
    if total:
        docs = [x['doc'] for x in rows if x.get('doc')]
        if docs:
            # an alert records the _id of the document that triggered it, so this is exact, not a text match
            ar = es.request('POST', '/.alerts-security.alerts-default/_search', {'size': 50, 'query': {'terms': {'kibana.alert.ancestors.id': docs}}, '_source': ['kibana.alert.rule.name']})
            covered = sorted({getf(a['_source'], 'kibana.alert.rule.name') for a in ar['hits']['hits'] if getf(a['_source'], 'kibana.alert.rule.name')})
    first_ts, last_ts = ag.get('mn', {}).get('value_as_string'), ag.get('mx', {}).get('value_as_string')
    def ago(ts):
        return rel((now - dt.datetime.fromisoformat(ts.replace('Z', '+00:00'))).total_seconds(), now) + ' ago' if ts else 'n/a'
    if not total:
        verdict = 'No results in the last %s.' % window
    else:
        verdict = '%d match(es) across %d principal(s); first %s, last %s; mostly %s. %s' % (
            total, len(actors), ago(first_ts), ago(last_ts), ', '.join('%s x%d' % (k, n) for k, n in ops[:3]) or 'n/a',
            ('Already covered by: ' + ', '.join(covered) + '.') if covered else 'No alert fired on the events shown: a detection candidate.')
    store.put('hunt', hunt_id, {'status': 'open', 'query': query, 'lucene': lucene, 'label': label, 'window': window, 'techs': techs, 'total': total,
                                'top_pack': (rows[0]['pack'] if rows else None), 'created_at': now_iso()})
    return clean({'hunt_id': hunt_id, 'query': label, 'window': window, 'total': total, 'verdict': verdict, 'rows': rows, 'covered': covered})


def render(h):
    lines = ['**Hunt** ' + BT + str(h['query'])[:160] + BT + ' \u00b7 last ' + h['window'] + ' \u00b7 **%d** match(es)' % h['total'], '**Verdict:** ' + h['verdict']]
    for x in h['rows'][:8]:
        lines.append('\u2022 ' + BT + (x['time'] or '')[5:19].replace('T', ' ') + BT + ' %s \u00b7 %s%s' % (x['op'], x['actor'], (' \u00b7 ' + x['src']) if x['src'] else ''))
    if h.get('hunt_id') and h['total']:
        lines.append('Save this as a detection candidate with the button below (hunt ' + BT + h['hunt_id'] + BT + ').')
    return '\n'.join(lines)


def render_plain(h):
    """Verdict first: did anything match, and is it already covered by a rule?"""
    w = h['window']
    if not h['total']:
        return pl.say('**Nothing matched** in the last %s, so there is nothing to act on.' % w)
    if h.get('covered'):
        verdict = '**Found %d matching event%s** in the last %s. A rule already catches these (%s), so no new detection is needed.' % (h['total'], '' if h['total'] == 1 else 's', w, ', '.join(h['covered']))
    else:
        verdict = '**Found %d matching event%s** in the last %s and **no alert fired on the ones shown** \u2014 this could be a gap in our detection. You can turn the search into a draft detection with the button below.' % (h['total'], '' if h['total'] == 1 else 's', w)
    lines = [verdict, '**Most recent:**']
    for x in h['rows'][:8]:
        lines.append('\u2022 %s \u2014 %s did: %s%s' % ((x['time'] or '')[5:19].replace('T', ' '), x['actor'], pl.op_plain(x['op']), (' (from ' + x['src'] + ')') if x['src'] else ''))
    return pl.say('\n'.join(lines))


_TERM = re.compile(r'^([A-Za-z_][A-Za-z0-9_.]*):("([^"]*)"|[^\s()]+)$')


def candidate_stub(h):
    """A Sigma stub for the hunt. Simple field:value AND-queries become a real selection; anything else is kept as a comment."""
    terms, simple = [], True
    for tok in re.split(r'\s+AND\s+|\s+', h['lucene'].strip()):
        if tok.upper() in ('AND', ''):
            continue
        m = _TERM.match(tok)
        if not m or '*' in tok or tok.startswith('('):
            simple = False
            break
        terms.append((m.group(1), m.group(3) if m.group(3) is not None else m.group(2)))
    pack = h.get('top_pack') or 'aws'
    sel = ('\n'.join('    %s: %s' % (k, json.dumps(v)) for k, v in terms)) if simple and terms else '    # TODO translate: ' + h['lucene'].replace('\n', ' ')[:200] + '\n    eventName: "TODO"'
    tags = ''.join('  - attack.%s\n' % t.lower() for t in h.get('techs', [])) or '  - attack.TODO\n'
    prov = 'aws' if pack == 'aws' else 'azure'
    svc = 'cloudtrail' if pack == 'aws' else 'auditlogs'
    slug = 'candidate-' + h['key']
    text = ('title: ' + json.dumps('Hunt candidate ' + h['key']) + '\nid: ' + str(uuid.uuid5(uuid.NAMESPACE_URL, 'hunt:' + h['key'])) + '\nstatus: experimental\n'
            'description: ' + json.dumps('Candidate promoted from an ad-hoc hunt. Needs review, tests and tuning before it ships. Hunt window %s, %d match(es) when saved.' % (h['window'], h['total'])) + '\n'
            'author: lab-console\ndate: ' + dt.date.today().isoformat() + '\ntags:\n' + tags + 'logsource:\n  product: ' + prov + '\n  service: ' + svc + '\ndetection:\n  selection:\n' + sel +
            '\n  condition: selection\nfalsepositives:\n  - "Unknown: review required"\nlevel: medium\n')
    return {'pack': pack, 'slug': slug, 'path': 'packs/%s/detections/candidates/%s.yml' % (pack, slug), 'text': text, 'simple': simple}
