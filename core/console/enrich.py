"""/enrich principal <id> window:<1h>: timeline plus a key / MFA / technique-chain summary from real CloudTrail and Entra data."""
import datetime as dt

from core import packs as pk
from core.console.fields import first, getf
from core.console.queries import esc, parse_window, rel
from core.console import plain as pl
from core.console.redact import clean, mask_ip, scrub


def _principal_query(pack, principal):
    q = esc(principal)
    if pack['provider'] == 'aws':
        return '(userIdentity.userName:%s OR userIdentity.sessionContext.sessionIssuer.userName:%s OR requestParameters.userName:%s OR userIdentity.arn:*%s*)' % (q, q, q, q)
    return '(initiatedBy.user.userPrincipalName:%s OR initiatedBy.app.displayName:%s OR targetResources.userPrincipalName:%s OR targetResources.displayName:%s)' % (q, q, q, q)


def enrich(es, principal, window='1h', limit=40, now=None):
    window, secs = parse_window(window)
    now = now or dt.datetime.now(dt.timezone.utc)
    rows, techniques, keys, mfa = [], [], [], set()
    total = 0
    for pack in pk.packs():
        body = {'size': limit, 'sort': [{'@timestamp': 'desc'}], 'track_total_hits': True,
                'query': {'bool': {'filter': [{'range': {'@timestamp': {'gte': 'now-' + window}}},
                                              {'query_string': {'query': _principal_query(pack, principal), 'analyze_wildcard': True, 'lenient': True}}]}}}
        try:
            r = es.request('POST', '/%s/_search' % pack['index'], body)
        except RuntimeError:
            continue
        total += r['hits']['total']['value']
        f = pack['fields']
        for h in r['hits']['hits']:
            s = h['_source']
            op = first(s, f['operation']) or '?'
            err = first(s, f.get('error')) if pack['provider'] == 'aws' else (None if getf(s, f.get('error')) == 'success' else getf(s, f.get('error')))
            rows.append({'time': first(s, pack['time_field']) or s.get('@timestamp'), 'pack': pack['name'], 'op': str(op),
                         'src': mask_ip(first(s, f.get('source_ip')) or '') or '', 'ok': not err})
            if op == 'CreateAccessKey':
                ak = getf(s, 'responseElements.accessKey.accessKeyId') or ''
                keys.append('key ending ' + ak[-4:] if ak else 'key created')
            m = getf(s, 'userIdentity.sessionContext.attributes.mfaAuthenticated')
            m2 = getf(s, 'additionalEventData.MFAUsed')
            if m is not None:
                mfa.add('session MFA ' + str(m))
            if m2 is not None:
                mfa.add('console MFA ' + str(m2))
    rows.sort(key=lambda x: x['time'] or '', reverse=True)
    # technique chain from alerts that touched this principal in the window
    ar = es.request('POST', '/.alerts-security.alerts-default/_search', {'size': 50, 'sort': [{'@timestamp': 'asc'}], 'query': {'bool': {'filter': [{'range': {'@timestamp': {'gte': 'now-' + window}}}]}}})
    for h in ar['hits']['hits']:
        s = h['_source']
        tags = getf(s, 'kibana.alert.rule.tags') or []
        tech = next((t.split('attack.')[1].upper() for t in tags if t.startswith('attack.t1')), None)
        blob = str(s).lower()
        if tech and principal.lower() in blob:
            techniques.append(tech)
    chain = []
    for t in techniques:
        if not chain or chain[-1] != t:
            chain.append(t)
    return clean({'principal': principal, 'window': window, 'events': total, 'timeline': rows[:limit], 'access_keys': keys, 'mfa': sorted(mfa), 'technique_chain': chain})


def render(r):
    if not r['events']:
        return '**No results** for principal `%s` in the last %s.' % (r['principal'], r['window'])
    lines = ['**Principal** `%s` \u00b7 last %s \u00b7 %d event(s)' % (r['principal'], r['window'], r['events'])]
    lines.append('**Technique chain:** ' + (' \u2192 '.join(r['technique_chain']) if r['technique_chain'] else 'no detections fired'))
    lines.append('**Access keys:** ' + ('; '.join(r['access_keys']) if r['access_keys'] else 'none created in window'))
    lines.append('**MFA:** ' + ('; '.join(r['mfa']) if r['mfa'] else 'n/a (not present in these events)'))
    lines.append('**Timeline** (newest first, up to 12):')
    for x in r['timeline'][:12]:
        lines.append('\u2022 `%s` %s \u00b7 %s%s' % ((x['time'] or '')[11:19], x['op'], x['pack'], '' if x['ok'] else ' \u00b7 failed'))
    return '\n'.join(lines)


def render_plain(r):
    """Verdict first, then what the account did, in everyday words."""
    if not r['events']:
        return pl.say('I found **no activity** for `%s` in the last %s, so there is nothing to look into.' % (r['principal'], r['window']))
    chain = [pl.TECH_PLAIN.get(t) or pl.TECH_PLAIN.get(t.split('.')[0]) or t for t in r['technique_chain']]
    verdict = ('Detection rules fired on this account, in this order: ' + '; then '.join(chain) + '.') if chain else 'No detection rules fired for this account.'
    lines = ['**%d action%s** by `%s` in the last %s. %s' % (r['events'], '' if r['events'] == 1 else 's', r['principal'], r['window'], verdict)]
    lines.append('**Access keys created:** ' + ('; '.join(r['access_keys']) if r['access_keys'] else 'none in this period.'))
    mfa = []
    for m in r['mfa']:
        used = m.rsplit(' ', 1)[-1].lower() in ('true', 'yes')
        mfa.append(('signed in with a second verification step' if used else 'signed in WITHOUT a second verification step') + (' (console)' if m.startswith('console') else ''))
    lines.append('**Second verification step (multi-factor authentication):** ' + ('; '.join(mfa) if mfa else 'not shown in these events.'))
    lines.append('**What it did** (newest first, up to 12):')
    for x in r['timeline'][:12]:
        lines.append('\u2022 %s \u2014 %s%s' % ((x['time'] or '')[11:19], pl.op_plain(x['op']), '' if x['ok'] else ' (it failed)'))
    return pl.say('\n'.join(lines))
