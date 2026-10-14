"""Rules deploy and drift check. The repo (packs/*/detections + core/config.json -> library/generated/rules.json)
is the source of truth; Kibana must match it. verify() returns every difference, so deployed == repo is provable."""
import json
from pathlib import Path

from core import packs as pk

FIELDS = ('name', 'description', 'type', 'language', 'query', 'index', 'enabled', 'interval', 'from', 'risk_score', 'severity')


def desired(root=pk.ROOT):
    return json.loads((Path(root) / 'library/generated/rules.json').read_text())


def deployed(kb):
    out, page = {}, 1
    while True:
        r = kb.request('GET', '/api/detection_engine/rules/_find?per_page=100&page=%d' % page)
        for rule in r['data']:
            out[rule['rule_id']] = rule
        if page * 100 >= r['total']:
            return out
        page += 1


def _norm(rule):
    n = {k: rule.get(k) for k in FIELDS}
    n['tags'] = sorted(rule.get('tags') or [])
    return n


def verify(kb, root=pk.ROOT):
    want = {r['rule_id']: r for r in desired(root)}
    have = deployed(kb)
    legacy = set(pk.config(root).get('deploy', {}).get('legacy_rule_ids', []))
    diffs = []
    for rid, w in want.items():
        h = have.get(rid)
        if h is None:
            diffs.append({'rule_id': rid, 'name': w['name'], 'problem': 'missing in Kibana'})
            continue
        a, b = _norm(w), _norm(h)
        for k in a:
            if a[k] != b[k]:
                diffs.append({'rule_id': rid, 'name': w['name'], 'field': k, 'repo': a[k] if k != 'query' else a[k][:60] + '...', 'kibana': b[k] if k != 'query' else str(b[k])[:60] + '...'})
    for rid, h in have.items():
        if rid not in want and rid not in legacy:
            diffs.append({'rule_id': rid, 'name': h['name'], 'problem': 'in Kibana but not in the repo'})
    return {'repo_rules': len(want), 'kibana_rules': len(have), 'enabled_in_repo': sum(1 for r in want.values() if r['enabled']),
            'enabled_in_kibana': sum(1 for rid, h in have.items() if rid in want and h['enabled']), 'diffs': diffs, 'match': not diffs}


def apply(kb, root=pk.ROOT):
    have = deployed(kb)
    changed = []
    for w in desired(root):
        body = {k: w[k] for k in ('rule_id', 'name', 'description', 'type', 'language', 'query', 'index', 'enabled', 'interval', 'from', 'risk_score', 'severity', 'tags', 'actions')}
        body['author'] = ['lab-library']
        body['license'] = 'MIT'
        if w['rule_id'] in have:
            if _norm(w) == _norm(have[w['rule_id']]):
                continue
            body.pop('rule_id')
            body['id'] = have[w['rule_id']]['id']
            kb.request('PUT', '/api/detection_engine/rules', body)
            changed.append((w['rule_id'], 'updated'))
        else:
            kb.request('POST', '/api/detection_engine/rules', body)
            changed.append((w['rule_id'], 'created'))
    return changed
