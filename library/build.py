"""Real pySigma compilation plus a deliberately bounded parsed-AST test oracle.
The oracle is NOT Lucene execution. Unknown AST/value types fail closed.
"""
import copy
import hashlib
import json
import uuid
from importlib.metadata import version
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import LuceneBackend
from sigma.conditions import ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression
from sigma.types import SigmaString, SigmaNull
from lab import field
from core import packs as pk

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'library/generated'
ACCOUNT = '111111111111'
TENANT = '00000000-0000-4000-8000-000000000001'
STAMP = '2026-10-14T01:00:00Z'
CFG = pk.config(ROOT)


def evaluate(node, event):
    if isinstance(node, ConditionAND):
        return all(evaluate(x, event) for x in node.args)
    if isinstance(node, ConditionOR):
        return any(evaluate(x, event) for x in node.args)
    if isinstance(node, ConditionNOT):
        return not evaluate(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        value = field(event, node.field)
        if isinstance(node.value, SigmaNull):
            return value is None
        if isinstance(node.value, SigmaString) and not node.value.contains_special():
            return value == str(node.value)
    raise ValueError('unsupported Sigma AST or value; no permissive fallback')


def put(event, key, value):
    parts = key.split('.')
    for part in parts[:-1]:
        event = event.setdefault(part, {})
    event[parts[-1]] = value


def rule_paths():
    for pack in pk.packs(ROOT):
        yield from sorted(pack['detections_dir'].glob('*.yml'))


def documents_full():
    for pack in pk.packs(ROOT):
        for path in sorted(pack['detections_dir'].glob('*.yml')):
            raw = yaml.safe_load(path.read_text())
            collection = SigmaCollection.from_yaml(path.read_text())
            yield pack, path.stem, raw, collection


def documents():
    for _, slug, raw, collection in documents_full():
        yield slug, raw, collection


def fixtures(slug, raw):
    """Explicit provider envelope; independent expected labels and adversarial mutations."""
    aws = raw['logsource']['product'] == 'aws'
    event = ({'eventVersion': '1.11', 'eventTime': STAMP, 'eventID': str(uuid.uuid5(uuid.NAMESPACE_URL, 'synthetic:' + slug)),
              'recipientAccountId': ACCOUNT, 'awsRegion': 'us-east-1',
              'userIdentity': {'type': 'IAMUser', 'accountId': ACCOUNT, 'userName': 'lab-actor'}}
             if aws else {'id': str(uuid.uuid5(uuid.NAMESPACE_URL, 'synthetic:' + slug)), 'activityDateTime': STAMP, 'tenantId': TENANT,
                          'initiatedBy': {'user': {'id': TENANT, 'userPrincipalName': 'synthetic@example.invalid'}},
                          'targetResources': [{'id': TENANT, 'type': 'ServicePrincipal' if 'credential' in slug else 'DirectoryRole' if 'role' in slug else 'Policy'}]})
    selection = raw['detection']['selection']
    for key, val in selection.items():
        put(event, key, val[0] if isinstance(val, list) else val)
    cases = [{'name': 'successful-operation', 'expected': True, 'event': event}]
    # Exercise every OR branch, not just the first administrator attachment.
    for key, val in selection.items():
        if isinstance(val, list):
            for item in val[1:]:
                changed = copy.deepcopy(event); put(changed, key, item)
                cases.append({'name': 'branch-' + item, 'expected': True, 'event': changed})
    for key in selection:
        changed = copy.deepcopy(event); put(changed, key, 'unrelated-value')
        cases.append({'name': 'wrong-' + key, 'expected': False, 'event': changed})
        changed = copy.deepcopy(event)
        parent = changed
        parts = key.split('.')
        for part in parts[:-1]: parent = parent[part]
        del parent[parts[-1]]
        cases.append({'name': 'missing-' + key, 'expected': False, 'event': changed})
    changed = copy.deepcopy(event)
    changed['errorCode' if aws else 'result'] = 'AccessDenied' if aws else 'failure'
    cases.append({'name': 'failed-operation', 'expected': False, 'event': changed})
    if aws:
        changed = copy.deepcopy(event); changed['errorCode'] = ''
        cases.append({'name': 'present-empty-error', 'expected': False, 'event': changed})
    cases.append({'name': 'other-provider-envelope', 'expected': False,
                  'event': {'activityDisplayName': event.get('eventName'), 'result': 'success'} if aws
                  else {'eventSource': 'iam.amazonaws.com', 'eventName': event.get('activityDisplayName')}})
    return cases


def build():
    exports, matrix, all_cases, contracts = [], [], {}, []
    techniques = {}
    ids = set()
    for pack, slug, raw, collection in documents_full():
        if raw['id'] in ids: raise ValueError('duplicate Sigma rule id')
        ids.add(raw['id'])
        query, = LuceneBackend().convert(collection)
        cases = fixtures(slug, raw)
        ast = collection.rules[0].detection.parsed_condition[0].parsed
        for case in cases:
            if evaluate(ast, case['event']) != case['expected']:
                raise ValueError(slug + ': ' + case['name'])
        provider = pack['provider']
        index = pack['index']
        severity = CFG['severity_map'][raw.get('level', 'high')]
        tech = next(t.split('attack.')[1].upper() for t in raw['tags'] if t.startswith('attack.t1'))
        exports.append({'rule_id': raw['id'], 'name': raw['title'], 'description': raw['description'],
                        'type': 'query', 'language': 'lucene', 'query': query, 'index': [index],
                        'enabled': slug in pack['enabled_rules'], 'interval': CFG['rule_defaults']['interval'],
                        'from': CFG['rule_defaults']['from'], 'risk_score': CFG['risk_score_map'][severity],
                        'severity': severity, 'actions': [], 'tags': raw['tags'] + ['lab-library']})
        row = {'slug': slug, 'id': raw['id'], 'provider': provider, 'logsource': raw['logsource'],
               'technique': tech, 'positive': sum(c['expected'] for c in cases),
               'negative': sum(not c['expected'] for c in cases), 'query_engine_live': False}
        matrix.append(row); all_cases[slug] = cases
        techniques.setdefault(tech, []).append(slug)
        contracts.append({'id': slug, 'rule_id': raw['id'], 'provider': provider,
                          'scope': ACCOUNT if provider == 'aws' else TENANT, 'max_age_seconds': 600,
                          'mode': 'dry_run', 'automatic_actions': [],
                          'review_prompt': 'Verify actor, target, authorization and evidence; do not remediate automatically.'})
    layer = {'name': 'Synthetic cloud lab — offline coverage, not efficacy', 'domain': 'enterprise-attack',
             'versions': {'layer': '4.5', 'navigator': '5.1.0'}, 'description': 'Technique mappings are behavioral hypotheses. Scores count rules, not coverage percentage; new rules lack live query proof.',
             'techniques': [{'techniqueID': t, 'score': len(slugs), 'enabled': True,
                             'comment': 'Offline pySigma AST replay only: ' + ', '.join(slugs)}
                            for t, slugs in sorted(techniques.items())]}
    result = {'rules.json': exports, 'matrix.json': matrix, 'fixtures.json': all_cases,
              'response-contracts.json': contracts, 'navigator.json': layer,
              'compiler.json': {'compiler': 'pySigma', 'version': version('pysigma'),
                                'backend_version': version('pysigma-backend-elasticsearch'),
                                'test_engine': 'bounded pySigma parsed AST; NOT Elasticsearch',
                                'rule_count': len(exports), 'source_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in rule_paths()}}}
    # Explicit mappings avoid text analyzer false parity; arrays are not queried here.
    fields = {}
    for _, raw, _ in documents():
        fields.update({k: {'type': 'keyword'} for k in raw['detection']['selection']})
    fields.update({'errorCode': {'type': 'keyword'}, '@timestamp': {'type': 'date'}})
    result['index-template.json'] = {'index_patterns': ['logs-cloud-response-lab-library-*'], 'priority': 502,
                                     'template': {'mappings': {'properties': fields}}}
    return result


def pack_layers():
    # One ATT&CK Navigator layer per pack, derived only from that pack's own rule files.
    names = pk.attack_names(ROOT)
    layers = {}
    for pack in pk.packs(ROOT):
        techs = {}

        def add(path, kind):
            raw = yaml.safe_load(path.read_text())
            tech = next(t.split('attack.')[1].upper() for t in raw['tags'] if t.startswith('attack.t1'))
            techs.setdefault(tech, {'enabled': [], 'disabled': [], 'fixture_only': []})[kind].append(path.stem)

        for path in sorted(pack['detections_dir'].glob('*.yml')):
            add(path, 'enabled' if path.stem in pack['enabled_rules'] else 'disabled')
        signin = pack['detections_dir'] / 'signin'
        if signin.is_dir():
            for path in sorted(signin.glob('*.yml')):
                add(path, 'fixture_only')
        rows = []
        for tech, groups in sorted(techs.items()):
            if groups['enabled']:
                color, note = '#31a354', 'enabled on real data: ' + ', '.join(groups['enabled'])
            elif groups['disabled']:
                color, note = '#fdae6b', 'rule exists but disabled: ' + ', '.join(groups['disabled'])
            else:
                color, note = '#bdbdbd', 'FIXTURE ONLY (' + pack.get('fixture_only_reason', 'no live data source') + '): ' + ', '.join(groups['fixture_only'])
            rows.append({'techniqueID': tech, 'score': len(groups['enabled']), 'color': color, 'enabled': True,
                         'comment': names.get(tech, {}).get('name', tech) + ' | ' + note})
        layers[pack['name']] = {'name': pack['log_source'] + ' pack', 'domain': 'enterprise-attack',
                                'versions': {'layer': '4.5', 'navigator': '5.1.0'},
                                'description': 'Green = enabled rule on a live source. Orange = rule disabled. Grey = fixture only. Mappings are hypotheses, not a coverage percentage.',
                                'techniques': rows}
    return layers


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, layer in pack_layers().items():
        (ROOT / 'packs' / name / 'attack-layer.json').write_text(json.dumps(layer, indent=2) + chr(10))
    result = build()
    for name, value in result.items():
        (OUT / name).write_text(json.dumps(value, indent=2) + chr(10))
    rows = result['matrix.json']
    print(f"{len(rows)} genuine Sigma rules; {sum(r['positive'] for r in rows)} positive / {sum(r['negative'] for r in rows)} negative AST fixtures; live query parity NOT claimed")


if __name__ == '__main__':
    main()
