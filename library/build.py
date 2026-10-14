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

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'library/generated'
ACCOUNT = '111111111111'
TENANT = '00000000-0000-4000-8000-000000000001'
STAMP = '2026-10-14T01:00:00Z'


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


def documents():
    for path in sorted((ROOT / 'detections/sigma').glob('*.yml')):
        raw = yaml.safe_load(path.read_text())
        collection = SigmaCollection.from_yaml(path.read_text())
        yield path.stem, raw, collection


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
    for slug, raw, collection in documents():
        if raw['id'] in ids: raise ValueError('duplicate Sigma rule id')
        ids.add(raw['id'])
        query, = LuceneBackend().convert(collection)
        cases = fixtures(slug, raw)
        ast = collection.rules[0].detection.parsed_condition[0].parsed
        for case in cases:
            if evaluate(ast, case['event']) != case['expected']:
                raise ValueError(slug + ': ' + case['name'])
        provider = 'aws' if raw['logsource']['product'] == 'aws' else 'entra'
        index = 'logs-cloud-response-lab-library-' + provider
        tech = next(t.split('attack.')[1].upper() for t in raw['tags'] if t.startswith('attack.t1'))
        exports.append({'rule_id': raw['id'], 'name': raw['title'], 'description': raw['description'],
                        'type': 'query', 'language': 'lucene', 'query': query, 'index': [index],
                        'enabled': False, 'interval': '1m', 'from': 'now-10m', 'risk_score': 73,
                        'severity': 'high', 'actions': [], 'tags': raw['tags'] + ['synthetic-library']})
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
                                'rule_count': len(exports), 'source_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT / 'detections/sigma').glob('*.yml'))}}}
    # Explicit mappings avoid text analyzer false parity; arrays are not queried here.
    fields = {}
    for _, raw, _ in documents():
        fields.update({k: {'type': 'keyword'} for k in raw['detection']['selection']})
    fields.update({'errorCode': {'type': 'keyword'}, '@timestamp': {'type': 'date'}})
    result['index-template.json'] = {'index_patterns': ['logs-cloud-response-lab-library-*'], 'priority': 502,
                                     'template': {'mappings': {'properties': fields}}}
    return result


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    result = build()
    for name, value in result.items():
        (OUT / name).write_text(json.dumps(value, indent=2) + chr(10))
    rows = result['matrix.json']
    print(f"{len(rows)} genuine Sigma rules; {sum(r['positive'] for r in rows)} positive / {sum(r['negative'] for r in rows)} negative AST fixtures; live query parity NOT claimed")


if __name__ == '__main__':
    main()
