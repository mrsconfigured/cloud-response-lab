"""Offline, deterministic Kibana QueryRuleCreateProps export; not runtime parity."""
import json
from pathlib import Path
from lab import field, load, validate_rule

ROOT = Path(__file__).resolve().parents[1]
MAP = {'eventSource': 'lab.event_source', 'eventName': 'lab.event_name',
       'requestParameters.policyArn': 'lab.policy_arn', 'category': 'lab.category',
       'activityDisplayName': 'lab.activity', 'result': 'lab.result'}


def normalize(raw, provider):
    if provider not in ('aws', 'entra') or not isinstance(raw, dict):
        raise ValueError('unsupported raw event')
    doc = {'lab': {'provider': provider}}
    timestamp = raw.get('eventTime' if provider == 'aws' else 'activityDateTime')
    if isinstance(timestamp, str):
        doc['@timestamp'] = timestamp
    for source, target in MAP.items():
        value = field(raw, source)
        if isinstance(value, str):
            doc['lab'][target.split('.')[1]] = value
        elif value is not None:
            raise ValueError('non-scalar normalized field')
    error = raw.get('errorCode')
    if error is not None:
        if not isinstance(error, str):
            raise ValueError('non-scalar errorCode')
        doc['lab']['error_code'] = error
    return doc


def export(rule):
    validate_rule(rule)
    provider = 'aws' if rule['logsource']['product'] == 'aws' else 'entra'
    terms = ['lab.provider: ' + json.dumps(provider)]
    terms += [MAP[k] + ': ' + json.dumps(v) for k, v in rule['detection']['selection'].items()]
    if 'filter_error' in rule['detection']:
        terms += ['NOT lab.error_code: *']
    return {'rule_id': rule['id'], 'name': rule['title'], 'description': rule['description'],
            'risk_score': 73, 'severity': rule['level'], 'type': 'query', 'language': 'kuery',
            'query': ' AND '.join(terms), 'index': ['logs-personal-lab-*'],
            'enabled': False, 'interval': '5m', 'from': 'now-6m', 'to': 'now',
            'actions': [], 'author': ['Owner A'], 'tags': ['experimental', 'offline-parity-unverified'],
            'false_positives': rule['falsepositives'], 'version': 1,
            'note': 'Owner B reviews every response. No automatic response or external connector.'}


def matches_export(rule, doc):
    """Strict evaluator for ONLY this exporter grammar, NOT a KQL implementation."""
    for term in rule['query'].split(' AND '):
        if term == 'NOT lab.error_code: *':
            if field(doc, 'lab.error_code') is not None:
                return False
        else:
            key, value = term.split(': ', 1)
            if key not in set(MAP.values()) | {'lab.provider'}:
                raise ValueError('unsupported field')
            if field(doc, key) != json.loads(value):
                return False
    return True


def main():
    out = ROOT / 'detections/elastic'
    out.mkdir(exist_ok=True)
    rules = [export(load(p)) for p in sorted((ROOT / 'detections').glob('*.json'))]
    for rule in rules:
        (out / (rule['rule_id'] + '.json')).write_text(json.dumps(rule, indent=2) + chr(10))
    (out / 'rules.ndjson').write_text(''.join(json.dumps(r) + chr(10) for r in rules))
    mapping = {'index_patterns': ['logs-personal-lab-*'], 'template': {'mappings': {
        'dynamic': 'strict', 'properties': {'@timestamp': {'type': 'date'}, 'lab': {'properties': {
            name: {'type': 'keyword'} for name in ['provider', 'event_source', 'event_name', 'policy_arn',
                                                 'category', 'activity', 'result', 'error_code']}}}}}}
    (out / 'index-template.json').write_text(json.dumps(mapping, indent=2) + chr(10))
    print('Exported 3 disabled query rules, NDJSON, strict normalization index template')


if __name__ == '__main__':
    main()
