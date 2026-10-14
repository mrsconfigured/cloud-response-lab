"""Compile real Sigma with the maintained pySigma Elasticsearch backend."""
import json
from pathlib import Path
from importlib.metadata import version
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import LuceneBackend

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'v1/generated'
RULE_ID = '965a1068-c2bf-4ea5-b1d0-000000000002'
# lookback and interval come from core/config.json, the single source of truth for every rule
DEFAULTS = json.loads((ROOT / 'core/config.json').read_text())['rule_defaults']
INDEX = 'logs-cloud-response-lab-v1'


def compile_rule():
    rules = SigmaCollection.from_yaml((ROOT / 'packs/aws/detections/aws-admin-attachment.yml').read_text())
    query, = LuceneBackend().convert(rules)
    return {'rule_id': RULE_ID, 'name': rules.rules[0].title,
            'description': rules.rules[0].description, 'type': 'query', 'language': 'lucene',
            'query': query, 'index': [INDEX], 'enabled': False, 'interval': DEFAULTS['interval'],
            'from': DEFAULTS['from'], 'to': 'now', 'risk_score': 73, 'severity': 'high',
            'author': ['1xLoZec'], 'tags': ['synthetic', 'attack.t1098.003'],
            'actions': [], 'version': 1}


def dump(path, value):
    path.write_text(json.dumps(value, indent=2) + chr(10))


def main():
    OUT.mkdir(exist_ok=True)
    rule = compile_rule()
    dump(OUT / 'elastic-rule.json', rule)
    dump(OUT / 'query.json', {'query': {'query_string': {'query': rule['query']}}})
    props = {key: {'type': 'keyword'} for key in ('eventSource', 'eventName', 'eventID', 'errorCode', 'recipientAccountId')}
    props.update({'@timestamp': {'type': 'date'}, 'eventTime': {'type': 'date'},
                  'requestParameters': {'properties': {'policyArn': {'type': 'keyword'}}},
                  'lab': {'properties': {'synthetic': {'type': 'boolean'}, 'case': {'type': 'keyword'}}}})
    dump(OUT / 'index-template.json', {'index_patterns': [INDEX], 'priority': 501, 'template': {'mappings': {'properties': props}}})
    dump(OUT / 'compiler.json', {'compiler': 'pySigma', 'version': version('pysigma'),
                               'backend': 'pysigma-backend-elasticsearch',
                               'backend_version': version('pysigma-backend-elasticsearch'),
                               'runtime_query_verified': False})
    view = {'type': 'index-pattern', 'id': 'cloud-response-lab-v1', 'attributes': {'title': INDEX, 'timeFieldName': '@timestamp'}}
    search = {'type': 'search', 'id': 'cloud-response-lab-v1-hits', 'attributes': {
        'title': 'Synthetic AdministratorAccess attachments',
        'columns': ['eventName', 'requestParameters.policyArn', 'userIdentity.arn', 'eventID'],
        'sort': [['@timestamp', 'desc']], 'kibanaSavedObjectMeta': {'searchSourceJSON': json.dumps({
            'indexRefName': 'kibanaSavedObjectMeta.searchSourceJSON.index',
            'query': {'language': 'lucene', 'query': rule['query']}, 'filter': []})}},
        'references': [{'type': 'index-pattern', 'id': view['id'], 'name': 'kibanaSavedObjectMeta.searchSourceJSON.index'}]}
    dash = {'type': 'dashboard', 'id': 'cloud-response-lab-v1', 'attributes': {
        'title': 'cloud-response-lab | synthetic v1', 'description': 'Synthetic CloudTrail only. No cloud actions.',
        'timeRestore': False, 'optionsJSON': json.dumps({'useMargins': True}),
        'panelsJSON': json.dumps([{'panelIndex': '1', 'type': 'search', 'panelRefName': 'panel_1',
            'gridData': {'x': 0, 'y': 0, 'w': 48, 'h': 20, 'i': '1'}, 'embeddableConfig': {}}]),
        'kibanaSavedObjectMeta': {'searchSourceJSON': json.dumps({'query': {'language': 'kuery', 'query': ''}, 'filter': []})}},
        'references': [{'name': 'panel_1', 'type': 'search', 'id': search['id']}]}
    (ROOT / 'v1/kibana/dashboard.ndjson').write_text(''.join(json.dumps(v) + chr(10) for v in (view, search, dash)))
    print('Real pySigma compilation:', rule['query'])


if __name__ == '__main__':
    main()
