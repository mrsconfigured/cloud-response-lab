"""Offline staging checks: conservative schema projections, never vendor certification."""
import json
import re
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(condition, why):
    if not condition:
        raise ValueError(why)


def validate_elastic(rule):
    # Subset of v9.5.5 QueryRuleCreateProps/BaseRequiredFields/Common attributes.
    # Every emitted field is intentionally checked; optional vendor features rejected.
    strings = {'rule_id', 'name', 'description', 'severity', 'type', 'language', 'query',
               'interval', 'from', 'to', 'note'}
    arrays = {'index', 'author', 'tags', 'false_positives'}
    require(set(rule) == strings | arrays | {'risk_score', 'enabled', 'actions', 'version'}, 'unsupported schema field')
    require(all(isinstance(rule[k], str) and rule[k] for k in strings), 'expected nonempty string')
    require(all(type(rule[k]) is list and all(type(v) is str for v in rule[k]) for k in arrays), 'expected string arrays')
    uuid.UUID(rule['rule_id'])
    require(rule['type'] == 'query' and rule['language'] == 'kuery', 'query/kuery required')
    require(rule['severity'] in ('low', 'medium', 'high', 'critical'), 'severity enum')
    require(type(rule['risk_score']) is int and 0 <= rule['risk_score'] <= 100, 'risk score bounds')
    require(type(rule['version']) is int and rule['version'] >= 1, 'version integer')
    require(rule['enabled'] is False and rule['actions'] == [], 'disabled/no-actions invariant')
    require(rule['index'] == ['logs-personal-lab-*'], 'personal normalized index only')
    require(rule['interval'] == '5m' and rule['from'] == 'now-6m' and rule['to'] == 'now', 'schedule')
    return True


def go_fields(name):
    source = (ROOT / 'docs/upstream/shuffle-structs.go').read_text()
    block = source.split('type ' + name + ' struct {', 1)[1].split(chr(10) + '}', 1)[0]
    # Direct top-level scalar/array fields, excluding anonymous struct children.
    fields = {}
    for line in block.splitlines():
        if not line.startswith(chr(9)) or line.startswith(chr(9) * 2):
            continue
        parts = line.strip().split()
        if len(parts) >= 3 and 'json:"' in line and parts[1] != 'struct':
            key = line.split('json:"', 1)[1].split('"', 1)[0].split(',')[0]
            fields[key] = parts[1]
    return fields


def typed_go_subset(value, type_name):
    fields = go_fields(type_name)
    for key, item in value.items():
        if key in ('configuration', 'position'):
            continue  # Anonymous/nested objects explicitly checked below.
        require(key in fields, 'unknown native field: ' + key)
        kind = fields[key]
        expected = str if kind == 'string' else bool if kind == 'bool' else list if kind.startswith('[]') else int
        require(type(item) is expected, 'native field type: ' + key)


def validate_shuffle(flow):
    typed_go_subset(flow, 'Workflow')
    uuid.UUID(flow['id'])
    require(flow['public'] is False and flow['is_valid'] is False, 'staging visibility/validity')
    require(flow['triggers'] == [] and flow['workflow_variables'] == [], 'no automatic entrypoint')
    require(flow['configuration'] == {'exit_on_error': True, 'start_from_top': True, 'skip_notifications': True}, 'safe configuration')
    actions = flow['actions']
    require(len(actions) == 2, 'two static review nodes only')
    ids = [a['id'] for a in actions]
    require(len(set(ids)) == len(ids) and flow['start'] == ids[0], 'unique reachable start')
    for i, action in enumerate(actions):
        typed_go_subset(action, 'Action')
        uuid.UUID(action['id'])
        require(action['app_name'] == 'Shuffle Tools' and action['app_version'] == '1.2.0' and
                action['name'] == 'repeat_back_to_me', 'only official no-op action')
        require(action['authentication_id'] == '' and action['app_id'] == '' and action['is_valid'] is False, 'unbound app/auth required')
        require(action['isStartNode'] is (i == 0), 'start flags')
        require(set(action['position']) == {'x', 'y'} and all(type(v) is int for v in action['position'].values()), 'position')
        require(len(action['parameters']) == 1, 'one call parameter')
        param = action['parameters'][0]
        typed_go_subset(param, 'WorkflowAppActionParameter')
        require(param['name'] == 'call' and param['variant'] == 'STATIC_VALUE', 'static only')
        require('$' not in param['value'] and 'human_review_required' in param['value'], 'no dynamic alert data')
    require(len(flow['branches']) == 1, 'one acyclic edge')
    branch = flow['branches'][0]
    typed_go_subset(branch, 'Branch')
    uuid.UUID(branch['id'])
    require(branch['source_id'] == ids[0] and branch['destination_id'] == ids[1] and branch['conditions'] == [], 'graph edge')
    return True


def main():
    for path in (ROOT / 'detections/elastic').glob('965*.json'):
        validate_elastic(json.loads(path.read_text()))
    for path in (ROOT / 'response/shuffle').glob('*.json'):
        validate_shuffle(json.loads(path.read_text()))
    print('PASS: 3 disabled Elastic schema projections; 3 upstream-typed Shuffle staged graphs')


if __name__ == '__main__':
    main()
