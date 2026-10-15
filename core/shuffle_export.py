"""Deterministic Shuffle workflow for a playbook spec. Three Shuffle Tools nodes: validate -> plan -> record.
Every node only echoes a dry-run record, so executing the workflow proves the run reached Shuffle without changing anything."""
import json
import uuid
from pathlib import Path

from core import packs as pk

APP = {'app_name': 'Shuffle Tools', 'app_version': '1.2.0', 'app_id': 'ccf48f29-1418-4e18-82cb-0f1aed55586d', 'name': 'repeat_back_to_me'}
NS = uuid.UUID('6f1b9b0e-6c47-4c76-9a55-2f0c3a1a5b11')


def _id(pb, label):
    return str(uuid.uuid5(NS, '%s@%s/%s' % (pb['id'], pb['version'], label)))


def _action(pb, label, call, x, start=False):
    a = dict(APP, id=_id(pb, label), is_valid=True, sharing=True, label=label, public=True, generated=False, environment='Shuffle',
             parameters=[{'id': '', 'name': 'call', 'value': call, 'multiselect': False, 'action_field': '', 'variant': 'STATIC_VALUE',
                          'skip_multicheck': False, 'custom_value': False, 'value_replace': None, 'unique_toggled': False, 'error': '', 'hidden': False}],
             execution_variable={'id': '', 'name': '', 'value': ''}, position={'x': x + 0.001, 'y': 100.001},
             authentication_id='', category='', reference_url='', sub_action=False, run_magic_output=False, run_magic_input=False,
             execution_delay=0, category_label=None, suggestion=False, parent_controlled=False, source_workflow='', source_execution='')
    if start:
        a['isStartNode'] = True
    return a


def workflow_name(pb):
    return 'lab/%s/%s@%s' % (pb['pack'], pb['id'], pb['version'])


def export(pb):
    validate_call = json.dumps({'playbook': pb['id'], 'version': pb['version'], 'mode': 'dry_run', 'check': 'runs only after human approval', 'exec': '$exec'}, sort_keys=True)
    plan_call = json.dumps({'playbook': pb['id'], 'target': '$exec.target', 'steps': [{'id': s['id'], 'action': s['action'], 'simulated': True} for s in pb['steps']]}, sort_keys=True)
    record_call = json.dumps({'playbook': pb['id'], 'result': 'simulated', 'changes_made': False, 'mode': 'dry_run', 'steps': [s['id'] for s in pb['steps']]}, sort_keys=True)
    actions = [_action(pb, 'validate', validate_call, 100, True), _action(pb, 'plan', plan_call, 400), _action(pb, 'record', record_call, 700)]
    branches = []
    for a, b in zip(actions, actions[1:]):
        branches.append({'destination_id': b['id'], 'id': _id(pb, a['label'] + '->' + b['label']), 'source_id': a['id'], 'label': 'then',
                         'has_errors': False, 'conditions': [], 'decorator': False, 'parent_controlled': False, 'source_parent': ''})
    return {'id': _id(pb, 'workflow'), 'name': workflow_name(pb), 'description': pb['title'] + '. Dry-run only: every node echoes a record and changes nothing.',
            'start': actions[0]['id'], 'actions': actions, 'branches': branches, 'triggers': [], 'tags': ['lab', 'dry-run', pb['pack']],
            'configuration': {'exit_on_error': False, 'start_from_top': True, 'skip_notifications': True},
            'workflow_variables': [], 'default_return_value': '', 'input_questions': None, 'public': False, 'sharing': 'private'}


def dump(pb):
    return json.dumps(export(pb), indent=2, sort_keys=True) + chr(10)


def main():
    for pack in pk.packs():
        for path in pack['playbooks']:
            pb = json.loads(path.read_text())
            out = path.with_name(path.stem + '.shuffle.json')
            out.write_text(dump(pb))
            print('wrote', out.relative_to(pk.ROOT))


if __name__ == '__main__':
    main()
