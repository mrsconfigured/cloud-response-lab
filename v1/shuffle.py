"""Build a native workflow bound to a real imported app; never fabricates IDs."""
import argparse
import json
import uuid
from .build import ROOT, RULE_ID
from .fixtures import generate

WORKFLOW = '58189b6a-7e99-4eb8-8c3c-aee473660640'
ACTION = '6517cd91-595a-45f5-b4ac-79e76f6388e4'


def workflow(app_id='', authentication_id=''):
    bound = bool(app_id and authentication_id)
    action = {'id': ACTION, 'app_name': 'Cloud Response Lab', 'app_version': '1.0.0',
              'app_id': app_id, 'name': 'triage_synthetic_alert', 'label': 'validate_deduplicate_review',
              'description': 'Executable synthetic policy API, persistent dedup, human review only',
              'is_valid': bound, 'isStartNode': True, 'authentication_id': authentication_id,
              'environment': 'Shuffle', 'public': False, 'position': {'x': 100, 'y': 100},
              'parameters': [{'name': 'alert', 'variant': 'STATIC_VALUE', 'value': '$exec', 'required': True, 'configuration': False}]}
    return {'id': WORKFLOW, 'name': 'cloud-response-lab synthetic IAM triage',
            'description': 'Executable custom app policy. Bind actual app/auth IDs and prove execution before claiming Shuffle integration.',
            'is_valid': bound, 'public': False, 'owner': '', 'start': ACTION, 'actions': [action],
            'branches': [], 'triggers': [], 'workflow_variables': [], 'execution_variables': [],
            'configuration': {'exit_on_error': True, 'start_from_top': True, 'skip_notifications': True},
            'tags': ['synthetic', 'dry-run'], 'example_argument': json.dumps({'synthetic': True, 'rule_id': RULE_ID, 'event': generate()[0]['event']})}


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--app-id', default=''); parser.add_argument('--authentication-id', default='')
    args = parser.parse_args()
    if bool(args.app_id) != bool(args.authentication_id): parser.error('both real app and authentication IDs required')
    output = ROOT / ('artifacts/v1/shuffle-bound.json' if args.app_id else 'response/v1/workflow.json')
    output.parent.mkdir(parents=True, exist_ok=True)
    flow = workflow(args.app_id, args.authentication_id)
    # Reproducible template: runtime execution arguments are always supplied separately.
    flow['example_argument'] = '{}'
    output.write_text(json.dumps(flow, indent=2) + '\n')
    print(str(output) + (' bound for runtime import' if args.app_id else ' unbound template; policy code is executable'))


if __name__ == '__main__': main()
