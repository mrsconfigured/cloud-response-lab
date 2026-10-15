"""Offline staged lab; stdlib only. No network, subprocess, or response execution."""
import datetime as dt
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def load(path):
    return json.loads(Path(path).read_text())


def field(event, path):
    value = event
    for part in path.split('.'):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def validate_rule(rule):
    required = {'title', 'id', 'status', 'author', 'logsource', 'detection', 'level'}
    if not required <= rule.keys() or rule['status'] != 'experimental':
        raise ValueError('incomplete or non-staged rule')
    detection = rule['detection']
    if detection.get('condition') not in ('selection', 'selection and filter_error'):
        raise ValueError('unsupported Sigma condition; fail closed')
    expected = {'selection', 'condition'}
    if detection['condition'] == 'selection and filter_error':
        expected.add('filter_error')
        if detection.get('filter_error') != {'errorCode': None}:
            raise ValueError('unsupported error filter')
    if set(detection) != expected or not detection['selection']:
        raise ValueError('unsupported selection structure')
    for key, value in detection['selection'].items():
        if '|' in key or not isinstance(value, str):
            raise ValueError('only exact scalar selections implemented')
    return True


def matches(rule, event):
    validate_rule(rule)
    d = rule['detection']
    if not all(field(event, k) == v for k, v in d['selection'].items()):
        return False
    return 'filter_error' not in d or field(event, 'errorCode') is None


def validate_playbook(book):
    if book.get('schema_version') != 1 or book.get('mode') != 'dry_run':
        raise ValueError('dry-run only')
    if book.get('automatic_actions') != []:
        raise ValueError('automatic actions forbidden')
    if book.get('steps') != ['validate', 'deduplicate', 'summarize', 'request_human_review']:
        raise ValueError('unknown or unsafe steps')
    if book.get('status') != 'staged-conceptual-not-shuffle-native':
        raise ValueError('native compatibility unproved')
    if any(type(book.get(k)) is not list or not book[k] or
           any(type(v) is not str or not v or v != v.strip() for v in book[k]) or
           len(set(book[k])) != len(book[k])
           for k in ('allowed_accounts', 'allowed_tenants')):
        raise ValueError('explicit exact scope lists required')
    if any(not v.isascii() or len(v) != 12 or not v.isdigit()
           for v in book['allowed_accounts']):
        raise ValueError('invalid account ID')
    if type(book.get('max_age_seconds')) is not int or not 0 < book['max_age_seconds'] <= 3600:
        raise ValueError('invalid age window')
    return True


def plan_response(book, alert, seen, now):
    """Returns a redacted proposal; caller-owned in-memory dedup, never executes."""
    validate_playbook(book)
    required = {'id', 'rule_id', 'provider', 'scope', 'timestamp'}
    if not required <= alert.keys() or any(not isinstance(alert[k], str) for k in required):
        raise ValueError('malformed alert')
    if not alert['id'] or len(alert['id']) > 200 or alert['rule_id'] != book['rule_id']:
        raise ValueError('unknown alert or rule')
    provider = alert['provider']
    scopes = {'aws': book['allowed_accounts'], 'entra': book['allowed_tenants']}
    if provider not in scopes or alert['scope'] not in scopes[provider]:
        raise ValueError('out-of-sandbox scope')
    expected_provider = 'aws' if book['id'].startswith('aws-') else 'entra'
    if provider != expected_provider:
        raise ValueError('provider mismatch')
    timestamp = dt.datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))
    if timestamp.tzinfo is None or now.tzinfo is None:
        raise ValueError('timezone required')
    age = (now - timestamp).total_seconds()
    if age < 0 or age > book['max_age_seconds']:
        raise ValueError('stale or future alert')
    key = hashlib.sha256(json.dumps([provider, alert['scope'], alert['rule_id'], alert['id']]).encode()).hexdigest()
    if key in seen:
        return {'status': 'duplicate', 'key': key, 'actions': []}
    seen.add(key)
    return {'status': 'human_review_required', 'mode': 'dry_run', 'key': key,
            'rule_id': book['rule_id'], 'owner': 'Owner B', 'actions': [],
            'summary': book['review_prompt']}


def main():
    total = 0
    for path in sorted((ROOT / 'detections').glob('*.json')):
        rule = load(path)
        fixture = load(ROOT / 'tests/fixtures' / path.name)
        for case in fixture['cases']:
            actual = matches(rule, case['event'])
            if actual != case['match']:
                raise SystemExit('FAIL ' + path.stem + ': ' + case['name'])
            total += 1
        print(path.stem + ': ' + str(len(fixture['cases'])) + ' cases PASS')
    print(str(total) + ' fixture cases PASS; synthetic/offline only')


if __name__ == '__main__':
    main()
