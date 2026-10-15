"""Fail-closed dry-run policy; persistent SQLite dedup, no cloud SDK/actions."""
import datetime as dt
import hashlib
import json
import sqlite3
import uuid

RULE = '965a1068-c2bf-4ea5-b1d0-000000000002'
ACCOUNT = '111122223333'
POLICY = 'arn:aws:iam::aws:policy/AdministratorAccess'


def validate(alert, now):
    if not isinstance(alert, dict) or alert.get('rule_id') != RULE or alert.get('synthetic') is not True:
        raise ValueError('only the synthetic v1 rule is allowed')
    event = alert.get('event')
    if not isinstance(event, dict):
        raise ValueError('event object required')
    uuid.UUID(event['eventID'])
    if event.get('recipientAccountId') != ACCOUNT or event.get('userIdentity', {}).get('accountId') != ACCOUNT:
        raise ValueError('synthetic account mismatch')
    if event.get('eventSource') != 'iam.amazonaws.com' or event.get('eventName') not in ('AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy'):
        raise ValueError('unexpected API')
    if event.get('requestParameters', {}).get('policyArn') != POLICY or event.get('errorCode') is not None:
        raise ValueError('not a successful AdministratorAccess attachment')
    timestamp = dt.datetime.fromisoformat(event['eventTime'].replace('Z', '+00:00'))
    if timestamp.tzinfo is None or now.tzinfo is None or not 0 <= (now - timestamp).total_seconds() <= 900:
        raise ValueError('stale, future, or naive event')
    target_key = {'AttachUserPolicy': 'userName', 'AttachRolePolicy': 'roleName', 'AttachGroupPolicy': 'groupName'}[event['eventName']]
    target = event['requestParameters'].get(target_key)
    if not isinstance(target, str) or not target.startswith('lab-') or len(target) > 128:
        raise ValueError('synthetic target required')
    return event, target_key, target


def respond(alert, database, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    event, target_key, target = validate(alert, now)
    key = hashlib.sha256((ACCOUNT + RULE + event['eventID']).encode()).hexdigest()
    digest = hashlib.sha256(json.dumps(event, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    result = {'status': 'human_review_required', 'mode': 'dry_run', 'key': key,
              'rule_id': RULE, 'event_id': event['eventID'], 'owner': 'mrsconfigured', 'actions': [],
              'proposal': {'operation': event['eventName'].replace('Attach', 'Detach'),
                           target_key: target, 'policyArn': POLICY},
              'summary': 'Verify original event and authorized change. Proposal ONLY; never executed.'}
    with sqlite3.connect(database, timeout=10) as db:
        db.execute('CREATE TABLE IF NOT EXISTS responses (key TEXT PRIMARY KEY, digest TEXT NOT NULL, result TEXT NOT NULL)')
        db.execute('BEGIN IMMEDIATE')
        previous = db.execute('SELECT digest FROM responses WHERE key=?', (key,)).fetchone()
        if previous:
            if previous[0] != digest:
                raise ValueError('event ID collision with changed payload')
            return {'status': 'duplicate', 'key': key, 'mode': 'dry_run', 'actions': []}
        db.execute('INSERT INTO responses VALUES (?, ?, ?)', (key, digest, json.dumps(result)))
    return result
