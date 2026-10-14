"""Offline response contract only; no transport, cloud client or remediation."""
import datetime as dt
import hashlib
import json
from library.build import build, documents, evaluate


def propose(alert, seen, now):
    contracts = {c['rule_id']: c for c in build()['response-contracts.json']}
    if not isinstance(alert, dict) or alert.get('synthetic') is not True:
        raise ValueError('synthetic envelope required')
    rule_id = alert.get('rule_id')
    if not isinstance(rule_id, str):
        raise ValueError('rule id required')
    contract = contracts.get(rule_id)
    if not contract or alert.get('provider') != contract['provider']:
        raise ValueError('unknown rule/provider')
    event = alert.get('event')
    if not isinstance(event, dict): raise ValueError('event required')
    aws = contract['provider'] == 'aws'
    scope = event.get('recipientAccountId' if aws else 'tenantId')
    if scope != contract['scope']: raise ValueError('foreign scope')
    identity = event.get('eventID' if aws else 'id')
    if not isinstance(identity, str) or not 1 <= len(identity) <= 200:
        raise ValueError('event identity required')
    try:
        stamp = dt.datetime.fromisoformat(event['eventTime' if aws else 'activityDateTime'].replace('Z', '+00:00'))
        if stamp.tzinfo is None or now.tzinfo is None: raise ValueError('timezone required')
        age = (now - stamp).total_seconds()
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError('invalid timestamp') from exc
    if not 0 <= age <= contract['max_age_seconds']: raise ValueError('stale/future')
    collection = next(c for _, r, c in documents() if r['id'] == contract['rule_id'])
    if not evaluate(collection.rules[0].detection.parsed_condition[0].parsed, event):
        raise ValueError('event does not satisfy detection')
    key = hashlib.sha256(json.dumps([contract['provider'], scope, contract['rule_id'], identity]).encode()).hexdigest()
    digest = hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()
    if key in seen:
        if seen[key] != digest: raise ValueError('event identity collision')
        return {'status': 'duplicate', 'actions': [], 'key': key}
    seen[key] = digest
    return {'status': 'human_review_required', 'mode': 'dry_run', 'actions': [], 'key': key,
            'rule_id': contract['rule_id'], 'summary': contract['review_prompt']}
