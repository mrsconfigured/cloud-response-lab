"""Reviewed one-shot bridge: scheduled Elastic alerts -> real Shuffle workflow API.

No timer installed. The parent may schedule only after runtime acceptance and review.
Retries are safe at policy layer; delivery itself is at-least-once, not exactly-once.
"""
import argparse
import json
import uuid
from pathlib import Path
from .runtime import Client, clients, EVIDENCE
from .build import RULE_ID
from .fixtures import ACCOUNT


def payload(hit):
    source = hit['_source']
    if source.get('kibana.alert.rule.rule_id') != RULE_ID:
        # Elasticsearch _source can represent nested fields as objects.
        if source.get('kibana', {}).get('alert', {}).get('rule', {}).get('rule_id') != RULE_ID:
            raise ValueError('foreign rule')
    if source.get('lab', {}).get('synthetic') is not True or source.get('recipientAccountId') != ACCOUNT:
        raise ValueError('not synthetic lab scope')
    keys = ('eventVersion', 'userIdentity', 'eventTime', 'eventSource', 'eventName', 'awsRegion',
            'sourceIPAddress', 'userAgent', 'requestParameters', 'responseElements', 'requestID',
            'readOnly', 'eventType', 'managementEvent', 'recipientAccountId', 'eventCategory', 'eventID')
    event = {key: source[key] for key in keys if key in source}
    if 'errorCode' in source: event['errorCode'] = source['errorCode']
    return {'synthetic': True, 'rule_id': RULE_ID, 'event': event}


def main():
    p = argparse.ArgumentParser(); p.add_argument('--reviewed', action='store_true')
    p.add_argument('--url', default='https://localhost:3443'); p.add_argument('--token-file', type=Path, required=True)
    p.add_argument('--ca', type=Path, required=True); p.add_argument('--workflow-id', required=True)
    args = p.parse_args()
    if not args.reviewed: p.error('parent review required')
    uuid.UUID(args.workflow_id)
    es, _ = clients()
    query = {'size': 100, 'query': {'bool': {'filter': [
        {'term': {'kibana.alert.rule.rule_id': RULE_ID}}, {'term': {'lab.synthetic': True}},
        {'range': {'@timestamp': {'gte': 'now-15m'}}}]}}}
    hits = es.call('POST', '/.alerts-security.alerts-default/_search', query)['hits']
    if hits['total']['value'] > 100: raise RuntimeError('batch exceeds cap; paginate before scheduling')
    client = Client(args.url, 'Bearer ' + args.token_file.read_text().strip(), args.ca)
    records = []
    for hit in hits['hits']:
        argument = payload(hit)
        result = client.call('POST', '/api/v1/workflows/' + args.workflow_id + '/execute',
                             {'execution_argument': json.dumps(argument), 'start': ''})
        execution_id = result.get('execution_id')
        if not execution_id: raise RuntimeError('Shuffle did not return execution_id')
        # Never save the execution authorization/token returned by some versions.
        records.append({'event_id': argument['event']['eventID'], 'execution_id': execution_id,
                        'status': 'submitted-not-completion-proof'})
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / 'shuffle-dispatch.json').write_text(json.dumps(records, indent=2) + '\n')
    print(f'Submitted {len(records)} alerts. Capture workflow completion separately; submission is not execution success.')


if __name__ == '__main__': main()
