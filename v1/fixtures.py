"""Realistic CloudTrail envelope, reserved example IPs and a synthetic account."""
import copy
import datetime as dt
import json
import uuid
from .build import ROOT

ACCOUNT = '111122223333'
POLICY = 'arn:aws:iam::aws:policy/AdministratorAccess'


def generate(now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    timestamp = (now - dt.timedelta(seconds=30)).isoformat().replace('+00:00', 'Z')
    base = {'eventVersion': '1.11', 'userIdentity': {'type': 'IAMUser',
        'principalId': 'AIDASYNTHETICEXAMPLE', 'arn': f'arn:aws:iam::{ACCOUNT}:user/lab-operator',
        'accountId': ACCOUNT, 'userName': 'lab-operator'}, 'eventTime': timestamp,
        'eventSource': 'iam.amazonaws.com', 'eventName': 'AttachUserPolicy', 'awsRegion': 'us-east-1',
        'sourceIPAddress': '192.0.2.10', 'userAgent': 'cloud-response-lab/synthetic',
        'requestParameters': {'userName': 'lab-target', 'policyArn': POLICY}, 'responseElements': None,
        'requestID': str(uuid.uuid5(uuid.NAMESPACE_DNS, 'synthetic-request')),
        'readOnly': False, 'eventType': 'AwsApiCall', 'managementEvent': True,
        'recipientAccountId': ACCOUNT, 'eventCategory': 'Management'}
    cases = []
    for name, changes, expected in [
        ('attack-user', {}, True),
        ('attack-role', {'eventName': 'AttachRolePolicy', 'requestParameters': {'roleName': 'lab-role', 'policyArn': POLICY}}, True),
        ('attack-group', {'eventName': 'AttachGroupPolicy', 'requestParameters': {'groupName': 'lab-group', 'policyArn': POLICY}}, True),
        ('benign-readonly', {'requestParameters': {'userName': 'lab-target', 'policyArn': 'arn:aws:iam::aws:policy/ReadOnlyAccess'}}, False),
        ('denied-admin', {'errorCode': 'AccessDenied', 'errorMessage': 'Synthetic access denied'}, False),
        ('benign-list', {'eventName': 'ListUsers', 'requestParameters': {}, 'readOnly': True}, False),
        ('wrong-service', {'eventSource': 'sts.amazonaws.com'}, False),
        ('case-sensitive', {'eventName': 'attachuserpolicy'}, False)]:
        event = copy.deepcopy(base); event.update(changes)
        event['eventID'] = str(uuid.uuid5(uuid.NAMESPACE_DNS, 'cloud-response-lab-v1-' + name + '-' + timestamp))
        cases.append({'name': name, 'expected': expected, 'event': event})
    return cases


def document(case):
    doc = copy.deepcopy(case['event'])
    doc['@timestamp'] = doc['eventTime']
    doc['lab'] = {'synthetic': True, 'case': case['name']}
    return doc


if __name__ == '__main__':
    cases = generate()
    from .runtime import save
    save('cloudtrail.json', {'Records': [c['event'] for c in cases]})
    save('cases.json', cases)
    print(f'Generated {len(cases)} synthetic CloudTrail records')
