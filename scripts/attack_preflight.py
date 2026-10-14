"""Offline authorization preflight; no AWS imports, credentials, subprocess or attack calls."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def check(plan, mapping):
    """A positive result is a planning check, NEVER authorization to execute."""
    try:
        allowed = {'aws.defense-evasion.cloudtrail-stop',
                   'aws.persistence.iam-create-admin-user'}
        if plan['technique'] not in allowed or plan['technique'] not in {t['id'] for t in mapping['techniques']}:
            raise ValueError('unmapped technique')
        account = plan['account_id']
        if type(account) is not str or len(account) != 12 or not account.isascii() or not account.isdigit():
            raise ValueError('invalid personal account')
        if account != plan['observed_identity']['account_id'] or plan['observed_identity']['partition'] != 'aws':
            raise ValueError('observed identity mismatch')
        if plan['region'] != plan['observed_identity']['region'] or not isinstance(plan['region'], str) or not plan['region'].startswith('us-'):
            raise ValueError('region mismatch or out of staged regions')
        if plan['profile'] != plan['observed_identity']['profile'] or not plan['profile'] or plan['profile'] == 'default':
            raise ValueError('explicit nondefault profile required')
        if plan['role_arn'] != plan['observed_identity']['role_arn'] or not plan['role_arn'].startswith('arn:aws:iam::' + account + ':role/'):
            raise ValueError('role mismatch')
        if plan['account_class'] != 'personal-isolated-sandbox' or plan['approved_incremental_usd'] != 0 or type(plan['approved_incremental_usd']) is not int:
            raise ValueError('personal scope and $0 default required')
        if plan['estimated_incremental_usd'] != 0 or type(plan['estimated_incremental_usd']) is not int:
            raise ValueError('nonzero or unpriced spend blocked')
        if plan['mode'] != 'synthetic-only' or plan['execute'] is not False:
            raise ValueError('live execution forbidden')
        if plan['technique'].endswith('cloudtrail-stop') and plan['independent_audit_verified'] is not True:
            raise ValueError('independent audit not verified')
        return True, 'synthetic-only plan matches stated identity and zero-cost boundaries'
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        return False, 'blocked: ' + str(exc)


if __name__ == '__main__':
    try:
        plan = json.load(sys.stdin)
        mapping = json.loads((ROOT / 'attacks/mapping.json').read_text())
        ok, reason = check(plan, mapping)
    except (ValueError, UnicodeError) as exc:
        ok, reason = False, 'malformed JSON: ' + str(exc)
    print(('PASS (no execution): ' if ok else 'FAIL: ') + reason)
    sys.exit(0 if ok else 1)
