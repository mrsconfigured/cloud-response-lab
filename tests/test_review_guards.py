import copy
import datetime as dt
import unittest
from lab import ROOT, load, plan_response, validate_playbook
from scripts.cross_owner_review import check as review_check
from scripts.attack_preflight import check as attack_check
from scripts.branch_preflight import check as policy_check

SHA = 'a' * 40


class ReviewDecision(unittest.TestCase):
    def snapshot(self):
        return {'partners': {'owner_a': 'OwnerAPersonal', 'owner_b': 'OwnerBPersonal'},
                'author': 'OwnerAPersonal', 'head_start': SHA, 'head_end': SHA,
                'draft': False, 'review_pages': [{'complete': True, 'items': []}]}

    def review(self, who, state='APPROVED', sha=SHA, id=1, type='User'):
        return {'id': id, 'user': {'login': who, 'type': type}, 'state': state, 'commit_id': sha}

    def test_positive_and_fail_closed_mutations(self):
        good = self.snapshot()
        good['review_pages'][0]['items'] = [self.review('OwnerBPersonal')]
        self.assertTrue(review_check(good)[0])
        changes = [
            {'author': 'OwnerBPersonal'}, {'author': 'stranger'},
            {'head_end': 'b' * 40}, {'draft': True},
            {'review_pages': [{'complete': False, 'items': good['review_pages'][0]['items']}]},
            {'review_pages': [{'complete': True, 'items': [self.review('OwnerBPersonal', sha='b' * 40)]}]},
            {'review_pages': [{'complete': True, 'items': [self.review('OwnerAPersonal')]}]},
            {'review_pages': [{'complete': True, 'items': [self.review('OwnerBPersonal', type='Bot')]}]},
            {'review_pages': [{'complete': True, 'items': [self.review('OwnerBPersonal'), self.review('OwnerBPersonal', 'CHANGES_REQUESTED', id=2)]}]},
            {'review_pages': [{'complete': True, 'items': [self.review('OwnerBPersonal'), self.review('OwnerBPersonal', 'DISMISSED', id=2)]}]},
            {'review_pages': [{'complete': True, 'items': [self.review('OwnerBPersonal'), self.review('OwnerBPersonal', id=1)]}]},
            {'partners': {'owner_a': 'same', 'owner_b': 'same'}}]
        for change in changes:
            with self.subTest(change=change):
                self.assertFalse(review_check({**good, **change})[0])
        third = copy.deepcopy(good)
        third['author'] = 'outsider'
        third['review_pages'][0]['items'].append(self.review('OwnerAPersonal', id=2))
        self.assertTrue(review_check(third)[0])
        third['review_pages'][0]['items'] = []
        self.assertFalse(review_check(third)[0])


class Guardrails(unittest.TestCase):
    def test_scope_not_substring_or_wrong_types(self):
        book = load(ROOT / 'response/playbooks/aws-cloudtrail-stop.json')
        for bad in ['123456789012', {'123456789012': True}, [], ['x'], [123456789012], ['123456789012', '123456789012']]:
            with self.subTest(bad=bad):
                mutant = copy.deepcopy(book)
                mutant['allowed_accounts'] = bad
                with self.assertRaises(ValueError):
                    validate_playbook(mutant)

    def test_attack_guard(self):
        mapping = load(ROOT / 'attacks/mapping.json')
        p = {'technique': 'aws.defense-evasion.cloudtrail-stop', 'account_id': '123456789012',
             'region': 'us-east-1', 'profile': 'personal-lab',
             'role_arn': 'arn:aws:iam::123456789012:role/lab',
             'account_class': 'personal-isolated-sandbox', 'approved_incremental_usd': 0,
             'estimated_incremental_usd': 0, 'mode': 'synthetic-only', 'execute': False,
             'independent_audit_verified': True}
        p['observed_identity'] = {k: p[k] for k in ('account_id', 'region', 'profile', 'role_arn')}
        p['observed_identity']['partition'] = 'aws'
        self.assertTrue(attack_check(p, mapping)[0])
        for key, bad in [('account_id', '999999999999'), ('region', 'us-west-2'),
                         ('profile', 'default'), ('role_arn', 'arn:aws:iam::999999999999:role/lab'),
                         ('account_class', 'work'), ('approved_incremental_usd', 1),
                         ('estimated_incremental_usd', 1), ('mode', 'live'), ('execute', True),
                         ('independent_audit_verified', False), ('technique', 'unknown')]:
            with self.subTest(key=key):
                q = copy.deepcopy(p)
                q[key] = bad
                self.assertFalse(attack_check(q, mapping)[0])

    def test_branch_policy_negative_controls(self):
        c = load(ROOT / '.github/branch-protection.staged.json')
        owners = (ROOT / '.github/CODEOWNERS.template').read_text()
        self.assertTrue(policy_check(c, owners))
        for key, bad in [('adminBypass', True), ('codeOwnerReview', False),
                         ('minimumApprovals', 0), ('latestPushApproval', False)]:
            with self.subTest(key=key):
                q = copy.deepcopy(c)
                q['policy'][key] = bad
                with self.assertRaises(ValueError):
                    policy_check(q, owners)


if __name__ == '__main__':
    unittest.main()
