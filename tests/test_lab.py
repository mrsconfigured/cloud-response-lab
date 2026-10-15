import copy
import datetime as dt
import unittest
from unittest.mock import patch
from lab import ROOT, load, matches, plan_response, validate_playbook


class Detections(unittest.TestCase):
    def test_acceptance(self):
        rules = sorted((ROOT / 'detections').glob('*.json'))
        self.assertEqual(len(rules), 3)
        for path in rules:
            rule = load(path)
            cases = load(ROOT / 'tests/fixtures' / path.name)['cases']
            self.assertTrue(any(c['match'] for c in cases))
            self.assertTrue(any(not c['match'] for c in cases))
            for case in cases:
                with self.subTest(rule=path.stem, case=case['name']):
                    self.assertEqual(matches(rule, case['event']), case['match'])

    def test_negative_control_mutated_rule_detected(self):
        for path in (ROOT / 'detections').glob('*.json'):
            rule = load(path)
            event = load(ROOT / 'tests/fixtures' / path.name)['cases'][0]['event']
            key = next(iter(rule['detection']['selection']))
            rule['detection']['selection'][key] = 'deliberate-negative-control'
            self.assertFalse(matches(rule, event))

    def test_unsupported_sigma_fails_closed(self):
        rule = load(ROOT / 'detections/aws-cloudtrail-stop.json')
        rule['detection']['condition'] = '1 of selection*'
        with self.assertRaises(ValueError):
            matches(rule, {})


class Response(unittest.TestCase):
    def books(self):
        return [load(p) for p in sorted((ROOT / 'response/playbooks').glob('*.json'))]

    def alert(self, book):
        aws = book['id'].startswith('aws-')
        return {'id': 'synthetic-alert-1', 'rule_id': book['rule_id'],
                'provider': 'aws' if aws else 'entra',
                'scope': book['allowed_accounts' if aws else 'allowed_tenants'][0],
                'timestamp': '2026-10-13T18:00:00Z', 'untrusted_extra': 'secret-like-do-not-copy'}

    def now(self):
        return dt.datetime(2026, 10, 13, 18, 1, tzinfo=dt.timezone.utc)

    def test_each_playbook_safe_and_idempotent(self):
        self.assertEqual(len(self.books()), 3)
        for book in self.books():
            with self.subTest(book=book['id']), patch('socket.socket', side_effect=AssertionError('network forbidden')):
                seen = set()
                alert = self.alert(book)
                result = plan_response(book, alert, seen, self.now())
                self.assertEqual(result['status'], 'human_review_required')
                self.assertEqual(result['actions'], [])
                self.assertNotIn('secret-like', str(result))
                self.assertEqual(plan_response(book, alert, seen, self.now())['status'], 'duplicate')

    def test_each_playbook_rejects_bad_alerts(self):
        for book in self.books():
            for changes in [{'scope': '222222222222'}, {'rule_id': 'unknown'},
                            {'provider': 'unknown'}, {'timestamp': '2020-01-01T00:00:00Z'},
                            {'timestamp': '2030-01-01T00:00:00Z'},
                            {'timestamp': '2026-10-13T18:00:00'}, {'id': ''}, {'id': 7}]:
                with self.subTest(book=book['id'], changes=changes):
                    with self.assertRaises(ValueError):
                        plan_response(book, {**self.alert(book), **changes}, set(), self.now())
            with self.assertRaises(ValueError):
                plan_response(book, {}, set(), self.now())

    def test_each_playbook_rejects_unsafe_mutations(self):
        for book in self.books():
            for change in [{'mode': 'live'}, {'automatic_actions': ['disable-user']},
                           {'steps': ['execute']}, {'max_age_seconds': 0},
                           {'allowed_accounts': []}, {'status': 'shuffle-native'}]:
                with self.subTest(book=book['id'], change=change):
                    unsafe = copy.deepcopy(book)
                    unsafe.update(change)
                    with self.assertRaises(ValueError):
                        validate_playbook(unsafe)


if __name__ == '__main__':
    unittest.main()
