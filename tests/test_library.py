import copy
import datetime as dt
import json
import unittest
from sigma.collection import SigmaCollection
from library.build import ROOT, OUT, build, documents, evaluate, fixtures
from library.response import propose
from core import packs as pk

NOW = dt.datetime(2026, 10, 14, 1, 0, tzinfo=dt.timezone.utc)


class Library(unittest.TestCase):
    def test_reproducible_exports_and_exact_inventory(self):
        result = build()
        for name, value in result.items():
            self.assertEqual(value, json.loads((OUT / name).read_text()), name)
        rows = result['matrix.json']
        self.assertEqual(len(rows), 11)
        self.assertEqual(sum(r['positive'] for r in rows), 14)
        self.assertEqual(sum(r['negative'] for r in rows), 101)
        self.assertEqual(sum(r['provider'] == 'aws' for r in rows), 5)
        self.assertEqual(len(result['navigator.json']['techniques']), 7)

    def test_independent_behavior_contracts(self):
        expected = json.loads((ROOT / 'tests/fixtures/library-semantics.json').read_text())
        for slug, raw, collection in documents():
            self.assertEqual(raw['detection']['selection'], expected[slug]['selection'])
            # Frozen expected operations are separate from generated fixtures, so rule
            # drift cannot silently regenerate its own passing expected behavior.
            event = {}
            from library.build import put
            for key, value in expected[slug]['selection'].items():
                put(event, key, value[0] if isinstance(value, list) else value)
            self.assertTrue(evaluate(collection.rules[0].detection.parsed_condition[0].parsed, event))

    def test_fail_closed_unsupported_ast(self):
        with self.assertRaises(ValueError): evaluate(object(), {})
        rule = SigmaCollection.from_yaml('''title: Wildcard
id: 419159fa-cf2d-40ec-a788-ea7928f43b52
logsource:
  product: aws
detection:
  s:
    x: "a*"
  condition: s
''').rules[0]
        with self.assertRaises(ValueError): evaluate(rule.detection.parsed_condition[0].parsed, {'x': 'abc'})

    def test_exports_follow_pack_config_and_provider_index_partition(self):
        result = build()
        enabled = {s for p in pk.packs(ROOT) for s in p['enabled_rules']}
        cfg = pk.config(ROOT)['rule_defaults']
        for rule, row in zip(result['rules.json'], result['matrix.json']):
            self.assertEqual(rule['enabled'], row['slug'] in enabled, row['slug'])
            self.assertEqual((rule['interval'], rule['from']), (cfg['interval'], cfg['from']), row['slug'])
            self.assertEqual(rule['actions'], [])
            self.assertEqual(rule['index'], ['logs-cloud-response-lab-library-' + row['provider']])
            self.assertFalse(row['query_engine_live'])

    def test_cross_provider_scope_and_collision_guards(self):
        result = build()
        for row in result['matrix.json']:
            event = result['fixtures.json'][row['slug']][0]['event']
            alert = {'synthetic': True, 'provider': row['provider'], 'rule_id': row['id'], 'event': event}
            for invalid_id in ([], {}, 17, None):
                bad = copy.deepcopy(alert); bad['rule_id'] = invalid_id
                with self.assertRaises(ValueError): propose(bad, {}, NOW)
            for key, value in [('synthetic', False), ('provider', 'wrong'), ('rule_id', 'wrong')]:
                bad = copy.deepcopy(alert); bad[key] = value
                with self.assertRaises(ValueError): propose(bad, {}, NOW)
            for key, value in [('recipientAccountId' if row['provider'] == 'aws' else 'tenantId', 'foreign'),
                               ('eventTime' if row['provider'] == 'aws' else 'activityDateTime', '2000-01-01T00:00:00Z'),
                               ('eventTime' if row['provider'] == 'aws' else 'activityDateTime', '2030-01-01T00:00:00Z')]:
                bad = copy.deepcopy(alert); bad['event'][key] = value
                with self.assertRaises(ValueError): propose(bad, {}, NOW)
            seen = {}; propose(alert, seen, NOW)
            bad = copy.deepcopy(alert); bad['event']['extra'] = 'changed'
            with self.assertRaises(ValueError): propose(bad, seen, NOW)


def per_rule(slug, raw, collection):
    def test(self):
        ast = collection.rules[0].detection.parsed_condition[0].parsed
        cases = fixtures(slug, raw)
        self.assertTrue(any(c['expected'] for c in cases))
        self.assertTrue(any(not c['expected'] for c in cases))
        for case in cases:
            with self.subTest(case=case['name']):
                self.assertEqual(evaluate(ast, case['event']), case['expected'])
                alert = {'synthetic': True, 'provider': 'aws' if raw['logsource']['product'] == 'aws' else 'entra',
                         'rule_id': raw['id'], 'event': case['event']}
                if case['expected']:
                    seen = {}; first = propose(alert, seen, NOW)
                    self.assertEqual(first['status'], 'human_review_required')
                    self.assertEqual(first['actions'], [])
                    self.assertEqual(propose(alert, seen, NOW)['status'], 'duplicate')
                    self.assertNotIn('synthetic@example.invalid', json.dumps(first))
                else:
                    with self.assertRaises(ValueError): propose(alert, {}, NOW)
    return test


for slug, raw, collection in documents():
    setattr(Library, 'test_rule_' + slug.replace('-', '_'), per_rule(slug, raw, collection))
