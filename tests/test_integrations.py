import copy
import hashlib
import json
import unittest
from pathlib import Path
from lab import load
from scripts.elastic_export import export, normalize, matches_export
from scripts.integration_validate import validate_elastic, validate_shuffle, go_fields
from scripts.resolve_public_images import verify_manifest

ROOT = Path(__file__).resolve().parents[1]


class IntegrationTests(unittest.TestCase):
    def test_elastic_export_schema_and_thirteen_fixtures(self):
        count = 0
        for path in (ROOT / 'detections').glob('*.json'):
            rule = export(load(path))
            self.assertTrue(validate_elastic(rule))
            self.assertEqual(load(ROOT / 'detections/elastic' / (rule['rule_id'] + '.json')), rule)
            fixture = load(ROOT / 'tests/fixtures' / path.name)
            for case in fixture['cases']:
                with self.subTest(rule=path.name, case=case['name']):
                    self.assertEqual(matches_export(rule, normalize(case['event'], fixture['provider'])), case['match'])
                    count += 1
        self.assertEqual(count, 13)
        ndjson = [json.loads(line) for line in (ROOT / 'detections/elastic/rules.ndjson').read_text().splitlines()]
        self.assertEqual(len(ndjson), 3)
        for rule in ndjson:
            self.assertTrue(validate_elastic(rule))

    def test_elastic_schema_negative_controls(self):
        rule = export(load(ROOT / 'detections/aws-cloudtrail-stop.json'))
        for key, value in [('enabled', True), ('actions', [{}]), ('risk_score', 101),
                           ('risk_score', True), ('language', 'invented'), ('index', ['*']),
                           ('severity', 'urgent'), ('surprise', 1)]:
            bad = copy.deepcopy(rule); bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_elastic(bad)

    def test_normalization_null_empty_error_and_case(self):
        rule = export(load(ROOT / 'detections/aws-cloudtrail-stop.json'))
        raw = {'eventSource': 'cloudtrail.amazonaws.com', 'eventName': 'StopLogging', 'errorCode': None}
        self.assertTrue(matches_export(rule, normalize(raw, 'aws')))
        raw['errorCode'] = ''
        self.assertFalse(matches_export(rule, normalize(raw, 'aws')))
        raw['errorCode'] = []
        with self.assertRaises(ValueError):
            normalize(raw, 'aws')
        raw.pop('errorCode'); raw['eventName'] = 'stoplogging'
        self.assertFalse(matches_export(rule, normalize(raw, 'aws')))
        raw['eventName'] = ['StopLogging']
        with self.assertRaises(ValueError):
            normalize(raw, 'aws')

    def test_shuffle_upstream_field_types_and_graph(self):
        self.assertEqual(go_fields('Action')['parameters'], '[]WorkflowAppActionParameter')
        files = list((ROOT / 'response/shuffle').glob('*.json'))
        self.assertEqual(len(files), 3)
        for path in files:
            self.assertTrue(validate_shuffle(load(path)))

    def test_shuffle_mutations_fail(self):
        flow = load(ROOT / 'response/shuffle/aws-cloudtrail-stop.json')
        mutations = [lambda b: b.update(public=True), lambda b: b.update(triggers=[{}]),
                     lambda b: b['branches'][0].update(destination_id=b['start']),
                     lambda b: b['actions'][0].update(name='execute_python'),
                     lambda b: b['actions'][0].update(authentication_id='unapproved'),
                     lambda b: b['actions'][0]['parameters'][0].update(value='$exec'),
                     lambda b: b.update(conceptual_only_field='wrong')]
        for mutation in mutations:
            bad = copy.deepcopy(flow); mutation(bad)
            with self.assertRaises(ValueError):
                validate_shuffle(bad)

    def test_registry_manifest_digest_negative_control(self):
        raw = b'{"schemaVersion":2}'
        digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
        self.assertEqual(verify_manifest(raw, digest)[0], digest)
        with self.assertRaises(ValueError):
            verify_manifest(raw + b' ', digest)
        with self.assertRaises(ValueError):
            verify_manifest(raw, 'sha256:' + '0' * 64)

    def test_upstream_sources_unchanged(self):
        evidence = load(ROOT / 'docs/upstream/provenance.json')
        for item in evidence['files']:
            data = (ROOT / 'docs/upstream' / item['file']).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), item['sha256'])
            self.assertEqual(len(data), item['bytes'])

    def test_registry_lock_platforms_and_immutable_refs(self):
        lock = load(ROOT / 'infra/image-lock.staged.json')
        self.assertEqual(lock['unresolved'], [])
        self.assertEqual(len(lock['images']), 5)
        for image in lock['images']:
            self.assertTrue(image['immutable_ref'].endswith('@' + image['digest']))
            self.assertFalse(image['signature_verified'])
            self.assertEqual({p['platform']['architecture'] for p in image['platforms']}, {'amd64', 'arm64'})
            for record in [image] + image['platforms']:
                self.assertRegex(record['digest'], '^sha256:[0-9a-f]{64}$')
