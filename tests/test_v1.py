import concurrent.futures
import copy
import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path
from v1.build import ROOT, compile_rule
from v1.fixtures import generate, document
from v1.shuffle import workflow
from response.v1.policy import respond, RULE

NOW = dt.datetime(2026, 10, 14, 1, 0, tzinfo=dt.timezone.utc)


class V1(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / 'dedup.sqlite')
        self.cases = generate(NOW)
        self.alert = {'rule_id': RULE, 'synthetic': True, 'event': self.cases[0]['event']}

    def test_real_compiler_reproducible_export(self):
        rule = compile_rule()
        self.assertEqual(rule, json.loads((ROOT / 'v1/generated/elastic-rule.json').read_text()))
        self.assertEqual(rule['language'], 'lucene')
        self.assertIn('NOT _exists_:errorCode', rule['query'])
        self.assertIn('AttachRolePolicy OR AttachGroupPolicy', rule['query'])
        self.assertFalse(rule['enabled'])

    def test_cloudtrail_real_shape(self):
        self.assertEqual(len(self.cases), 8)
        self.assertEqual(sum(c['expected'] for c in self.cases), 3)
        for case in self.cases:
            event = case['event']
            self.assertEqual(event['eventVersion'], '1.11')
            self.assertEqual(event['userIdentity']['accountId'], event['recipientAccountId'])
            self.assertEqual(document(case)['@timestamp'], event['eventTime'])

    def test_policy_all_synthetic_cases(self):
        for case in self.cases:
            alert = dict(self.alert, event=case['event'])
            if case['expected']:
                result = respond(alert, self.db, NOW)
                self.assertEqual(result['status'], 'human_review_required')
                self.assertEqual(result['actions'], [])
                self.assertTrue(result['proposal']['operation'].startswith('Detach'))
            else:
                with self.assertRaises(ValueError): respond(alert, self.db, NOW)

    def test_persistent_replay_and_concurrency(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: respond(self.alert, self.db, NOW), range(16)))
        self.assertEqual(sum(r['status'] == 'human_review_required' for r in results), 1)
        self.assertEqual(sum(r['status'] == 'duplicate' for r in results), 15)
        self.assertEqual(respond(self.alert, self.db, NOW)['status'], 'duplicate')

    def test_payload_collision_rejected(self):
        respond(self.alert, self.db, NOW)
        self.alert['event']['requestParameters']['userName'] = 'lab-other'
        with self.assertRaises(ValueError): respond(self.alert, self.db, NOW)

    def test_safety_negative_controls(self):
        mutations = [lambda a: a.update(synthetic=False), lambda a: a.update(rule_id='wrong'),
            lambda a: a['event'].update(recipientAccountId='999999999999'),
            lambda a: a['event'].update(eventTime='2020-01-01T00:00:00Z'),
            lambda a: a['event'].update(eventTime='2030-01-01T00:00:00Z'),
            lambda a: a['event'].update(eventTime='2026-10-14T01:00:00'),
            lambda a: a['event'].update(eventID='not-uuid'),
            lambda a: a['event']['requestParameters'].update(userName='production'),
            lambda a: a['event'].update(errorCode='')]
        for mutation in mutations:
            bad = copy.deepcopy(self.alert); mutation(bad)
            with self.assertRaises(ValueError): respond(bad, self.db, NOW)

    def test_workflow_exec_argument_not_static_noop(self):
        flow = workflow('actual-app-id', 'actual-auth-id')
        self.assertTrue(flow['is_valid'])
        self.assertEqual(flow['actions'][0]['name'], 'triage_synthetic_alert')
        self.assertEqual(flow['actions'][0]['parameters'][0]['value'], '$exec')
        self.assertFalse(workflow()['is_valid'])

    def test_dashboard_references_resolve(self):
        objects = [json.loads(line) for line in (ROOT / 'v1/kibana/dashboard.ndjson').read_text().splitlines()]
        ids = {(o['type'], o['id']) for o in objects}
        for obj in objects:
            for ref in obj.get('references', []): self.assertIn((ref['type'], ref['id']), ids)
        search = next(o for o in objects if o['type'] == 'search')
        source = json.loads(search['attributes']['kibanaSavedObjectMeta']['searchSourceJSON'])
        self.assertEqual(source['query']['query'], compile_rule()['query'])

    def test_private_runtime(self):
        compose = json.loads((ROOT / 'infra/compose.v1.json').read_text())
        self.assertTrue(compose['networks']['lab']['internal'])
        for service in compose['services'].values():
            self.assertEqual(service['profiles'], ['reviewed'])
            self.assertEqual(service['restart'], 'no')
            for port in service.get('ports', []): self.assertTrue(port.startswith('127.0.0.1:'))
            self.assertNotIn('docker.sock', json.dumps(service))

    def test_dispatch_from_scheduled_alert(self):
        from v1.dispatch import payload
        source = document(self.cases[0]); source['kibana.alert.rule.rule_id'] = RULE
        actual = payload({'_source': source})
        self.assertEqual(actual['event'], self.cases[0]['event'])
        self.assertEqual(respond(actual, self.db, NOW)['status'], 'human_review_required')
        source['lab']['synthetic'] = False
        with self.assertRaises(ValueError): payload({'_source': source})

    def test_new_replay_batch_has_new_ids(self):
        later = generate(NOW + dt.timedelta(minutes=1))
        self.assertNotEqual(self.cases[0]['event']['eventID'], later[0]['event']['eventID'])

    def test_runtime_clients_refuse_nonlocal_or_plaintext(self):
        from v1.runtime import Client
        for url in ('http://localhost:9200', 'https://example.com', 'https://user@localhost:9200'):
            with self.assertRaises(ValueError): Client(url, 'test', '/nonexistent')

    def test_policy_has_no_cloud_or_network_imports(self):
        import ast
        tree = ast.parse((ROOT / 'response/v1/policy.py').read_text())
        imports = {n.names[0].name for n in ast.walk(tree) if isinstance(n, ast.Import)}
        self.assertEqual(imports, {'datetime', 'hashlib', 'json', 'sqlite3', 'uuid'})

    def test_openapi_operation_matches_workflow(self):
        api = json.loads((ROOT / 'response/v1/openapi.json').read_text())
        self.assertEqual(api['paths']['/respond']['post']['operationId'], workflow()['actions'][0]['name'])
        self.assertEqual(api['servers'][0]['url'], 'https://response:8443')
        self.assertTrue(api['security'])

    def test_bootstrap_and_bulk_wire_payloads(self):
        from unittest.mock import patch
        from v1.runtime import bootstrap, ingest
        class Fake:
            def __init__(self): self.calls = []
            def call(self, *args, **kwargs):
                self.calls.append(args)
                return {'success': True, 'errors': False}
        es, kb = Fake(), Fake()
        with patch('v1.runtime.save'):
            bootstrap(es, kb); ingest(es)
        body = kb.calls[-1][2]
        self.assertIn(bytes([13, 10]), body)
        self.assertIn(b'Content-Disposition:', body)
        bulk = es.calls[-1][2]
        self.assertTrue(bulk.endswith(bytes([10])))
        self.assertEqual(len(bulk.splitlines()), 16)
        for line in bulk.splitlines(): json.loads(line)

    def test_response_images_share_official_immutable_digest(self):
        import re
        compose = json.loads((ROOT / 'infra/compose.v1.json').read_text())
        image = compose['services']['response-init']['image']
        self.assertRegex(image, r'^docker\.io/library/python:3\.12-slim@sha256:[a-f0-9]{64}$')
        dockerfile = (ROOT / 'response/v1/Dockerfile').read_text()
        self.assertEqual(dockerfile.splitlines()[0], 'FROM ' + image)
