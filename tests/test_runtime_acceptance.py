import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from v1 import runtime
from v1.fixtures import generate


class RuntimeAcceptance(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name) / 'evidence'
        self.patch = patch.object(runtime, 'EVIDENCE', self.folder)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.cases = generate()
        runtime.save('cases.json', self.cases)

    def test_fixed_internal_endpoints(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(runtime.ssl, 'create_default_context'):
            self.assertEqual(runtime.endpoint('elasticsearch'), 'https://localhost:9200')
            with self.assertRaises(ValueError):
                runtime.Client('https://elasticsearch:9200', '', '')
        with patch.dict(os.environ, {'LAB_INTERNAL_CLIENT': '1'}), patch.object(runtime.ssl, 'create_default_context'):
            for service, port in [('elasticsearch', 9200), ('kibana', 5601), ('response', 8443)]:
                url = f'https://{service}:{port}'
                self.assertEqual(runtime.endpoint(service), url)
                runtime.Client(url, '', '')
            for url in ['http://elasticsearch:9200', 'https://elasticsearch:443', 'https://example.com:9200', 'https://user@kibana:5601', 'https://response:9200']:
                with self.assertRaises(ValueError):
                    runtime.Client(url, '', '')

    def test_hit_mismatch_fails_even_optimized(self):
        es = Mock()
        es.call.return_value = {'hits': {'hits': []}}
        with self.assertRaises(AssertionError):
            runtime.assert_hits(es)
        self.assertFalse((self.folder / 'elastic-hits.json').exists())

    def test_scheduled_source_only_ids_and_negative_exclusion(self):
        expected = {c['event']['eventID'] for c in self.cases if c['expected']}
        es = Mock()
        es.call.return_value = {'hits': {'total': {'value': 3}, 'hits': [{'_source': c['event']} for c in self.cases if c['expected']]}}
        runtime.assert_scheduled(es, expected)
        self.assertNotIn('eventID', json.dumps(es.call.call_args.args[2]))
        es.call.return_value = {'hits': {'total': {'value': 8}, 'hits': [{'_source': c['event']} for c in self.cases]}}
        with patch.object(runtime.time, 'monotonic', side_effect=[0, 0, 241]), patch.object(runtime.time, 'sleep'):
            with self.assertRaises(AssertionError):
                runtime.assert_scheduled(es, expected)

    def test_exact_hit_set_succeeds(self):
        es = Mock()
        es.call.return_value = {'hits': {'hits': [{'_source': c['event']} for c in self.cases if c['expected']]}}
        runtime.assert_hits(es)
        self.assertTrue((self.folder / 'elastic-hits.json').exists())

    def replay(self, first, second):
        with patch.object(runtime, 'Client') as client, patch.object(Path, 'read_text', return_value='test-token'):
            client.return_value.call.side_effect = [first, second]
            runtime.response_replay(self.cases[:1])

    def test_fresh_duplicate_is_not_success(self):
        with self.assertRaises(AssertionError):
            self.replay({'status': 'duplicate', 'actions': []}, {'status': 'duplicate', 'actions': []})

    def test_actions_and_replay_fail_even_optimized(self):
        for first, second in [
            ({'status': 'human_review_required', 'actions': ['bad']}, {'status': 'duplicate', 'actions': []}),
            ({'status': 'human_review_required', 'actions': []}, {'status': 'duplicate', 'actions': ['bad']}),
            ({'status': 'human_review_required', 'actions': []}, {'status': 'human_review_required', 'actions': []}),
            ({'status': 'human_review_required', 'actions': None}, {'status': 'duplicate', 'actions': []}),
        ]:
            with self.assertRaises(AssertionError):
                self.replay(first, second)

    def test_fresh_proposal_and_duplicate_succeed(self):
        self.replay({'status': 'human_review_required', 'actions': []}, {'status': 'duplicate', 'actions': []})
        self.assertTrue((self.folder / 'response-api.json').exists())

    def test_private_evidence_modes_under_permissive_umask(self):
        self.folder.chmod(0o755)
        (self.folder / 'cases.json').chmod(0o644)
        old = os.umask(0)
        try:
            runtime.save('cases.json', self.cases)
            kb = Mock()
            kb.call.return_value = b'{}' + bytes([10])
            runtime.capture(kb)
        finally:
            os.umask(old)
        self.assertEqual(self.folder.stat().st_mode & 0o777, 0o700)
        for path in self.folder.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_offline_replay_negative_controls(self):
        from v1 import offline_replay
        for response in ({'status': 'duplicate', 'actions': []}, {'status': 'human_review_required', 'actions': ['bad']}):
            with patch.object(offline_replay, 'respond', return_value=response):
                with self.assertRaises(AssertionError):
                    offline_replay.main()
        with patch.object(offline_replay, 'respond', side_effect=ValueError('rejected')):
            with self.assertRaises(AssertionError):
                offline_replay.main()

    def test_evidence_refuses_symlink(self):
        target = Path(self.tmp.name) / 'target'
        target.write_text('preserve')
        (self.folder / 'link').symlink_to(target)
        with self.assertRaises(OSError):
            runtime.save('link', {})
        self.assertEqual(target.read_text(), 'preserve')
