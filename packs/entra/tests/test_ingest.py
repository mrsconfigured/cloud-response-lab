import datetime as dt
import json
import os
import tempfile
import unittest

from packs.entra.ingest import graph_audit as ga

GOOD = {'AZURE_TENANT_ID': '11111111-2222-4333-8444-555555555555', 'AZURE_CLIENT_ID': '66666666-7777-4888-8999-000000000000', 'AZURE_CLIENT_SECRET': 'x' * 40}


class Loader(unittest.TestCase):
    def write(self, creds):
        f = tempfile.NamedTemporaryFile('w', delete=False)
        f.write(''.join('%s=%s\n' % kv for kv in creds.items()))
        f.close()
        return f.name

    def test_credentials_are_consumed_and_the_file_is_deleted(self):
        path = self.write(GOOD)
        self.assertEqual(ga.take_credentials(path)['AZURE_CLIENT_ID'], GOOD['AZURE_CLIENT_ID'])
        self.assertFalse(os.path.exists(path), 'the secret file must not survive the first read')

    def test_placeholder_credentials_are_rejected(self):
        for bad in ({}, dict(GOOD, AZURE_TENANT_ID='placeholder-not-a-guid'), dict(GOOD, AZURE_CLIENT_SECRET='short')):
            path = self.write(bad)
            self.assertIsNone(ga.take_credentials(path))
            self.assertFalse(os.path.exists(path))

    def test_missing_file_means_no_credentials(self):
        self.assertIsNone(ga.take_credentials('/nonexistent/azenv'))

    def test_documents_are_indexed_by_graph_id_with_a_timestamp(self):
        d = ga.normalize({'id': 'abc', 'activityDateTime': '2026-10-14T13:40:48Z'})
        self.assertEqual(d['@timestamp'], '2026-10-14T13:40:48Z')
        lines = ga.bulk_body([d, {'id': '', 'activityDateTime': 'x'}, {'id': 'z'}]).decode().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0])['index']['_id'], 'abc')

    def test_query_window_and_error_scrubbing(self):
        url = ga.first_url(7, dt.datetime(2026, 10, 14, 12, 0, tzinfo=dt.timezone.utc))
        self.assertIn('2026-10-07T12%3A00%3A00Z', url)
        self.assertEqual(ga.window_filter(7, dt.datetime(2026, 10, 14, 12, 0, tzinfo=dt.timezone.utc)), 'activityDateTime ge 2026-10-07T12:00:00Z')
        self.assertNotIn('11111111-2222-4333-8444-555555555555', ga.scrub_error('tenant 11111111-2222-4333-8444-555555555555 failed'))
