import gzip
import json
import unittest

from packs.aws.ingest import cloudtrail as ct


def gz(records):
    return gzip.compress(json.dumps({'Records': records}).encode())


class Loader(unittest.TestCase):
    def test_only_complete_records_are_loaded_and_ids_are_event_ids(self):
        good, skipped = ct.records_from_gz(gz([
            {'eventID': 'a', 'eventTime': '2026-10-14T19:32:04Z', 'eventName': 'CreateUser'},
            {'eventID': '', 'eventTime': '2026-10-14T19:32:04Z'},
            {'eventID': 'b'}]))
        self.assertEqual([i for i, _ in good], ['a'])
        self.assertEqual(skipped, 2)
        self.assertEqual(good[0][1]['@timestamp'], '2026-10-14T19:32:04Z')

    def test_bulk_body_is_idempotent_by_event_id(self):
        body = ct.bulk_body('idx', [('a', {'x': 1}), ('b', {'x': 2})]).decode().splitlines()
        self.assertEqual(json.loads(body[0]), {'index': {'_index': 'idx', '_id': 'a'}})
        self.assertEqual(len(body), 4)

    def test_summarize_counts_rejected_documents(self):
        self.assertEqual(ct.summarize([{'index': {'status': 201}}, {'index': {'status': 200}}, {'index': {'status': 400}}]), (2, 1))

    def test_prefixes_cover_the_day_boundary(self):
        import datetime as dt
        pre = list(ct.day_prefixes('111111111111', ['us-east-1'], 2, today=dt.date(2026, 10, 14)))
        self.assertEqual(pre, ['AWSLogs/111111111111/CloudTrail/us-east-1/2026/10/14/', 'AWSLogs/111111111111/CloudTrail/us-east-1/2026/10/13/'])

    def test_run_loads_batches_and_reports_counts(self):
        class S3:
            def list_objects_v2(self, **kw):
                return {'CommonPrefixes': [{'Prefix': 'AWSLogs/111111111111/CloudTrail/us-east-1/'}]}

            def get_paginator(self, name):
                outer = self

                class P:
                    def paginate(self, **kw):
                        return [{'Contents': [{'Key': kw['Prefix'] + 'f.json.gz'}]}]
                return P()

            def get_object(self, **kw):
                class B:
                    def read(self_inner):
                        return gz([{'eventID': 'e%d' % i, 'eventTime': '2026-10-14T19:32:04Z'} for i in range(3)])
                return {'Body': B()}
        sent = []
        res = ct.run({'LAB_AWS_BUCKET': 'b', 'LAB_AWS_ACCOUNT': '111111111111'}, S3(), lambda pairs: sent.append(len(pairs)) or [{'index': {'status': 201}}] * len(pairs), days=1, log=lambda *a: None)
        self.assertEqual(res['indexed'], 3 * res['files'])
        self.assertEqual(res['errors'], 0)
