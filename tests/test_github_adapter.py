import unittest
from unittest.mock import patch
from scripts.github_review_adapter import GitHubReviews, AdapterError
from scripts.github_status_publisher import publish

SHA = 'a' * 40
BASE = 'https://api.github.com/repos/owner_a/lab/pulls/7'


def pr(sha=SHA):
    return {'state': 'open', 'merged': False, 'draft': False, 'head': {'sha': sha}, 'user': {'login': 'owner_a'}}


def review(state='APPROVED', sha=SHA, rid=1):
    return {'id': rid, 'state': state, 'commit_id': sha, 'user': {'login': 'owner_b', 'type': 'User'}}


class MockHTTP:
    def __init__(self, replies):
        self.replies, self.calls = list(replies), []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, body))
        if headers['Authorization'] != 'Bearer synthetic-test-token':
            raise AssertionError('missing test auth')
        return self.replies.pop(0)


def adapter(replies):
    transport = MockHTTP(replies)
    return GitHubReviews('owner_a/lab', {'owner_a': 'owner_a', 'owner_b': 'owner_b'}, transport,
                         lambda: 'synthetic-test-token'), transport


def snapshot(items=None, end=SHA):
    return [(200, {}, pr()), (200, {}, [review()] if items is None else items), (200, {}, pr(end))]


class GitHubAdapterTests(unittest.TestCase):
    def test_read_only_and_current_head(self):
        client, mock = adapter(snapshot())
        self.assertTrue(client.evaluate(7)['ok'])
        self.assertEqual([c[0] for c in mock.calls], ['GET'] * 3)
        self.assertEqual(mock.calls[-1][1], BASE)

    def test_pagination(self):
        link = '<' + BASE + '/reviews?per_page=100&page=2>; rel="next"'
        client, mock = adapter([(200, {}, pr()), (200, {'Link': link}, []),
                                (200, {}, [review()]), (200, {}, pr())])
        self.assertEqual(client.evaluate(7)['pages'], 2)
        self.assertTrue(mock.calls[2][1].endswith('page=2'))

    def test_stale_head_and_stale_review(self):
        for replies in (snapshot(end='b' * 40), snapshot([review(sha='b' * 40)])):
            client, _ = adapter(replies)
            self.assertFalse(client.evaluate(7)['ok'])

    def test_changes_requested_and_dismissed(self):
        for state in ('CHANGES_REQUESTED', 'DISMISSED'):
            client, _ = adapter(snapshot([review(), review(state=state, rid=2)]))
            self.assertFalse(client.evaluate(7)['ok'])

    def test_pagination_attack_and_malformed(self):
        for link in ('<https://evil.invalid/reviews>; rel="next"', 'broken',
                     '<' + BASE + '/reviews?per_page=100&page=1>; rel="next"'):
            client, mock = adapter([(200, {}, pr()), (200, {'link': link}, [])])
            with self.assertRaises(AdapterError):
                client.evaluate(7)
            self.assertEqual(len(mock.calls), 2)

    def test_failed_page_duplicate_and_draft(self):
        client, _ = adapter([(200, {}, pr()), (429, {'retry-after': '60'}, {})])
        with self.assertRaises(AdapterError):
            client.evaluate(7)
        client, _ = adapter(snapshot([review(), review()]))
        self.assertFalse(client.evaluate(7)['ok'])
        draft = pr(); draft['draft'] = True
        client, _ = adapter([(200, {}, draft)])
        with self.assertRaises(AdapterError):
            client.evaluate(7)

    def test_no_environment_access_until_request(self):
        with patch.dict('os.environ', {}, clear=True):
            client = GitHubReviews('owner_a/lab', {}, transport=lambda *a: self.fail('network'))
            with self.assertRaises(AdapterError):
                client.evaluate(7)

    def test_publish_gates_and_fresh_recheck(self):
        for allowed in (False, True):
            client, mock = adapter([])
            with self.assertRaises(AdapterError):
                publish(client, 7, allow_publish=allowed, reviewed_repository="owner_a/lab")
            self.assertEqual(mock.calls, [])

    def test_exception_details_never_escape(self):
        def bad(*args):
            raise RuntimeError('synthetic-test-token')
        client = GitHubReviews('owner_a/lab', {}, bad, lambda: 'synthetic-test-token')
        with self.assertRaises(AdapterError) as caught:
            client.evaluate(7)
        self.assertNotIn('synthetic-test-token', str(caught.exception))

    def test_transport_redirect_and_size_fail_closed(self):
        from scripts.github_review_adapter import http, NoRedirect
        with self.assertRaises(AdapterError):
            NoRedirect().redirect_request(None, None, 302, '', {}, 'https://evil.invalid')
        class Response:
            status = 200
            headers = {}
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self, limit):
                return b'x' * limit
        with patch('urllib.request.build_opener') as opener:
            opener.return_value.open.return_value = Response()
            with self.assertRaises(AdapterError):
                http('GET', BASE, {})

    def test_invalid_repository_no_network(self):
        for repo in ('../lab', 'owner_a/..', 'owner_a/lab/extra', 'https://evil.invalid/lab', None):
            with self.assertRaises(AdapterError):
                GitHubReviews(repo, {})
