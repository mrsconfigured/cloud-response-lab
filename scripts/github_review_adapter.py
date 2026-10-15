"""Experimental trusted-host REST adapter. Import is offline; CLI network is opt-in.
Never run this from untrusted PR code with a token. Status publishing is separate.
"""
import argparse
import json
import os
import re
import urllib.error
import urllib.request
from urllib.parse import urlsplit, parse_qs

from scripts.cross_owner_review import check

API = 'https://api.github.com'


class AdapterError(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AdapterError('redirect refused')


def http(method, url, headers, body=None):
    """Injected transport contract: (status, lower-case headers, decoded JSON).
    No request/response logging, redirects, automatic retry, or exception bodies.
    """
    try:
        req = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(),
                                     headers=headers, method=method)
        with urllib.request.build_opener(NoRedirect).open(req, timeout=20) as response:
            data = response.read(2_000_001)
            if len(data) > 2_000_000:
                raise AdapterError('response too large')
            return response.status, {k.lower(): v for k, v in response.headers.items()}, json.loads(data)
    except Exception:
        raise AdapterError('HTTP transport failed; details suppressed') from None


class GitHubReviews:
    def __init__(self, repository, partners, transport=http, token_provider=None):
        if (not isinstance(repository, str) or
                not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*', repository)):
            raise AdapterError('invalid repository')
        self.repository, self.partners, self.transport = repository, partners, transport
        self.token_provider = token_provider or (lambda: os.environ.get('GITHUB_TOKEN'))

    def request(self, method, path, body=None):
        if (method not in ('GET', 'POST') or not path.startswith('/repos/' + self.repository + '/')
                or '..' in path.split('/') or '#' in path):
            raise AdapterError('out-of-repository request')
        try:
            token = self.token_provider()
        except Exception:
            raise AdapterError('runtime authentication unavailable') from None
        if not token or not isinstance(token, str) or any(ord(c) < 32 for c in token):
            raise AdapterError('runtime GITHUB_TOKEN required')
        headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
                   'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'personal-lab-review-adapter',
                   'Content-Type': 'application/json'}
        try:
            status, response_headers, data = self.transport(method, API + path, headers, body)
        except Exception:
            raise AdapterError('HTTP transport failed; details suppressed') from None
        if status != (201 if method == 'POST' else 200):
            raise AdapterError('GitHub request rejected; no retry')
        return {k.lower(): v for k, v in response_headers.items()}, data

    def pull(self, number):
        if type(number) is not int or number <= 0:
            raise AdapterError('positive PR number required')
        _, pr = self.request('GET', f'/repos/{self.repository}/pulls/{number}')
        try:
            if pr['state'] != 'open' or pr['merged'] is not False or pr['draft'] is not False:
                raise AdapterError('PR not open and ready')
            sha, author = pr['head']['sha'], pr['user']['login']
            if not re.fullmatch('[0-9a-f]{40}', sha) or not isinstance(author, str) or not author:
                raise AdapterError('invalid PR metadata')
            return sha, author
        except (KeyError, TypeError):
            raise AdapterError('incomplete PR metadata') from None

    def evaluate(self, number):
        head, author = self.pull(number)
        root = f'/repos/{self.repository}/pulls/{number}/reviews'
        path = root + '?per_page=100&page=1'
        pages, visited = [], set()
        for page in range(1, 101):
            if path in visited:
                raise AdapterError('pagination cycle')
            visited.add(path)
            headers, items = self.request('GET', path)
            if not isinstance(items, list) or len(items) > 100:
                raise AdapterError('invalid reviews page')
            pages.append({'complete': True, 'items': items})
            link = headers.get('link', '')
            next_links = []
            for part in link.split(',') if link else []:
                match = re.fullmatch(r' *<([^>]+)>; *rel="([a-z]+)" *', part)
                if not match:
                    raise AdapterError('malformed pagination')
                if match[2] == 'next':
                    next_links.append(match[1])
            if not next_links:
                break
            if len(next_links) != 1:
                raise AdapterError('ambiguous pagination')
            parsed = urlsplit(next_links[0])
            if (parsed.scheme != 'https' or parsed.netloc != 'api.github.com' or parsed.path != root
                    or parsed.fragment or parse_qs(parsed.query) != {'per_page': ['100'], 'page': [str(page + 1)]}):
                raise AdapterError('unsafe pagination target')
            path = parsed.path + '?' + parsed.query
        else:
            raise AdapterError('pagination limit exceeded')
        end, end_author = self.pull(number)
        if end_author != author:
            raise AdapterError('PR author changed')
        snapshot = {'partners': self.partners, 'author': author, 'head_start': head,
                    'head_end': end, 'draft': False, 'review_pages': pages}
        ok, reason = check(snapshot)
        return {'ok': ok, 'reason': reason, 'sha': head, 'number': number, 'pages': len(pages)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('repository')
    parser.add_argument('number', type=int)
    parser.add_argument('--owner_a', required=True)
    parser.add_argument('--owner_b', required=True)
    parser.add_argument('--allow-read-network', action='store_true')
    args = parser.parse_args()
    if not args.allow_read_network:
        parser.error('offline default: explicit --allow-read-network required')
    try:
        result = GitHubReviews(args.repository, {'owner_a': args.owner_a, 'owner_b': args.owner_b}).evaluate(args.number)
        print(json.dumps(result))
        return 0 if result['ok'] else 1
    except (AdapterError, ValueError, TypeError):
        print('FAIL: review snapshot could not be verified')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
