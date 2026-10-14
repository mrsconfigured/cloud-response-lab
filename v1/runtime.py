"""Post-review runtime commands. TLS verified, loopback only; no cloud endpoints."""
import argparse
import base64
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from .build import ROOT, INDEX, RULE_ID, compile_rule
from .fixtures import generate, document

EVIDENCE = ROOT / 'artifacts/v1'
SECRETS = ROOT / 'infra/secrets/v1'


def endpoint(service):
    ports = {'elasticsearch': 9200, 'kibana': 5601, 'response': 8443}
    host = service if os.environ.get('LAB_INTERNAL_CLIENT') == '1' else 'localhost'
    return f'https://{host}:{ports[service]}'


class Client:
    def __init__(self, url, auth, ca):
        parsed = urllib.parse.urlsplit(url)
        internal = os.environ.get('LAB_INTERNAL_CLIENT') == '1' and (parsed.hostname, parsed.port) in {('elasticsearch', 9200), ('kibana', 5601), ('response', 8443)}
        if parsed.scheme != 'https' or (parsed.hostname not in ('localhost', '127.0.0.1') and not internal) or parsed.username:
            raise ValueError('TLS loopback endpoint required; tunnel private hosts locally')
        self.url, self.auth = url.rstrip('/'), auth
        self.context = ssl.create_default_context(cafile=str(ca))

    def call(self, method, path, data=None, content_type='application/json', raw=False):
        if not path.startswith('/') or path.startswith('//'):
            raise ValueError('absolute local API path required')
        if data is not None and not isinstance(data, bytes):
            data = json.dumps(data).encode()
        request = urllib.request.Request(self.url + path, data=data, method=method,
            headers={'Authorization': self.auth, 'Content-Type': content_type, 'kbn-xsrf': 'cloud-response-lab'})
        # Redirects are forbidden: credentials must never leave the reviewed endpoint.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=self.context))
        with opener.open(request, timeout=30) as response:
            payload = response.read()
        return payload if raw else json.loads(payload)


def clients():
    password = (SECRETS / 'elastic_password').read_text().strip()
    auth = 'Basic ' + base64.b64encode(('elastic:' + password).encode()).decode()
    ca = SECRETS / 'certs/ca.crt'
    return Client(endpoint('elasticsearch'), auth, ca), Client(endpoint('kibana'), auth, ca)


def save_bytes(name, value):
    EVIDENCE.mkdir(parents=True, exist_ok=True, mode=0o700)
    EVIDENCE.chmod(0o700)
    fd = os.open(EVIDENCE / name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(value)


def save(name, value):
    save_bytes(name, (json.dumps(value, indent=2) + '\n').encode())


def bootstrap(es, kibana):
    es.call('PUT', '/_index_template/cloud-response-lab-v1', json.loads((ROOT / 'v1/generated/index-template.json').read_text()))
    try:
        es.call('PUT', '/' + INDEX, {})
    except urllib.error.HTTPError as exc:
        if exc.code != 400 or 'resource_already_exists_exception' not in exc.read().decode():
            raise
    rule = compile_rule(); rule['enabled'] = True
    try:
        result = kibana.call('POST', '/api/detection_engine/rules', rule)
    except urllib.error.HTTPError as exc:
        if exc.code != 409:
            raise
        result = kibana.call('PUT', '/api/detection_engine/rules', rule)
    save('scheduled-rule.json', result)
    boundary = 'cloudresponselabsyntheticboundary'
    crlf = chr(13) + chr(10)
    body = ("--" + boundary + crlf + 'Content-Disposition: form-data; name="file"; filename="dashboard.ndjson"' + crlf + 'Content-Type: application/ndjson' + crlf + crlf).encode()
    body += (ROOT / 'v1/kibana/dashboard.ndjson').read_bytes() + (crlf + '--' + boundary + '--' + crlf).encode()
    result = kibana.call('POST', '/api/saved_objects/_import?overwrite=true', body, 'multipart/form-data; boundary=' + boundary)
    if not result.get('success'):
        raise AssertionError(result)
    save('dashboard-import.json', result)


def ingest(es):
    cases = generate()
    lines = []
    for case in cases:
        lines.extend([json.dumps({'index': {'_index': INDEX, '_id': case['event']['eventID']}}), json.dumps(document(case))])
    result = es.call('POST', '/_bulk?refresh=wait_for', ('\n'.join(lines) + '\n').encode(), 'application/x-ndjson')
    if result.get('errors'):
        raise AssertionError('bulk ingest errors: ' + json.dumps(result))
    save('cases.json', cases); save('ingest.json', result)


def assert_hits(es):
    cases = json.loads((EVIDENCE / 'cases.json').read_text())
    expected = {c['event']['eventID'] for c in cases if c['expected']}
    body = {'size': 100, 'query': {'bool': {'must': [{'query_string': {'query': compile_rule()['query']}}], 'filter': [{'terms': {'eventID': [c['event']['eventID'] for c in cases]}}]}}}
    result = es.call('POST', '/' + INDEX + '/_search', body)
    actual = {h['_source']['eventID'] for h in result['hits']['hits']}
    if actual != expected:
        raise AssertionError((actual, expected))
    save('elastic-hits.json', result)
    print('PASS real compiled Lucene query: exactly three attacks; five negatives excluded')
    return cases, expected


def assert_scheduled(es, expected):
    deadline = time.monotonic() + 240
    # Security alert indices retain custom CloudTrail fields in _source only.
    # Query indexed rule identity, then select this entire eight-case batch.
    batch_ids = {c['event']['eventID'] for c in json.loads((EVIDENCE / 'cases.json').read_text())}
    body = {'size': 100, 'query': {'term': {'kibana.alert.rule.rule_id': RULE_ID}}}
    while time.monotonic() < deadline:
        try:
            result = es.call('POST', '/.alerts-security.alerts-default/_search', body)
            if result['hits']['total']['value'] > 100:
                raise AssertionError('Alert evidence exceeds bounded fetch; pagination required')
            result['hits']['hits'] = [h for h in result['hits']['hits'] if h['_source'].get('eventID') in batch_ids]
            actual = {h['_source'].get('eventID') for h in result['hits']['hits']}
            if actual == expected:
                save('scheduled-alerts.json', result); print('PASS scheduled Elastic detection emitted all three alerts'); return result
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise
        time.sleep(10)
    raise AssertionError('No complete scheduled alert evidence within 240s; inspect rule execution failures')


def response_replay(cases):
    ca = SECRETS / 'certs/ca.crt'
    client = Client(endpoint('response'), 'Bearer ' + (SECRETS / 'response_token').read_text().strip(), ca)
    results = []
    for case in cases:
        if case['expected']:
            payload = {'synthetic': True, 'rule_id': RULE_ID, 'event': case['event']}
            first = client.call('POST', '/respond', payload)
            second = client.call('POST', '/respond', payload)
            if first['status'] != 'human_review_required':
                raise AssertionError('Fresh event did not produce human_review_required')
            if second['status'] != 'duplicate' or first['actions'] != [] or second['actions'] != []:
                raise AssertionError('Response replay or dry-run action invariant failed')
            results.append({'case': case['name'], 'first': first, 'replay': second})
    save('response-api.json', results)


def capture(kibana):
    export = kibana.call('POST', '/api/saved_objects/_export', {'objects': [{'type': 'dashboard', 'id': 'cloud-response-lab-v1'}], 'includeReferencesDeep': True}, raw=True)
    save_bytes('kibana-runtime-export.ndjson', export)
    print('Captured runtime Kibana export. Screenshot still requires logged-in browser at https://localhost:5601/app/dashboards#/view/cloud-response-lab-v1')


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('command', choices=['bootstrap', 'ingest', 'assert', 'capture'])
    parser.add_argument('--reviewed', action='store_true'); args = parser.parse_args()
    if not args.reviewed:
        parser.error('Activation is blocked until parent review; then pass --reviewed explicitly')
    es, kibana = clients()
    if args.command == 'bootstrap': bootstrap(es, kibana)
    elif args.command == 'ingest': ingest(es)
    elif args.command == 'assert':
        cases, expected = assert_hits(es); assert_scheduled(es, expected); response_replay(cases)
    else: capture(kibana)


if __name__ == '__main__':
    main()
