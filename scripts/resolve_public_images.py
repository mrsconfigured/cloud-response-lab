"""Opt-in anonymous public-registry metadata fetch. Never reads Docker credentials,
loads layers, starts Docker, or modifies Compose. Anonymous pull tokens stay in RAM.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import urllib.request
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
TARGETS = [
    ('elasticsearch', 'docker.elastic.co', 'elasticsearch/elasticsearch', '9.5.5',
     'https://docker-auth.elastic.co/auth', 'token-service'),
    ('kibana', 'docker.elastic.co', 'kibana/kibana', '9.5.5',
     'https://docker-auth.elastic.co/auth', 'token-service'),
    ('shuffle-frontend', 'ghcr.io', 'shuffle/shuffle-frontend', 'latest', 'https://ghcr.io/token', 'ghcr.io'),
    ('shuffle-backend', 'ghcr.io', 'shuffle/shuffle-backend', 'latest', 'https://ghcr.io/token', 'ghcr.io'),
    ('shuffle-opensearch', 'registry-1.docker.io', 'opensearchproject/opensearch', '3.2.0',
     'https://auth.docker.io/token', 'registry.docker.io')]
ACCEPT = ', '.join(['application/vnd.oci.image.index.v1+json',
                    'application/vnd.docker.distribution.manifest.list.v2+json',
                    'application/vnd.oci.image.manifest.v1+json',
                    'application/vnd.docker.distribution.manifest.v2+json'])


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise ValueError('registry redirect refused')


def fetch(url, headers=None):
    with urllib.request.build_opener(NoRedirect).open(
            urllib.request.Request(url, headers=headers or {}), timeout=25) as response:
        raw = response.read(4_000_001)
        if len(raw) > 4_000_000:
            raise ValueError('metadata bound exceeded')
        return raw, response.headers


def verify_manifest(raw, declared):
    digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
    if declared != digest:
        raise ValueError('registry digest mismatch')
    document = json.loads(raw)
    if document.get('schemaVersion') != 2:
        raise ValueError('unsupported manifest schema')
    return digest, document


def resolve(target):
    name, host, repository, tag, realm, service = target
    token_url = realm + '?' + urllib.parse.urlencode({'service': service, 'scope': 'repository:' + repository + ':pull'})
    raw, _ = fetch(token_url)
    auth = json.loads(raw)
    token = auth.get('token') or auth.get('access_token')
    if not isinstance(token, str) or not token:
        raise ValueError('anonymous public access unavailable')
    headers = {'Authorization': 'Bearer ' + token, 'Accept': ACCEPT}
    url = 'https://' + host + '/v2/' + repository + '/manifests/' + tag
    raw, response = fetch(url, headers)
    digest, doc = verify_manifest(raw, response.get('Docker-Content-Digest'))
    records = []
    for entry in doc.get('manifests', []):
        platform = entry.get('platform', {})
        if platform.get('os') != 'linux' or platform.get('architecture') not in ('amd64', 'arm64'):
            continue
        child_digest = entry['digest']
        if not child_digest.startswith('sha256:') or len(child_digest) != 71:
            raise ValueError('invalid child digest')
        child_raw, child_headers = fetch('https://' + host + '/v2/' + repository + '/manifests/' + child_digest, headers)
        verified, child = verify_manifest(child_raw, child_headers.get('Docker-Content-Digest'))
        if verified != child_digest:
            raise ValueError('platform descriptor mismatch')
        records.append({'platform': platform, 'digest': verified, 'media_type': child['mediaType'],
                        'manifest_bytes': len(child_raw), 'config_digest': child['config']['digest']})
    if not records:
        raise ValueError('no verified linux amd64/arm64 child manifests')
    ref_host = 'docker.io' if host == 'registry-1.docker.io' else host
    return {'service': name, 'source_url': url, 'source_tag': tag,
            'immutable_ref': ref_host + '/' + repository + '@' + digest,
            'digest': digest, 'media_type': doc['mediaType'], 'manifest_bytes': len(raw),
            'platforms': records, 'signature_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allow-public-network', action='store_true')
    args = parser.parse_args()
    if not args.allow_public_network:
        parser.error('offline default; --allow-public-network required')
    report = {'checked_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'method': 'anonymous public registry GET; manifest SHA256 independently recomputed; no blobs',
              'images': [], 'unresolved': []}
    for target in TARGETS:
        try:
            item = resolve(target)
            report['images'].append(item)
            print(target[0] + ': manifest/platform digests verified')
        except Exception as exc:
            report['unresolved'].append({'service': target[0], 'error_type': type(exc).__name__})
            print(target[0] + ': unresolved (' + type(exc).__name__ + ')')
    (ROOT / 'infra/image-lock.staged.json').write_text(json.dumps(report, indent=2) + chr(10))
    return 1 if report['unresolved'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
