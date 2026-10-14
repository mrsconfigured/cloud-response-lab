"""Generate NEW private local TLS/logins after review; refuses existing secrets."""
import argparse
import json
import os
import secrets
import subprocess
from pathlib import Path
from .build import ROOT


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--reviewed', action='store_true'); args = parser.parse_args()
    if not args.reviewed: parser.error('parent review required')
    folder = ROOT / 'infra/secrets/v1'
    if folder.exists(): raise SystemExit('Refusing to overwrite existing secrets; inspect/preserve them')
    os.umask(0o077); folder.mkdir(parents=True); certs = folder / 'certs'; certs.mkdir()
    for name in ('elastic_password', 'kibana_password', 'response_token'):
        (folder / name).write_text(secrets.token_urlsafe(36) + '\n')
    def openssl(*args):
        subprocess.run(['openssl', *args], cwd=certs, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    openssl('req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt', '-days', '365', '-subj', '/CN=cloud-response-lab-local-CA')
    for name in ('elasticsearch', 'kibana', 'response'):
        openssl('req', '-newkey', 'rsa:3072', '-nodes', '-keyout', name + '.key', '-out', name + '.csr', '-subj', '/CN=' + name)
        ext = certs / (name + '.ext'); ext.write_text('subjectAltName=DNS:' + name + ',DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n')
        openssl('x509', '-req', '-in', name + '.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', name + '.crt', '-days', '90', '-extfile', name + '.ext')
    # Exact file mounts, container service UID 1000; no directory-wide chmod/chown.
    # Docker Desktop UID access may differ; parent must verify on target host.
    kibana = {'server.host': '0.0.0.0', 'server.ssl.enabled': True,
              'server.ssl.certificate': '/usr/share/kibana/config/certs/kibana.crt',
              'server.ssl.key': '/usr/share/kibana/config/certs/kibana.key',
              'elasticsearch.hosts': ['https://elasticsearch:9200'],
              'elasticsearch.username': 'kibana_system',
              'elasticsearch.password': (folder / 'kibana_password').read_text().strip(),
              'elasticsearch.ssl.certificateAuthorities': ['/usr/share/kibana/config/certs/ca.crt'],
              'xpack.encryptedSavedObjects.encryptionKey': secrets.token_hex(32),
              'xpack.security.encryptionKey': secrets.token_hex(32),
              'xpack.reporting.encryptionKey': secrets.token_hex(32), 'telemetry.enabled': False}
    (folder / 'kibana.yml').write_text(json.dumps(kibana, indent=2) + '\n')
    # Parent directories stay 0700; only exact mounts are container-readable.
    for path in [folder / 'elastic_password', folder / 'response_token', folder / 'kibana.yml'] + [certs / name for name in ('ca.crt', 'elasticsearch.crt', 'elasticsearch.key', 'kibana.crt', 'kibana.key', 'response.crt', 'response.key')]:
        path.chmod(0o444)
    # Elasticsearch entrypoint rejects world-readable password files.
    # Host owner and service UID are both verified as 1000 on this target.
    (folder / 'elastic_password').chmod(0o400)
    print('Generated private files under infra/secrets/v1; no credentials printed. Review target-host UID readability before launch.')


if __name__ == '__main__': main()
