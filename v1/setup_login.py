"""Run after Elasticsearch starts, before Kibana; local reviewed bootstrap only."""
import argparse
from .runtime import clients, SECRETS


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--reviewed', action='store_true'); args = parser.parse_args()
    if not args.reviewed: parser.error('parent review required')
    es, _ = clients()
    es.call('POST', '/_security/user/kibana_system/_password', {'password': (SECRETS / 'kibana_password').read_text().strip()})
    # Named human accounts must be created by their actual owners; no impersonation.
    print('Kibana service login initialized; elastic bootstrap login is local only. Create distinct Owner A/Owner B users before collaboration.')


if __name__ == '__main__': main()
