"""Scheduled CloudTrail loader (read-only).

Pulls the last N days of CloudTrail objects from S3 and bulk-loads them into the pack's Elasticsearch index.
Idempotent: the document id is the CloudTrail eventID, so a re-run updates instead of duplicating.
Credentials: a dedicated IAM user that can only list and read the trail prefix (policy in the README). It never uses the
attack-simulation identity and never holds a write or admin permission.
Configuration comes from the environment file read by core.console.es.load_env:
  LAB_AWS_BUCKET, LAB_AWS_ACCOUNT, LAB_AWS_REGION, LAB_AWS_CREDENTIALS (shared credentials file), LAB_AWS_PROFILE,
  LAB_ES_URL/LAB_ES_CA, LAB_INGEST_USER/LAB_INGEST_PASSWORD (write on the log index), LAB_ES_USER/LAB_ES_PASSWORD (console state)."""
import datetime as dt
import gzip
import json
import os
import sys
import time

INDEX = 'logs-cloud-response-lab-library-aws'


def records_from_gz(blob):
    """One CloudTrail log file -> list of (eventID, document). Records without an id or time are dropped and counted."""
    data = json.loads(gzip.decompress(blob))
    good, skipped = [], 0
    for rec in data.get('Records', []):
        if not rec.get('eventID') or not rec.get('eventTime'):
            skipped += 1
            continue
        rec['@timestamp'] = rec['eventTime']
        good.append((rec['eventID'], rec))
    return good, skipped


def bulk_body(index, pairs):
    return ''.join(json.dumps({'index': {'_index': index, '_id': i}}) + '\n' + json.dumps(d) + '\n' for i, d in pairs).encode()


def day_prefixes(account, regions, days, today=None):
    today = today or dt.datetime.now(dt.timezone.utc).date()
    for r in regions:
        for d in range(days):
            day = today - dt.timedelta(days=d)
            yield 'AWSLogs/%s/CloudTrail/%s/%04d/%02d/%02d/' % (account, r, day.year, day.month, day.day)


def summarize(items):
    ok = sum(1 for it in items if (it.get('index') or it.get('create') or {}).get('status') in (200, 201))
    return ok, len(items) - ok


def run(env, s3, es_write, days=2, max_files=400, log=print):
    bucket, account = env['LAB_AWS_BUCKET'], env['LAB_AWS_ACCOUNT']
    base = 'AWSLogs/%s/CloudTrail/' % account
    regions = [p['Prefix'].split('/')[-2] for p in s3.list_objects_v2(Bucket=bucket, Prefix=base, Delimiter='/').get('CommonPrefixes', [])]
    keys = []
    for pre in day_prefixes(account, regions, days):
        for page in s3.get_paginator('list_objects_v2').paginate(Bucket=bucket, Prefix=pre):
            keys += [o['Key'] for o in page.get('Contents', []) if o['Key'].endswith('.json.gz')]
    keys = sorted(keys, reverse=True)[:max_files]
    indexed = errors = skipped = files = 0
    batch = []
    for key in keys:
        pairs, sk = records_from_gz(s3.get_object(Bucket=bucket, Key=key)['Body'].read())
        files += 1
        skipped += sk
        batch += pairs
        while len(batch) >= 500:
            ok, bad = summarize(es_write(batch[:500]))
            indexed, errors, batch = indexed + ok, errors + bad, batch[500:]
    if batch:
        ok, bad = summarize(es_write(batch))
        indexed, errors = indexed + ok, errors + bad
    log('files=%d indexed=%d errors=%d skipped=%d regions=%s' % (files, indexed, errors, skipped, regions))
    return {'files': files, 'indexed': indexed, 'errors': errors, 'skipped': skipped}


def main():
    import boto3
    from core.console import es as eslib
    from core.console.store import ElasticStore, now_iso
    from core import packs as pk
    env = eslib.load_env()
    os.environ['AWS_SHARED_CREDENTIALS_FILE'] = env['LAB_AWS_CREDENTIALS']
    session = boto3.Session(profile_name=env.get('LAB_AWS_PROFILE', 'lab-reader'), region_name=env.get('LAB_AWS_REGION', 'us-east-2'))
    ident = session.client('sts').get_caller_identity()
    if ident['Account'] != env['LAB_AWS_ACCOUNT']:
        print('account mismatch; nothing loaded')
        return 2
    s3 = session.client('s3')
    writer = eslib.Http(env['LAB_ES_URL'], env['LAB_INGEST_USER'], env['LAB_INGEST_PASSWORD'], env.get('LAB_ES_CA'))

    def es_write(pairs):
        import urllib.request
        req = urllib.request.Request(writer.base + '/_bulk', data=bulk_body(INDEX, pairs), method='POST', headers=dict(writer.headers, **{'Content-Type': 'application/x-ndjson'}))
        with urllib.request.urlopen(req, timeout=120, context=writer.ctx) as r:
            return json.load(r)['items']

    t0 = time.time()
    res = run(env, s3, es_write, days=int(env.get('LAB_INGEST_DAYS', '2')))
    state = ElasticStore(eslib.elastic(env), pk.config()['indices']['state'])
    state.put('ingest_run', 'aws:' + now_iso(), {'source': 'aws', 'docs': res['indexed'], 'errors': res['errors'], 'at': now_iso(), 'seconds': round(time.time() - t0, 1)})
    return 0


if __name__ == '__main__':
    sys.exit(main())
