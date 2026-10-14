"""Entra directory-audit loader (read-only Graph scopes: AuditLog.Read.All, Directory.Read.All).

The Azure client secret is NOT stored on the lab host. The gateway side pipes AZURE_TENANT_ID / AZURE_CLIENT_ID /
AZURE_CLIENT_SECRET over SSH stdin into a 0600 temp file, which this module reads and deletes before doing anything else.
Idempotent: the document id is the Graph audit id. Sign-in logs are not requested: they need Entra ID P1 or P2."""
import datetime as dt
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

INDEX = 'logs-cloud-response-lab-library-entra'


def _default_envfile():
    from core.console import paths
    return os.environ.get('LAB_AZURE_ENVFILE', str(paths.azure_envfile()))


GUID = re.compile(r'^[0-9a-fA-F-]{36}$')


def take_credentials(path=None):
    path = path or _default_envfile()
    creds = {}
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                k, _, v = line.rstrip('\n').partition('=')
                creds[k] = v
        os.unlink(path)
    ok = bool(GUID.match(creds.get('AZURE_TENANT_ID', '')) and GUID.match(creds.get('AZURE_CLIENT_ID', '')) and len(creds.get('AZURE_CLIENT_SECRET', '')) >= 20)
    return creds if ok else None


def normalize(doc):
    doc['@timestamp'] = doc.get('activityDateTime')
    return doc


def window_filter(days, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    return "activityDateTime ge %s" % (now - dt.timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%SZ')


def first_url(days, now=None):
    q = urllib.parse.urlencode({'$top': '100', '$filter': window_filter(days, now)})
    return 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?' + q


def scrub_error(text):
    return re.sub(r'[0-9a-fA-F-]{36}', '[guid]', text)[:300]


def bulk_body(docs):
    return ''.join(json.dumps({'index': {'_index': INDEX, '_id': d['id']}}) + '\n' + json.dumps(d) + '\n' for d in docs if d.get('id') and d.get('activityDateTime')).encode()


def main():
    from core import packs as pk
    from core.console import es as eslib
    from core.console.store import ElasticStore, now_iso
    creds = take_credentials()
    if not creds:
        print('Azure credentials missing or malformed; nothing loaded')
        return 2
    env = eslib.load_env()
    body = urllib.parse.urlencode({'client_id': creds['AZURE_CLIENT_ID'], 'client_secret': creds['AZURE_CLIENT_SECRET'], 'scope': 'https://graph.microsoft.com/.default', 'grant_type': 'client_credentials'}).encode()
    try:
        tok = json.load(urllib.request.urlopen(urllib.request.Request('https://login.microsoftonline.com/%s/oauth2/v2.0/token' % creds['AZURE_TENANT_ID'], data=body), timeout=30))['access_token']
    except urllib.error.HTTPError as e:
        print('token request failed', e.code, scrub_error(e.read().decode()))
        return 3
    docs, url, pages = [], first_url(int(env.get('LAB_ENTRA_DAYS', '7'))), 0
    while url and pages < 30:
        try:
            j = json.load(urllib.request.urlopen(urllib.request.Request(url, headers={'Authorization': 'Bearer ' + tok}), timeout=60))
        except urllib.error.HTTPError as e:
            print('graph request failed', e.code, scrub_error(e.read().decode()))
            return 4
        docs += [normalize(d) for d in j.get('value', [])]
        url, pages = j.get('@odata.nextLink'), pages + 1
    writer = eslib.Http(env['LAB_ES_URL'], env['LAB_INGEST_USER'], env['LAB_INGEST_PASSWORD'], env.get('LAB_ES_CA'))
    ok = bad = 0
    for i in range(0, len(docs), 500):
        chunk = docs[i:i + 500]
        req = urllib.request.Request(writer.base + '/_bulk', data=bulk_body(chunk), method='POST', headers=dict(writer.headers, **{'Content-Type': 'application/x-ndjson'}))
        with urllib.request.urlopen(req, timeout=120, context=writer.ctx) as r:
            for it in json.load(r)['items']:
                if (it.get('index') or {}).get('status') in (200, 201):
                    ok += 1
                else:
                    bad += 1
    ElasticStore(eslib.elastic(env), pk.config()['indices']['state']).put('ingest_run', 'entra:' + now_iso(), {'source': 'entra', 'docs': ok, 'errors': bad, 'at': now_iso()})
    print('fetched=%d indexed=%d errors=%d' % (len(docs), ok, bad))
    return 0


if __name__ == '__main__':
    sys.exit(main())
