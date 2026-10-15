"""Minimal stdlib HTTP client for Elasticsearch, Kibana and Shuffle. No third-party dependencies."""
import base64
import json
import os
import ssl
import urllib.error
import urllib.request


def load_env(path=None):
    from core.console import paths
    path = path or os.environ.get('LAB_ENV', str(paths.env_file()))
    env = {}
    try:
        for line in open(path):
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, _, v = line.partition('=')
                env[k.strip()] = v.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    env.update({k: v for k, v in os.environ.items() if k.startswith('LAB_')})
    return env


class Http:
    def __init__(self, base, user=None, password=None, cafile=None, kibana=False, bearer=None, timeout=30):
        self.base = base.rstrip('/')
        self.kibana = kibana
        self.timeout = timeout
        self.headers = {'Content-Type': 'application/json'}
        if user:
            self.headers['Authorization'] = 'Basic ' + base64.b64encode((user + ':' + password).encode()).decode()
        if bearer:
            self.headers['Authorization'] = 'Bearer ' + bearer
        if kibana:
            self.headers['kbn-xsrf'] = 'true'
        self.ctx = ssl.create_default_context(cafile=cafile) if base.startswith('https') and cafile else None

    def request(self, method, path, body=None, allow=(), timeout=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=self.headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout, context=self.ctx) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            if e.code in allow:
                return {}
            raise RuntimeError('%s %s -> HTTP %s %s' % (method, path, e.code, e.read()[:300].decode('utf-8', 'replace')))
        return json.loads(raw) if raw else {}


def elastic(env, admin=False):
    user = env.get('LAB_ADMIN_USER') if admin else env.get('LAB_ES_USER')
    pw = env.get('LAB_ADMIN_PASSWORD') if admin else env.get('LAB_ES_PASSWORD')
    return Http(env['LAB_ES_URL'], user, pw, env.get('LAB_ES_CA'))


def kibana(env, admin=True):
    user = env.get('LAB_ADMIN_USER') if admin else env.get('LAB_ES_USER')
    pw = env.get('LAB_ADMIN_PASSWORD') if admin else env.get('LAB_ES_PASSWORD')
    return Http(env['LAB_KIBANA_URL'], user, pw, kibana=True)


def shuffle(env):
    return Http(env['LAB_SHUFFLE_URL'], bearer=env['LAB_SHUFFLE_APIKEY'])
