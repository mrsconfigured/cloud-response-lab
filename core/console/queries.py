"""Shared Elasticsearch query helpers for enrich/hunt/status/metrics."""
import re

TECH = re.compile(r'^T[0-9]{4}(\.[0-9]{3})?$', re.I)


def parse_window(text, default='1h'):
    m = re.fullmatch(r'\s*(\d+)\s*([smhdw])\s*', text or default)
    if not m:
        raise ValueError('window must look like 30m, 1h, 7d')
    n, unit = int(m.group(1)), m.group(2)
    secs = n * {'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}[unit]
    if secs > 30 * 86400:
        raise ValueError('window is capped at 30d')
    return '%d%s' % (n, unit), secs


def esc(value):
    return re.sub(r'([\\+\-=&|!(){}\[\]^"~*?:/<>\s])', r'\\\1', value)


def index_pattern():
    return 'logs-cloud-response-lab-library-*'


def rel(secs, now):
    if secs is None:
        return 'n/a'
    secs = int(secs)
    if secs < 90:
        return '%ds' % secs
    if secs < 5400:
        return '%dm' % round(secs / 60)
    if secs < 172800:
        return '%.1fh' % (secs / 3600)
    return '%.1fd' % (secs / 86400)
