"""Redaction for anything that leaves the droplet (Discord embeds, screenshots, commits).
Rule: no raw account IDs, IP addresses, e-mail addresses or access-key IDs."""
import re

_ACCT = re.compile(r'(?<![0-9A-Za-z-])[0-9]{12}(?![0-9A-Za-z-])')
_IP = re.compile(r'(?<![0-9.])((?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2}))\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(?![0-9.])')
_MAIL = re.compile(r'([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
_KEY = re.compile(r'\b(AKIA|ASIA|AIDA|AROA)[0-9A-Z]{12,16}([0-9A-Z]{4})\b')
_GUID = re.compile(r'\b([0-9a-fA-F]{8})-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')


def mask_ip(ip):
    return _IP.sub(lambda m: m.group(1) + '.x.x', ip) if isinstance(ip, str) else ip


def scrub(text, keep_guid=True):
    if not isinstance(text, str):
        return text
    t = _MAIL.sub(lambda m: m.group(1) + '***@[domain]', text)
    t = _KEY.sub(lambda m: m.group(1) + '\u2026' + m.group(2), t)
    t = _IP.sub(lambda m: m.group(1) + '.x.x', t)
    t = _ACCT.sub('[acct]', t)
    if not keep_guid:
        t = _GUID.sub(lambda m: m.group(1) + '\u2026', t)
    return t


def scrub_keep(text, protect):
    # scrub everything except literal protected strings (the lab's own Kibana address, which is meant to be a working link)
    marks = {}
    for i, p in enumerate(p for p in protect if p):
        marks['\x00%d\x00' % i] = p
        text = text.replace(p, '\x00%d\x00' % i)
    text = scrub(text)
    for k, v in marks.items():
        text = text.replace(k, v)
    return text


def clean(obj, protect=()):
    if isinstance(obj, dict):
        return {k: clean(v, protect) for k, v in obj.items()}
    if isinstance(obj, list):
        return [clean(v, protect) for v in obj]
    return scrub_keep(obj, protect) if isinstance(obj, str) and protect else scrub(obj)


def leaks(text):
    """Names of the patterns still present. Used by tests and the poster as a final gate."""
    found = []
    if _ACCT.search(text):
        found.append('account-id')
    if re.search(r'(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])', text) and not re.search(r'^\s*$', text):
        # an address that is not masked ends in .x.x
        for m in re.finditer(r'(?<![0-9.])((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?![0-9.])', text):
            found.append('ip')
            break
    if re.search(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}', text):
        found.append('email')
    if re.search(r'\b(AKIA|ASIA)[0-9A-Z]{16}\b', text):
        found.append('access-key-id')
    return found
