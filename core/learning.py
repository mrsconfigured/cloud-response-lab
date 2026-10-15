"""The learning log: one source, the web page is the reference, Discord only carries a launcher.

learning-log.json (served to the web page) has exactly this shape:
  {"updated": "...Z", "entries": [{"command", "topic", "does", "when", "added_by", "added_at"}]}
learning-meta.json (not served) holds what the page does not need: a few-word gloss and the optional reason an entry was added, keyed by entry id.
LEARNING-LOG.md is generated. Secrets are refused; addresses, e-mails and account ids are masked.
"""
import datetime as dt
import hashlib
import json
import os
import re
from pathlib import Path

from core.console.redact import clean, scrub

TOPIC_ORDER = ['git', 'python', 'pytest', 'pull request', 'tailscale', 'elastic', 'shuffle']
PURPLE = 0xA98BF0
PUBLIC_KEYS = ('command', 'topic', 'does', 'when', 'added_by', 'added_at')

SECRET_PATTERNS = [r'ghp_[A-Za-z0-9]{20,}', 'github' + r'_pat_[A-Za-z0-9_]{20,}', 'tsk' + r'ey-[A-Za-z0-9-]{10,}', r'\b(AKIA|ASIA)[0-9A-Z]{16}\b', r'-----BEGIN [A-Z ]*PRIVATE KEY',
                   r'xox[abprs]-[A-Za-z0-9-]{10,}', r'\bsk-[A-Za-z0-9]{20,}',
                   r'(?i)(password|passwd|secret[a-z_]*|token|api[_-]?key|authkey|access[_-]?key[a-z_]*)\s*[=:]\s*\S{6,}', r'(?i)bearer\s+[A-Za-z0-9._-]{20,}',
                   r'[MN][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}']
HEURISTICS = [('git', r'^(git|gh)\b'), ('pytest', r'\bpytest\b'), ('python', r'^(python3?|pip3?|venv|source\b.*activate|deactivate)\b|\bvenv\b'), ('tailscale', r'^tailscale\b'),
              ('elastic', r'\b(elastic|kibana|curl .*9200)\b'), ('shuffle', r'\bshuffle\b'), ('docker', r'^docker\b'), ('ssh', r'^(ssh|scp)\b'), ('terraform', r'^terraform\b')]


class RefusedEntry(ValueError):
    pass


def learning_dir():
    d = os.environ.get('LAB_LEARNING_DIR')
    return Path(d) if d else Path(os.environ.get('LAB_HOME', '.')) / 'learning'


def now_iso():
    return dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def entry_id(topic, command):
    return 'e' + hashlib.sha1(('%s|%s' % (topic.lower().strip(), command.strip())).encode()).hexdigest()[:6]


def _auto_gloss(does):
    return ' '.join(str(does or '').split()[:5])


def load(directory=None):
    """Internal view: every entry has id and gloss too (merged from the sidecar). Legacy files (with 'what') are accepted."""
    d = Path(directory or learning_dir())
    p = d / 'learning-log.json'
    if not p.is_file():
        return {'updated': None, 'entries': []}
    raw = json.loads(p.read_text())
    items = raw if isinstance(raw, list) else raw.get('entries', [])
    mp = d / 'learning-meta.json'
    meta = json.loads(mp.read_text()) if mp.is_file() else {}
    out = []
    for e in items:
        topic = (e.get('topic') or 'general').lower()
        does = e.get('does') or e.get('what') or ''
        eid = e.get('id') or entry_id(topic, e['command'])
        m = meta.get(eid, {})
        ent = {'id': eid, 'command': e['command'], 'topic': topic, 'gloss': e.get('gloss') or m.get('gloss') or _auto_gloss(does), 'does': does, 'when': e.get('when', ''),
               'added_by': e.get('added_by', 'analyst'), 'added_at': e.get('added_at', '')}
        goal = e.get('goal') or m.get('goal')
        if goal:
            ent['goal'] = goal
        out.append(ent)
    return {'updated': None if isinstance(raw, list) else raw.get('updated'), 'entries': out}


def _public(doc):
    return [{k: e[k] for k in PUBLIC_KEYS} for e in doc['entries']]


def save(doc, directory=None):
    d = Path(directory or learning_dir())
    d.mkdir(parents=True, exist_ok=True)
    pub = _public(doc)
    old = None
    if (d / 'learning-log.json').is_file():
        try:
            old = json.loads((d / 'learning-log.json').read_text())
        except ValueError:
            old = None
    same = isinstance(old, dict) and old.get('entries') == pub and old.get('updated')
    body = {'updated': old['updated'] if same else now_iso(), 'entries': pub}
    meta = {e['id']: dict({'gloss': e['gloss']}, **({'goal': e['goal']} if e.get('goal') else {})) for e in doc['entries']}
    for name, obj in (('learning-log.json', body), ('learning-meta.json', meta)):
        tmp = d / (name + '.tmp')
        tmp.write_text(json.dumps(obj, indent=1, ensure_ascii=False) + '\n')
        tmp.chmod(0o644)
        os.replace(tmp, d / name)
    md = d / 'LEARNING-LOG.md'
    md.write_text(render_md(doc))
    md.chmod(0o644)


def topic_for(command):
    c = command.strip()
    for topic, pat in HEURISTICS:
        if re.search(pat, c):
            return topic
    return 'general'


def _check_secret(*texts):
    for t in texts:
        for pat in SECRET_PATTERNS:
            if t and re.search(pat, t):
                raise RefusedEntry('That looks like it contains a secret (a token, key or password), so it was not saved. Remove the secret and try again.')


def _clean(text, limit):
    return re.sub(r'\s+', ' ', scrub(str(text or '')).strip())[:limit]


def make_entry(command, topic, gloss, does, when, by, goal=None, now=None):
    command = str(command or '').strip()
    if not command:
        raise RefusedEntry('There is no command or step to save.')
    _check_secret(command, goal, does, when, gloss)
    topic = _clean(topic or topic_for(command), 30).lower() or 'general'
    e = {'id': entry_id(topic, scrub(command)), 'command': scrub(command)[:300], 'topic': topic, 'gloss': _clean(gloss, 70), 'does': _clean(does, 600), 'when': _clean(when, 600),
         'added_by': _clean(by or 'assistant', 40), 'added_at': now or now_iso()}
    if goal:
        e['goal'] = _clean(goal, 200)
    for k, name in (('gloss', 'gloss'), ('does', 'what it does'), ('when', 'when to use it')):
        if not e[k]:
            raise RefusedEntry('The write-up is missing "%s".' % name)
    return e


def add(entry, directory=None):
    d = Path(directory or learning_dir())
    d.mkdir(parents=True, exist_ok=True)
    doc = load(d)
    for e in doc['entries']:
        if e['id'] == entry['id']:
            return e, False
    doc['entries'].append(entry)
    save(doc, d)
    return entry, True


def topics(doc):
    seen = {}
    for e in doc['entries']:
        seen.setdefault(e['topic'], []).append(e)
    order = [t for t in TOPIC_ORDER if t in seen] + sorted(t for t in seen if t not in TOPIC_ORDER)
    return [(t, seen[t]) for t in order]


def label(topic):
    return topic[:1].upper() + topic[1:]


def stats(doc):
    return len(doc['entries']), len(topics(doc))


def render_md(doc):
    n, m = stats(doc)
    out = ['# Learning log', '', 'Commands and steps we have learned, each with what it does and when to use it. %d entries across %d topics.' % (n, m), '',
           '> Generated from learning-log.json. The searchable web page is the main reference; add entries from Discord (#learning-log) or the console and this file regenerates. Do not edit it by hand.', '']
    if n:
        out += ['**Topics:** ' + ' \u00b7 '.join('[%s](#%s) (%d)' % (label(t), re.sub(r'[^a-z0-9]+', '-', t), len(es)) for t, es in topics(doc)), '']
    for t, es in topics(doc):
        out += ['## ' + label(t), '']
        for e in es:
            out += ['### `%s`' % e['command'].replace('`', "'"), '', '**What it does:** ' + e['does'], '', '**When to use it:** ' + e['when'], '', '<sub>Added by %s on %s</sub>' % (e['added_by'], e['added_at'][:10]), '']
    return '\n'.join(out).rstrip() + '\n'


# ---- search -----------------------------------------------------------------------------------------------------------

def find(doc, term):
    toks = [t.lower() for t in re.findall(r'[^\s]+', term or '')]
    if not toks:
        return []
    scored = []
    for e in doc['entries']:
        hay_cmd, hay = e['command'].lower(), ' '.join(str(e.get(k, '')) for k in ('command', 'topic', 'gloss', 'does', 'when', 'goal')).lower()
        if all(t in hay for t in toks):
            score = sum(3 for t in toks if t in hay_cmd) + sum(2 for t in toks if t in e['topic'].lower()) + sum(1 for t in toks if t in e['gloss'].lower())
            scored.append((-score, e['topic'], e['command'], e))
    return [x[3] for x in sorted(scored, key=lambda x: x[:3])]


def highlight(text, term):
    for t in sorted({t for t in re.findall(r'[^\s]+', term or '') if len(t) > 1}, key=len, reverse=True):
        text = re.sub('(' + re.escape(t) + ')', r'**\1**', text, flags=re.I) if '**' not in t else text
    return text


def _cmd(e, term=None):
    c = e['command'].replace('`', "'")
    toks = sorted({t for t in re.findall(r'[^\s]+', term or '') if len(t) > 1}, key=len, reverse=True)
    if not toks:
        return '`%s`' % c
    pat = re.compile('(' + '|'.join(re.escape(t) for t in toks) + ')', re.I)
    parts, last = [], 0
    for m in pat.finditer(c):
        if m.start() > last:
            parts.append('`%s`' % c[last:m.start()])
        parts.append('**`%s`**' % m.group(0))
        last = m.end()
    if not parts:
        return '`%s`' % c
    if last < len(c):
        parts.append('`%s`' % c[last:])
    return ''.join(parts)


def render_find(doc, term, url=None, limit=8):
    hits = find(doc, term)
    if not hits:
        return {'text': 'Nothing in the learning log matches **%s**. Try a shorter word, for example a command name. To save it, tap **Add** on the launcher in #learning-log or type `/log <command>`.' % scrub(term)[:80], 'hits': []}
    lines = ['**%d result%s for %s**' % (len(hits), '' if len(hits) == 1 else 's', scrub(term)[:80])]
    for e in hits[:limit]:
        lines.append('\u2022 **%s** \u00b7 %s \u2014 %s' % (label(e['topic']), _cmd(e, term), highlight(e['gloss'], term)))
    if len(hits) > limit:
        lines.append('\u2026 and %d more. Narrow it down, or search the web page.' % (len(hits) - limit))
    if url:
        lines.append('Full explanations (what it does, when to use it) are on the web page: ' + url)
    return {'text': '\n'.join(lines), 'hits': hits}


# ---- the Discord launcher: one embed + one button ---------------------------------------------------------------------

def _short(text, n):
    text = text.replace('`', "'")
    return text if len(text) <= n else text[:n - 1] + '\u2026'


def _five(gloss):
    w = gloss.split()
    return ' '.join(w[:5]) + ('\u2026' if len(w) > 5 else '')


def launcher(doc, url):
    """Returns (embed, button). The embed's title links to the web page; the button opens the add form."""
    n, m = stats(doc)
    recent = sorted(range(len(doc['entries'])), key=lambda i: (doc['entries'][i]['added_at'], i), reverse=True)[:3]
    lines = ['**%s** \u00b7 `%s` \u2014 %s' % (label(doc['entries'][i]['topic'])[:20], _short(doc['entries'][i]['command'], 60), _five(doc['entries'][i]['gloss'])) for i in recent]
    where = url or 'ask the owner for the link'
    embed = {'title': '\U0001F4D2 Learning Log', 'color': PURPLE,
             'description': 'Your command cheat-sheet for the lab. Everything you learn, explained in plain English.\n\n**%d entr%s \u00b7 %d topic%s**' % (n, 'y' if n == 1 else 'ies', m, '' if m == 1 else 's'),
             'fields': [{'name': 'Open the Learning Log', 'value': where, 'inline': False},
                        {'name': 'Add a command', 'value': 'Tap Add below, or type /log <command>', 'inline': True},
                        {'name': 'Find something', 'value': 'Search right on the page, or /find <term>', 'inline': True},
                        {'name': 'Recently added', 'value': '\n'.join(lines) if lines else 'Nothing yet. Be the first to add one.', 'inline': False}]}
    if url:
        embed['url'] = url
    embed = clean(embed, [url] if url else ())
    button = {'reusable': True, 'text': 'Learned something you want to keep? Tap below.', 'blocks': [],
              'modal': {'title': 'Add to the learning log', 'triggerLabel': '\u2795 Add to log', 'fields': [{'type': 'text', 'label': 'Command or step'}, {'type': 'text', 'label': 'What were you trying to do? (optional)'}]}}
    return embed, button


def part_hash(obj):
    return hashlib.sha1(json.dumps(obj, sort_keys=True).encode()).hexdigest()[:10]
