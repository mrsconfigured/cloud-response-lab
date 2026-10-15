"""The learning log: one structured source, rendered to every surface.

Source of truth: learning-log.json (entries). Everything else is generated from it, so nothing can drift:
  - LEARNING-LOG.md           the readable reference
  - Discord card (3 parts)     band with Add, band with Search, and the entries by topic
  - the web page               reads learning-log.json live
Every entry: command/step, topic, short gloss, plain "what it does", plain "when to use", who added it, timestamp.
Secrets are refused; addresses, e-mails and account ids are masked.
"""
import datetime as dt
import hashlib
import json
import os
import re
from pathlib import Path

from core.console.redact import scrub

TOPIC_ORDER = ['git', 'python', 'pytest', 'pull request', 'tailscale', 'elastic', 'shuffle']
MAX_TOPIC_LINES = 8          # per topic on the Discord card; the web page shows everything
SELECT_MAX = 25              # Discord select menus hold 25 options
TEXT_BUDGET = 3700           # a components-v2 message may carry about 4000 characters of text

SECRET_PATTERNS = [r'ghp_[A-Za-z0-9]{20,}', 'github' + r'_pat_[A-Za-z0-9_]{20,}', 'tsk' + r'ey-[A-Za-z0-9-]{10,}', r'\b(AKIA|ASIA)[0-9A-Z]{16}\b', r'-----BEGIN [A-Z ]*PRIVATE KEY',
                   r'xox[abprs]-[A-Za-z0-9-]{10,}', r'\bsk-[A-Za-z0-9]{20,}', r'(?i)(password|passwd|secret[a-z_]*|token|api[_-]?key|authkey|access[_-]?key[a-z_]*)\s*[=:]\s*\S{6,}', r'(?i)bearer\s+[A-Za-z0-9._-]{20,}',
                   r'[MN][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}']
HEURISTICS = [('git', r'^(git|gh)\b'), ('pytest', r'\bpytest\b'), ('python', r'^(python3?|pip3?|venv|source\b.*activate|deactivate)\b|\bvenv\b'), ('tailscale', r'^tailscale\b'),
              ('elastic', r'\b(elastic|kibana|curl .*9200)\b'), ('shuffle', r'\bshuffle\b'), ('docker', r'^docker\b'), ('ssh', r'^(ssh|scp)\b'), ('terraform', r'^terraform\b')]


class RefusedEntry(ValueError):
    pass


def learning_dir():
    d = os.environ.get('LAB_LEARNING_DIR')
    if d:
        return Path(d)
    return Path(os.environ.get('LAB_HOME', '.')) / 'learning'


def now_iso():
    return dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def load(directory=None):
    p = Path(directory or learning_dir()) / 'learning-log.json'
    if not p.is_file():
        return {'version': 1, 'entries': []}
    return json.loads(p.read_text())


def entry_id(topic, command):
    return 'e' + hashlib.sha1(('%s|%s' % (topic.lower().strip(), command.strip())).encode()).hexdigest()[:6]


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


def make_entry(command, topic, gloss, what, when, by, goal=None, now=None):
    command = str(command or '').strip()
    if not command:
        raise RefusedEntry('There is no command or step to save.')
    _check_secret(command, goal, what, when, gloss)
    topic = _clean(topic or topic_for(command), 30).lower() or 'general'
    e = {'id': entry_id(topic, scrub(command)), 'command': scrub(command)[:300], 'topic': topic, 'gloss': _clean(gloss, 70), 'what': _clean(what, 600), 'when': _clean(when, 600),
         'added_by': _clean(by or 'assistant', 40), 'added_at': now or now_iso()}
    if goal:
        e['goal'] = _clean(goal, 200)
    for k in ('gloss', 'what', 'when'):
        if not e[k]:
            raise RefusedEntry('The write-up is missing "%s".' % k)
    return e


def add(entry, directory=None):
    """Append (or report a duplicate), then re-render the markdown. Returns (entry, created)."""
    d = Path(directory or learning_dir())
    d.mkdir(parents=True, exist_ok=True)
    doc = load(d)
    for e in doc['entries']:
        if e['id'] == entry['id']:
            return e, False
    doc['entries'].append(entry)
    save(doc, d)
    return entry, True


def save(doc, directory=None):
    d = Path(directory or learning_dir())
    d.mkdir(parents=True, exist_ok=True)
    tmp = d / 'learning-log.json.tmp'
    tmp.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + '\n')
    tmp.chmod(0o644)
    os.replace(tmp, d / 'learning-log.json')
    md = d / 'LEARNING-LOG.md'
    md.write_text(render_md(doc))
    md.chmod(0o644)


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


# ---- markdown -----------------------------------------------------------------------------------------------------------

def render_md(doc):
    n, m = stats(doc)
    out = ['# Learning log', '', 'Commands and steps we have learned, each with what it does and when to use it. %d entries across %d topics.' % (n, m), '',
           '> Generated from learning-log.json. Add an entry in Discord (#learning-log) or with the console and this file regenerates; do not edit it by hand.', '']
    if n:
        out += ['**Topics:** ' + ' · '.join('[%s](#%s) (%d)' % (label(t), re.sub(r'[^a-z0-9]+', '-', t), len(es)) for t, es in topics(doc)), '']
    for t, es in topics(doc):
        out += ['## ' + label(t), '']
        for e in es:
            out += ['### `%s`' % e['command'].replace('`', "'"), '', '**What it does:** ' + e['what'], '', '**When to use it:** ' + e['when'], '',
                    '<sub>Added by %s on %s</sub>' % (e['added_by'], e['added_at'][:10]), '']
    return '\n'.join(out).rstrip() + '\n'


# ---- search -------------------------------------------------------------------------------------------------------------

def find(doc, term):
    toks = [t.lower() for t in re.findall(r'[^\s]+', term or '')]
    if not toks:
        return []
    scored = []
    for e in doc['entries']:
        hay_cmd, hay = e['command'].lower(), ' '.join(str(e.get(k, '')) for k in ('command', 'topic', 'gloss', 'what', 'when', 'goal')).lower()
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
        return {'text': 'Nothing in the learning log matches **%s**. Try a shorter word (for example a command name), or add it with **Add to log**.' % scrub(term)[:80], 'hits': []}
    lines = ['**%d result%s for %s**' % (len(hits), '' if len(hits) == 1 else 's', scrub(term)[:80])]
    for e in hits[:limit]:
        lines.append('\u2022 **%s** \u00b7 %s \u2014 %s' % (label(e['topic']), _cmd(e, term), highlight(e['gloss'], term)))
    if len(hits) > limit:
        lines.append('\u2026 and %d more. Narrow it down, or use the web page%s.' % (len(hits) - limit, (' (' + url + ')') if url else ''))
    lines.append('Pick one below for the full explanation, sent to you privately.')
    return {'text': '\n'.join(lines), 'hits': hits[:SELECT_MAX]}


def details_dm(e):
    lines = ['**%s** \u00b7 %s' % (label(e['topic']), _cmd(e)), '', '**What it does:** ' + e['what'], '**When to use it:** ' + e['when']]
    if e.get('goal'):
        lines.append('**Added because:** ' + e['goal'])
    lines.append('_Added by %s on %s_' % (e['added_by'], e['added_at'][:10]))
    return '\U0001F512 ' + '\n'.join(lines) + '\n_Only you can see this message._'


# ---- Discord card (three parts, each edited in place) ---------------------------------------------------------------------

def select_block(entries, placeholder):
    opts = [{'label': ('%s \u00b7 %s' % (e['command'], e['id']))[:100], 'value': e['id']} for e in entries[:SELECT_MAX]]
    return {'type': 'actions', 'select': {'type': 'string', 'placeholder': placeholder, 'options': opts}} if opts else None


def card_parts(doc, url=None):
    n, m = stats(doc)
    band = {'reusable': True, 'text': '# \U0001F4DA Learning Log\n**%d entr%s \u00b7 %d topic%s**\nTap **\u2795 Add to log**, or type `/log <command>` \u00b7 search with `/find <term>`%s' % (
        n, 'y' if n == 1 else 'ies', m, '' if m == 1 else 's', ('\n\U0001F310 Searchable web page: ' + url) if url else ''), 'blocks': [],
        'modal': {'title': 'Add to the learning log', 'triggerLabel': '\u2795 Add to log', 'fields': [{'type': 'text', 'label': 'Command or step'}, {'type': 'text', 'label': 'What were you trying to do? (optional)'}]}}
    search = {'reusable': True, 'text': '**\U0001F50E Find something** \u2014 tap **Search**, or type `/find <term>`', 'blocks': [],
              'modal': {'title': 'Search the learning log', 'triggerLabel': '\U0001F50E Search', 'fields': [{'type': 'text', 'label': 'What are you looking for?'}]}}
    blocks, used, hidden = [], 0, 0
    for t, es in topics(doc):
        shown = es[:MAX_TOPIC_LINES]
        lines = ['**%s** \u00b7 %d' % (label(t), len(es))] + ['%s \u2014 %s' % (_cmd(e)[:80], e['gloss'][:48]) for e in shown]
        if len(es) > len(shown):
            lines.append('\u2026 +%d more (use Search or the web page)' % (len(es) - len(shown)))
        block = '\n'.join(lines)
        if used + len(block) > TEXT_BUDGET:
            hidden += len(es)
            continue
        used += len(block)
        blocks.append({'type': 'text', 'text': block})
    if hidden:
        blocks.append({'type': 'text', 'text': '\u2026 and more topics. Use **Search** or the web page.'})
    if not blocks:
        blocks.append({'type': 'text', 'text': '_Nothing here yet. Tap **Add to log** above to save the first command._'})
    blocks.append({'type': 'text', 'text': '_Pick an entry below to get its full \u201cwhat it does / when to use it\u201d, sent to you privately._'})
    recent = sorted(doc['entries'], key=lambda e: e['added_at'], reverse=True)[:SELECT_MAX]
    sb = select_block(recent, 'See the full explanation for\u2026')
    if sb:
        blocks.append(sb)
    body = {'reusable': True, 'text': '**Saved commands, by topic**', 'blocks': blocks}
    return [('band-add', band), ('band-search', search), ('entries', body)]


def part_hash(components):
    return hashlib.sha1(json.dumps(components, sort_keys=True).encode()).hexdigest()[:10]
