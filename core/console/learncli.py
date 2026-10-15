"""Learning-log commands for the console CLI. File-based (no Elastic needed) except queueing the Discord launcher, which uses the outbox."""
import datetime as dt
import json
import shutil
import sys
import uuid
from pathlib import Path

from core import learning as L
from core import packs as pk
from core.console import outbox as ob
from core.console.es import load_env

PAGE_FILES = ('index.html', 'learning-log.json', 'LEARNING-LOG.md')


def _out(obj):
    print(json.dumps(obj, indent=1, default=str, ensure_ascii=False))


def _url(env):
    return (env.get('LAB_LEARNING_URL') or '').strip() or None


def who(env, user_id):
    """A role label, never a name or id: the entries are exported to a public repo."""
    ids = {p.strip().split(':')[0] for p in (env.get('LAB_APPROVERS') or '').split(',') if ':' in p}
    return 'owner' if str(user_id) in ids else ('assistant' if str(user_id) == 'assistant' else 'analyst')


def _state_path(d):
    return Path(d) / 'card-state.json'


def _state(d):
    p = _state_path(d)
    return json.loads(p.read_text()) if p.is_file() else {'rev': 0, 'parts': {}}


def _save_state(d, st):
    _state_path(d).write_text(json.dumps(st, indent=1))


def render(d=None):
    """Make sure the directory holds the json, the markdown and the web page (the page is copied verbatim from the repo). Seeds from the repo copy on first run."""
    d = Path(d or L.learning_dir())
    d.mkdir(parents=True, exist_ok=True)
    seed = Path(pk.ROOT) / 'docs'
    if not (d / 'learning-log.json').is_file() and (seed / 'learning-log.json').is_file():
        shutil.copy(seed / 'learning-log.json', d / 'learning-log.json')
        if (seed / 'learning-meta.json').is_file():
            shutil.copy(seed / 'learning-meta.json', d / 'learning-meta.json')
    doc = L.load(d)
    L.save(doc, d)
    page = seed / 'learning-web' / 'index.html'
    if page.is_file():
        shutil.copyfile(page, d / 'index.html')
    for name in PAGE_FILES:
        f = d / name
        if f.is_file():
            f.chmod(0o644)      # the web server runs as another user and must be able to read these
    return doc


def _supersede(ctx, pred):
    n = 0
    for doc in ctx.store.list('outbox', status='pending', limit=500):
        if pred(doc.get('payload') or {}):
            ctx.store.update('outbox', doc['key'], status='superseded')
            n += 1
    return n


def refresh_card(ctx, d=None, force=False):
    """Queue what the launcher needs. Never blocks anything: the web page is always current; the embed's count and 'recently added' are best effort."""
    d = Path(d or L.learning_dir())
    doc = L.load(d)
    st = _state(d)
    queued = []
    legacy = [k for k in ('band-add', 'band-search', 'entries') if k in st['parts']]
    if legacy:                      # the three-message card is retired: forget it and drop every queued edit for it
        st['legacy_messages'] = sorted({st['parts'][k]['message_id'] for k in legacy if st['parts'][k].get('message_id')})
        for k in legacy:
            del st['parts'][k]
    _supersede(ctx, lambda p: p.get('kind') == 'card' and 'components' in p)
    embed, button = L.launcher(doc, _url(ctx.env))
    h = L.part_hash(embed)
    cur = st['parts'].get('launcher', {})
    if cur.get('message_id'):
        if force or cur.get('hash') != h:
            _supersede(ctx, lambda p: p.get('kind') == 'card' and p.get('part') == 'launcher')   # only the newest edit stays pending
            st['rev'] += 1
            key = 'learning-card:launcher:%d' % st['rev']
            ob.enqueue(ctx.store, key, {'channel': 'learning-log', 'kind': 'card', 'part': 'launcher', 'hash': h, 'message_id': cur['message_id'], 'embed': embed, 'message': ''})
            queued.append(key)
    else:
        pending = [x for x in ctx.store.list('outbox', status='pending', limit=500) if (x.get('payload') or {}).get('kind') == 'launcher']
        payload = {'channel': 'learning-log', 'kind': 'launcher', 'hash': h, 'embed': embed, 'button': button, 'message': ''}
        if pending:                 # not posted yet: refresh its content instead of queueing a second launcher
            ctx.store.update('outbox', pending[0]['key'], payload=payload)
        else:
            st['rev'] += 1
            key = 'learning-launcher:%d' % st['rev']
            ob.enqueue(ctx.store, key, payload)
            queued.append(key)
    _save_state(d, st)
    return queued


def card_set(part, message_id, h, d=None):
    d = Path(d or L.learning_dir())
    st = _state(d)
    st['parts'][part] = {'message_id': message_id, 'hash': h}
    _save_state(d, st)


def pending_cards(ctx, d=None, claim=False, ttl=600):
    """Launcher edits that only a real #learning-log turn can apply (Discord allows edits only from inside the channel's own conversation)."""
    items = []
    for doc in ctx.store.list('outbox', status='pending', limit=500):
        p = doc.get('payload') or {}
        if p.get('kind') != 'card' or not p.get('message_id') or 'embed' not in p:
            continue
        fresh = bool(doc.get('requested_at')) and (_age(doc['requested_at']) < ttl)
        items.append({'action': 'edit', 'key': doc['key'], 'part': p['part'], 'message_id': p['message_id'], 'hash': p['hash'], 'embed': p['embed'], '_claimed': fresh})
    new = [i for i in items if not i['_claimed']]
    if claim:
        for i in new:
            ctx.store.update('outbox', i['key'], requested_at=now_iso_s())
    for i in items:
        i.pop('_claimed')
    return {'edits': items, 'claimed': len(new)}


def now_iso_s():
    return dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _age(ts):
    return (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(ts.replace('Z', '+00:00'))).total_seconds()


def card_done(ctx, key=None, part=None, message_id=None, h=None, d=None):
    d = Path(d or L.learning_dir())
    if key:
        ob.ack(ctx.store, key, [message_id] if message_id else [])
        if part and message_id and h:
            card_set(part, message_id, h, d)
    return {'ok': True}


def _ctx():
    from core.console import service as sv
    return sv.Ctx()


def _read_stdin():
    raw = sys.stdin.read().strip()
    return json.loads(raw) if raw else {}


def cmd_add(a):
    env = load_env()
    d = L.learning_dir()
    render(d)
    if a.draft:
        dp = Path(d) / 'drafts' / (a.draft + '.json')
        if not a.draft.isalnum() or not dp.is_file():
            return _out({'ok': False, 'text': 'That draft has expired. Ask again and tap **Log this?** on the new message.'})
        data = json.loads(dp.read_text())
    else:
        data = _read_stdin()
    try:
        e = L.make_entry(data.get('command'), data.get('topic'), data.get('gloss'), data.get('does') or data.get('what'), data.get('when'), who(env, a.by or data.get('by')), data.get('goal'))
    except L.RefusedEntry as ex:
        return _out({'ok': False, 'text': str(ex)})
    e, created = L.add(e, d)
    try:
        queued = refresh_card(_ctx(), d) if created else []
    except Exception as ex:         # the launcher is best effort; the entry is already saved and on the web page
        queued = []
    if a.draft and created:
        (Path(d) / 'drafts' / (a.draft + '.json')).unlink()
    n, m = L.stats(L.load(d))
    url = _url(env)
    text = ('\u2705 Added `%s` to **%s**. The log now has %d entries across %d topics. It is on the web page now%s.' % (e['command'], L.label(e['topic']), n, m, (': ' + url) if url else '')) if created else \
        ('That is already in the log under **%s**: `%s` \u2014 %s' % (L.label(e['topic']), e['command'], e['gloss']))
    _out({'ok': True, 'created': created, 'id': e['id'], 'topic': e['topic'], 'entry': e, 'text': text, 'card_queued': queued})


def cmd_find(a):
    env = load_env()
    data = _read_stdin() if a.stdin else {'term': a.term}
    term = str(data.get('term') or '').strip()[:100]
    if not term:
        return _out({'ok': False, 'text': 'Type a word to search for, for example `/find venv`.'})
    r = L.render_find(render(L.learning_dir()), term, _url(env))
    _out({'ok': True, 'text': r['text'], 'matches': len(r['hits'])})


def cmd_topics(a):
    doc = L.load(L.learning_dir())
    _out({'topics': [{'topic': t, 'entries': len(es), 'examples': [e['command'] for e in es[:2]]} for t, es in L.topics(doc)], 'total': len(doc['entries'])})


def cmd_draft(a):
    d = Path(L.learning_dir())
    data = _read_stdin()
    try:
        e = L.make_entry(data.get('command'), data.get('topic'), data.get('gloss'), data.get('does') or data.get('what'), data.get('when'), 'draft')
    except L.RefusedEntry as ex:
        return _out({'ok': False, 'text': str(ex)})
    did = uuid.uuid4().hex[:8]
    (d / 'drafts').mkdir(parents=True, exist_ok=True)
    (d / 'drafts' / (did + '.json')).write_text(json.dumps(data))
    _out({'ok': True, 'id': did, 'card': {'reusable': False, 'text': '\U0001F4DA Save `%s` to the Learning Log (under **%s**)?' % (e['command'], L.label(e['topic'])), 'blocks': [{'type': 'actions', 'buttons': [
        {'label': '\U0001F4DA Log this? \u00b7 %s' % did, 'style': 'primary'}]}]}})


def cmd_card(a):
    ctx = _ctx()
    render()
    _out({'queued': refresh_card(ctx, force=a.force)})


def cmd_card_set(a):
    card_set(a.part, a.message_id, a.hash)
    _out({'ok': True})


def cmd_card_pending(a):
    r = pending_cards(_ctx(), claim=a.claim)
    if a.count:
        return _out({'claimed': r['claimed'], 'edits': len(r['edits'])})
    _out(r)


def cmd_card_done(a):
    _out(card_done(_ctx(), key=a.key, part=a.part, message_id=a.message_id, h=a.hash))


def cmd_render(a):
    doc = render()
    n, m = L.stats(doc)
    _out({'entries': n, 'topics': m, 'dir': str(L.learning_dir())})


def register(sub):
    s = sub.add_parser('log-add'); s.add_argument('--stdin', action='store_true'); s.add_argument('--draft'); s.add_argument('--by', default='analyst')
    s = sub.add_parser('log-find'); s.add_argument('term', nargs='?'); s.add_argument('--stdin', action='store_true')
    sub.add_parser('log-topics')
    sub.add_parser('log-draft').add_argument('--stdin', action='store_true')
    s = sub.add_parser('log-card'); s.add_argument('--force', action='store_true')
    s = sub.add_parser('log-card-set'); s.add_argument('part'); s.add_argument('message_id'); s.add_argument('hash')
    s = sub.add_parser('log-card-pending'); s.add_argument('--claim', action='store_true'); s.add_argument('--count', action='store_true')
    s = sub.add_parser('log-card-done'); s.add_argument('--key'); s.add_argument('--part'); s.add_argument('--message-id'); s.add_argument('--hash')
    sub.add_parser('log-render')
    return {'log-add': cmd_add, 'log-find': cmd_find, 'log-topics': cmd_topics, 'log-draft': cmd_draft, 'log-card': cmd_card, 'log-card-set': cmd_card_set,
            'log-card-pending': cmd_card_pending, 'log-card-done': cmd_card_done, 'log-render': cmd_render}
