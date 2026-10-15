"""Learning-log commands for the console CLI. File-based (no Elastic needed) except queueing the Discord card, which uses the outbox."""
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


def render(d=None):
    """Make sure the directory holds the json, the markdown and the web page. Seeds from the repo copy on first run."""
    d = Path(d or L.learning_dir())
    d.mkdir(parents=True, exist_ok=True)
    seed = Path(pk.ROOT) / 'docs' / 'learning-log.json'
    if not (d / 'learning-log.json').is_file() and seed.is_file():
        shutil.copy(seed, d / 'learning-log.json')
    doc = L.load(d)
    L.save(doc, d)
    page = Path(pk.ROOT) / 'docs' / 'learning-web' / 'index.html'
    if page.is_file():
        shutil.copy(page, d / 'index.html')
    for name in ('index.html', 'learning-log.json', 'LEARNING-LOG.md'):
        f = d / name
        if f.is_file():
            f.chmod(0o644)      # the web server runs as another user and must be able to read these
    return doc


def refresh_card(ctx, d=None, force=False):
    d = Path(d or L.learning_dir())
    doc = L.load(d)
    st = _state(d)
    queued = []
    for part, comp in L.card_parts(doc, _url(ctx.env)):
        h = L.part_hash(comp)
        cur = st['parts'].get(part, {})
        if not force and cur.get('hash') == h and cur.get('message_id'):
            continue
        st['rev'] += 1
        key = 'learning-card:%s:%d' % (part, st['rev'])
        ob.enqueue(ctx.store, key, {'channel': 'learning-log', 'kind': 'card', 'part': part, 'hash': h, 'message_id': cur.get('message_id'), 'components': comp, 'message': ''})
        queued.append(key)
    _state_path(d).write_text(json.dumps(st, indent=1))
    return queued


def card_set(part, message_id, h, d=None):
    d = Path(d or L.learning_dir())
    st = _state(d)
    old = st['parts'].get(part, {})
    st['parts'][part] = {'message_id': message_id, 'hash': h, 'pinned': bool(old.get('pinned')) and old.get('message_id') == message_id}
    _state_path(d).write_text(json.dumps(st, indent=1))


def pending_cards(ctx, d=None, claim=False, ttl=600):
    """Card edits and pins that only the #learning-log session can apply (Discord allows edit and pin only from inside the channel's own conversation)."""
    d = Path(d or L.learning_dir())
    now = now_iso_s()
    items = []
    for doc in ctx.store.list('outbox', status='pending', limit=500):
        p = doc.get('payload') or {}
        if p.get('kind') != 'card' or not p.get('message_id'):
            continue
        fresh = bool(doc.get('requested_at')) and (_age(doc['requested_at']) < ttl)
        items.append({'action': 'edit', 'key': doc['key'], 'part': p['part'], 'message_id': p['message_id'], 'hash': p['hash'], 'components': p['components'], '_claimed': fresh})
    st = _state(d)
    pins = [{'action': 'pin', 'part': k, 'message_id': v['message_id']} for k, v in sorted(st['parts'].items()) if v.get('message_id') and not v.get('pinned')]
    new = [i for i in items if not i['_claimed']]
    newpins = bool(pins) and (not st.get('pin_requested_at') or _age(st['pin_requested_at']) >= ttl)
    if claim:
        for i in new:
            ctx.store.update('outbox', i['key'], requested_at=now)
        if newpins:
            st['pin_requested_at'] = now
            _state_path(d).write_text(json.dumps(st, indent=1))
    for i in items:
        i.pop('_claimed')
    return {'edits': items, 'pins': pins, 'claimed': len(new) + (1 if newpins else 0)}


def now_iso_s():
    return dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _age(ts):
    return (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(ts.replace('Z', '+00:00'))).total_seconds()


def card_done(ctx, key=None, part=None, message_id=None, h=None, pinned=None, d=None):
    d = Path(d or L.learning_dir())
    if key:
        ob.ack(ctx.store, key, [message_id] if message_id else [])
        if part and message_id and h:
            card_set(part, message_id, h, d)
    if pinned:
        st = _state(d)
        if pinned in st['parts']:
            st['parts'][pinned]['pinned'] = True
            _state_path(d).write_text(json.dumps(st, indent=1))
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
        e = L.make_entry(data.get('command'), data.get('topic'), data.get('gloss'), data.get('what'), data.get('when'), who(env, a.by or data.get('by')), data.get('goal'))
    except L.RefusedEntry as ex:
        return _out({'ok': False, 'text': str(ex)})
    e, created = L.add(e, d)
    queued = refresh_card(_ctx(), d) if created else []
    if a.draft and created:
        (Path(d) / 'drafts' / (a.draft + '.json')).unlink()
    doc = L.load(d)
    n, m = L.stats(doc)
    text = ('\u2705 Added `%s` to **%s**. The log now has %d entries across %d topics. The web page shows it now; the #learning-log card refreshes the next time it is used in the channel.' % (e['command'], L.label(e['topic']), n, m)) if created else \
        ('That is already in the log under **%s**: `%s` \u2014 %s' % (L.label(e['topic']), e['command'], e['gloss']))
    _out({'ok': True, 'created': created, 'id': e['id'], 'topic': e['topic'], 'entry': e, 'text': text, 'card_queued': queued})


def cmd_find(a):
    env = load_env()
    d = L.learning_dir()
    data = _read_stdin() if a.stdin else {'term': a.term}
    term = str(data.get('term') or '').strip()[:100]
    if not term:
        return _out({'ok': False, 'text': 'Type a word to search for, for example `/find venv`.'})
    r = L.render_find(render(d), term, _url(env))
    card = None
    sb = L.select_block(r['hits'], 'Full explanation for\u2026')
    if sb:
        card = {'reusable': True, 'text': '**Details** are sent to you privately.', 'blocks': [sb]}
    _out({'ok': True, 'text': r['text'], 'card': card, 'matches': len(r['hits'])})


def cmd_details(a):
    d = L.learning_dir()
    e = next((x for x in L.load(d)['entries'] if x['id'] == a.id), None)
    if not e:
        return _out({'ok': False, 'text': 'I cannot find that entry. It may have been renamed; try `/find`.'})
    url = _url(load_env())
    link = (url.rstrip('/') + '/#' + e['id']) if url else None
    fallback = '\U0001F4DA **%s** \u2014 the full explanation is on the web page (private network only): %s' % (e['command'], link) if link else None
    _out({'ok': True, 'dm': L.details_dm(e), 'link': link, 'fallback': fallback, 'id': e['id']})


def cmd_topics(a):
    doc = L.load(L.learning_dir())
    _out({'topics': [{'topic': t, 'entries': len(es), 'examples': [e['command'] for e in es[:2]]} for t, es in L.topics(doc)], 'total': len(doc['entries'])})


def cmd_draft(a):
    d = Path(L.learning_dir())
    data = _read_stdin()
    try:
        e = L.make_entry(data.get('command'), data.get('topic'), data.get('gloss'), data.get('what'), data.get('when'), 'draft')
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
        return _out({'claimed': r['claimed'], 'edits': len(r['edits']), 'pins': len(r['pins'])})
    _out(r)


def cmd_card_done(a):
    _out(card_done(_ctx(), key=a.key, part=a.part, message_id=a.message_id, h=a.hash, pinned=a.pinned))


def cmd_render(a):
    doc = render()
    n, m = L.stats(doc)
    _out({'entries': n, 'topics': m, 'dir': str(L.learning_dir())})


def register(sub):
    s = sub.add_parser('log-add'); s.add_argument('--stdin', action='store_true'); s.add_argument('--draft'); s.add_argument('--by', default='analyst')
    s = sub.add_parser('log-find'); s.add_argument('term', nargs='?'); s.add_argument('--stdin', action='store_true')
    s = sub.add_parser('log-details'); s.add_argument('id'); s.add_argument('--by')
    sub.add_parser('log-topics')
    sub.add_parser('log-draft').add_argument('--stdin', action='store_true')
    s = sub.add_parser('log-card'); s.add_argument('--force', action='store_true')
    s = sub.add_parser('log-card-set'); s.add_argument('part'); s.add_argument('message_id'); s.add_argument('hash')
    s = sub.add_parser('log-card-pending'); s.add_argument('--claim', action='store_true'); s.add_argument('--count', action='store_true')
    s = sub.add_parser('log-card-done'); s.add_argument('--key'); s.add_argument('--part'); s.add_argument('--message-id'); s.add_argument('--hash'); s.add_argument('--pinned')
    sub.add_parser('log-render')
    return {'log-add': cmd_add, 'log-find': cmd_find, 'log-details': cmd_details, 'log-topics': cmd_topics, 'log-draft': cmd_draft, 'log-card': cmd_card, 'log-card-set': cmd_card_set, 'log-card-pending': cmd_card_pending, 'log-card-done': cmd_card_done, 'log-render': cmd_render}
