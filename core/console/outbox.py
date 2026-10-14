"""Outbox: everything the console wants to say in Discord is queued here, then posted by the gateway-side poster.
The droplet never holds a Discord token; the poster ships entries and acknowledges them."""
import datetime as dt

from core.console.store import now_iso

LEASE_SECONDS = 120
MAX_ATTEMPTS = 4


def enqueue(store, key, payload):
    """Idempotent: a given key is queued once."""
    if store.exists('outbox', key):
        return False
    store.put('outbox', key, {'status': 'pending', 'attempts': 0, 'payload': payload, 'created_at': now_iso()})
    return True


def next_batch(store, limit=5, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    out = []
    for doc in store.list('outbox', limit=500):
        if len(out) >= limit:
            break
        st = doc.get('status')
        if st == 'pending' or (st == 'posting' and doc.get('lease_until', '') < now.strftime('%Y-%m-%dT%H:%M:%SZ')):
            lease = (now + dt.timedelta(seconds=LEASE_SECONDS)).strftime('%Y-%m-%dT%H:%M:%SZ')
            store.update('outbox', doc['key'], status='posting', lease_until=lease, attempts=doc.get('attempts', 0) + 1)
            out.append({'key': doc['key'], 'attempt': doc.get('attempts', 0) + 1, 'payload': doc['payload']})
    return out


def ack(store, key, message_ids):
    store.update('outbox', key, status='posted', posted_at=now_iso(), message_ids=message_ids)


def fail(store, key, error):
    doc = store.get('outbox', key)
    status = 'failed' if doc and doc.get('attempts', 0) >= MAX_ATTEMPTS else 'pending'
    store.update('outbox', key, status=status, last_error=str(error)[:300])
    return status
