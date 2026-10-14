"""State store for approvals, outbox entries and posted-alert markers.
MemoryStore is used by tests; ElasticStore persists in the lab-console-state index."""
import copy
import datetime as dt


def now_iso():
    return dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


class MemoryStore:
    def __init__(self):
        self.docs = {}

    def put(self, kind, key, doc):
        self.docs[(kind, key)] = dict(copy.deepcopy(doc), kind=kind, key=key)
        return doc

    def get(self, kind, key):
        d = self.docs.get((kind, key))
        return copy.deepcopy(d) if d is not None else None

    def update(self, kind, key, **fields):
        d = self.docs[(kind, key)]
        d.update(copy.deepcopy(fields))
        return copy.deepcopy(d)

    def list(self, kind, status=None, limit=100):
        out = [copy.deepcopy(v) for (k, _), v in self.docs.items() if k == kind and (status is None or v.get('status') == status)]
        out.sort(key=lambda d: d.get('created_at', ''))
        return out[:limit]

    def exists(self, kind, key):
        return (kind, key) in self.docs


class ElasticStore:
    def __init__(self, es, index):
        self.es, self.index = es, index

    def _id(self, kind, key):
        return kind + ':' + key

    def put(self, kind, key, doc):
        body = dict(doc, kind=kind, key=key)
        body.setdefault('created_at', now_iso())
        self.es.request('PUT', '/%s/_doc/%s?refresh=wait_for' % (self.index, self._id(kind, key)), body)
        return body

    def get(self, kind, key):
        r = self.es.request('GET', '/%s/_doc/%s' % (self.index, self._id(kind, key)), allow=(404,))
        return r.get('_source') if r and r.get('found') else None

    def update(self, kind, key, **fields):
        self.es.request('POST', '/%s/_update/%s?refresh=wait_for' % (self.index, self._id(kind, key)), {'doc': fields})
        return self.get(kind, key)

    def list(self, kind, status=None, limit=100):
        flt = [{'term': {'kind': kind}}]
        if status is not None:
            flt.append({'term': {'status': status}})
        r = self.es.request('POST', '/%s/_search' % self.index, {'size': limit, 'sort': [{'created_at': 'asc'}], 'query': {'bool': {'filter': flt}}})
        return [h['_source'] for h in r['hits']['hits']]

    def exists(self, kind, key):
        return self.get(kind, key) is not None
