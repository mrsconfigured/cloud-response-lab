"""Field access that works on nested dicts, flat dotted keys, and list indexes (targetResources.0.id)."""


def getf(doc, path, default=None):
    if doc is None or not path:
        return default
    if isinstance(doc, dict) and path in doc:
        return doc[path]
    cur = doc
    parts = path.split('.')
    i = 0
    while i < len(parts):
        if isinstance(cur, dict):
            # try the longest dotted key first (flat documents), then single segment
            for j in range(len(parts), i, -1):
                key = '.'.join(parts[i:j])
                if key in cur:
                    cur = cur[key]
                    i = j
                    break
            else:
                return default
        elif isinstance(cur, list):
            try:
                cur = cur[int(parts[i])]
            except (ValueError, IndexError):
                return default
            i += 1
        else:
            return default
    return cur


def first(doc, paths, default=None):
    for p in ([paths] if isinstance(paths, str) else (paths or [])):
        v = getf(doc, p)
        if v not in (None, '', []):
            return v
    return default
