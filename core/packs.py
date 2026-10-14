"""Pack discovery. A pack is packs/<name>/ with pack.json, detections/, playbooks/, tests/.
Everything platform-side (console, CI, metrics) asks this module what exists; nothing hard-codes a log source."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKS = ROOT / 'packs'
REQUIRED_DIRS = ('detections', 'playbooks', 'tests')
REQUIRED_META = ('name', 'provider', 'lane', 'log_source', 'index', 'time_field', 'id_field', 'fields', 'actions', 'data_view')


def load_json(path):
    return json.loads(Path(path).read_text())


def config(root=ROOT):
    return load_json(Path(root) / 'core/config.json')


def attack_names(root=ROOT):
    return load_json(Path(root) / 'core/attack.json')


def pack_dirs(root=ROOT):
    base = Path(root) / 'packs'
    return sorted(d for d in base.iterdir() if (d / 'pack.json').is_file()) if base.is_dir() else []


def load_pack(path):
    path = Path(path)
    meta = load_json(path / 'pack.json')
    missing = [k for k in REQUIRED_META if k not in meta]
    if missing:
        raise ValueError('%s: pack.json missing %s' % (path.name, missing))
    for d in REQUIRED_DIRS:
        if not (path / d).is_dir():
            raise ValueError('%s: missing directory %s/' % (path.name, d))
    meta = dict(meta)
    meta['path'] = path
    meta['playbooks'] = sorted(p for p in (path / 'playbooks').glob('*.json') if not p.name.endswith('.shuffle.json'))
    meta['detections_dir'] = path / 'detections'
    return meta


def packs(root=ROOT):
    return [load_pack(d) for d in pack_dirs(root)]


def by_name(name, root=ROOT):
    for p in packs(root):
        if p['name'] == name:
            return p
    raise KeyError(name)


def find_playbook(playbook_id, root=ROOT):
    for p in packs(root):
        f = p['path'] / 'playbooks' / (playbook_id + '.json')
        if f.is_file():
            return p, load_json(f)
    raise KeyError(playbook_id)
