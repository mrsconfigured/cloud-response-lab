"""ATT&CK coverage: per-pack layers merged into one map, plus a 'what shipped' digest against the last posted snapshot."""
import json
from pathlib import Path

from core import packs as pk

TACTIC_ORDER = ['initial-access', 'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access']
TACTIC_LABEL = {'initial-access': 'Initial Access', 'persistence': 'Persistence', 'privilege-escalation': 'Privilege Escalation', 'defense-evasion': 'Defense Evasion', 'credential-access': 'Credential Access'}


def snapshot(root=pk.ROOT):
    root = Path(root)
    snap = {'rules': {}, 'playbooks': {}, 'techniques': {}}
    names = pk.attack_names(root)
    for p in pk.packs(root):
        gen = json.loads((root / 'library/generated/matrix.json').read_text())
        rules = json.loads((root / 'library/generated/rules.json').read_text())
        en = {r['rule_id']: r['enabled'] for r in rules}
        for m in gen:
            if m['provider'] == p['provider']:
                snap['rules'][m['slug']] = {'pack': p['name'], 'technique': m['technique'], 'enabled': en.get(m['id'], False)}
        for pb in p['playbooks']:
            d = json.loads(pb.read_text())
            snap['playbooks'][d['id']] = {'pack': p['name'], 'version': d['version']}
        layer = json.loads((p['path'] / 'attack-layer.json').read_text())
        for t in layer['techniques']:
            cur = snap['techniques'].setdefault(t['techniqueID'], {'name': names.get(t['techniqueID'], {}).get('name', t['techniqueID']), 'tactics': names.get(t['techniqueID'], {}).get('tactics', []), 'enabled': 0, 'fixture_only': 0})
            if t['score'] > 0:
                cur['enabled'] += t['score']
            else:
                cur['fixture_only'] += 1
    return snap


def diff(old, new):
    old = old or {'rules': {}, 'playbooks': {}, 'techniques': {}}
    d = {'rules_added': sorted(set(new['rules']) - set(old['rules'])), 'rules_removed': sorted(set(old['rules']) - set(new['rules'])),
         'playbooks_added': sorted(set(new['playbooks']) - set(old['playbooks'])), 'playbooks_removed': sorted(set(old['playbooks']) - set(new['playbooks'])),
         'techniques_added': sorted(set(new['techniques']) - set(old['techniques']))}
    cov = lambda s: sum(1 for v in s['techniques'].values() if v['enabled'] > 0)
    d['covered_before'], d['covered_after'] = cov(old), cov(new)
    return d


def html(snap):
    cols = {t: [] for t in TACTIC_ORDER}
    for tid, v in sorted(snap['techniques'].items()):
        for t in v['tactics']:
            if t in cols:
                cols[t].append((tid, v))
    cell = lambda tid, v: '<div class="c %s"><b>%s</b><span>%s</span></div>' % ('on' if v['enabled'] else 'fx', tid, v['name'])
    body = ''.join('<div class="col"><h3>%s</h3>%s</div>' % (TACTIC_LABEL[t], ''.join(cell(tid, v) for tid, v in cols[t]) or '<div class="c none">no technique mapped</div>') for t in TACTIC_ORDER)
    cov = sum(1 for v in snap['techniques'].values() if v['enabled'] > 0)
    return ('<html><head><meta charset="utf-8"><style>body{font-family:Inter,Arial,sans-serif;background:#0f1419;color:#e6edf3;margin:0;padding:24px;width:1400px}'
            'h1{font-size:22px;margin:0 0 4px}p{color:#9fb0c0;margin:0 0 16px;font-size:14px}.grid{display:flex;gap:12px}.col{flex:1}h3{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:#9fb0c0;margin:0 0 8px}'
            '.c{border-radius:6px;padding:9px 10px;margin-bottom:8px;font-size:12px;line-height:1.3}.c b{display:block;font-size:13px}.c span{color:#d7e3ee}.on{background:#1f6f43}.fx{background:#4a4f57}.none{background:#1a2129;color:#6b7b8b}'
            '.leg{margin-top:14px;font-size:12px;color:#9fb0c0}.leg i{display:inline-block;width:10px;height:10px;border-radius:2px;margin:0 4px 0 12px}</style></head><body>'
            '<h1>ATT&amp;CK coverage \u2014 cloud detection lab</h1><p>%d of %d mapped techniques have an enabled rule on a live log source. Mappings are hypotheses, not a coverage percentage.</p>'
            '<div class="grid">%s</div><div class="leg"><i style="background:#1f6f43"></i>enabled rule, live source<i style="background:#4a4f57"></i>fixture only (needs a license or data)</div></body></html>') % (
        cov, len(snap['techniques']), body)
