"""ATT&CK coverage: per-pack layers merged into one map, plus a 'what shipped' digest against the last posted snapshot."""
import json
from pathlib import Path

from core import packs as pk
from core.console import plain as pl

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
    cell = lambda tid, v: '<div class="c %s"><b>%s</b><span>%s</span><em>%s</em></div>' % ('on' if v['enabled'] else 'fx', tid, v['name'], pl.TECH_PLAIN.get(tid) or pl.TECH_PLAIN.get(tid.split('.')[0]) or '')
    body = ''.join('<div class="col"><h3>%s</h3>%s</div>' % (TACTIC_LABEL[t], ''.join(cell(tid, v) for tid, v in cols[t]) or '<div class="c none">no technique mapped</div>') for t in TACTIC_ORDER)
    cov = sum(1 for v in snap['techniques'].values() if v['enabled'] > 0)
    return ('<html><head><meta charset="utf-8"><style>body{font-family:Inter,Arial,sans-serif;background:#0f1419;color:#e6edf3;margin:0;padding:24px;width:1400px}'
            'h1{font-size:22px;margin:0 0 4px}p{color:#9fb0c0;margin:0 0 16px;font-size:14px}.grid{display:flex;gap:12px}.col{flex:1}h3{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:#9fb0c0;margin:0 0 8px}'
            '.c{border-radius:6px;padding:9px 10px;margin-bottom:8px;font-size:12px;line-height:1.3}.c b{display:block;font-size:13px}.c span{color:#d7e3ee}.c em{display:block;color:#b9c7d4;font-size:11px;margin-top:3px}.on{background:#1f6f43}.fx{background:#4a4f57}.none{background:#1a2129;color:#6b7b8b}'
            '.leg{margin-top:14px;font-size:12px;color:#9fb0c0}.leg i{display:inline-block;width:10px;height:10px;border-radius:2px;margin:0 4px 0 12px}</style></head><body>'
            '<h1>Attack types we can catch</h1><p>%d of %d tracked attack types have a live rule. Codes like T1098 come from MITRE ATT&amp;CK, a public catalogue of attacker techniques. This is a guide, not a guarantee.</p>'
            '<div class="grid">%s</div><div class="leg"><i style="background:#1f6f43"></i>live rule, real data<i style="background:#4a4f57"></i>not covered yet (test data only)</div></body></html>') % (
        cov, len(snap['techniques']), body)


def embed(snap, old, context=None, digest=False):
    d = diff(old, snap)
    total, c = len(snap['techniques']), d['covered_after']
    head = ('\U0001F4E6 This week: we can now catch %d of the %d attack types we track' if digest else '\U0001F5FA We can currently catch %d of the %d attack types we are tracking') % (c, total)
    lines = []
    if old:
        lines.append(('That is up from %d last time.' % d['covered_before']) if c > d['covered_before'] else ('Last time it was also %d \u2014 no change.' % d['covered_before'] if c == d['covered_before'] else 'That is down from %d last time.' % d['covered_before']))
    else:
        lines.append('This is the first map, so there is nothing to compare it with yet.')
    new = []
    if not old:
        lines.append('It contains %d detection rules and %d response playbooks.' % (len(snap['rules']), len(snap['playbooks'])))
    if old and d['rules_added']:
        new.append('%d detection rule%s' % (len(d['rules_added']), '' if len(d['rules_added']) == 1 else 's'))
    if old and d['playbooks_added']:
        new.append('%d response playbook%s' % (len(d['playbooks_added']), '' if len(d['playbooks_added']) == 1 else 's'))
    if new:
        lines.append('**New since last time:** ' + ' and '.join(new) + '.')
    if context:
        lines.append(context)
    lines.append('In the picture, green boxes are attack types with a live rule; grey ones are not covered yet.')
    return {'title': head, 'color': 3066993, 'description': '\n'.join(lines), 'footer': {'text': 'Attack types come from ATT&CK. Show details lists every one with its rules.'}}, d


def details_text(snap):
    by = {}
    for slug, r in snap['rules'].items():
        by.setdefault(r['technique'], []).append(slug + ('' if r['enabled'] else ' (off)'))
    out = []
    for tid, v in sorted(snap['techniques'].items()):
        meaning = pl.TECH_PLAIN.get(tid) or pl.TECH_PLAIN.get(tid.split('.')[0]) or ''
        out.append('%s %s%s\n   %s' % (tid, v['name'], (' \u2014 ' + meaning) if meaning else '', ('covered by: ' + ', '.join(by[tid])) if v['enabled'] and tid in by else ('not covered yet' if not v['enabled'] else 'covered')))
    return '\n'.join(out)


def render_png(snap, path):
    from pathlib import Path as _P
    tmp = _P(path).with_suffix('.html')
    tmp.write_text(html(snap))
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        b = p.chromium.launch(channel='chrome', headless=True)
        pg = b.new_page(viewport={'width': 1450, 'height': 720})
        pg.goto('file://' + str(tmp))
        pg.screenshot(path=str(path), full_page=True)
        b.close()
    return str(path)
