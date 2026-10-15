"""Turn a detection-engine alert into a Discord post (rich embed + action buttons).
Pack-agnostic: which fields to show, which buttons to offer and which Kibana data view to link comes from pack.json."""
import datetime as dt
import urllib.parse

from core import packs as pk
from core.console import plain as pl
from core.console.fields import first, getf
from core.console.redact import clean, mask_ip, scrub

SEV_EMOJI = {'critical': '\U0001F7E3', 'high': '\U0001F534', 'medium': '\U0001F7E0', 'low': '\u26AA'}
ACTION_EMOJI = {'acknowledge': '\u2705', 'investigate': '\U0001F50D', 'contain': '\U0001F6E1\uFE0F', 'reset_mfa': '\U0001F511',
                'revoke_sessions': '\u26D4', 'disable_principal': '\U0001F6AB'}
ALERTS_INDEX = '.alerts-security.alerts-default'


def short(uuid_):
    return str(uuid_).replace('-', '')[:8]


def technique(rule_tags):
    for t in rule_tags or []:
        if t.startswith('attack.t1'):
            return t.split('attack.')[1].upper()
    return None


def pack_for_index(index, packs):
    for p in packs:
        if index and (index == p['index'] or index.startswith(p['index'])):
            return p
    return None


def kibana_link(public, pack, event_id, when):
    t0 = (dt.datetime.fromisoformat(when.replace('Z', '+00:00')) - dt.timedelta(minutes=30)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
    t1 = (dt.datetime.fromisoformat(when.replace('Z', '+00:00')) + dt.timedelta(hours=6)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
    g = "(time:(from:'%s',to:'%s'))" % (t0, t1)
    a = "(columns:!(),dataSource:(dataViewId:%s,type:dataView),filters:!(),interval:auto,query:(language:kuery,query:'%s:\"%s\"'),sort:!(!('@timestamp',desc)))" % (
        pack['data_view'], pack['id_field'], event_id)
    # fully percent-encoded: Discord rejects raw quotes in an embed URL and brackets break markdown links
    return public.rstrip('/') + '/app/discover#/?_g=' + urllib.parse.quote(g, safe='') + '&_a=' + urllib.parse.quote(a, safe='')


def describe(alert, source, pack, attack, cfg, public_url):
    f = pack['fields']
    rule_name = getf(alert, 'kibana.alert.rule.name') or 'Detection'
    rule_id = getf(alert, 'kibana.alert.rule.rule_id') or ''
    sev = (getf(alert, 'kibana.alert.severity') or 'low').lower()
    risk = getf(alert, 'kibana.alert.risk_score')
    tags = getf(alert, 'kibana.alert.rule.tags') or []
    tech = technique(tags)
    tech_label = '%s \u00b7 %s' % (tech, attack.get(tech, {}).get('name', 'unmapped')) if tech else 'unmapped'
    event_id = first(source, pack['id_field']) or ''
    when = first(source, pack['time_field']) or getf(alert, 'kibana.alert.original_time') or getf(alert, '@timestamp')
    actor = first(source, f['actor']) or 'unknown'
    actor_type = getf(source, f.get('actor_type')) if f.get('actor_type') else None
    op = first(source, f['operation']) or 'unknown'
    svc = first(source, f.get('service')) or ''
    ip = first(source, f.get('source_ip'))
    region = first(source, f.get('region')) if f.get('region') else None
    where = ' \u00b7 '.join(x for x in (mask_ip(ip) if ip else None, region) if x) or 'n/a'
    target = first(source, f.get('target')) or None
    return {'rule_name': rule_name, 'rule_id': rule_id, 'severity': sev, 'risk': risk, 'technique': tech, 'technique_label': tech_label,
            'event_id': event_id, 'when': when, 'actor': scrub(str(actor)), 'actor_type': scrub(str(actor_type)) if actor_type else None,
            'operation': (svc.split('.')[0] + ': ' if svc and '.' in svc else '') + str(op), 'where': where,
            'target': scrub(str(target)) if target else None, 'lane': pack['lane'],
            'link': kibana_link(public_url, pack, event_id, when) if event_id and when else None}


def build_embed(d, pack, cfg, protect=(), names=None):
    return clean(pl.alert_embed(d, pack, cfg, protect, names), protect)


def build_buttons(sid, pack, approvers):
    return pl.alert_buttons(sid, pack, approvers)


def build_post(alert_doc, source, pack, attack, cfg, public_url, approvers):
    uuid_ = getf(alert_doc, 'kibana.alert.uuid') or alert_doc.get('_id') or ''
    sid = short(uuid_)
    d = describe(alert_doc, source, pack, attack, cfg, public_url)
    post = {'channel': 'alerts', 'kind': 'alert', 'alert_id': sid, 'message': '', 'embed': build_embed(d, pack, cfg, [public_url.rstrip('/')], attack),
            'buttons': build_buttons(sid, pack, approvers), 'summary': d}
    return pl.finish(post, [public_url.rstrip('/')])
