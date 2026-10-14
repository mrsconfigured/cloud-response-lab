"""The shared plain-English layer. Every message the console posts or replies with goes through here.

Rules it enforces (and tests/test_plain.py asserts for every message type):
  1. a plain-language headline comes first; the so-what follows in everyday words,
  2. acronyms are spelled out on first use (finish() does it, lint() checks it),
  3. the technical payload never goes in the channel: it is stored, and a "Show details" button hands it to the clicker privately,
  4. buttons use plain verbs and the message explains what each one does,
  5. everything is still masked (redact.clean) - no account ids, addresses, e-mails or key ids.
"""
import datetime as dt
import hashlib
import json
import re

from core.console.redact import clean, leaks, scrub

# First use of each acronym is replaced by the spelled-out form. AWS, IP and ID are treated as everyday names.
FIRST_USE = {
    'MFA': 'multi-factor authentication (MFA)',
    'IAM': 'identity and access management (IAM)',
    'ATT&CK': 'MITRE ATT&CK (a public catalogue of attacker techniques)',
    'CI': 'continuous integration (CI)',
    'UAT': 'user acceptance testing (UAT)',
    'MTTD': 'mean time to detect (MTTD)',
    'MTTR': 'mean time to respond (MTTR)',
    'MTTA': 'mean time to acknowledge (MTTA)',
    'SOC': 'security operations centre (SOC)',
    'SOAR': 'security orchestration and response (SOAR)',
    'API': 'application programming interface (API)',
    'PR': 'pull request (PR)',
    'ARN': 'Amazon resource name (ARN)',
}
EXEMPT = ('AWS', 'IP', 'ID')
_PAT = {k: re.compile(r'(?<![A-Za-z0-9])(?:MITRE )?' + re.escape(k) + r'(?![A-Za-z0-9])') for k in FIRST_USE}

SEV = {'critical': ('\U0001F7E3', 'Critical', 'act on this now'), 'high': ('\U0001F534', 'High', 'look at this soon'),
       'medium': ('\U0001F7E0', 'Medium', 'review this today'), 'low': ('\u26AA', 'Low', 'for awareness')}

# Plain meaning of each attack technique (the official name comes from the pack; this says what it means for a person).
TECH_PLAIN = {
    'T1098': 'someone changed account permissions',
    'T1098.001': 'someone added a new password or access key to an account',
    'T1098.003': 'someone gave an account more permissions',
    'T1562.008': 'someone tried to switch off activity logging',
    'T1078.004': 'someone signed in with a real cloud account, possibly not its owner',
    'T1556.009': 'someone changed or removed a sign-in safety rule',
    'T1528': 'an app was given access to data, possibly without the user really meaning it',
    'T1136.003': 'a new cloud account was created',
}

# rule id -> headline / why it matters / suggested next step. {t} is the affected account when the event names one.
RULES = {
    '965a1068-c2bf-4ea5-b1d0-000000000002': dict(
        headline='A user was just granted full admin rights in AWS', headline_t='The AWS user {t} was just granted full admin rights',
        why='Full admin rights let an account do anything in the cloud. Attackers grant them to themselves to take over.',
        nxt='Check that this change was planned. If it was not, ask for a lockdown of the account.'),
    '8a7d441b-870b-4fce-bac4-000000000003': dict(
        headline='A new access key was just created for an AWS user', headline_t='A new access key was just created for the AWS user {t}',
        why='An access key works like a long-lived password for programs. Attackers make one to keep access after a password reset.',
        nxt='Ask the owner of the account whether they made it. If not, ask for a lockdown.'),
    '8a7d441b-870b-4fce-bac4-000000000001': dict(
        headline='Activity logging was just switched off in AWS',
        why='Without logs nobody can see what happens next. Attackers do this to hide what they are doing.',
        nxt='Find out who did it and turn logging back on. If it was not planned, treat it as an attack.'),
    '8a7d441b-870b-4fce-bac4-000000000002': dict(
        headline='An activity log was just deleted in AWS',
        why='Deleting the log removes the record of what happened. Attackers do this to cover their tracks.',
        nxt='Find out who did it and restore logging. If it was not planned, treat it as an attack.'),
    '8a7d441b-870b-4fce-bac4-000000000004': dict(
        headline='Someone signed in to the AWS console without a second verification step',
        why='A password alone is easy to steal. Sign-ins without multi-factor authentication (MFA) are the usual way accounts are taken over.',
        nxt='Confirm it was the real owner, and make sure the account has MFA turned on.'),
    '8a7d441b-870b-4fce-bac4-000000000005': dict(
        headline='Someone was just added to an admin role in Microsoft Entra', headline_t='{t} was just added to an admin role in Microsoft Entra',
        why='Admin roles control the whole company directory. Attackers add themselves to one to take over.',
        nxt='Check that this was planned. If not, sign the user out everywhere and ask for a lockdown.'),
    '8a7d441b-870b-4fce-bac4-000000000006': dict(
        headline='A new secret was just added to an application in Microsoft Entra',
        why='A secret lets a program sign in as that application. Attackers add one to keep a hidden way in.',
        nxt='Ask the application owner whether they added it. If not, disable the application.'),
    '8a7d441b-870b-4fce-bac4-000000000007': dict(
        headline='A sign-in safety rule was just deleted in Microsoft Entra',
        why='These rules decide who may sign in and from where. Removing one makes it easier to get in.',
        nxt='Find out who deleted it and restore it. If it was not planned, treat it as an attack.'),
    '8a7d441b-870b-4fce-bac4-000000000008': dict(
        headline='An application was just given extra permissions in Microsoft Entra',
        why='An application with more permissions can read or change more data. Attackers use this to reach data quietly.',
        nxt='Check that the new permissions were planned. If not, disable the application.'),
    '8a7d441b-870b-4fce-bac4-000000000009': dict(
        headline='An app was just given permission to access data in Microsoft Entra',
        why='A user or admin said yes to an app. Attackers trick people into this to read mail and files without a password.',
        nxt='Check that the app is known and the approval was intended. If not, disable the application.'),
    '8a7d441b-870b-4fce-bac4-00000000000a': dict(
        headline='A new user account was just created in Microsoft Entra', headline_t='A new user account ({t}) was just created in Microsoft Entra',
        why='New accounts are normal, but attackers also create them to keep access.',
        nxt='Check that someone asked for this account. If not, sign the user out everywhere.'),
}

# Buttons: emoji, plain label, one-line description of exactly what it does.
ACTIONS = {
    'acknowledge': ('\u2705', 'Mark as seen', 'tells the team you have looked at this. Nothing in your cloud changes.'),
    'investigate': ('\U0001F50D', 'Investigate', 'opens a discussion thread with this account\u2019s last 6 hours of activity.'),
    'contain': ('\U0001F6E1\uFE0F', 'Request lockdown', 'asks an approver to confirm a practice (dry-run) lockdown of the account. Nothing happens until someone clicks Confirm.'),
    'reset_mfa': ('\U0001F511', 'Reset 2-step sign-in', 'asks an approver to confirm a practice removal of the user\u2019s multi-factor authentication methods. Nothing happens until Confirm.'),
    'revoke_sessions': ('\u26D4', 'Sign user out everywhere', 'asks an approver to confirm a practice sign-out of every device. Nothing happens until Confirm.'),
    'disable_principal': ('\U0001F6AB', 'Disable the application', 'asks an approver to confirm a practice shutdown of the application\u2019s sign-in. Nothing happens until Confirm.'),
}

# What a playbook does, in words: will = before approval, done = after.
PLAYBOOKS = {
    'contain-iam-user': ('switch off every access key of the AWS user {t} and block everything that user can do', 'Locked down the AWS user {t}: all its access keys switched off and everything it could do blocked'),
    'disable-service-principal': ('disable the application {t} so it can no longer sign in', 'Disabled the application {t} so it can no longer sign in'),
    'reset-mfa': ('remove {t}\u2019s registered multi-factor authentication methods so they must set them up again', 'Removed {t}\u2019s registered multi-factor authentication methods'),
    'revoke-sessions': ('sign {t} out of every device so they must log in again', 'Signed {t} out of every device'),
}

OPS = {'CreateAccessKey': 'created an access key', 'AttachUserPolicy': 'attached a permissions policy to a user', 'AttachRolePolicy': 'attached a permissions policy to a role',
       'AttachGroupPolicy': 'attached a permissions policy to a group', 'StopLogging': 'switched off activity logging', 'DeleteTrail': 'deleted an activity log',
       'ConsoleLogin': 'signed in to the console', 'CreateUser': 'created a user', 'DeleteUser': 'deleted a user', 'CreateLoginProfile': 'gave a user a console password',
       'DeleteLoginProfile': 'removed a user\u2019s console password', 'PutUserPolicy': 'added a permissions policy to a user', 'UpdateAccessKey': 'changed an access key\u2019s status',
       'DeleteAccessKey': 'deleted an access key', 'AssumeRole': 'took on a role', 'GetCallerIdentity': 'checked which account it is signed in as',
       'Add member to role': 'added someone to a role', 'Add user': 'created a user', 'Add service principal credentials': 'added a secret to an application',
       'Consent to application': 'approved an app\u2019s access', 'Add app role assignment to service principal': 'gave an application extra permissions'}


def op_plain(op):
    op = str(op or '')
    if op in OPS:
        return OPS[op]
    if re.fullmatch(r'[A-Z][A-Za-z0-9]+', op):
        words = re.findall(r'[A-Z][a-z0-9]*', op)
        verb = {'List': 'listed', 'Get': 'looked up', 'Describe': 'looked up', 'Create': 'created', 'Delete': 'deleted', 'Put': 'set', 'Update': 'changed',
                'Attach': 'attached', 'Detach': 'detached', 'Add': 'added', 'Remove': 'removed', 'Assume': 'took on', 'Stop': 'stopped', 'Start': 'started',
                'Enable': 'enabled', 'Disable': 'disabled', 'Tag': 'tagged', 'Untag': 'untagged', 'Generate': 'generated'}.get(words[0])
        rest = ' '.join(words[1:]).lower()
        return ('%s %s' % (verb, rest)).strip() if verb else ' '.join(words).lower()
    return op.lower()


def tech_plain(tech, names=None):
    """'T1098.003 Additional Cloud Roles \u2014 someone gave an account more permissions'"""
    if not tech:
        return 'not mapped to a known attack technique'
    name = ((names or {}).get(tech) or {}).get('name')
    base = '%s %s' % (tech, name) if name else tech
    meaning = TECH_PLAIN.get(tech) or TECH_PLAIN.get(tech.split('.')[0])
    return base + ((' \u2014 ' + meaning) if meaning else '')


def sev_line(sev, risk=None):
    e, label, hint = SEV.get(sev, SEV['low'])
    return '%s \u2014 %s%s' % (label, hint, (' (risk score %s of 100)' % risk) if risk is not None else '')


# ---- first-use expansion and lint ------------------------------------------------------------------------------

def _expand(text, seen):
    if not isinstance(text, str):
        return text
    for ac, rep in FIRST_USE.items():
        if ac in seen:
            continue
        m = _PAT[ac].search(text)
        if not m:
            continue
        seen.add(ac)
        lead = rep.split(' (')[0].lower()
        if text[:m.start()].lower().endswith(lead + ' (') or text[m.end():].startswith(' ('):
            continue   # already spelled out right here
        text = text[:m.start()] + rep + text[m.end():]
    return text


def _walk(post):
    """Yield (container, key) for every visible string, in the order a reader meets them."""
    if post.get('message'):
        yield post, 'message'
    e = post.get('embed') or {}
    for k in ('title', 'description'):
        if e.get(k):
            yield e, k
    for f in e.get('fields') or []:
        yield f, 'name'
        yield f, 'value'
    if (e.get('footer') or {}).get('text'):
        yield e['footer'], 'text'
    for c in (post.get('buttons'), post.get('card')):
        if c and c.get('text'):
            yield c, 'text'


def finish(post, protect=()):
    """Mask, then spell out every acronym on first use. Returns the same post."""
    seen = set()
    for box, key in _walk(post):
        box[key] = _expand(box[key], seen)
    return clean(post, protect)


def visible_text(post):
    return '\n'.join(str(box[key]) for box, key in _walk(post))


def lint(post, detail_body=None, need_details=True):
    """Return a list of problems; empty means the message meets the plain-English rules."""
    problems = []
    e = post.get('embed') or {}
    head = e.get('title') or post.get('message') or ''
    if len(head.strip(' \u00b7-')) < 15:
        problems.append('no plain-English headline')
    if re.search(r'[a-z]+_[a-z]+', head) or '{' in head or '}' in head:
        problems.append('headline looks like machine output: ' + head[:60])
    text = visible_text(post)
    # acronyms: expanding again must change nothing
    again = {}
    seen = set()
    for box, key in _walk(post):
        t = box[key]
        if _expand(t, seen) != t:
            problems.append('acronym not spelled out on first use in: ' + t[:70])
            break
    if re.search(r'\{\s*"|"\s*:\s*[\{\["]|eventVersion|userIdentity|requestParameters', text):
        problems.append('raw JSON/event fields are in the channel post')
    if detail_body and len(detail_body) > 40 and detail_body[:60] in json.dumps(post, default=str):
        problems.append('the technical detail is posted in the channel')
    if need_details:
        labels = [b.get('label', '') for c in (post.get('buttons'), post.get('card')) if c for blk in c.get('blocks', []) for b in blk.get('buttons', [])]
        if not any('Show details' in x or 'Show raw' in x for x in labels):
            problems.append('no Show details button')
    safe = re.sub(r'https?://100\.[0-9.]+:[0-9]+\S*', '', json.dumps(post, default=str))
    found = leaks(safe)
    if found:
        problems.append('unmasked: ' + ','.join(found))
    return problems


# ---- details: stored on the droplet, handed to the clicker privately -----------------------------------------------

def detail_id(key):
    return hashlib.sha1(key.encode()).hexdigest()[:10]


def stash(store, key, title, body):
    i = detail_id(key)
    store.put('detail', i, {'status': 'ready', 'title': title, 'body': scrub(body)[:60000]})
    return i


def details_card(i, text=None, label='Show details'):
    return {'reusable': True, 'text': text or '**%s** sends you the technical detail privately. This channel stays clean.' % label,
            'blocks': [{'type': 'actions', 'buttons': [{'label': '\U0001F50E %s \u00b7 %s' % (label, i), 'style': 'secondary'}]}]}


def as_json(obj):
    return json.dumps(obj, indent=1, default=str, sort_keys=True)


def dm_text(title, body, limit=1850):
    body = body if len(body) <= limit else body[:limit].rsplit('\n', 1)[0] + '\n\u2026 (shortened; the full record is on the lab server)'
    return '\U0001F512 **%s**\n_Only you can see this message._\n```\n%s\n```' % (title, body)


# ---- alerts ----------------------------------------------------------------------------------------------------------

def alert_headline(d):
    r = RULES.get(d.get('rule_id'))
    if r:
        return (r['headline_t'].format(t=d['target']) if d.get('target') and 'headline_t' in r else r['headline']), r['why'], r['nxt']
    return ('A detection rule fired: %s' % d.get('rule_name', 'unknown rule'),
            'A rule that watches for risky activity matched something in your logs.',
            'Open Show details to see what matched, then investigate.')


def alert_embed(d, pack, cfg, protect=(), names=None):
    headline, why, nxt = alert_headline(d)
    sev = d['severity']
    when = ''
    if d.get('when'):
        ts = int(dt.datetime.fromisoformat(d['when'].replace('Z', '+00:00')).timestamp())
        when = '<t:%d:R>' % ts
    who = d['actor'] + ((' (%s)' % d['actor_type']) if d.get('actor_type') and d['actor_type'] != d['actor'] else '')
    f1 = ' \u00b7 '.join(x for x in ('**Who:** ' + who, ('**When:** ' + when) if when else None, ('**From:** ' + d['where']) if d.get('where') not in (None, 'n/a') else None) if x)
    f2 = '**Rule:** %s \u00b7 **Severity:** %s' % (d['rule_name'], sev_line(sev, d.get('risk')))
    f3 = '**Attack technique:** ' + tech_plain(d.get('technique'), names)
    desc = '**Why it matters:** %s\n**Suggested next step:** %s\n\n%s\n%s\n%s' % (why, nxt, f1, f2, f3)
    emb = {'title': '%s %s' % (SEV.get(sev, SEV['low'])[0], headline), 'description': desc, 'color': cfg['embed_colors'].get(sev, cfg['embed_colors']['low']),
           'footer': {'text': 'Seen in %s. Technique names follow ATT&CK. Click Show details for the technical record.' % pack['log_source']}}
    if d.get('when'):
        emb['timestamp'] = d['when'] if d['when'].endswith('Z') else d['when'] + 'Z'
    return emb


def alert_buttons(sid, pack, approvers):
    buttons, help_ = [], []
    for a in pack['actions']:
        emoji, label, what = ACTIONS.get(a['id'], ('', a['label'], 'runs this step.'))
        b = {'label': '%s %s \u00b7 %s' % (emoji, label, sid), 'style': a.get('style', 'secondary')}
        if approvers:
            b['allowedUsers'] = list(approvers)
        buttons.append(b)
        help_.append('\u2022 **%s** \u2014 %s' % (label, what))
    buttons.append({'label': '\U0001F50E Show details \u00b7 %s' % sid, 'style': 'secondary'})
    help_.append('\u2022 **Show details** \u2014 sends you the technical record privately.')
    return {'reusable': True, 'text': '**What the buttons do** (alert `%s`)\n%s' % (sid, '\n'.join(help_)), 'blocks': [{'type': 'actions', 'buttons': buttons[:5]}]}


# ---- approval and result ---------------------------------------------------------------------------------------------

def playbook_will(pb_id, target):
    return (PLAYBOOKS.get(pb_id) or ('run the %s playbook on {t}' % pb_id, 'Ran %s on {t}' % pb_id))[0].format(t=target)


def playbook_done(pb_id, target):
    return (PLAYBOOKS.get(pb_id) or ('', 'Ran %s on {t}' % pb_id))[1].format(t=target)


def say(text, protect=()):
    """Plain text reply (slash commands, thread starters): spell out acronyms on first use and mask."""
    return clean(_expand(text, set()), protect)


def post_with_details(store, key, channel, embed, title, body, kind='embed', protect=(), **extra):
    """A channel post whose technical payload is stored, not posted: the Show details button hands it over privately."""
    i = stash(store, key, title, body)
    post = dict({'channel': channel, 'kind': kind, 'message': '', 'embed': embed, 'buttons': details_card(i)}, **extra)
    return finish(post, protect)


PB_TITLE = {'contain-iam-user': 'Lock down an AWS user', 'disable-service-principal': 'Disable an application', 'reset-mfa': 'Reset 2-step sign-in', 'revoke-sessions': 'Sign a user out everywhere'}


def metrics_embed(s, rel, now=None):
    def t(x):
        return rel(x['median'], now) if x else None
    n = s['alerts_24h']
    mttd = s['mttd']
    title = '\U0001F4CA Daily scorecard: %d alert%s in the last 24 hours%s' % (n, '' if n == 1 else 's', (', typically noticed within %s' % t(mttd)) if mttd else '')
    F = []
    F.append(('How fast we noticed an attack', ('%s typical (time to detect) \u2014 how long after something happened we raised the alert. It includes the cloud provider\u2019s own log delay.' % t(mttd)) if mttd else 'Not enough data yet \u2014 nothing to measure.'))
    F.append(('How fast we responded', ('%s typical (time to respond) \u2014 from the alert to the first practice lockdown.' % t(s['mttr'])) if s['mttr'] else 'Not enough data yet \u2014 no practice lockdown has run on a real alert.'))
    F.append(('How fast someone looked', ('%s typical (time to acknowledge) \u2014 from the alert to someone marking it as seen.' % t(s['mtta'])) if s['mtta'] else 'Not enough data yet \u2014 no alert has been marked as seen.'))
    sev = ', '.join('%s %d' % kv for kv in sorted(s['alerts_by_severity_24h'].items()))
    F.append(('Alerts, last 24 hours', '%d%s \u2014 how many things the rules flagged.' % (n, (' (' + sev + ')') if n else '')))
    fp = s['false_positive_rate']
    F.append(('False alarms', ('%d%% \u2014 %d of the %d alerts reviewed turned out harmless.' % (round(100 * fp['rate']), fp['benign'], fp['triaged'])) if fp['triaged'] else 'Not enough data yet \u2014 no alert has been judged harmless or real.'))
    pb = s['playbooks']
    F.append(('Response tests', ('%s of %s passing \u2014 checks that the practice lockdown scripts still behave.' % (pb['passed'], pb['total'])) if pb else 'No test run recorded yet.'))
    F.append(('Attack types we can catch', '%d of %d \u2014 attack types in ATT&CK that have at least one live rule.' % (s['techniques']['enabled'], s['techniques']['mapped'])))
    return {'title': title, 'color': 3447003, 'fields': [{'name': k, 'value': v, 'inline': False} for k, v in F], 'timestamp': s['at'],
            'footer': {'text': 'Real data only. \u201cNot enough data yet\u201d means there is nothing to measure.'}}
