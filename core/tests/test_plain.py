"""Every message the console can produce meets the plain-English rules:
a plain headline first, acronyms spelled out, the technical detail kept out of the channel (it goes to the clicker privately), masking intact."""
import json
import unittest
from types import SimpleNamespace

from core import packs as pk
from core.console import alerts as al, cipoll, coverage as cov, enrich as en, hunt as hu, plain as pl, playbooks as pbk, service as sv, status as stt
from core.console.audit import MemoryAudit
from core.console.queries import rel
from core.console.store import MemoryStore
from core.tests.test_console import ATT, CFG, ENTRA, NASTY, alert

ADMIN_RULE = '965a1068-c2bf-4ea5-b1d0-000000000002'
ROLE_RULE = '8a7d441b-870b-4fce-bac4-000000000005'
PUBLIC = 'http://100.64.1.2:5601'


def aws_post(rule_id=ADMIN_RULE):
    a = alert('AWS Admin Policy Attached', tags=('attack.t1098.003',))
    a['kibana.alert.rule.rule_id'] = rule_id
    return al.build_post(dict(a, _id='x'), NASTY, pk.by_name('aws'), ATT, CFG, PUBLIC, ['u1'])


def channel_view(post):
    return {k: v for k, v in post.items() if k != 'summary'}   # what Discord receives: summary is for the lab's own logs


class Alerts(unittest.TestCase):
    def test_headline_is_a_plain_sentence_and_the_card_explains_itself(self):
        p = aws_post()
        self.assertIn('full admin rights', p['embed']['title'])
        d = p['embed']['description']
        self.assertIn('Why it matters', d)
        self.assertIn('Suggested next step', d)
        self.assertIn('someone gave an account more permissions', d, 'technique shown with its plain meaning, not just the code')
        self.assertEqual(pl.lint(channel_view(p)), [])

    def test_every_rule_has_a_plain_headline_why_and_next_step(self):
        import yaml
        ids = set()
        for pack in pk.packs():
            for f in (pack['path'] / 'detections').glob('*.yml'):
                ids.add(yaml.safe_load(f.read_text())['id'])
        self.assertEqual(sorted(i for i in ids if i not in pl.RULES), [], 'a shipped rule has no plain-English text')

    def test_every_pack_action_has_a_plain_label_and_a_helper_line(self):
        for pack in pk.packs():
            card = pl.alert_buttons('abcdef12', pack, ['u1'])
            for a in pack['actions']:
                self.assertIn(pl.ACTIONS[a['id']][1], card['text'])

    def test_details_are_private_and_never_in_the_channel(self):
        p = aws_post()
        ctx = SimpleNamespace(store=MemoryStore(), env={'LAB_KIBANA_PUBLIC': PUBLIC}, attack=ATT, cfg=CFG)
        ctx.store.put('alert', 'abcdef12', {'status': 'open', 'pack': 'aws', 'rule_id': ADMIN_RULE, 'rule_name': 'AWS Admin Policy Attached', 'severity': 'high', 'event': NASTY, 'technique': 'T1098.003'})
        r = sv.details(ctx, 'abcdef12')
        self.assertTrue(r['ok'])
        self.assertIn('AttachUserPolicy', r['dm'], 'the raw event is in the private message')
        self.assertIn('Only you can see this message', r['dm'])
        self.assertIn(PUBLIC + '/app/discover', r['dm'], 'the Kibana link is in the private message')
        self.assertNotIn('AttachUserPolicy', json.dumps(channel_view(p)), 'the raw event is not in the channel post')
        self.assertNotIn('app/discover', json.dumps(channel_view(p)), 'the Kibana link is not in the channel post')
        self.assertEqual(pl.lint(channel_view(p), detail_body=r['dm']), [])

    def test_masking_is_unchanged(self):
        r = sv.details(SimpleNamespace(store=MemoryStore(), env={'LAB_KIBANA_PUBLIC': PUBLIC}, attack=ATT, cfg=CFG), 'nope')
        self.assertFalse(r['ok'])
        ctx = SimpleNamespace(store=MemoryStore(), env={'LAB_KIBANA_PUBLIC': PUBLIC}, attack=ATT, cfg=CFG)
        ctx.store.put('alert', 'abcdef12', {'status': 'open', 'pack': 'aws', 'rule_id': ADMIN_RULE, 'rule_name': 'x', 'severity': 'high', 'event': NASTY, 'technique': None})
        dm = sv.details(ctx, 'abcdef12')['dm']
        self.assertNotIn('203.0.113.77', dm)
        self.assertNotIn('123456789012', dm)

    def test_unknown_rule_still_gets_a_plain_card(self):
        p = aws_post('r-unknown')
        self.assertEqual(pl.lint(channel_view(p)), [])


class Verbs(unittest.TestCase):
    def test_operations_read_as_what_the_account_did(self):
        self.assertEqual(pl.op_plain('ListAccessKeys'), 'listed access keys')
        self.assertEqual(pl.op_plain('DescribeInstances'), 'looked up instances')
        self.assertEqual(pl.op_plain('CreateAccessKey'), 'created an access key')
        self.assertEqual(pl.op_plain('PutBucketPolicy'), 'set bucket policy')


class Acronyms(unittest.TestCase):
    def test_first_use_is_spelled_out_once(self):
        post = {'message': '', 'embed': {'title': 'MFA was reset for a user', 'description': 'MFA again. ATT&CK says so. Also IAM and CI.'}}
        pl.finish(post)
        self.assertEqual(post['embed']['title'], 'multi-factor authentication (MFA) was reset for a user')
        self.assertTrue(post['embed']['description'].startswith('MFA again.'))
        self.assertIn('MITRE ATT&CK (a public catalogue of attacker techniques)', post['embed']['description'])
        self.assertIn('identity and access management (IAM)', post['embed']['description'])
        self.assertIn('continuous integration (CI)', post['embed']['description'])

    def test_already_spelled_out_is_left_alone(self):
        post = {'embed': {'title': 'Sign-in uses multi-factor authentication (MFA) now'}}
        pl.finish(post)
        self.assertEqual(post['embed']['title'], 'Sign-in uses multi-factor authentication (MFA) now')

    def test_lint_flags_an_unexpanded_acronym_and_raw_json_and_missing_headline(self):
        bad = {'message': '', 'embed': {'title': 'ok', 'description': 'MFA {"eventVersion": "1.08"}'}}
        probs = ' | '.join(pl.lint(bad))
        self.assertIn('headline', probs)
        self.assertIn('acronym', probs)
        self.assertIn('raw JSON', probs)
        self.assertIn('Show details', probs)

    def test_masking_still_applies_to_everything_that_goes_through_finish(self):
        post = pl.finish({'message': '', 'embed': {'title': 'Sign-in from 203.0.113.77 by real.person@contoso.example'}})
        self.assertNotIn('203.0.113.77', post['embed']['title'])
        self.assertNotIn('real.person', post['embed']['title'])


class Approvals(unittest.TestCase):
    def ctx(self):
        store, audit, ex = MemoryStore(), MemoryAudit(), pbk.FakeExecutor()
        ap = {'u1': 'detection-owner'}
        c = SimpleNamespace(store=store, audit=audit, approvers=ap, env={'LAB_KIBANA_PUBLIC': PUBLIC}, cfg=CFG, attack=ATT, es=None, kb=None, packs=pk.packs())
        c.gate = lambda: pbk.Gate(store, audit, ex, ap)
        c.who = lambda uid: ap.get(str(uid))
        return c

    def test_approval_result_and_cancel_are_plain_and_offer_details(self):
        c = self.ctx()
        c.store.put('alert', 'sidtest1', {'status': 'open', 'pack': 'entra', 'rule_id': ROLE_RULE, 'rule_name': 'Entra Directory Role Member Added', 'severity': 'high',
                                          'event': ENTRA, 'alert_time': '2026-10-14T19:38:49Z', 'technique': 'T1098.003', 'alert_doc_id': 'x'})
        r = sv.action(c, 'sidtest1', 'revoke_sessions', 'u1')
        self.assertTrue(r['ok'], r)
        card = r['card']
        self.assertIn('nothing has changed yet', card['text'])
        self.assertIn('practice run', card['text'])
        self.assertIn('sign', card['text'])
        self.assertEqual(pl.lint({'message': card['text'], 'card': card}), [])
        done = sv.confirm(c, r['approval_id'], 'u1')
        self.assertTrue(done['ok'], done)
        self.assertIn('practice run only', done['text'])
        self.assertEqual(pl.lint({'message': done['text'], 'card': done['card']}), [])
        dm = sv.details(c, r['approval_id'])
        self.assertTrue(dm['ok'])
        self.assertIn('Steps (simulated)', dm['dm'])
        self.assertNotIn('Steps (simulated)', json.dumps(card) + json.dumps(done))

    def test_acknowledging_and_judging_are_plain(self):
        c = self.ctx()
        c.store.put('alert', 'sidtest2', {'status': 'open', 'pack': 'entra', 'rule_id': ROLE_RULE, 'rule_name': 'Entra Directory Role Member Added', 'severity': 'high',
                                          'event': ENTRA, 'alert_time': '2026-10-14T19:38:49Z', 'technique': 'T1098.003', 'alert_doc_id': 'x'})
        v = sv.verdict(c, 'sidtest2', 'benign', 'u1')
        self.assertIn('harmless', v['text'])
        self.assertEqual(pl.lint({'message': v['text'], 'card': v['card']}), [])


class Scorecard(unittest.TestCase):
    def test_every_number_has_a_plain_label_and_a_meaning(self):
        s = {'at': '2026-10-14T20:00:00Z', 'alerts_24h': 3, 'alerts_by_severity_24h': {'high': 3}, 'mttd': {'n': 3, 'median': 18, 'p90': 40}, 'mttr': None, 'mtta': None,
             'false_positive_rate': {'benign': 1, 'triaged': 2, 'rate': 0.5}, 'playbooks': {'passed': 28, 'total': 28, 'at': 'x'}, 'techniques': {'mapped': 9, 'enabled': 7}}
        emb = pl.metrics_embed(s, rel)
        post = pl.post_with_details(MemoryStore(), 'metrics:test', 'metrics', emb, 'Raw scorecard numbers', pl.as_json(s))
        self.assertEqual(pl.lint(post, detail_body=pl.as_json(s)), [])
        text = pl.visible_text(post)
        self.assertIn('18s typical (time to detect)', text)
        self.assertIn('how long after something happened we raised the alert', text)
        self.assertNotIn('MTTD', text)
        self.assertIn('Not enough data yet', text, 'a missing number says so plainly')

    def test_empty_scorecard_never_invents_a_number(self):
        s = {'at': '2026-10-14T20:00:00Z', 'alerts_24h': 0, 'alerts_by_severity_24h': {}, 'mttd': None, 'mttr': None, 'mtta': None,
             'false_positive_rate': {'benign': 0, 'triaged': 0, 'rate': None}, 'playbooks': None, 'techniques': {'mapped': 9, 'enabled': 0}}
        post = pl.post_with_details(MemoryStore(), 'metrics:empty', 'metrics', pl.metrics_embed(s, rel), 'Raw', pl.as_json(s))
        self.assertEqual(pl.lint(post), [])


class Coverage(unittest.TestCase):
    def test_summary_leads_and_the_full_map_is_behind_show_details(self):
        snap = cov.snapshot()
        emb, d = cov.embed(snap, None)
        post = pl.post_with_details(MemoryStore(), 'cov:test', 'coverage', emb, 'Every attack type', cov.details_text(snap), kind='coverage', image='/x/coverage-abc.png')
        self.assertEqual(pl.lint(post), [])
        self.assertTrue(post['embed']['title'].startswith('\U0001F5FA We can currently catch'))
        self.assertIn('someone', cov.details_text(snap))


class Checks(unittest.TestCase):
    PR = {'number': 1, 'title': 'Add the lab', 'html_url': 'https://example.test/pr/1', 'head': {'sha': 'abcdef1234567'}}
    RUN = {'conclusion': 'success', 'html_url': 'https://example.test/run/1', 'updated_at': '2026-10-14T19:45:47Z'}

    def rep(self, fail=False):
        return {'detections': {'passed': 16, 'total': 16, 'failed': []}, 'playbooks': {'passed': 26 if fail else 28, 'total': 28, 'failed': ['x'] if fail else []},
                'platform': {'passed': 99, 'total': 99, 'failed': []}, 'backtest_real': {'passed': 5, 'total': 5, 'failed': []},
                'snapshot': {'rules': {'a': 1}, 'playbooks': {'b': 1}, 'techniques': {'T1': 1}},
                'matrix': [{'playbook': 'contain-iam-user', 'case': 'spec_valid', 'status': 'pass', 'ms': 1}, {'playbook': 'reset-mfa', 'case': 'noops_on_benign_events', 'status': 'pass' if not fail else 'fail', 'ms': 2}]}

    def test_automatic_checks_say_pass_or_fail_first(self):
        ok = cipoll.ci_embed(self.PR, self.RUN, self.rep())
        self.assertTrue(ok['title'].startswith('\u2705 All automatic checks passed'))
        bad = cipoll.ci_embed(self.PR, self.RUN, self.rep(fail=True))
        self.assertTrue(bad['title'].startswith('\u274C Automatic checks failed'))
        for e in (ok, bad):
            post = pl.post_with_details(MemoryStore(), 'ci:' + e['title'][:5], 'detection-ci', e, 'Result', cipoll.ci_details(self.PR, self.RUN, self.rep()))
            self.assertEqual(pl.lint(post), [])

    def test_response_tests_summary_and_matrix_behind_details(self):
        e = cipoll.uat_embed(self.PR, self.rep())
        self.assertEqual(e['title'], '\u2705 All 2 response tests passed (code change #1)')
        self.assertNotIn('spec_valid', json.dumps(e), 'the per-case matrix is not in the channel')
        self.assertIn('spec_valid', cipoll.uat_details(self.rep()))
        post = pl.post_with_details(MemoryStore(), 'uat:t', 'playbook-uat', e, 'Every test', cipoll.uat_details(self.rep()))
        self.assertEqual(pl.lint(post, detail_body=cipoll.uat_details(self.rep())), [])
        bad = cipoll.uat_embed(self.PR, self.rep(fail=True))
        self.assertTrue(bad['title'].startswith('\u274C 1 of 2 response tests failed'))


class SlashCommands(unittest.TestCase):
    def test_enrich_hunt_status_lead_with_a_verdict_in_plain_english(self):
        r = {'principal': 'lab-operator', 'window': '1h', 'events': 3, 'timeline': [{'time': '2026-10-14T19:32:04Z', 'pack': 'aws', 'op': 'CreateAccessKey', 'src': '203.0.x.x', 'ok': True}],
             'access_keys': ['key ending ABCD'], 'mfa': ['session MFA False'], 'technique_chain': ['T1098.001']}
        t = en.render_plain(r)
        self.assertTrue(t.startswith('**3 actions**'))
        self.assertIn('created an access key', t)
        self.assertIn('WITHOUT a second verification step', t)
        self.assertEqual(pl.lint({'message': t}, need_details=False), [])
        h = {'query': 'eventName:CreateAccessKey', 'window': '7d', 'total': 2, 'covered': [], 'rows': [{'time': '2026-10-14T19:32:04Z', 'actor': 'lab-operator', 'op': 'CreateAccessKey', 'src': '203.0.x.x'}]}
        ht = hu.render_plain(h)
        self.assertTrue(ht.startswith('**Found 2 matching events**'))
        self.assertIn('no alert fired', ht)
        self.assertEqual(pl.lint({'message': ht}, need_details=False), [])
        self.assertTrue(hu.render_plain(dict(h, total=0, rows=[])).startswith('**Nothing matched**'))
        s = {'at': 'x', 'elastic': {'status': 'green', 'nodes': 1}, 'sources': [{'pack': 'aws', 'log_source': 'AWS CloudTrail', 'docs': 10, 'lag': '5m'}], 'rules': {'total': 11, 'enabled': 7, 'last_run_ok': 7, 'failing': []},
             'alerts_24h': 2, 'shuffle': 'up', 'outbox': {'pending': 0, 'failed': 0}, 'playbooks': {'passing': 28, 'total': 28, 'at': 'x'}}
        st = stt.render_plain(s)
        self.assertTrue(st.startswith('\u2705 **Everything is healthy.**'))
        self.assertEqual(pl.lint({'message': st}, need_details=False), [])
        bad = stt.render_plain(dict(s, shuffle='down'))
        self.assertTrue(bad.startswith('\u26A0\uFE0F **Needs attention:**'))


if __name__ == '__main__':
    unittest.main()
