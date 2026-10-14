import copy
import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path

from core import deploy, packs as pk
from core.console import alerts as al, coverage as cov, hunt as hu, metrics as me, outbox as ob, redact
from core.console.fields import first, getf
from core.console.store import MemoryStore

ROOT = pk.ROOT
CFG = pk.config()
ATT = pk.attack_names()
NASTY = {'eventID': '11111111-2222-4333-8444-555555555555', 'eventTime': '2026-10-14T19:32:04Z', 'sourceIPAddress': '203.0.113.77', 'awsRegion': 'us-east-1',
         'eventSource': 'iam.amazonaws.com', 'eventName': 'AttachUserPolicy', 'recipientAccountId': '123456789012',
         'userIdentity': {'type': 'IAMUser', 'userName': 'lab-operator', 'accountId': '123456789012', 'arn': 'arn:aws:iam::123456789012:user/lab-operator', 'accessKeyId': 'AKI' + 'AABCDEFGHIJKLMNOP'},
         'requestParameters': {'userName': 'example-user', 'policyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'}}
ENTRA = {'id': 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', 'activityDateTime': '2026-10-14T19:32:04Z', 'activityDisplayName': 'Consent to application', 'loggedByService': 'Core Directory',
         'result': 'success', 'initiatedBy': {'user': {'userPrincipalName': 'real.person@contoso.example', 'ipAddress': '198.51.100.9'}},
         'targetResources': [{'displayName': 'example-app', 'type': 'ServicePrincipal', 'userPrincipalName': None}]}


def alert(rule='AWS IAM Access Key Created', sev='high', tags=('attack.t1098.001',)):
    return {'kibana.alert.uuid': 'abcdef12-0000-4000-8000-000000000000', 'kibana.alert.rule.name': rule, 'kibana.alert.rule.rule_id': 'r-1', 'kibana.alert.severity': sev,
            'kibana.alert.risk_score': 73, 'kibana.alert.rule.tags': list(tags), '@timestamp': '2026-10-14T19:38:49.920Z'}


class Redaction(unittest.TestCase):
    def test_masks_every_identifier_class(self):
        t = redact.scrub('acct 123456789012 ip 203.0.113.77 mail real.person@contoso.example key AKI' + 'AABCDEFGHIJKLMNOP arn:aws:iam::123456789012:user/x')
        self.assertEqual(redact.leaks(t), [], t)
        self.assertIn('203.0.x.x', t)

    def test_guid_tails_are_not_mistaken_for_account_ids(self):
        g = '11111111-2222-4333-8444-555555555555'
        self.assertEqual(redact.scrub('event ' + g), 'event ' + g)

    def test_leak_detector_catches_raw_values(self):
        for raw in ('123456789012', '203.0.113.77', 'a@b.example', 'AKI' + 'AABCDEFGHIJKLMNOP'):
            self.assertTrue(redact.leaks('x ' + raw + ' y'), raw)


class Fields(unittest.TestCase):
    def test_nested_flat_and_list_access(self):
        self.assertEqual(getf({'a': {'b': 1}}, 'a.b'), 1)
        self.assertEqual(getf({'a.b': 2}, 'a.b'), 2)
        self.assertEqual(getf({'t': [{'n': 'x'}]}, 't.0.n'), 'x')
        self.assertIsNone(getf({'t': []}, 't.0.n'))
        self.assertEqual(first({'b': 'v'}, ['a', 'b']), 'v')


class Embeds(unittest.TestCase):
    def post(self, pack_name, doc, source):
        return al.build_post(dict(doc, _id='x'), source, pk.by_name(pack_name), ATT, CFG, 'http://100.64.1.2:5601', ['u1', 'u2'])

    def test_aws_alert_has_all_required_fields_and_no_raw_identifiers(self):
        p = self.post('aws', alert(), NASTY)
        e = p['embed']
        self.assertNotIn('url', e, 'the technical link lives behind Show details, not on the card')
        self.assertEqual(e['color'], CFG['embed_colors']['high'])
        text = json.dumps(e)
        self.assertIn('T1098.001', text)
        self.assertIn('someone added a new password or access key to an account', text, 'the technique is explained in plain words')
        self.assertIn('AWS CloudTrail', e['footer']['text'])
        self.assertNotIn(NASTY['eventID'], text, 'the raw event id belongs in the details, not on the card')
        self.assertEqual(redact.leaks(text.replace('100.64.1.2', 'kibana-host')), [], text)
        url = p['summary']['link']
        for bad in ('"', "'", '(', ')', ' '):
            self.assertNotIn(bad, url, 'the Kibana link must be fully percent-encoded: ' + repr(bad))
        self.assertIn('%22' + NASTY['eventID'] + '%22', url)

    def test_severity_colours(self):
        for sev in ('high', 'medium', 'low'):
            self.assertEqual(self.post('aws', alert(sev=sev), NASTY)['embed']['color'], CFG['embed_colors'][sev])

    def test_button_sets_follow_the_pack(self):
        aws = self.post('aws', alert(), NASTY)['buttons']['blocks'][0]['buttons']
        ent = self.post('entra', alert('Entra Application Consent', tags=('attack.t1528',)), ENTRA)['buttons']['blocks'][0]['buttons']
        name = lambda b: b['label'].split(' ', 1)[1].split(' \u00b7')[0]
        self.assertEqual([name(b) for b in aws], ['Mark as seen', 'Investigate', 'Request lockdown', 'Show details'])
        self.assertEqual([name(b) for b in ent], ['Mark as seen', 'Reset 2-step sign-in', 'Sign user out everywhere', 'Disable the application', 'Show details'])
        self.assertTrue(all(b['allowedUsers'] == ['u1', 'u2'] for b in aws[:-1] + ent[:-1]))
        self.assertTrue(all(post_id in aws[0]['label'] for post_id in ['abcdef12']))

    def test_entra_alert_masks_the_user_and_the_address(self):
        p = self.post('entra', alert('Entra Application Consent', tags=('attack.t1528',)), ENTRA)
        text = json.dumps(p['embed'])
        self.assertEqual(redact.leaks(text.replace('100.64.1.2', 'kibana-host')), [], text)
        self.assertNotIn('real.person', text)

    def test_a_brand_new_pack_needs_no_console_change(self):
        meta = copy.deepcopy(pk.by_name('aws'))
        meta.update({'name': 'gcp', 'log_source': 'GCP Audit Logs', 'lane': 'Detection', 'index': 'logs-gcp', 'id_field': 'insertId', 'time_field': 'timestamp', 'data_view': 'lab-gcp',
                     'fields': {'actor': ['protoPayload.authenticationInfo.principalEmail'], 'operation': 'protoPayload.methodName', 'service': 'protoPayload.serviceName', 'source_ip': 'protoPayload.requestMetadata.callerIp', 'region': None, 'target': [], 'error': None}})
        src = {'insertId': 'abc', 'timestamp': '2026-10-14T19:32:04Z', 'protoPayload': {'authenticationInfo': {'principalEmail': 'someone@example.com'}, 'methodName': 'SetIamPolicy', 'serviceName': 'cloudresourcemanager.googleapis.com', 'requestMetadata': {'callerIp': '203.0.113.5'}}}
        p = al.build_post(dict(alert(), _id='x'), src, meta, ATT, CFG, 'http://k:5601', [])
        self.assertIn('GCP Audit Logs', p['embed']['footer']['text'])
        self.assertEqual(redact.leaks(json.dumps(p['embed'])), [])


class Outbox(unittest.TestCase):
    def test_idempotent_leased_acked_and_bounded_retries(self):
        s = MemoryStore()
        self.assertTrue(ob.enqueue(s, 'k1', {'x': 1}))
        self.assertFalse(ob.enqueue(s, 'k1', {'x': 2}), 'same key queued once')
        now = dt.datetime(2026, 10, 14, 12, 0, tzinfo=dt.timezone.utc)
        first_batch = ob.next_batch(s, 5, now=now)
        self.assertEqual(len(first_batch), 1)
        self.assertEqual(ob.next_batch(s, 5, now=now), [], 'a leased entry is not handed out twice')
        later = now + dt.timedelta(seconds=ob.LEASE_SECONDS + 5)
        self.assertEqual(len(ob.next_batch(s, 5, now=later)), 1, 'an expired lease is retried')
        ob.ack(s, 'k1', ['m1'])
        self.assertEqual(s.get('outbox', 'k1')['status'], 'posted')
        self.assertEqual(ob.next_batch(s, 5, now=later + dt.timedelta(hours=1)), [])
        ob.enqueue(s, 'k2', {})
        for i in range(ob.MAX_ATTEMPTS):
            ob.next_batch(s, 5, now=now + dt.timedelta(hours=i + 2))
            status = ob.fail(s, 'k2', 'boom')
        self.assertEqual(status, 'failed')


class Metrics(unittest.TestCase):
    def test_summary_is_none_when_empty_never_a_placeholder(self):
        self.assertIsNone(me._summ([]))
        self.assertEqual(me._summ([10, 20, 30])['median'], 20)
        shown = me.render({'mttd': None, 'mttr': None, 'mtta': None, 'alerts_24h': 0, 'alerts_by_severity_24h': {}, 'false_positive_rate': {'benign': 0, 'triaged': 0, 'rate': None},
                           'playbooks': None, 'techniques': {'mapped': 7, 'enabled': 7}})
        for k in ('MTTD (event to alert, includes CloudTrail delivery)', 'MTTR (alert to first dry-run containment)', 'False-positive rate', 'Playbooks passing'):
            self.assertIn('n/a', shown[k])


class FakeEs:
    def __init__(self):
        self.calls = []

    def request(self, method, path, body=None, **kw):
        self.calls.append((path, body))
        if path.startswith('/logs-'):
            return {'hits': {'total': {'value': 1}, 'hits': [{'_id': 'doc-1', '_index': 'logs-cloud-response-lab-library-aws', '_source': {'eventID': 'e-1', 'eventTime': '2026-10-14T19:32:04Z', 'eventName': 'CreateAccessKey', 'userIdentity': {'userName': 'u'}}}]},
                    'aggregations': {'ops': {'buckets': [{'key': 'CreateAccessKey', 'doc_count': 1}]}, 'aops': {'buckets': []}, 'users': {'buckets': [{'key': 'u', 'doc_count': 1}]}, 'roles': {'buckets': []}, 'upn': {'buckets': []}, 'idx': {'buckets': []}, 'mn': {'value_as_string': '2026-10-14T19:32:04Z'}, 'mx': {'value_as_string': '2026-10-14T19:32:04Z'}}}
        return {'hits': {'hits': [{'_source': {'kibana.alert.rule.name': 'AWS IAM Access Key Created'}}]}}


class Hunt(unittest.TestCase):
    def test_coverage_check_matches_on_ancestor_document_ids(self):
        es = FakeEs()
        r = hu.hunt(es, MemoryStore(), 'eventName:CreateAccessKey', '7d', now=dt.datetime(2026, 10, 14, 21, 0, tzinfo=dt.timezone.utc))
        self.assertEqual(r['covered'], ['AWS IAM Access Key Created'])
        self.assertIn('Already covered by', r['verdict'])
        alert_query = [b for p, b in es.calls if p.startswith('/.alerts')][0]
        self.assertEqual(alert_query['query'], {'terms': {'kibana.alert.ancestors.id': ['doc-1']}})

    def test_simple_query_becomes_a_real_selection(self):
        stub = hu.candidate_stub({'key': 'ab12cd34', 'lucene': 'eventName:CreateAccessKey AND eventSource:"iam.amazonaws.com"', 'window': '7d', 'total': 4, 'techs': ['T1098.001'], 'top_pack': 'aws'})
        self.assertTrue(stub['simple'])
        self.assertIn('eventName: "CreateAccessKey"', stub['text'])
        self.assertIn('/detections/candidates/', stub['path'])
        self.assertIn('attack.t1098.001', stub['text'])

    def test_complex_query_is_kept_as_a_todo_not_silently_translated(self):
        stub = hu.candidate_stub({'key': 'ab12cd34', 'lucene': '(a:1 OR b:2) AND NOT c:3', 'window': '1d', 'total': 1, 'techs': [], 'top_pack': 'entra'})
        self.assertFalse(stub['simple'])
        self.assertIn('TODO', stub['text'])


class FakeKb:
    def __init__(self, rules):
        self.rules = rules

    def request(self, method, path, body=None, **kw):
        return {'data': list(self.rules), 'total': len(self.rules)}


class Drift(unittest.TestCase):
    def deployed_copy(self):
        return [dict(r, id='id-' + r['rule_id']) for r in deploy.desired()]

    def test_matching_deployment_has_no_diff(self):
        self.assertTrue(deploy.verify(FakeKb(self.deployed_copy()))['match'])

    def test_lookback_drift_is_caught(self):
        rules = self.deployed_copy()
        rules[0]['from'] = 'now-10m'
        res = deploy.verify(FakeKb(rules))
        self.assertFalse(res['match'])
        self.assertEqual(res['diffs'][0]['field'], 'from')

    def test_missing_and_extra_rules_are_caught(self):
        rules = self.deployed_copy()
        gone = rules.pop()
        rules.append({'rule_id': 'rogue', 'id': 'x', 'name': 'rogue', 'enabled': True, 'tags': []})
        problems = {d.get('problem') for d in deploy.verify(FakeKb(rules))['diffs']}
        self.assertEqual(problems, {'missing in Kibana', 'in Kibana but not in the repo'})

    def test_repo_lookback_comes_from_config(self):
        self.assertTrue(all(r['from'] == CFG['rule_defaults']['from'] for r in deploy.desired()))


class Coverage(unittest.TestCase):
    def test_snapshot_and_diff(self):
        snap = cov.snapshot()
        self.assertEqual(len(snap['rules']), 11)
        self.assertEqual(sorted(snap['playbooks']), ['contain-iam-user', 'disable-service-principal', 'reset-mfa', 'revoke-sessions'])
        d = cov.diff(None, snap)
        self.assertEqual(len(d['rules_added']), 11)
        self.assertEqual(cov.diff(snap, snap)['rules_added'], [])
        self.assertIn('Persistence', cov.html(snap))

    def test_pack_layers_are_current(self):
        from library.build import pack_layers
        for name, layer in pack_layers().items():
            self.assertEqual(json.loads((ROOT / 'packs' / name / 'attack-layer.json').read_text()), layer, name + ' layer is stale: run python -m library.build')


class ServiceRedaction(unittest.TestCase):
    def ctx(self):
        from types import SimpleNamespace
        from core.console import playbooks as pbk
        from core.console.audit import MemoryAudit
        store, audit, ex = MemoryStore(), MemoryAudit(), pbk.FakeExecutor()
        approvers = {'u1': 'detection-owner'}
        c = SimpleNamespace(store=store, audit=audit, approvers=approvers, env={'LAB_KIBANA_PUBLIC': 'http://100.64.1.2:5601'}, cfg=CFG, attack=ATT, es=None, kb=None, packs=pk.packs())
        c.gate = lambda: pbk.Gate(store, audit, ex, approvers)
        c.who = lambda uid: approvers.get(str(uid))
        return c, store, ex

    def test_an_email_address_target_never_reaches_discord_text_but_still_drives_the_plan(self):
        from core.console import service as sv
        c, store, ex = self.ctx()
        store.put('alert', 'sidtest1', {'status': 'open', 'pack': 'entra', 'rule_id': '8a7d441b-870b-4fce-bac4-000000000005', 'rule_name': 'Entra Directory Role Member Added',
                                        'severity': 'high', 'event': ENTRA, 'alert_time': '2026-10-14T19:38:49Z', 'technique': 'T1098.003', 'alert_doc_id': 'x'})
        r = sv.action(c, 'sidtest1', 'revoke_sessions', 'u1')
        self.assertTrue(r['ok'], r)
        self.assertNotIn('real.person', json.dumps(r), 'the approval prompt must mask the user')
        done = sv.confirm(c, r['approval_id'], 'u1')
        self.assertTrue(done['ok'], done)
        self.assertNotIn('real.person', done['text'])
        self.assertEqual(ex.calls[0]['payload']['target'], 'real.person@contoso.example', 'the real value still drives the dry-run plan')
        self.assertEqual(r['approval_id'], r['card']['blocks'][0]['buttons'][0]['label'].split(' \u00b7 ')[1], 'button labels must keep the exact approval id')


class CiCards(unittest.TestCase):
    def test_a_commit_that_predates_the_pack_structure_is_reported_as_n_a_not_as_a_failure(self):
        from core.console import cipoll
        pr = {'number': 1, 'title': 't', 'html_url': 'https://example.test/pr/1', 'head': {'sha': 'abcdef1234567'}}
        run = {'conclusion': 'success', 'html_url': 'https://example.test/run/1', 'updated_at': '2026-10-14T19:45:47Z'}
        emb = cipoll.ci_embed(pr, run, {'legacy': True, 'error': 'this commit predates the pack structure, so there is nothing to backtest'})
        text = json.dumps(emb)
        self.assertIn('predates the pack structure', text)
        self.assertNotIn('failed', text.lower().replace('the deeper tests could not run', ''))


class PrFiles(unittest.TestCase):
    def test_a_pr_with_more_than_one_page_of_files_is_read_to_the_end(self):
        from core.console import cipoll
        pages = {1: [{'filename': 'f%d' % i} for i in range(100)], 2: [{'filename': 'packs/aws/playbooks/x.json'}] + [{'filename': 'g%d' % i} for i in range(5)]}
        orig = cipoll.gh
        cipoll.gh = lambda path: pages[int(path.rsplit('page=', 1)[1])]
        try:
            names = cipoll.pr_files('o/r', 1)
        finally:
            cipoll.gh = orig
        self.assertEqual(len(names), 106)
        self.assertIn('packs/aws/playbooks/x.json', names)


class CiPollIdempotence(unittest.TestCase):
    def test_a_handled_head_costs_no_further_api_calls(self):
        from types import SimpleNamespace
        from core.console import cipoll
        store = MemoryStore()
        store.put('ci_done', '1:abc', {'status': 'done'})
        calls = []
        orig = cipoll.gh
        def fake(path):
            calls.append(path)
            if '/pulls?' in path:
                return [{'number': 1, 'head': {'sha': 'abc', 'ref': 'b'}, 'base': {'ref': 'main'}, 'title': 't', 'html_url': 'u', 'merged_at': None}]
            raise AssertionError('no further call is allowed for a finished head: ' + path)
        cipoll.gh = fake
        try:
            cipoll.poll(SimpleNamespace(store=store), 'o/r')
        finally:
            cipoll.gh = orig
        self.assertEqual(len(calls), 1)


class CoverageEmbed(unittest.TestCase):
    def test_embed_reports_the_change_against_the_previous_snapshot(self):
        snap = cov.snapshot()
        emb, d = cov.embed(snap, None)
        self.assertIn('We can currently catch %d of the %d' % (d['covered_after'], len(snap['techniques'])), emb['title'])
        self.assertIn('first map', emb['description'])
        emb2, d2 = cov.embed(snap, snap)
        self.assertIn('no change', emb2['description'])
        self.assertEqual(d2['rules_added'], [])


class Packs(unittest.TestCase):
    def test_every_pack_has_the_same_shape(self):
        found = pk.packs()
        self.assertEqual([p['name'] for p in found], ['aws', 'entra'])
        for p in found:
            for d in pk.REQUIRED_DIRS:
                self.assertTrue((p['path'] / d).is_dir())
            self.assertTrue((p['path'] / 'README.md').is_file())
            self.assertTrue(p['playbooks'], 'each pack ships at least one playbook')

    def test_a_malformed_pack_is_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / 'packs/bad/detections').mkdir(parents=True)
            (Path(t) / 'packs/bad/pack.json').write_text('{"name": "bad"}')
            with self.assertRaises(ValueError):
                pk.packs(t)


if __name__ == '__main__':
    unittest.main()
