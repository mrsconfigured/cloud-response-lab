"""Shared test kit. A pack's tests are two lines (see packs/aws/tests/test_detections.py), so a new pack gets the
same detection and response-as-code checks without writing new test code."""
import datetime as dt
import json
import unittest
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection

from core import packs as pk
from core import shuffle_export
from core.console import playbooks as pbk
from core.console.audit import MemoryAudit
from core.console.store import MemoryStore

APPROVER = 'approver-owner'
OTHER = 'someone-else'


def all_rule_paths(pack):
    yield from sorted(pack['detections_dir'].glob('*.yml'))
    signin = pack['detections_dir'] / 'signin'
    if signin.is_dir():
        yield from sorted(signin.glob('*.yml'))


def _load(path):
    text = path.read_text()
    return yaml.safe_load(text), SigmaCollection.from_yaml(text).rules[0].detection.parsed_condition[0].parsed


def detection_suite(pack_name):
    from library.build import evaluate
    pack = pk.by_name(pack_name)
    attack = pk.attack_names()
    ns = {}

    def make(path):
        def test(self):
            raw, ast = _load(path)
            fx = json.loads((pack['path'] / 'tests/fixtures' / (path.stem + '.json')).read_text())
            self.assertTrue(fx['positive'], 'needs at least one positive case')
            self.assertTrue(fx['negative'], 'needs at least one negative case')
            for case in fx['positive']:
                with self.subTest(positive=case['name']):
                    self.assertTrue(evaluate(ast, case['event']), 'should fire')
            for case in fx['negative']:
                with self.subTest(negative=case['name']):
                    self.assertFalse(evaluate(ast, case['event']), 'must not fire')
            tech = next(t.split('attack.')[1].upper() for t in raw['tags'] if t.startswith('attack.t1'))
            self.assertIn(tech, attack, 'technique %s is missing from core/attack.json' % tech)
            fixture_only = path.stem in pack.get('fixture_only', [])
            self.assertEqual(fixture_only, path.parent.name == 'signin', 'fixture-only rules live in detections/signin/')
            if fixture_only:
                self.assertNotIn(path.stem, pack['enabled_rules'], 'a fixture-only rule must not be enabled')
        return test

    for path in all_rule_paths(pack):
        ns['test_' + path.stem.replace('-', '_')] = make(path)

    def test_pack_shape(self):
        self.assertTrue((pack['path'] / 'README.md').is_file(), 'pack README.md')
        self.assertTrue((pack['path'] / 'attack-layer.json').is_file(), 'pack attack-layer.json')
        slugs = {p.stem for p in all_rule_paths(pack)}
        for s in pack['enabled_rules'] + pack.get('fixture_only', []):
            self.assertIn(s, slugs, 'pack.json names a rule that does not exist: ' + s)
    ns['test_pack_shape'] = test_pack_shape
    return type('Test%sDetections' % pack_name.title(), (unittest.TestCase,), ns)


def _gate(clock=None):
    store, audit, ex = MemoryStore(), MemoryAudit(), pbk.FakeExecutor()
    gate = pbk.Gate(store, audit, ex, {APPROVER: 'detection-owner'}, clock=clock)
    return gate, store, audit, ex


def playbook_suite(pack_name):
    pack = pk.by_name(pack_name)
    ns = {}

    def make(path):
        pb = json.loads(path.read_text())
        fx = json.loads((pack['path'] / 'tests/fixtures/playbooks' / (pb['id'] + '.json')).read_text())
        key = pb['id'].replace('-', '_')

        def spec_valid(self):
            pbk.validate(pb)
            self.assertEqual(pb['pack'], pack['name'])
            self.assertEqual(path.with_name(path.stem + '.shuffle.json').read_text(), shuffle_export.dump(pb), 'regenerate with python -m core.shuffle_export')

        def acts_only_on_matching_events(self):
            for c in fx['match']:
                with self.subTest(match=c['name']):
                    self.assertTrue(pbk.evaluate(pb, c['alert'])['match'])
            for c in fx['no_match']:
                with self.subTest(no_match=c['name']):
                    self.assertFalse(pbk.evaluate(pb, c['alert'])['match'])

        def halts_for_approval_before_any_change(self):
            gate, store, audit, ex = _gate()
            r = gate.request(pb, fx['match'][0]['alert'], 'tester')
            self.assertEqual(r['status'], 'awaiting_approval')
            self.assertEqual(ex.calls, [], 'executor must not run before approval')
            self.assertIn(r['target'], r['prompt'], 'prompt must name exactly what changes')
            refused = gate.confirm(r['approval_id'], OTHER, pb)
            self.assertEqual(refused['status'], 'refused')
            self.assertEqual(ex.calls, [], 'an unauthorised approver must not run it')
            c = gate.cancel(r['approval_id'], APPROVER, pb)
            self.assertEqual(c['status'], 'cancelled')
            self.assertEqual(ex.calls, [], 'cancel must not run it')
            self.assertEqual(gate.confirm(r['approval_id'], APPROVER, pb)['status'], 'refused', 'a cancelled approval cannot be confirmed')
            self.assertEqual(ex.calls, [])

        def executes_dry_run_only_after_confirm(self):
            gate, store, audit, ex = _gate()
            r = gate.request(pb, fx['match'][0]['alert'], 'tester')
            done = gate.confirm(r['approval_id'], APPROVER, pb)
            self.assertEqual(done['status'], 'executed')
            self.assertEqual(len(ex.calls), 1)
            self.assertEqual(ex.calls[0]['payload']['mode'], 'dry_run')
            self.assertEqual([s['id'] for s in ex.calls[0]['payload']['plan']], [s['id'] for s in pb['steps']])
            again = gate.confirm(r['approval_id'], APPROVER, pb)
            self.assertEqual(again['status'], 'refused')
            self.assertEqual(len(ex.calls), 1, 'a second confirm must not run it again')

        def expired_approval_is_refused(self):
            t = [dt.datetime(2026, 10, 14, 12, 0, tzinfo=dt.timezone.utc)]
            gate, store, audit, ex = _gate(clock=lambda: t[0])
            r = gate.request(pb, fx['match'][0]['alert'], 'tester')
            t[0] += dt.timedelta(seconds=pbk.APPROVAL_TTL_SECONDS + 60)
            self.assertEqual(gate.confirm(r['approval_id'], APPROVER, pb)['status'], 'refused')
            self.assertEqual(ex.calls, [])

        def noops_on_benign_events(self):
            for c in fx['no_match']:
                with self.subTest(no_match=c['name']):
                    gate, store, audit, ex = _gate()
                    r = gate.request(pb, c['alert'], 'tester')
                    self.assertEqual(r['status'], 'no_op')
                    self.assertEqual(ex.calls, [])
                    self.assertEqual(store.list('approval'), [], 'a no-op must not open an approval')
                    self.assertEqual(audit.records[-1]['action'], 'no_op')

        def writes_audit_for_every_outcome(self):
            gate, store, audit, ex = _gate()
            r = gate.request(pb, fx['match'][0]['alert'], 'tester')
            gate.confirm(r['approval_id'], OTHER, pb)
            gate.confirm(r['approval_id'], APPROVER, pb)
            r2 = gate.request(pb, fx['match'][0]['alert'], 'tester')
            gate.cancel(r2['approval_id'], APPROVER, pb)
            gate.request(pb, fx['no_match'][0]['alert'], 'tester')
            actions = [x['action'] for x in audit.records]
            for needed in ('approval_requested', 'confirm_refused', 'executed', 'cancelled', 'no_op'):
                self.assertIn(needed, actions)
            for rec in audit.records:
                for k in ('@timestamp', 'actor', 'action', 'approver', 'playbook', 'run_id', 'result'):
                    self.assertIn(k, rec)
                self.assertEqual(rec['mode'], 'dry-run')
            done = [x for x in audit.records if x['action'] == 'executed'][0]
            self.assertEqual(done['approver'], 'detection-owner', 'the audit shows the role, not a raw id')
            self.assertEqual(done['approver_id'], APPROVER)
            self.assertNotIn('approver-owner', done['actor'])

        for name, fn in (('spec_valid', spec_valid), ('acts_only_on_matching_events', acts_only_on_matching_events),
                         ('halts_for_approval_before_any_change', halts_for_approval_before_any_change),
                         ('executes_dry_run_only_after_confirm', executes_dry_run_only_after_confirm),
                         ('expired_approval_is_refused', expired_approval_is_refused),
                         ('noops_on_benign_events', noops_on_benign_events), ('writes_audit_for_every_outcome', writes_audit_for_every_outcome)):
            ns['test_%s__%s' % (key, name)] = fn

    for path in pack['playbooks']:
        make(path)
    return type('Test%sPlaybooks' % pack_name.title(), (unittest.TestCase,), ns)
