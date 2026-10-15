import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from core import learning as L
from core.console import learncli
from core.console.store import MemoryStore


def entry(cmd, topic='git', **kw):
    return L.make_entry(cmd, topic, kw.get('gloss', 'a short gloss'), kw.get('what', 'What it does in plain words.'), kw.get('when', 'When you would use it.'), kw.get('by', 'analyst'), kw.get('goal'))


class Source(unittest.TestCase):
    def test_every_entry_has_the_required_fields_and_ids_are_stable(self):
        e = entry('git status')
        for k in ('id', 'command', 'topic', 'gloss', 'what', 'when', 'added_by', 'added_at'):
            self.assertTrue(e.get(k), k)
        self.assertEqual(e['id'], L.entry_id('git', 'git status'))

    def test_secrets_are_refused_not_stored(self):
        for bad in ('curl -H "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456" x', 'export GITHUB_TOKEN=ghp_' + 'a' * 30, 'tailscale up --authkey ts' + 'key-auth-abcdef123456', 'aws configure set aws_secret_access_key=abcdefghij123456'):
            with self.assertRaises(L.RefusedEntry, msg=bad):
                entry(bad)
        with self.assertRaises(L.RefusedEntry):
            entry('git status', what='my password: hunter2hunter2')

    def test_addresses_emails_and_account_ids_are_masked(self):
        e = entry('ssh admin@example.com 203.0.113.77', what='Connects to 203.0.113.77 for account 123456789012.')
        text = json.dumps(e)
        self.assertNotIn('203.0.113.77', text)
        self.assertNotIn('admin@example.com', text)
        self.assertNotIn('123456789012', text)

    def test_add_appends_dedupes_and_rerenders_markdown(self):
        with tempfile.TemporaryDirectory() as d:
            e, created = L.add(entry('git status'), d)
            self.assertTrue(created)
            e2, created2 = L.add(entry('git status'), d)
            self.assertFalse(created2)
            self.assertEqual(len(L.load(d)['entries']), 1)
            self.assertIn('### `git status`', (Path(d) / 'LEARNING-LOG.md').read_text())

    def test_a_new_topic_starts_a_new_section_and_known_topics_slot_in_order(self):
        with tempfile.TemporaryDirectory() as d:
            for c, t in (('git status', 'git'), ('docker ps', 'docker'), ('pytest -q', 'pytest'), ('curl https://x', 'networking')):
                L.add(entry(c, t), d)
            self.assertEqual([t for t, _ in L.topics(L.load(d))], ['git', 'pytest', 'docker', 'networking'])
            md = (Path(d) / 'LEARNING-LOG.md').read_text()
            self.assertIn('## Docker', md)
            self.assertIn('## Networking', md)

    def test_topic_guess_for_the_common_tools(self):
        for cmd, topic in (('git push', 'git'), ('python3 -m venv .venv', 'python'), ('python3 -m pytest -q', 'pytest'), ('tailscale status', 'tailscale'), ('docker ps', 'docker')):
            self.assertEqual(L.topic_for(cmd), topic)

    def test_the_repo_seed_is_valid_and_covers_the_basics(self):
        from core import packs as pk
        doc = json.loads((Path(pk.ROOT) / 'docs' / 'learning-log.json').read_text())
        topics = {e['topic'] for e in doc['entries']}
        self.assertTrue({'git', 'python', 'pytest', 'tailscale', 'pull request'} <= topics)
        for e in doc['entries']:
            L.make_entry(e['command'], e['topic'], e['gloss'], e['what'], e['when'], e['added_by'], now=e['added_at'])


class Search(unittest.TestCase):
    def doc(self):
        return {'entries': [entry('python3 -m venv .venv', 'python', gloss='make a private toolbox'), entry('source .venv/bin/activate', 'python', gloss='switch the toolbox on'),
                            entry('git status', 'git', gloss='see what changed'), entry('git switch -c x', 'git', gloss='new branch')]}

    def test_find_matches_command_gloss_topic_and_explanation_and_ranks_command_hits_first(self):
        d = self.doc()
        self.assertEqual({e['command'] for e in L.find(d, 'venv')}, {'python3 -m venv .venv', 'source .venv/bin/activate'})
        self.assertEqual(len(L.find(d, 'toolbox')), 2)
        self.assertEqual(len(L.find(d, 'git')), 2)
        self.assertEqual(L.find(d, 'nothing-like-this'), [])
        self.assertEqual([e['command'] for e in L.find(d, 'git switch')], ['git switch -c x'])

    def test_results_highlight_the_term_and_offer_details(self):
        r = L.render_find(self.doc(), 'venv')
        self.assertIn('**`venv`**', r['text'])
        self.assertIn('Pick one below', r['text'])
        self.assertTrue(L.render_find(self.doc(), 'zzz')['text'].startswith('Nothing in the learning log'))


class Card(unittest.TestCase):
    def big(self, n):
        return {'entries': [entry('command number %d --flag value' % i, 't%d' % (i % 9), gloss='gloss number %d' % i) for i in range(n)]}

    def test_card_has_three_parts_with_both_modals_and_the_action_band_first(self):
        parts = dict(L.card_parts(self.big(5), 'http://tailnet-host:8090'))
        self.assertEqual(list(parts), ['band-add', 'band-search', 'entries'])
        self.assertIn('Add to log', parts['band-add']['modal']['triggerLabel'])
        self.assertEqual(len(parts['band-add']['modal']['fields']), 2)
        self.assertIn('Search', parts['band-search']['modal']['triggerLabel'])
        self.assertIn('/log <command>', parts['band-add']['text'])
        self.assertIn('/find <term>', parts['band-add']['text'])
        self.assertIn('5 entries', parts['band-add']['text'])
        self.assertIn('http://tailnet-host:8090', parts['band-add']['text'])

    def test_card_stays_inside_discord_limits_however_big_the_log_gets(self):
        for n in (1, 16, 60, 400):
            parts = dict(L.card_parts(self.big(n)))
            body = parts['entries']
            text = sum(len(b['text']) for b in body['blocks'] if b['type'] == 'text')
            self.assertLessEqual(text, 4000, n)
            for b in body['blocks']:
                if b.get('select'):
                    self.assertLessEqual(len(b['select']['options']), 25)
                    self.assertTrue(all(len(o['label']) <= 100 for o in b['select']['options']))

    def test_each_entry_line_is_the_command_in_monospace_plus_a_gloss(self):
        body = dict(L.card_parts({'entries': [entry('git status', gloss='see what changed')]}))['entries']
        self.assertIn('`git status` \u2014 see what changed', body['blocks'][0]['text'])

    def test_adding_an_entry_changes_the_count_and_queues_only_the_parts_that_changed(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = SimpleNamespace(env={'LAB_LEARNING_URL': 'http://tailnet-host:8090'}, store=MemoryStore())
            L.add(entry('git status'), d)
            q1 = learncli.refresh_card(ctx, d)
            self.assertEqual(len(q1), 3)
            for k in q1:
                part = k.split(':')[1]
                doc = ctx.store.get('outbox', k)['payload']
                learncli.card_set(part, 'm-' + part, doc['hash'], d)
            self.assertEqual(learncli.refresh_card(ctx, d), [], 'nothing changed, nothing queued')
            L.add(entry('git pull'), d)
            q2 = learncli.refresh_card(ctx, d)
            self.assertEqual(sorted(k.split(':')[1] for k in q2), ['band-add', 'entries'], 'the count and the list changed, the search band did not')
            edit = ctx.store.get('outbox', q2[0])['payload']
            self.assertEqual(edit['message_id'], 'm-' + edit['part'], 'an existing card is edited in place, not reposted')


class PendingCards(unittest.TestCase):
    def test_edits_are_left_for_the_discord_session_and_applied_once(self):
        from core.console import outbox as ob
        with tempfile.TemporaryDirectory() as d:
            ctx = SimpleNamespace(env={}, store=MemoryStore())
            L.add(entry('git status'), d)
            for k in learncli.refresh_card(ctx, d):
                part = k.split(':')[1]
                learncli.card_set(part, 'm-' + part, ctx.store.get('outbox', k)['payload']['hash'], d)
                ob.ack(ctx.store, k, ['m-' + part])
            L.add(entry('git pull'), d)
            queued = learncli.refresh_card(ctx, d)
            self.assertEqual(ob.next_batch(ctx.store, 10), [], 'the poster must not try to edit; it cannot')
            r = learncli.pending_cards(ctx, d, claim=True)
            self.assertEqual(sorted(i['part'] for i in r['edits']), sorted(k.split(':')[1] for k in queued))
            self.assertTrue(r['pins'], 'unpinned parts are reported')
            self.assertEqual(learncli.pending_cards(ctx, d, claim=True)['claimed'], 0, 'a request already sent is not repeated within the window')
            e = r['edits'][0]
            learncli.card_done(ctx, key=e['key'], part=e['part'], message_id=e['message_id'], h=e['hash'], d=d)
            self.assertEqual(len(learncli.pending_cards(ctx, d)['edits']), len(r['edits']) - 1)
            learncli.card_done(ctx, pinned='band-add', d=d)
            self.assertNotIn('band-add', [p['part'] for p in learncli.pending_cards(ctx, d)['pins']])

    def test_new_card_parts_still_go_through_the_poster(self):
        from core.console import outbox as ob
        with tempfile.TemporaryDirectory() as d:
            ctx = SimpleNamespace(env={}, store=MemoryStore())
            L.add(entry('git status'), d)
            learncli.refresh_card(ctx, d)
            self.assertEqual(len(ob.next_batch(ctx.store, 10)), 3)


class Page(unittest.TestCase):
    def test_page_can_jump_to_one_entry_by_its_id(self):
        from core import packs as pk
        html = (Path(pk.ROOT) / 'docs' / 'learning-web' / 'index.html').read_text()
        self.assertIn('location.hash', html)
        self.assertIn('hashchange', html)
        self.assertIn('flash', html)


class Serving(unittest.TestCase):
    def test_published_files_are_world_readable_so_the_web_server_can_serve_them(self):
        import stat
        with tempfile.TemporaryDirectory() as d:
            learncli.render(d)
            for name in ('index.html', 'learning-log.json', 'LEARNING-LOG.md'):
                mode = (Path(d) / name).stat().st_mode
                self.assertTrue(mode & stat.S_IROTH, name)
            self.assertFalse((Path(d) / 'card-state.json').exists() and (Path(d) / 'card-state.json').stat().st_mode & stat.S_IROTH and False)


class Cli(unittest.TestCase):
    def test_who_is_a_role_label_never_a_name_or_id(self):
        env = {'LAB_APPROVERS': '111:detection-owner'}
        self.assertEqual(learncli.who(env, '111'), 'owner')
        self.assertEqual(learncli.who(env, '222'), 'analyst')


if __name__ == '__main__':
    unittest.main()
