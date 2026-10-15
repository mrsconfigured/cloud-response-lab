import json
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from core import learning as L
from core import packs as pk
from core.console import learncli
from core.console import outbox as ob
from core.console.store import MemoryStore

URL = 'http://100.64.9.9:8090'


def entry(cmd, topic='git', **kw):
    return L.make_entry(cmd, topic, kw.get('gloss', 'a short gloss here'), kw.get('does', 'What it does in plain words.'), kw.get('when', 'When you would use it.'), kw.get('by', 'analyst'), kw.get('goal'))


class Source(unittest.TestCase):
    def test_every_entry_has_the_required_fields_and_ids_are_stable(self):
        e = entry('git status')
        for k in ('id', 'command', 'topic', 'gloss', 'does', 'when', 'added_by', 'added_at'):
            self.assertTrue(e.get(k), k)
        self.assertEqual(e['id'], L.entry_id('git', 'git status'))

    def test_secrets_are_refused_not_stored(self):
        for bad in ('curl -H "Authorization: Bearer ' + 'a' * 30 + '" x', 'export GITHUB_TOKEN=' + 'a' * 30, 'tailscale up --authkey ts' + 'key-auth-abcdef123456', 'aws configure set aws_secret_access_key=abcdefghij123456'):
            with self.assertRaises(L.RefusedEntry, msg=bad):
                entry(bad)
        with self.assertRaises(L.RefusedEntry):
            entry('git status', does='my password: abcdefgh123')

    def test_addresses_emails_and_account_ids_are_masked(self):
        e = entry('ssh admin@example.com 203.0.113.77', does='Connects to 203.0.113.77 for account 123456789012.')
        text = json.dumps(e)
        for raw in ('203.0.113.77', 'admin@example.com', '123456789012'):
            self.assertNotIn(raw, text)

    def test_add_appends_dedupes_and_rerenders_markdown(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertTrue(L.add(entry('git status'), d)[1])
            self.assertFalse(L.add(entry('git status'), d)[1])
            self.assertEqual(len(L.load(d)['entries']), 1)
            self.assertIn('### `git status`', (Path(d) / 'LEARNING-LOG.md').read_text())

    def test_a_new_topic_starts_a_new_section_and_known_topics_slot_in_order(self):
        with tempfile.TemporaryDirectory() as d:
            for c, t in (('git status', 'git'), ('docker ps', 'docker'), ('pytest -q', 'pytest'), ('curl https://x', 'networking')):
                L.add(entry(c, t), d)
            self.assertEqual([t for t, _ in L.topics(L.load(d))], ['git', 'pytest', 'docker', 'networking'])

    def test_topic_guess_for_the_common_tools(self):
        for cmd, topic in (('git push', 'git'), ('python3 -m venv .venv', 'python'), ('python3 -m pytest -q', 'pytest'), ('tailscale status', 'tailscale'), ('docker ps', 'docker')):
            self.assertEqual(L.topic_for(cmd), topic)


class Schema(unittest.TestCase):
    def test_the_served_json_has_exactly_the_page_schema(self):
        with tempfile.TemporaryDirectory() as d:
            L.add(entry('git status', goal='learning'), d)
            raw = json.loads((Path(d) / 'learning-log.json').read_text())
            self.assertEqual(sorted(raw), ['entries', 'updated'])
            self.assertTrue(raw['updated'].endswith('Z'))
            self.assertEqual(sorted(raw['entries'][0]), sorted(['command', 'topic', 'does', 'when', 'added_by', 'added_at']), 'no id, gloss or goal in the served file')
            self.assertEqual(raw['entries'][0]['topic'], raw['entries'][0]['topic'].lower())
            meta = json.loads((Path(d) / 'learning-meta.json').read_text())
            self.assertEqual(list(meta.values())[0]['goal'], 'learning')
            self.assertTrue(list(meta.values())[0]['gloss'])

    def test_extra_data_survives_a_round_trip_through_the_sidecar(self):
        with tempfile.TemporaryDirectory() as d:
            L.add(entry('git status', gloss='see what changed', goal='why'), d)
            e = L.load(d)['entries'][0]
            self.assertEqual((e['gloss'], e['goal'], e['id']), ('see what changed', 'why', L.entry_id('git', 'git status')))

    def test_a_legacy_file_with_what_is_converted_and_updated_is_stable_when_nothing_changed(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'learning-log.json').write_text(json.dumps({'version': 1, 'entries': [{'id': 'eabcdef', 'command': 'git pull', 'topic': 'git', 'gloss': 'get changes', 'what': 'Downloads.', 'when': 'Daily.', 'added_by': 'owner', 'added_at': '2026-10-15T00:00:00Z'}]}))
            L.save(L.load(d), d)
            raw = json.loads((Path(d) / 'learning-log.json').read_text())
            self.assertEqual(raw['entries'][0]['does'], 'Downloads.')
            self.assertNotIn('what', raw['entries'][0])
            first = raw['updated']
            L.save(L.load(d), d)
            self.assertEqual(json.loads((Path(d) / 'learning-log.json').read_text())['updated'], first)

    def test_the_repo_seed_is_valid_page_schema_and_covers_the_basics(self):
        doc = L.load(Path(pk.ROOT) / 'docs')
        raw = json.loads((Path(pk.ROOT) / 'docs' / 'learning-log.json').read_text())
        self.assertEqual(sorted(raw['entries'][0]), sorted(L.PUBLIC_KEYS))
        self.assertTrue({'git', 'python', 'pytest', 'tailscale', 'pull request'} <= {e['topic'] for e in doc['entries']})
        for e in doc['entries']:
            L.make_entry(e['command'], e['topic'], e['gloss'], e['does'], e['when'], e['added_by'], now=e['added_at'])


class Search(unittest.TestCase):
    def doc(self):
        return {'entries': [entry('python3 -m venv .venv', 'python', gloss='make a private toolbox'), entry('source .venv/bin/activate', 'python', gloss='switch the toolbox on'),
                            entry('git status', 'git', gloss='see what changed'), entry('git switch -c x', 'git', gloss='new branch')]}

    def test_find_matches_and_ranks(self):
        d = self.doc()
        self.assertEqual({e['command'] for e in L.find(d, 'venv')}, {'python3 -m venv .venv', 'source .venv/bin/activate'})
        self.assertEqual(len(L.find(d, 'toolbox')), 2)
        self.assertEqual(L.find(d, 'nothing-like-this'), [])
        self.assertEqual([e['command'] for e in L.find(d, 'git switch')], ['git switch -c x'])

    def test_results_highlight_the_term_point_at_the_page_and_have_no_details_menu(self):
        r = L.render_find(self.doc(), 'venv', URL)
        self.assertIn('**`venv`**', r['text'])
        self.assertIn(URL, r['text'])
        self.assertNotIn('Pick one below', r['text'])
        self.assertTrue(L.render_find(self.doc(), 'zzz')['text'].startswith('Nothing in the learning log'))


class Launcher(unittest.TestCase):
    def doc(self, n):
        return {'entries': [dict(entry('command number %d --flag' % i, 't%d' % (i % 4), gloss='one two three four five six seven'), added_at='2026-10-15T00:%02d:%02dZ' % (i // 60, i % 60)) for i in range(n)]}

    def test_it_is_a_real_embed_with_the_requested_shape(self):
        e, b = L.launcher(self.doc(5), URL)
        self.assertEqual(e['color'], 0xA98BF0)
        self.assertEqual(e['title'], '\U0001F4D2 Learning Log')
        self.assertEqual(e['url'], URL, 'the title links to the web page and the address is not masked')
        self.assertIn('Your command cheat-sheet for the lab. Everything you learn, explained in plain English.', e['description'])
        self.assertIn('**5 entries \u00b7 4 topics**', e['description'])
        names = [f['name'] for f in e['fields']]
        self.assertEqual(names, ['Open the Learning Log', 'Add a command', 'Find something', 'Recently added'])
        self.assertEqual(e['fields'][0]['value'], URL)
        self.assertEqual(e['fields'][1]['value'], 'Tap Add below, or type /log <command>')
        self.assertEqual(e['fields'][2]['value'], 'Search right on the page, or /find <term>')
        self.assertNotIn('footer', e)

    def test_recently_added_lists_the_latest_three_with_topic_command_and_a_short_gloss(self):
        e, _ = L.launcher(self.doc(10), URL)
        lines = e['fields'][3]['value'].split('\n')
        self.assertEqual(len(lines), 3)
        self.assertIn('`command number 9 --flag`', lines[0])
        self.assertIn('`command number 7 --flag`', lines[2])
        for ln in lines:
            self.assertLessEqual(len(ln.rsplit('\u2014 ', 1)[1].rstrip('\u2026').split()), 5, 'the gloss is at most five words')
            self.assertTrue(ln.endswith('\u2026'), 'a cut gloss is marked')
            self.assertTrue(ln.startswith('**T'), 'the topic leads')

    def test_a_gloss_of_five_words_or_fewer_is_shown_whole(self):
        d = {'entries': [entry('git status', gloss='see what changed')]}
        e, _ = L.launcher(d, URL)
        self.assertTrue(e['fields'][3]['value'].endswith('— see what changed'))

    def test_one_button_that_opens_the_add_form_and_nothing_else(self):
        _, b = L.launcher(self.doc(1), URL)
        self.assertEqual(b['blocks'], [])
        self.assertEqual(b['modal']['triggerLabel'], '\u2795 Add to log')
        self.assertEqual(len(b['modal']['fields']), 2)
        self.assertNotIn('select', json.dumps(b), 'no details menu')

    def test_it_stays_inside_discord_limits_however_big_the_log_gets(self):
        for n in (0, 1, 3, 400):
            e, _ = L.launcher(self.doc(n), URL)
            self.assertLessEqual(len(json.dumps(e, ensure_ascii=False)), 4000)
            for f in e['fields']:
                self.assertLessEqual(len(f['value']), 1024)
        e0, _ = L.launcher(self.doc(0), URL)
        self.assertIn('0 entries', e0['description'])

    def test_masking_still_applies_but_not_to_the_lab_address(self):
        d = {'entries': [entry('ssh 203.0.113.9', 'ssh', gloss='connect to host')]}
        e, _ = L.launcher(d, URL)
        self.assertNotIn('203.0.113.9', json.dumps(e))
        self.assertIn(URL, json.dumps(e))


class Refresh(unittest.TestCase):
    def ctx(self):
        return SimpleNamespace(env={'LAB_LEARNING_URL': URL}, store=MemoryStore())

    def test_the_first_refresh_queues_one_launcher_and_more_adds_before_it_posts_do_not_duplicate_it(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = self.ctx()
            L.add(entry('git status'), d)
            q1 = learncli.refresh_card(ctx, d)
            self.assertEqual(len(q1), 1)
            L.add(entry('git pull'), d)
            self.assertEqual(learncli.refresh_card(ctx, d), [])
            batch = ob.next_batch(ctx.store, 10)
            self.assertEqual(len(batch), 1)
            self.assertEqual(batch[0]['payload']['kind'], 'launcher')
            self.assertIn('2 entries', batch[0]['payload']['embed']['description'], 'the queued launcher has the newest count')

    def test_after_posting_only_a_changed_embed_queues_an_edit_and_the_newest_edit_wins(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = self.ctx()
            L.add(entry('git status'), d)
            key = learncli.refresh_card(ctx, d)[0]
            h = ctx.store.get('outbox', key)['payload']['hash']
            ob.ack(ctx.store, key, ['m1', 'm2'])
            learncli.card_set('launcher', 'm1', h, d)
            self.assertEqual(learncli.refresh_card(ctx, d), [], 'nothing changed, nothing queued')
            L.add(entry('git pull'), d)
            e1 = learncli.refresh_card(ctx, d)
            L.add(entry('git push'), d)
            e2 = learncli.refresh_card(ctx, d)
            self.assertEqual((len(e1), len(e2)), (1, 1))
            self.assertEqual(ctx.store.get('outbox', e1[0])['status'], 'superseded')
            self.assertEqual(ob.next_batch(ctx.store, 10), [], 'the poster never tries an edit; it cannot')
            r = learncli.pending_cards(ctx, d, claim=True)
            self.assertEqual([i['key'] for i in r['edits']], e2)
            self.assertEqual(r['edits'][0]['message_id'], 'm1')
            self.assertEqual(learncli.pending_cards(ctx, d, claim=True)['claimed'], 0)
            learncli.card_done(ctx, key=e2[0], part='launcher', message_id='m1', h=r['edits'][0]['hash'], d=d)
            self.assertEqual(learncli.pending_cards(ctx, d)['edits'], [])

    def test_the_retired_three_message_card_is_forgotten_and_its_queued_edits_dropped(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = self.ctx()
            L.add(entry('git status'), d)
            learncli.card_set('entries', 'old1', 'x', d)
            learncli.card_set('band-add', 'old2', 'x', d)
            ob.enqueue(ctx.store, 'learning-card:entries:9', {'kind': 'card', 'part': 'entries', 'message_id': 'old1', 'components': {}, 'hash': 'x'})
            learncli.refresh_card(ctx, d)
            self.assertEqual(ctx.store.get('outbox', 'learning-card:entries:9')['status'], 'superseded')
            st = json.loads((Path(d) / 'card-state.json').read_text())
            self.assertEqual(st['legacy_messages'], ['old1', 'old2'])
            self.assertNotIn('entries', st['parts'])


class Page(unittest.TestCase):
    def test_the_page_is_the_provided_one_and_reads_the_page_schema(self):
        html = (Path(pk.ROOT) / 'docs' / 'learning-web' / 'index.html').read_text()
        self.assertIn('fetch("learning-log.json"', html)
        for key in ('e.does', 'e.when', 'e.added_by', 'e.added_at', 'data.entries'):
            self.assertIn(key, html)
        self.assertIn('#a98bf0', html)


class Serving(unittest.TestCase):
    def test_published_files_are_world_readable_so_the_web_server_can_serve_them(self):
        with tempfile.TemporaryDirectory() as d:
            learncli.render(d)
            for name in learncli.PAGE_FILES:
                self.assertTrue((Path(d) / name).stat().st_mode & stat.S_IROTH, name)

    def test_render_copies_the_page_verbatim(self):
        with tempfile.TemporaryDirectory() as d:
            learncli.render(d)
            self.assertEqual((Path(d) / 'index.html').read_bytes(), (Path(pk.ROOT) / 'docs' / 'learning-web' / 'index.html').read_bytes())


class Cli(unittest.TestCase):
    def test_who_is_a_role_label_never_a_name_or_id(self):
        env = {'LAB_APPROVERS': '111:detection-owner'}
        self.assertEqual(learncli.who(env, '111'), 'owner')
        self.assertEqual(learncli.who(env, '222'), 'analyst')


if __name__ == '__main__':
    unittest.main()
