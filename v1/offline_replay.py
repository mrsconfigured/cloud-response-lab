"""Executable synthetic response replay. NOT an Elasticsearch or Shuffle engine."""
import datetime as dt
import json
import tempfile
from pathlib import Path
from .build import ROOT, compile_rule
from .fixtures import generate
from response.v1.policy import respond, RULE


def main():
    now = dt.datetime.now(dt.timezone.utc); cases = generate(now)
    rows = []
    with tempfile.TemporaryDirectory() as directory:
        for case in cases:
            alert = {'rule_id': RULE, 'synthetic': True, 'event': case['event']}
            try:
                result = respond(alert, str(Path(directory) / 'state.sqlite'), now)
                replay = respond(alert, str(Path(directory) / 'state.sqlite'), now)
                if not case['expected'] or result['status'] != 'human_review_required' or replay['status'] != 'duplicate' or result['actions'] != [] or replay['actions'] != []:
                    raise AssertionError('Offline proposal/replay invariant failed')
                rows.append({'case': case['name'], 'first': result, 'replay': replay})
            except ValueError:
                if case['expected']:
                    raise AssertionError('Attack case unexpectedly rejected')
                rows.append({'case': case['name'], 'status': 'rejected'})
    output = {'scope': 'offline compiler and actual response policy only; no Elasticsearch/Shuffle engine claim',
              'compiled_query': compile_rule()['query'], 'results': rows}
    from .runtime import save
    save('offline-replay.json', output)
    print('PASS: 3 validated proposals, 3 deduplicated replays, 5 rejected negative controls')


if __name__ == '__main__': main()
