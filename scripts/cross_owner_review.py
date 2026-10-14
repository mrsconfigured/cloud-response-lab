"""Pure offline review-decision core. Only a trusted base-branch integration may attest API input."""
import json
import sys


def check(data):
    """Fail closed on incomplete GitHub review snapshots; return (bool, reason)."""
    try:
        users = data['partners']
        owner_a, owner_b = users['owner_a'], users['owner_b']
        if any(type(h) is not str or not h or h.startswith('@') for h in (owner_a, owner_b)):
            raise ValueError('unresolved handles')
        if owner_a.casefold() == owner_b.casefold():
            raise ValueError('partners must be distinct')
        author = data['author']
        head = data['head_start']
        if type(author) is not str or not author or type(head) is not str or len(head) != 40 or any(c not in '0123456789abcdef' for c in head):
            raise ValueError('invalid author or SHA')
        if head != data['head_end'] or data['draft'] is not False:
            raise ValueError('head changed or draft')
        pages = data['review_pages']
        if type(pages) is not list or not pages or any(type(p) is not dict or p.get('complete') is not True or type(p.get('items')) is not list for p in pages):
            raise ValueError('incomplete review pages')
        reviews = [r for p in pages for r in p['items']]
        ids = [r['id'] for r in reviews]
        if any(type(i) is not int or i <= 0 for i in ids) or len(ids) != len(set(ids)):
            raise ValueError('invalid or duplicate review IDs')
        latest = {}
        for review in sorted(reviews, key=lambda r: r['id']):
            user = review['user']
            login = user['login']
            if type(login) is not str or not login or user['type'] != 'User' or review['state'] not in ('APPROVED', 'CHANGES_REQUESTED', 'COMMENTED', 'DISMISSED', 'PENDING'):
                raise ValueError('unsupported reviewer or state')
            if review['state'] == 'APPROVED' and (review.get('commit_id') != head or login.casefold() == author.casefold()):
                # Stale/self approvals never become eligible, even when they are latest.
                latest[login.casefold()] = False
            else:
                latest[login.casefold()] = review['state'] == 'APPROVED'
        required = [owner_b] if author.casefold() == owner_a.casefold() else [owner_a] if author.casefold() == owner_b.casefold() else [owner_a, owner_b]
        if any(not latest.get(handle.casefold(), False) for handle in required):
            return False, 'missing current-head approval from required cross-owner reviewer(s)'
        return True, 'current-head cross-owner approval present in complete snapshot'
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        return False, 'invalid/incomplete snapshot: ' + str(exc)


if __name__ == '__main__':
    # JSON must be acquired from authenticated, paginated API by a trusted integration.
    # This command NEVER fetches reviews or writes a GitHub status.
    try:
        data = json.load(sys.stdin)
    except (ValueError, UnicodeError) as exc:
        print('FAIL: malformed JSON: ' + str(exc))
        sys.exit(1)
    ok, why = check(data)
    print(('PASS: ' if ok else 'FAIL: ') + why)
    sys.exit(0 if ok else 1)
