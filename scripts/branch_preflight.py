"""No-network branch policy preflight. Never calls GitHub or applies protection."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def check(config, codeowners):
    if config.get('status') != 'staged-not-applied' or config.get('target', {}).get('branch') != 'main':
        raise ValueError('not staged main policy')
    expected = {'pullRequestRequired': True, 'minimumApprovals': 1,
                'codeOwnerReview': True, 'dismissStaleReviews': True,
                'latestPushApproval': True, 'resolvedConversations': True,
                'forcePushes': False, 'deletions': False, 'adminBypass': False}
    if config.get('policy') != expected or config.get('requiredChecks') != ['offline-validation', 'cross-owner-review']:
        raise ValueError('missing branch safety requirement')
    if 'REPLACE_' not in config.get('target', {}).get('repository', ''):
        raise ValueError('this dry-run config must not name a live repo')
    if '@OWNER_A_GITHUB_HANDLE' not in codeowners or '@OWNER_B_GITHUB_HANDLE' not in codeowners:
        raise ValueError('expected unresolved template handles')
    return True


if __name__ == '__main__':
    config = json.loads((ROOT / '.github/branch-protection.staged.json').read_text())
    check(config, (ROOT / '.github/CODEOWNERS.template').read_text())
    print('PASS: staged policy invariant only; no GitHub API, no enforcement')
