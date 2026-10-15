"""Publishing is disabled pending protected issuer and policy integration.
Offline review decisions are not merge authorization.
"""
from scripts.github_review_adapter import AdapterError


def publish(adapter, number, *, allow_publish=False, reviewed_repository=None):
    raise AdapterError(
        "publishing unavailable: protected policy, issuer and review invalidation unimplemented"
    )
