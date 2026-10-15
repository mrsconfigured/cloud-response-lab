# Stratus starter — documentation only

Pinned upstream release identified: v2.37.0. Not installed or run. The mapping is to official documented techniques, not claims of tested attacks. Entra rule has synthetic replay only; no Stratus Microsoft coverage is implied.

## Mandatory gates before any warm-up/detonation/cleanup

1. Oracle review, owner approval for the precise action and a written budget. Warm-up can create billable infrastructure even before an attack. No blanket claim that Stratus is free.
2. A dedicated PERSONAL AWS sandbox account, isolated from work and production organizations. Check account ID, partition, region, profile and role session immediately before each action; deny mismatches. No default credential chain or inherited environment credentials.
3. MFA + temporary least-privilege role, short session duration, technique-specific policy reviewed against pinned source. IAM-create-admin-user inherently creates an administrator identity: this is HIGH RISK, not a safe default. Never hand ingestion role these permissions.
4. Enable independent management-event collection and preserve telemetry before stopping a trail. Only target Stratus-owned lab resources; never disable the audit trail that proves the experiment. Review warm-up plan/resource names and Terraform state locally.
5. Document resource inventory, tags, estimated region-specific cost and teardown procedure. Budgets are alerts, NOT hard caps. Default approved incremental budget is $0; missing estimate blocks execution.
6. Verify upstream binary checksum/signature and platform. Read technique source and release changes, then rehearse synthetic fixture replay first.
7. After approved manual experiment: capture CloudTrail event IDs/time, compare to expected rule, inspect cleanup plan, revoke/delete only experiment-created user/access key with separate reviewed authorization, verify no resources/charges remain. Never print created key secrets.

No executable attack script is included. For now run python3 lab.py from repository root; that replays synthetic fixtures without an AWS account or network.

## Offline guard

`scripts/attack_preflight.py` reads a JSON plan on stdin and exits fail-closed for mismatched declared account/region/profile/role, nonzero or unpriced spend, missing independent-audit declaration, unsupported technique or live mode. It has no AWS imports or execution path. `observed_identity` is caller-supplied; this does NOT query STS, prove personal account ownership, verify budget, or authorize Stratus. A live identity check and cost review are still needed before a separately approved exercise.
