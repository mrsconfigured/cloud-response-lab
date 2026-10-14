# Entra pack (directory audit)

Owner lane: **response** for the playbooks, **detection** for the rules. Log source: Microsoft Graph `auditLogs/directoryAudits`, loaded into `logs-cloud-response-lab-library-entra`.

| Piece | Where |
|---|---|
| Sigma rules on live data | `detections/*.yml` (6) |
| Sign-in rules, fixture only | `detections/signin/*.yml` (3) |
| Playbooks (response as code) | `playbooks/*.json` (3) with generated `*.shuffle.json` |
| Tests | `tests/` |
| ATT&CK layer | `attack-layer.json` |

## Live rules (directory audit)
Service principal credential added, app role assigned to a service principal, application consent or delegated permission granted, directory role member added, conditional access policy deleted, new user created.

## Fixture-only rules: requires Entra ID P1 or P2
MFA prompt not answered (MFA fatigue proxy), impossible travel risk event, account locked after repeated failures. Microsoft Graph returns sign-in logs and Identity Protection risk data only to tenants with a P1 or P2 license (`Authentication_RequestFromNonPremiumTenantOrB2CTenant`). No license is bought, no trial is started, so these three are tested against fixtures only and never deployed. Note that the status codes are strings in the fixtures; the real Graph API returns numbers, so field mapping needs a check once real data exists.

## Playbooks (dry-run only)
`disable-service-principal`, `revoke-sessions`, `reset-mfa`. The Azure app holds read-only Graph scopes (AuditLog.Read.All, Directory.Read.All), so none of them can run live. Each lists the write permission it would need.
