# Real-data validation (2026-10-14)

Technical record behind [PORTFOLIO.md](PORTFOLIO.md). It states only what was measured.

## Loaded
- AWS CloudTrail: 1,266 documents in `logs-cloud-response-lab-library-aws`, event times 2026-10-14 13:52:40Z to 19:36:34Z. 1,269 records were read; 3 were rejected for field-type conflicts in unrelated services' request parameters.
- Entra directory audit: 65 documents in `logs-cloud-response-lab-library-entra`, 13:02:47Z to 14:28:02Z. 51 successes and 14 failures. Categories: ApplicationManagement 56, DirectoryManagement 3, UserManagement 3, Policy 2, Authentication 1.
- Entra sign-in logs: not loaded. Graph returned `Authentication_RequestFromNonPremiumTenantOrB2CTenant`; the tenant has no Entra P1 or P2 licence.

## Simulation
Stratus Red Team v2.37.0, IAM-only techniques: iam-create-admin-user at 18:41Z and 19:32Z, iam-backdoor-user at 18:41Z. After cleanup an IAM re-list showed only the lab user with one access key, and Stratus reported COLD for each technique. The first backdoor-user teardown was denied `iam:DeleteLoginProfile`, so its leftover IAM user was removed directly and the teardown rerun.

## Detections on real events
| Rule | Real hits |
|---|---|
| IAM AdministratorAccess policy attached | 3 |
| IAM access key created | 4 |
| Console login without MFA | 0 |
| CloudTrail logging stopped | 0 |
| CloudTrail trail deleted | 0 |
| Entra application credential added | 0 |
| Entra conditional access policy deleted | 0 |
| Entra directory role member added | 0 |

## Scheduled alerts
Two rules were enabled with a 1 minute interval. With a 10 minute lookback they produced no alerts, because the events were older than the window when the rules were enabled. The lookback was set to 30 minutes. A new simulation ran at 19:32:04Z, the events were indexed at 19:38:36Z, and the scheduler created two alerts on its own at 19:38:49.920Z and 19:38:58.929Z. See [evidence/auto-alerts-redacted-20261014.json](evidence/auto-alerts-redacted-20261014.json). Events from the earlier runs did not alert because they were already outside the lookback window.

## Triage of the early matches
The AttachUserPolicy at 13:58:54Z and CreateAccessKey at 13:59:54Z predate the simulation. They are the lab's own bootstrap: a console session without MFA on an administrator role created the lab IAM user, attached AdministratorAccess, and created its access key. Finding: the lab identity is over-privileged.

## Evidence
- [real-hits-redacted-20261014.json](evidence/real-hits-redacted-20261014.json): three matched events from the first simulation, identifiers redacted.
- [auto-alerts-redacted-20261014.json](evidence/auto-alerts-redacted-20261014.json): scheduler-generated alerts and rule run states.
- Screenshots in [evidence/screenshots](evidence/screenshots), captured with a read-only account and checked for identifying data.

## Not proven
Entra sign-ins; 6 of 8 rules on real data; continuous ingestion; automated response; HTTPS; branch protection; a genuine second-owner review.
