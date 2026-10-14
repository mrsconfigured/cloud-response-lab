# Real-data validation (2026-10-14)

This note records what ran against **real** AWS CloudTrail from a personal sandbox account. It does not claim more than the numbers below.

## What was loaded
- Source: CloudTrail trail delivered to S3 in a personal sandbox AWS account, pulled with boto3 and bulk-loaded to a private Elasticsearch 9.5.5 (TLS, auth, single node, not exposed publicly).
- Window: 2026-10-14 13:52Z to 18:52Z. 1,238 documents indexed. 3 documents were rejected for field-type conflicts in unrelated services' request parameters and are not counted.
- Ingest is idempotent (document id = CloudTrail eventID), so reruns update rather than duplicate.

## Attack simulation
Stratus Red Team v2.37.0, IAM-only, no-cost techniques:
- aws.persistence.iam-create-admin-user
- aws.persistence.iam-backdoor-user
Cleanup: the first technique cleaned up fully. The second's Terraform destroy was denied iam:DeleteLoginProfile for the sandbox user, so the created IAM user was deleted directly and Stratus cleanup was then rerun (state COLD).

## Detections that matched real events
| Rule | ATT&CK | Real hits | Example eventID |
|---|---|---|---|
| IAM AdministratorAccess policy attached | T1098.003 | 2 | 383a748d-b8d8-4844-8602-ce4fca0868f9 |
| IAM access key created | T1098.001 | 3 | 31e5b6af-013a-4fec-bb7a-6fe19f0c2658 |

Three hits come from the Stratus run at 18:41Z. One AttachUserPolicy (13:58Z) and one CreateAccessKey (13:59Z) are older events whose cause was not established.
Rules with zero hits on this window: console login without MFA, CloudTrail logging stopped, CloudTrail trail deleted. Zero hits means no matching events in this window, not proof that the rule works; those three rules still have only synthetic-fixture coverage.
Redacted raw evidence: reports/golive-real-hits-redacted-20261014.json (identifiers redacted).

## Not proven
- Entra ingestion: the app credentials were not readable by the lab operator, so no Entra events were loaded and the three Entra rules have no real-data evidence.
- Shuffle executed the staged workflows in dry-run only. No automated response was taken against the account.
- Branch protection and a genuine second-owner review are still open on this PR.
- Access to Kibana and Shuffle is plain HTTP inside the tailnet. HTTPS needs Tailscale Serve to be enabled on the tailnet.

## MITRE ATT&CK map
- T1098.003 Account Manipulation: Additional Cloud Roles (admin policy attach)
- T1098.001 Account Manipulation: Additional Cloud Credentials (access key create)
- T1562.008 Impair Defenses: Disable or Modify Cloud Logs (stop/delete trail; no real hits yet)
- T1078.004 Valid Accounts: Cloud Accounts (console login without MFA; no real hits yet)
- T1556.009 Modify Authentication Process: Conditional Access Policies (Entra; no real data yet)
