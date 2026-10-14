# Building a cloud-response lab without cloud accounts

**Partial project, not an end-to-end Shuffle success story.** This draft is for review before publication. Synthetic telemetry lets us test detection contracts without accessing any work account or launching cloud attacks.

## What actually ran

A separate bounded runtime acceptance on 2026-10-14 used the genuine pySigma AdministratorAccess attachment query against Elasticsearch. Eight fresh synthetic CloudTrail cases produced exactly three attack hits and excluded five negatives. The actual scheduled Elastic detection emitted three alert documents with matching source IDs. A directly called authenticated TLS response API produced three human-review proposals and three duplicate replays; every result had empty actions. Foreign/stale input was rejected with HTTP400 and unauthenticated input with HTTP401. Kibana dashboard import succeeded and an authenticated export was captured (2,282 bytes).

Evidence filenames in the privately retained runtime packet: elastic-hits.json, scheduled-alerts.json, rule-runtime-status.json, response-api.json, boundary-checks.json, dashboard-import.json, kibana-runtime-export.ndjson and live-assert-fixed.log. These names identify prior evidence; this code-only increment did not rerun or independently recapture it. Runtime source culminated in bfc8804 (with 3f85d84 and 9c5d9bf fixes). The stack was stopped before its temporary network guard was removed. No service is claimed currently running.

**No authenticated browser screenshot exists in this packet.** The checked-in V1 dashboard NDJSON is the reproducible source, not a screenshot or the runtime export. Do not substitute an illustration. Review and sanitize the private export before adding it to a public PR.

## What the library adds

Eight genuine Sigma YAML rules (five AWS CloudTrail, three Entra audit), not eight live-proven detections. Seven YAML rules are new; the existing AdministratorAccess rule is reused unchanged. The three older root JSON rules are historical prototypes and are not added to this count. The compiler produces disabled Lucene rules with provider-separated indices, a deterministic matrix and [Navigator layer](../library/generated/navigator.json). Ten positive and 71 negative generated cases exercise the bounded pySigma AST test oracle; independent fixed operation contracts prevent silent selection drift. Every rule has an individual unit test and offline dry-run response contract.

ATT&CK hypotheses: T1562.008 (trail stop/delete), T1098.001 (key/credential addition), T1098.003 (admin policy/role membership), T1078.004 (successful console sign-in without MFA), T1556.009 (conditional access deletion). These are behavioral mappings, not adversary attribution or a coverage percentage. Authorized changes can fire. Missing logs and alternate operation names can miss.

## Important engineering lessons

- Compiler success is not query-engine parity. The prior V1 live proof does not transfer to new rules or indices.
- Source-only CloudTrail identifiers in scheduled alerts must be checked in _source; querying an unindexed field gave a false failure. The bounded verifier refuses more than 100 results rather than silently truncating.
- Docker internal networks do not necessarily block the host gateway. Runtime isolation required an independently reviewed host guard; no blind restart is safe.
- Direct API response is not Shuffle orchestration. A workflow export is not execution evidence.
- Terraform output manifests are not provisioning. The provider-free staging module has no resource/apply action and still lacks a local Terraform formatter/validator run.

## Remaining proof and collaboration

Shuffle execution/worker isolation remains unproved. GitHub push, actual hosted CI, PR links and branch-protection enforcement remain outside this local batch; prior publication was blocked on appropriate workflow permission and human review. Tailnet enrollment/Serve remain parent-owned and unresolved by this batch; no address or login link is published here. AWS and Azure personal sandbox accounts and least-privilege ingestion remain required for real-log proof. Discord and old-session cleanup are not touched.

Follow the [12-week guide and lifecycle gates](BUILD-GUIDE.md). Next: independent review of the new library, then query-engine parity for each rule in a separately authorized bounded runtime. No provider credential, private host address, private path or secret belongs in portfolio evidence.
