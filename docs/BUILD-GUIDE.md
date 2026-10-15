# Zero-account build and bounded existing-host lifecycle

## Reproduce offline deliverables

Python 3.10+; CI uses 3.12. Install pinned dependencies only in a virtual environment. First installation requires package access; subsequent build/replay is offline. This does not install Elastic, Terraform, Atomic or Stratus.

    python3 -m venv .venv
    .venv/bin/python -m pip install -r requirements-v1.lock
    .venv/bin/python -m v1.build
    .venv/bin/python -m library.build
    .venv/bin/python scripts/validate.py
    .venv/bin/python -m unittest discover -s tests -v
    .venv/bin/python -O -m unittest discover -s tests -v
    .venv/bin/python -m v1.offline_replay
    git diff --check

Library generation writes deterministic fixtures, disabled Elastic rules, response contracts, index mapping, per-rule counts and a Navigator layer under library/generated/. No cloud client or live ingestion is invoked. Upload navigator.json into a locally reviewed ATT&CK Navigator instance to visualize five technique hypotheses; this run did not prove Navigator UI import. CI compiles/replays on every PR; hosted CI execution and branch enforcement still require publication.

## Field contract and limits

- AWS: raw CloudTrail eventSource/eventName/errorCode, nested requestParameters, additionalEventData and responseElements. Absent/null errorCode matches Sigma absence semantics; present empty error does not. Management activity and console login success differ. The console rule uses ConsoleLogin=Success and MFAUsed=No, not an Entra sign-in schema. Federated sign-in behavior and alternate partitions need their own tuning.
- Entra: Microsoft Graph directoryAudit-style activityDisplayName/category/loggedByService/result, activityDateTime, initiatedBy, targetResources. tenantId is a lab ingestion envelope field, **not guaranteed by the directoryAudit resource itself**; a real adapter must bind it from verified tenant context. Azure Monitor AuditLogs uses a different casing/envelope and must be normalized; Entra SignInLogs is not supported by these rules.
- Index separation is essential: Sigma logsource metadata is not automatically injected as a query filter. New exports explicitly select an AWS-only or Entra-only synthetic index. A mixed or untrusted index is outside the contract.
- All signals can be authorized administration. Role additions are not restricted to privileged roles; access-key creation alone is not proof of persistence. Target arrays are retained for human investigation, not correlated by the detection. Exact English operation names require validation against real sanitized samples. No anomaly baseline or ATT&CK coverage percentage is claimed.
- AST replay tests Sigma parsing/boolean semantics and independently frozen operation expectations. They do not execute the compiled Lucene string. Preserve the older V1 live proof separately; new library index/rules have never run in Elasticsearch.
- Response library is offline, caller-owned in-memory dedup and redacted proposals, actions always empty. No persistence/concurrency/authentication claim for that helper; do not expose it as a service. The separately proven V1 response API remains unchanged.

## Existing-host start gate (NOT permission to start)

The previous bounded stack was stopped before its temporary isolation rule was removed. **Do not simply run Compose up.** Docker internal networking alone permitted host-gateway SSH until the reviewed guard was installed.

1. Parent independently reviews exact host isolation and lifecycle changes. Inspect current containers, bridge/IPs, firewall and SSH before edits; preserve existing rules/workloads. No public ports, host socket, privileged worker or work account.
2. Confirm at least 4 GiB free RAM and 10 GiB free disk after estimated services; keep pinned images, original secrets and volumes. Never regenerate existing credentials casually.
3. Arrange a tested automatic stop within 25 minutes and isolation rollback later (prior proof used 30 minutes), with stop-before-rollback ordering. Confirm separate SSH access survives. No persistent scheduler is installed by this repository increment.
4. Probe host gateway, public IP and metadata from each execution plane. No default route is necessary but insufficient. Abort on reachable host services or unexpected egress. Verify CA/hostname TLS, authentication and zero published ports.
5. Only after review, use the existing V1 prepare/setup/bootstrap/ingest/assert/capture workflow. Pin the project name to the inspected existing lab project to avoid duplicate volumes. Prove new queries per provider before enabling them. Shuffle requires its own isolated execution proof; direct response is not Shuffle.
6. On success, failure, resource pressure or timeout: stop only the inspected lab Compose project, preserve named volumes and secrets, verify stopped, then remove only the exact temporary isolation rule. Never down -v, global prune, broad firewall replacement or destructive Terraform provisioners.
7. Export sanitized evidence before shutdown; record service status, free RAM/disk, listeners, timers and rule removal. No unexplained background process may remain.

## Cost controls

No new VPS, managed Elastic, AWS/Azure resources, paid provider or attack is provisioned. Image pulls, existing VPS and retained volumes may still have provider billing/egress; stopping containers does not stop those charges. No resizing, new subscription or cloud warm-up is authorized. Retain minimal synthetic data; any deletion needs separately scoped approval. AWS budgets are alerts, not hard caps; account-specific budget review precedes tomorrow's real work.

## Twelve-week practical build-along

Each week ends with a reviewable artifact; account blockers do not prevent the offline alternative.

1. Run baseline and library tests; explain one positive and one negative event to your partner. Deliver test log and source SHA.
2. Submit a small PR to the existing canonical repo; configure and negatively test current-head opposite-owner review. Deliver actual PR/enforcement evidence, not CODEOWNERS alone.
3. Trace CloudTrail envelopes into normalized fields; keep synthetic fallback. Deliver an ingestion mapping and sanitized sample only after personal sandbox approval.
4. Distinguish Graph directoryAudit, Azure Monitor AuditLogs and SignInLogs. Deliver tenant-bound adapter tests; no credentials in fixture files.
5. Review pinned Compose, capacity and isolation. Deliver authenticated TLS health plus deny probes in a bounded window, then stop.
6. Replay each library rule in the real query engine with exact hit IDs and negatives; document authorized-operation false positives. Deliver query parity matrix.
7. Challenge scope/time/provider/dedup/redaction contracts. Deliver response proposal tests with empty actions and human-review record.
8. Isolate Shuffle's execution plane; import/export workflow and execute a fresh synthetic alert. Deliver run ID and result; direct API proof is insufficient.
9. Read Atomic/Stratus mappings without executing. With separate sandbox/budget permission, select one supported technique and documented teardown; otherwise deliver only synthetic replay.
10. Run CI on the actual PR, review dependency/provenance drift and permission restrictions. Deliver hosted checks plus branch-protection negative test.
11. Produce redacted authenticated dashboard screenshot, export and Navigator map. Deliver evidence manifest; do not label a mock as a screenshot.
12. Review public write-up against evidence, independent security review and partner approval. Deliver approved release/portfolio link only after publication authorization.
