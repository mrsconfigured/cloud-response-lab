# Experimental integration adapters

Nothing here is promoted, installed, authenticated, deployed, or enabled. Oracle review remains pending browser authentication. Local validation is not vendor runtime parity.

## GitHub (Owner A/Owner B cross-owner review)

Read-only usage after account authorization, from a trusted checkout OUTSIDE PR-controlled code:

    python3 -m scripts.github_review_adapter OWNER/REPO 123 --owner_a REAL_HANDLE --owner_b REAL_HANDLE --allow-read-network

GITHUB_TOKEN is read at request time only, never on import, persisted, or printed. Use a personal-repo scoped GitHub App token with pull requests read permission. No actual token was read during this increment: tests inject a synthetic value. Requests pin api.github.com and API version 2022-11-28; redirects, malformed/cross-origin pagination, incomplete/error responses, cycles and >100 pages fail closed. Both start and end heads are fetched. Every review page is fetched via Link rel=next. No retry on 429; operator must honor Retry-After before a later run.

The adapter itself only calls GET. scripts/github_status_publisher.py is a separate library, not connected to CI or a CLI. It requires allow_publish=True AND an exact reviewed_repository, acquires its own fresh snapshot and rechecks head immediately before POST. It writes the status to that SHA, never an arbitrary caller-supplied success verdict. A head race after recheck cannot make a status apply to a newer SHA, but a review dismissal after the snapshot can invalidate approval on the same SHA. Therefore this is NOT merge enforcement: trusted App identity, webhook-driven invalidation on submitted/dismissed reviews, pending-before-recompute, required status app binding, stale-review dismissal, no bypass and disposable-repo race tests are still required. Do not wire a PR-controlled workflow with a write token. Conservative core treats latest COMMENTED/PENDING reviews as non-approval too (false negatives intentional).

Sources: https://docs.github.com/en/rest/pulls/reviews?apiVersion=2022-11-28#list-reviews-for-a-pull-request ; https://docs.github.com/en/rest/pulls/pulls#get-a-pull-request ; https://docs.github.com/en/rest/commits/statuses#create-a-commit-status

## Elastic native query-rule payloads

Regenerate offline: python3 -m scripts.elastic_export

Three detections/elastic/<rule-id>.json files are request bodies for POST /api/detection_engine/rules, type=query, language=kuery, enabled=false, actions=[]. rules.ndjson is the corresponding detection-rule import stream (not Kibana saved-object NDJSON). No IDs/credentials or system-generated saved-object fields are invented. Index template is a separate Elasticsearch PUT /_index_template/personal-lab-normalized request body. Nothing submits these payloads.

The selected fields follow official Kibana v9.5.5 QueryRuleCreateProps and BaseRequiredFields. docs/upstream records exact source files/hashes. The stdlib offline schema checker is an intentionally strict projection of emitted fields, not a complete OpenAPI validator or Kibana server acceptance test. It rejects extra fields/unsafe activation; no official JS/Zod runtime was installed. KQL is supported by Elastic; our tiny fixture evaluator is NOT its parser. Runtime parity is explicitly UNVERIFIED.

### Raw-event normalization contract

Use scripts.elastic_export.normalize on individual raw CloudTrail events (unwrap Records[] first) or Microsoft Graph directoryAudit objects (unwrap value[] first). This is an explicit custom personal-lab normalization path, NOT a claim that Elastic's managed AWS/Azure integrations emit these lab.* fields.

- CloudTrail eventTime / Graph activityDateTime -> @timestamp (date mapping).
- Constant explicit provider aws/entra -> lab.provider (keyword).
- eventSource -> lab.event_source; eventName -> lab.event_name.
- requestParameters.policyArn -> lab.policy_arn.
- category -> lab.category; activityDisplayName -> lab.activity; result -> lab.result.
- Non-null errorCode -> lab.error_code. Missing/null is omitted; empty string is retained and therefore exists (the event is NOT treated as successful).
- All lab fields are exact case-sensitive keyword values; no normalizer, tokenization, wildcard expansion, string coercion or array flattening. Non-string non-null selected values fail closed.
- Unknown fields (including actor PII) are dropped. Ingestion must validate timestamps and reject/quarantine missing/invalid @timestamp before indexing; fixture missing-field cases remain negative. Provider/scope authenticity requires a trusted ingestion source; the normalizer is not an account boundary.

The 13 synthetic cases pass normalized-query subset evaluation. Before activation, ingest timestamp-shifted fixtures into a disposable matching Elasticsearch/Kibana version; call _validate/query or KQL conversion on actual server, execute all queries, check missing/null/empty/case handling, and confirm rule scheduler alerts. The index pattern excludes work accounts by naming only; real tenant/account routing and authorizations remain an engineering gate.

## Shuffle native layout, honest compatibility boundary

response/shuffle/*.json now use actual upstream Workflow/Action/Branch/WorkflowAppActionParameter JSON fields. Version chain: Shuffle v2.3.0 backend go.mod -> shuffle-shared v1.3.22; local type checks parse the pinned Go source. Official Shuffle Tools 1.2.0 repeat_back_to_me action accepts call and returns it without provider actions. Two static nodes and one acyclic branch show Owner B's human-review instructions; there are no triggers, credentials, variable interpolation or external connectors.

This is a native-format STAGED skeleton, not a fabricated execution schema. Actual import/native runtime compatibility is NOT established: app_id is intentionally empty because installation-local application identity is unknown, is_valid=false, and no Shuffle server/worker is running. These flags are documentation/validation state, not a security boundary against manual execution. The static action itself is harmless even if manually run.

The original response/playbooks files remain offline policy/test specifications; they are NOT Shuffle imports. Their validation/dedup/scope/time logic has NOT been ported into these native nodes. Do not equate static review notices with an implemented response workflow. Remaining engineering: install/bind reviewed app in disposable engine, import/export round trip, port tested fail-closed validation + persistent atomic dedup, inject only redacted summaries, verify no connectors/side effects, and prove malicious/stale/out-of-scope alert rejection. Need safe worker isolation without copying upstream docker.sock/unconfined defaults; no runtime is started here.

## Immutable image staging

infra/image-lock.staged.json records official registry index and amd64/arm64 child manifest digests, source URLs, byte counts and config descriptors. scripts/resolve_public_images.py uses only anonymous registry read tokens held in RAM (no user account credentials); SHA256 is computed on exact response bytes and matched against registry Docker-Content-Digest and index descriptors. No image layers/config blobs, docker pulls or containers are used. These are content-integrity observations over HTTPS, NOT signature/provenance/vulnerability attestations.

All five staged services resolved. Shuffle upstream compose uses latest; the lock captures its immutable content at the check timestamp, but does NOT prove those component images correspond to v2.3.0. Compose remains unchanged and blocked; installing a digest is not deployment consent. Remaining checks: signed provenance/release correspondence, platform/config compatibility, component worker/orborus app image locking, TLS/auth wiring, memory/cost inventory and disposable service tests. Explicit --allow-public-network is needed for any re-resolution; never auto-update lock during CI.
