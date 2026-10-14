# Ingestion — configuration plan, not connected

## AWS: Owner A

Use only a new personal sandbox. Never use a work or production account, or credentials belonging to another service. Prefer temporary STS/SSO roles; no root keys. Separate log-reader and attack-operator identities. First record account ID with a human-verified read-only identity check. No AWS API was called in this build.

Cheapest first step: manually export a small CloudTrail Event History management-event sample if available, sanitize locally and compare to fixtures. Event History is not a continuous S3 ingestion pipeline, and data events are different. Avoid duplicate paid trails. Continuous pipeline, after budget approval: CloudTrail management events -> private S3 log prefix -> S3 notification -> SQS -> Elastic AWS CloudTrail integration. Configure region, queue URL, short polling interval only if needed, scoped assumed-role ARN, external ID if appropriate, and CA-verified Elastic output. Use official integration UI for the installed package rather than treating this document as an importable agent policy.

Draft least-privilege read role actions (review actual package docs and resource ARNs): s3:GetObject on ONLY log prefix; s3:ListBucket if required with prefix condition; sqs:ReceiveMessage, sqs:DeleteMessage, sqs:ChangeMessageVisibility, sqs:GetQueueAttributes on ONLY queue; kms:Decrypt only if customer KMS key is used with relevant encryption-context restrictions. DeleteMessage removes queue messages, not source logs: this operational write needs explicit review. Do not give this role IAM admin, CloudTrail modification or S3 deletion. Resource trust, bucket/queue notification policies and KMS permissions are not auto-provisioned here.

Validate event.original retention, event.id, event.action, event.provider, event.outcome, cloud.account.id, aws.cloudtrail.request_parameters and timestamps against the exact integration version. Raw fixture nested fields are NOT assumed identical to ECS fields. Decode CloudTrail Records envelopes, not a single Records field string. Alert on pipeline lag/parse failures; replay dedup must use event IDs. Define retention before sending data. S3, SQS, KMS, egress and extra CloudTrail copies can cost money.

## Microsoft: Owner B + Owner A

A free Microsoft account is not automatically an Entra tenant or Microsoft 365 developer sandbox. Eligibility and licenses must be checked in a PERSONAL tenant. Do not borrow a work tenant. Developer program eligibility/trials can be restricted or expire; no promise of a free Microsoft 365 E5 subscription.

Entra audit logs and sign-in logs are distinct from Microsoft 365 Unified Audit/Purview logs and Azure Activity logs. This starter tests only Entra directory-audit role additions. It does NOT detect risky sign-ins, impossible travel or Defender incidents. Features, Graph access and retention depend on tenant licensing; sign-in Graph downloads commonly require P1/P2. Check current Microsoft licensing table and the exact endpoint before enabling; access denied is a STOP, not a reason to grant broad permissions or start a paid trial. Free portal retention may be short (commonly 7 days); verify in this tenant.

Zero-spend fallback: human exports a small permitted Entra audit JSON sample from admin center, sanitizes identifiers/IPs locally, preserves activityDisplayName/category/result/targetResources, and adds fixture cases. Reports Reader is the documented least-privileged log-viewing role; audit events exist only for licensed features. Graph directoryAudits automation requires an app registration, appropriate AuditLog.Read.All consent and endpoint/license verification. Store client credentials/certificates outside git; never pass tokens in chat, CI logs or fixtures. The Graph response value array must be unpacked.

Continuous Elastic Azure integration commonly reads Event Hub streams from diagnostic settings. Event Hubs, storage checkpoints and Azure resources may be paid even when Entra is Free. STOP until a priced plan is approved. Select only AuditLogs category, use separate event hub/consumer group and least-privilege Listen credentials, secret storage for checkpoint storage credentials, private/CA-verified transport and bounded retention. Verify dataset and fields from actual sample; never silently reuse CloudTrail mapping. Microsoft 365 audit integration is a separate licensed pipeline and is NOT configured by this starter.

## Detection promotion gate

1. Obtain sanitized real sample and record package version and raw->ECS mapping.
2. Use official Sigma tooling/backend with pinned versions and reviewed pipeline OR manually implement disabled Elastic rule, reviewed against the raw acceptance contract.
3. Test against a disposable index, prove positive and negatives on actual Elastic query engine. No native rule import is provided or claimed today.
4. Record ingestion latency, duplicate behavior, false positives and missed events; tune narrowly with reviewer sign-off.
5. Oracle review before security logic is finalized or any live rule is enabled.
