# Upstream preflight / version provenance

Checked 2026-10-13 (API timestamps 2026-10-14 UTC). Existing maintained formats preferred over a custom SIEM/SOAR: Elastic integrations + Sigma-style rules + Shuffle + Stratus. Python is a small offline exact-match acceptance oracle, NOT a replacement SIEM or full Sigma engine.

- Elasticsearch latest release API: https://api.github.com/repos/elastic/elasticsearch/releases/latest -> v9.5.5, published 2026-10-06.
- Official Docker docs https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-docker-basic show 9.5.5. Kibana must match Elastic version; its registry manifest was NOT checked. Platform digests remain STOP.
- Shuffle release API https://api.github.com/repos/Shuffle/Shuffle/releases/latest -> v2.3.0, published 2026-09-28.
- Inspected https://raw.githubusercontent.com/Shuffle/Shuffle/v2.3.0/docker-compose.yml : latest Shuffle component tags, OpenSearch 3.2.0. Thus NO invented component version pins. Upstream Docker socket and unconfined seccomp are not copied. Native engine remains gated.
- Stratus https://api.github.com/repos/DataDog/stratus-red-team/releases/latest -> v2.37.0. No binary downloaded; checksum/signature verification required before installation.
- https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.cloudtrail-stop/ verified StopLogging and warm-up trail creation.
- https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.iam-create-admin-user/ verified CreateUser, AttachUserPolicy, CreateAccessKey and administrator policy attachment. This is deliberately not automated.
- Elastic AWS CloudTrail: https://www.elastic.co/docs/reference/integrations/aws/cloudtrail
- Entra access: https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-access-activity-logs
- Entra licensing: https://learn.microsoft.com/en-us/entra/fundamentals/licensing (Free included with applicable subscriptions; not a guarantee anyone can create a free tenant or access every API).
- CI pins resolved through GitHub ref API: actions/checkout v4.2.2 -> 11bd71901bbe5b1630ceea73d27597364c9af683; actions/setup-python v5.6.0 -> a26af69be951a213d495a4c3e4e4022e16d87065. Re-review action/runtime support before publication; verified pins are not a claim of newest versions.

Failed guessed URLs were not used as evidence: Microsoft concept-activity-logs-licenses and Stratus iam-create-user returned 404; the working official links above replace them.

Historical baseline only: no dependencies had been installed at that stage. The later V1 and library increments use pinned pySigma 1.5.1 and Elasticsearch backend 2.1.1 for genuine conversion; the separate runtime batch pulled pinned images and proved the V1 path. Library AST replay is not Lucene runtime proof. See docs/PORTFOLIO.md for current boundaries.

Integration follow-up: official registry manifest SHA256 and linux amd64/arm64 child manifests for all five staged services are now verified in infra/image-lock.staged.json (2026-10-14 UTC). Earlier 'not checked' statements describe the baseline, not the new lock. No signatures/release correspondence or Docker runtime proven. Pinned Elastic/Shuffle schema and license evidence: docs/upstream/provenance.json; detailed boundaries: docs/INTEGRATIONS.md.
