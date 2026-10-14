# Infrastructure — current boundary and historical staging notes

Current: the separate V1 Compose stack was deployed in a bounded reviewed window and is now stopped; Elastic/direct response/dashboard export passed. Shuffle execution is still unproved. The notes below describe the earlier compose.staged.json skeleton, not current V1 runtime evidence. See ../docs/PORTFOLIO.md and terraform/README.md. No blind restart: persistent host isolation/lifecycle review is required.

Compose JSON is accepted by Docker Compose. No Terraform provider, cloud resource, SSH, paid provisioning or attack is invoked. This is a review skeleton, not a one-command production install.

- Elastic/Kibana 9.5.5 release verified from official release/docs. Tag pins are not immutable; resolve platform-specific digests and verify signatures before any pull/run. No image was pulled.
- Shuffle upstream v2.3.0 Compose uses mutable latest tags, Docker socket mounts, seccomp:unconfined and OpenSearch 3.2.0. We deliberately do NOT invent matching v2.3.0 image tags. Required digest variables block Compose expansion until reviewed. OpenSearch tag comes from that upstream manifest.
- Frontend/backend only are staged. Orborus/workers and automatic app downloads are NOT enabled. No Docker socket mount; app build/execution will not work. This is intentional, not a complete Shuffle deployment. A dedicated isolated worker host/network and native workflow round-trip are later STOP gates.
- Internal networks deny default external routing; loopback UI ports only. No public Elasticsearch/OpenSearch ports. No credentials or live webhook. Resource caps total ~6.5 GiB plus host overhead; combined services likely require >=8 GiB available RAM and storage budgeting, NOT a promise about the existing droplet. Prefer offline or one stack at a time; never resize without approval.
- Elasticsearch TLS certificate/key/CA and password file must be provisioned locally after review. SAN must include elasticsearch. Kibana needs reviewed TLS server settings, encrypted-saved-object key and scoped service-account token in secrets/kibana.yml. Do not use the elastic superuser in Kibana. No secrets are checked in.
- Shuffle secrets/shuffle.env must use the exact pinned backend configuration, verified TLS/CA to shuffle-opensearch and unique local admin credentials. No sample password is runnable. Compatibility/auth bootstrap remains untested.

## Validation versus activation

Safe syntax-only check (intentionally skips variable/file resolution and may succeed while activation stays blocked):

    docker compose -f infra/compose.staged.json config --no-interpolate --no-env-resolution

CI uses structural validation only. Parser validation does NOT certify service connectivity, TLS, licensing, memory fit or image availability. Activation requires Oracle review and owner gates in docs/STOP.md. No up/start command is part of the build.

## Deployment acceptance checklist (future)

1. Read-only inventory existing personal droplet capacity, architecture, firewall, workloads and backups; parent authorizes access separately.
2. Approve incremental storage/egress costs; record limit, retention and shutdown owner.
3. Lock all platform digests, verify supply-chain provenance, patch compatibility and licenses. Create certificates and secrets outside git.
4. Review effective Compose config with secrets redacted. Prove no 0.0.0.0 public bindings or socket exposure. Back up any existing volumes before changes.
5. After explicit activation: HTTPS readiness for Elasticsearch, Kibana and Shuffle; authenticated health checks; synthetic ingest -> disabled rule -> alert -> dry-run proposal; record time and evidence.
6. Teardown later: stop only lab project containers; inspect volumes, export needed evidence, obtain deletion approval before removing volumes. Never use global prune.
