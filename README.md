# cloud-response-lab

Canonical home: **mrsconfigured/cloud-response-lab**. 1xLoZec owns detections; Owner B (mrsconfigured) owns response. This local increment is not published and does not prove GitHub branch protection.

**Partially built and proven.** A bounded live synthetic V1 run proved three Elastic hits, five negative exclusions, three scheduled alerts, direct dry-run response and Kibana dashboard import/export. The stack is now stopped. Shuffle execution, authenticated screenshot, tailnet access, hosted CI and reviewed publication are not claimed. [Evidence narrative and limitations](docs/PORTFOLIO.md).

## Build without cloud accounts

    python3 -m venv .venv
    .venv/bin/python -m pip install -r requirements-v1.lock
    .venv/bin/python -m v1.build
    .venv/bin/python -m library.build
    .venv/bin/python scripts/validate.py
    .venv/bin/python -m unittest discover -s tests -v
    .venv/bin/python -O -m unittest discover -s tests -v

First dependency installation requires network; replay is offline. Eight genuine Sigma rules (5 AWS + 3 Entra), ten positive / 71 negative AST cases, provider-separated disabled exports, eight response contracts and five ATT&CK technique hypotheses. New library rules are **not live-query-proven**. Root JSON detections are three historical prototypes, not additional Sigma rules.

- [Build-along: 12 weeks, source distinctions, start/stop/cost controls](docs/BUILD-GUIDE.md)
- [Exact generated detection matrix](library/generated/matrix.json)
- [ATT&CK Navigator layer](library/generated/navigator.json)
- [Terraform plan-only staging, not full provisioning](infra/terraform/README.md)
- [Atomic + Stratus synthetic exercise mappings](attacks/EXERCISES.md)
- [Governance](docs/GOVERNANCE.md) and [upstream provenance](docs/UPSTREAM.md)

## Boundaries

No work account, new spend, real attack or cloud provisioning. Existing V1 code/tests and evidence are retained. New response helpers return proposals only, never cloud actions. A Docker internal network alone does not isolate the host gateway: **do not restart the stopped stack until persistent isolation and stop-before-rollback lifecycle are independently reviewed.**

All earlier BUILD/INTEGRATION/V1 reports are historical snapshots; current component truth is the portfolio narrative above. Security drafts still require independent review before publication or activation; CODEOWNERS alone does not enforce review. AWS/Azure account work remains on STOP.
