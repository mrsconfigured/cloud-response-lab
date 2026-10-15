# cloud-response-lab

Canonical home: **mrsconfigured/cloud-response-lab**. 1xLoZec owns detections; mrsconfigured owns response. CODEOWNERS records that split; it does not enforce review, and branch protection is not enabled.

A two-person cloud detection and response lab built on real logs from personal sandbox accounts. Detections and response playbooks are code, organised in **packs** (one per log source), and a Discord **console** runs the lab: alert cards, approval-gated dry-run containment, hunts, a daily scorecard. Everything that can change an account is **dry-run only**.

**Status: working end to end for AWS CloudTrail and Entra directory audit; partial overall.** Five of eleven live rules have matched real events, the rest are fixture-tested. Sign-in rules need Entra ID P1/P2 and are fixture-only. Read [docs/PORTFOLIO.md](docs/PORTFOLIO.md) for exactly what is proven and what is not.

## Layout

| Path | What |
|---|---|
| `packs/aws/`, `packs/entra/` | One pack per log source: `detections/`, `playbooks/`, `tests/`, `attack-layer.json`, `README.md`, `pack.json` |
| `core/` | Pack-agnostic platform: console, approval gate, playbook runner, CI report, metrics, deploy and drift check |
| `library/` | Compiles every pack's Sigma rules with pySigma into disabled/enabled Elastic rules, fixtures and a Navigator layer |
| `tests/`, `lab.py`, `v1/`, `response/`, `detections/*.json` | The earlier single-rule prototype and its tests. Kept and still tested; new work goes in packs |

## Build and test without cloud accounts

    python3 -m venv .venv
    .venv/bin/python -m pip install -r requirements-v1.lock
    .venv/bin/python -m v1.build
    .venv/bin/python -m library.build         # also regenerates each pack's ATT&CK layer
    .venv/bin/python -m core.shuffle_export   # Shuffle workflows are generated from the playbook files
    .venv/bin/python scripts/validate.py
    .venv/bin/python -m unittest discover -s tests
    .venv/bin/python -m unittest discover -s packs -t .    # detection tests and playbook UAT for every pack
    .venv/bin/python -m unittest discover -s core -t .     # console, approval gate, pack structure

CI runs all of the above, plus an optimized (`-O`) pass, and fails if any generated file is out of date.

- [Portfolio write-up: what ran, what is proven, what is not](docs/PORTFOLIO.md)
- [Operating the console](docs/CONSOLE.md)
- [AWS pack](packs/aws/README.md) and [Entra pack](packs/entra/README.md)
- [Build-along: 12 weeks, source distinctions, start/stop/cost controls](docs/BUILD-GUIDE.md)
- [Terraform plan-only staging, not provisioning](infra/terraform/README.md)
- [Governance](docs/GOVERNANCE.md) and [upstream provenance](docs/UPSTREAM.md)

## Boundaries

No work account, no unapproved spend, no live containment. The response identity holds no destructive permission and the Azure app holds read-only Graph scopes, so every playbook is dry-run and says so on every result. Earlier BUILD, INTEGRATION and V1 reports are historical snapshots; the portfolio document is the current truth.
