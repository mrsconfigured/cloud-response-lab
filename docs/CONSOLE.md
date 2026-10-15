# Operating the console

The console is a set of Discord channels over real data. Nothing in it is cosmetic: cards come from real Elastic alerts, buttons start real (dry-run) Shuffle workflows, slash commands query real indices, and a value that cannot be computed shows `n/a`.

## Channels

| Category | Channel | Purpose |
|---|---|---|
| OPS | `#control` | Private line to the operator (the assistant) |
| OPS | `#metrics` | Daily scorecard |
| DETECTION | `#alerts` | One card per detection hit, with action buttons |
| DETECTION | `#detection-ci` | PRs, CI result, backtest, rule deploys, drift |
| RESPONSE | `#response` | Approval gates and audit records |
| RESPONSE | `#playbook-uat` | Playbook test matrix per PR touching playbooks |
| SHARED | `#lab-shared` | Both owners; triage threads open here; logins |
| SHARED | `#coverage` | ATT&CK map, weekly what-shipped digest |

Everything but `#lab-shared` is hidden from `@everyone`.

## Alert cards

Each alert is an embed coloured by severity (red high, amber medium, grey low) with: rule, ATT&CK technique, severity and risk, principal, operation, source, event time, lane (Detection or Identity), and a **View in Kibana** link that opens that exact event. The footer names the log source and the event id. Addresses, account ids, e-mail addresses and access-key ids are masked, and the poster refuses to send a payload that still contains one.

A second message replies to the card with its buttons. AWS alerts offer Acknowledge, Investigate, Contain. Entra alerts offer Acknowledge, Reset MFA, Revoke sessions, Disable principal. The set comes from `pack.json`, not from code.

## The approval gate

Contain-type buttons never act. A click posts an **Approval required** prompt that names exactly what would change; only a **Confirm** from an authorised approver starts the Shuffle workflow. Properties enforced in code and asserted by tests for every playbook:

1. it acts only on events that match its trigger;
2. it halts for approval before any change: the executor is never called before a confirm, an unauthorised or expired confirm is refused, a cancel runs nothing, and a second confirm is refused;
3. it does nothing on a benign or non-matching event;
4. every outcome, including refusals and no-ops, writes an audit record (`lab-response-audit`: actor, action, approver, timestamp, playbook, run id, result).

Every result is labelled **(dry-run · lab)**. The playbook files say `live.supported: false` and list the write permission each would need.

## Slash commands

`/enrich <principal> [window:1h]` (timeline, key and MFA summary, ATT&CK chain), `/hunt <lucene or technique> [window:7d]` (top matches, a computed verdict, offer to save as a detection candidate), `/lab_status` (stack health). The chat gateway already owns a built-in `/status`, so the lab command is `/lab_status`. User text reaches the shell only through stdin, never the command line.

## What runs unattended, and where

| Job | Where | Model call |
|---|---|---|
| Alert poll (1 min), CI poll (5 min), CloudTrail load (10 min), playbook UAT (30 min), rule drift check (hourly), scorecard (daily), coverage digest (weekly) | cron on the lab host | none |
| Ship the outbox to Discord (1 min), Entra audit pull (hourly) | gateway-side scheduled scripts | none |
| Button clicks and slash commands | the assistant | yes |

The lab host holds no Discord token. The Azure client secret is never stored on it: the gateway pipes it over SSH into a temp file that the loader reads and deletes first.

## Configuration

Set `LAB_HOME` to the lab host's working directory. The env file `$LAB_HOME/lab.env` holds the Elasticsearch, Kibana and Shuffle endpoints and credentials, the approver map (`id:role,id:role`), the GitHub repo, and the AWS bucket and account. Nothing host-specific is in the repository.

## Adding a log source

Copy a pack's shape: `pack.json` (field mapping for cards, Kibana data view, action buttons, enabled rules), `detections/`, `playbooks/`, `tests/` (two lines each, using `core/testkit.py`), and a README. The console, CI and metrics read `pack.json`; a test builds a card for a made-up cloud to show no console change is needed.
