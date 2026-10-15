# Owner B owns response

playbooks/*.json are **conceptual orchestration contracts**, NOT Shuffle native exports and NOT import-compatible files. Their schema is local and deliberately explicit. The Python planner validates, deduplicates, emits a redacted human-review proposal and executes nothing. No external tickets/messages, account lockout, key deletion, session revocation or attack is implemented.

Run all safety tests with python3 -m unittest discover -s tests -v. Each plan is tested for success, duplicates, out-of-sandbox scope, rule/provider mismatch, old/future/malformed alerts and unsafe mutations. Dedup is caller-owned memory only; restart persistence, concurrency, delivery retries and webhook authenticity are NOT solved. Do not expose this library as a webhook service.

## Future Shuffle native workflow (manual promotion)

After Oracle and deployment approval, Owner B builds in the pinned Shuffle UI: disabled webhook trigger -> authenticated alert validation -> allowlisted sandbox scope -> persistent atomic dedup -> redacted summary -> local human approval task -> end. Keep actions read-only/dry-run. Use actual installed app IDs, action names, parameter schemas and versions from that instance; never invent them. Export the native workflow, remove secrets/URLs/instance identifiers, import into a second disposable instance and run the same acceptance cases. Only then place export under response/shuffle-native/ and label import compatibility with exact Shuffle/app versions and evidence. Export/import round-trip, apps, licensing and authenticated webhook remain STOP items.

Owner A reviews response PRs; Owner B reviews detections. Human review is required even if CI passes. Prompt/event text is untrusted data, never executable code or policy.

Native-layout staging now lives in shuffle/*.json; local types derive from Shuffle's pinned Go model and official Shuffle Tools action definition. App binding/import/runtime compatibility and validation/dedup node implementation remain unverified. These static no-op review graphs do NOT execute the conceptual policy in playbooks/*.json. See ../docs/INTEGRATIONS.md.
