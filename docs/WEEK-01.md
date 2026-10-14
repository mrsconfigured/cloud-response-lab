# Week 1 — build together without cloud spend

Goal: each partner can explain one raw event, one test and one reviewed change. No accounts needed.

Day 1 (together, 45 min): read README/STOP; run all four offline commands; save output in a PR description later. Discuss why passing fixtures do not prove production detection.

Day 2 (Owner A): inspect StopLogging positive vs AccessDenied negative. Make a local branch, add a benign operation fixture, run tests. Explain eventSource, userIdentity, recipientAccountId and eventTime; do not add real credentials.

Day 3 (Owner B): inspect response contract, run the response tests, add a missing-provider negative. Explain why alert text cannot authorize actions and why in-memory dedup is not durable.

Day 4 (cross-review): Owner B reviews Owner A's rule and false-positive rationale; Owner A reviews Owner B's safe response behavior. Until GitHub approval, exchange a local diff through an owner-approved channel, not automatic external sending. No self-approval claim.

Day 5 (together): read upstream and ingestion docs. Inventory personal account availability manually without logging into work systems. Record tenant eligibility, permitted log access, AWS sandbox plan, usernames and incremental budget; do not provision.

Weekend deliverable: test transcript, two review notes, one synthetic incident narrative: actor -> operation -> evidence -> alert -> human-review proposal -> no executed action. Screenshot only sanitized offline output. Keep incomplete gates visible.

Acceptance: all tests pass; each partner can intentionally mutate a selection so its positive event no longer matches, and explain why the acceptance test catches it. No service-up or real-attack claims.
