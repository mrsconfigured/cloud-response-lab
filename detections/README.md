# Owner A owns detections — experimental, staged

Three raw-event Sigma-style rules in JSON (valid YAML subset). Only exact scalar selection + null errorCode filter are supported by lab.py. This small harness is NOT a full Sigma compiler and has not been checked with pySigma. It refuses unsupported condition syntax rather than pretending to evaluate it. No Elastic native import or enabled rule is claimed.

- aws-cloudtrail-stop: successful StopLogging, T1562.008. Misses DeleteTrail and other logging impairment; authorized maintenance also matches.
- aws-admin-policy: successful AttachUserPolicy of AWS AdministratorAccess, T1098. Does not correlate creation, catch role/group attachments, inline policy escalation or equivalent custom policies. Authorized administrators can match.
- entra-role-member: successful Add member to role audit activity, T1098. Intentionally broad over all roles; not specifically Global Administrator. Does not cover every PIM/eligible role or localized/variant operation. Confirm actual tenant activity names before promotion.

Every rule has at least one positive, benign negative, failed-operation negative and missing-fields negative; admin policy also has ReadOnlyAccess negative. Metrics are 13/13 synthetic acceptance cases, NOT population precision/recall or attack coverage. Synthetic IDs, example.invalid and RFC5737 IPs are intentional. tests/fixtures wrap raw events in case metadata; unwrap Records/value separately for live exports. See docs/INGESTION.md for ECS mapping gates.

Review by Owner B plus literal Oracle review before finalization. Status stays experimental until actual query-engine parity and representative samples are proven.
