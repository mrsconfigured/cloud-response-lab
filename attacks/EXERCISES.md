# Atomic Red Team + Stratus: read-only exercise staging

Neither tool is installed or executed by this increment. No warm-up, dependency installer, cloud mutation or cleanup command is invoked. Synthetic replay is the only runnable exercise here: run python -m library.build in the pinned virtual environment, then the unit suite.

## Verified upstream references

Atomic Red Team T1098 YAML was fetched through the public GitHub API on 2026-10-14: https://api.github.com/repos/redcanaryco/atomic-red-team/contents/atomics/T1098/T1098.yaml . Git blob SHA 4393186a189027d7716f58bde13d1fbc059d0cfb; 52,744 decoded bytes. Only metadata was inspected; no upstream command was executed or copied into a runner.

- Azure AD - adding user to Azure AD role: test GUID 0e65ae27-5385-46b4-98ac-607a8ee82261, platform azure-ad. Synthetic analogue: entra-role-member, expected successful Add member to role plus failed/wrong-category/wrong-service/missing-field negatives.
- Azure AD - adding service principal to Azure AD role: GUID 92c40b3f-c406-4d1f-8d2b-c039bf5009e4. Same broad role-add signal; actor/target array semantics need real-log confirmation. This is NOT proof the exact Atomic test produces our fixture.
- AWS - Create a group and add a user to that group: GUID 8822c3b0-d9f9-4daf-a043-49f110a31122. **Not covered** by AdministratorAccess attachment: AddUserToGroup is a different event. Do not count it as a covered attack.
- Azure subscription-role tests are **not** Entra directory-role tests; no ARM ActivityLog support is claimed.

The guessed Atomic T1562.008 YAML endpoint returned HTTP404; no nonexistent Atomic test was invented. For CloudTrail stop, use the already sourced Stratus documentation instead.

Existing attacks/mapping.json records Stratus v2.37.0 cloudtrail-stop and iam-create-admin-user. Their synthetic analogues are aws-cloudtrail-stop and aws-admin-attachment. Stratus warm-up can create billable resources; credential creation and logging interruption require explicit personal sandbox scope, budget, human authorization and reviewed teardown. No auto-install/run script is supplied.

## Tomorrow's acceptance record

Before any real exercise record tool version/checksum, exact supported test ID, personal account/tenant identity, least privilege, expected event names, cost ceiling, stop owner and teardown evidence. Run one authorized technique at a time; collect sanitized raw logs; compare exact engine hit IDs with the expected set and prove negatives. A fixture pass alone never proves tool execution or telemetry arrival.
