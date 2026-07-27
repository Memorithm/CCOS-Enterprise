# Human Approval Policies

`PolicyDecision::RequireApproval` is a first-class outcome.

Approval-gated by default: tenant deletion/suspension, quota overrides,
policy disabling, license revocation, model-allowlist changes, any
Enterprise-side schema migration.

An approval record names: approver (ZEKRITI Tarek), artifact hash, decision,
timestamp, justification. Unrecorded approval = denial.
