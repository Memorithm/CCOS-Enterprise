# Human Approval Policies

`PolicyDecision::RequireApproval` is a first-class outcome, and this document
describes the durable engine that makes it a real product behavior
(`ccos-enterprise-approval`, wired into `ccos-enterprise-runtime`).

## What is implemented

- **Approval-gated by default**: `tenant.delete`, `tenant.suspend`,
  `quota.override`, `policy.disable`, `license.revoke`,
  `model.allowlist` changes, and Enterprise-side schema migrations are the
  canonical approval-gated actions. `Deployment::require_approval(tool)`
  marks any governed tool as approval-gated.
- **Canonical durable `ApprovalRecord`**: approval id, tenant/org scope,
  approver identity, target action, artifact hash (SHA-256), decision,
  recorded timestamp, optional expiry, written justification, schema
  version.
- **Security rules (all executable and tested)**:
  - unrecorded approval == denial;
  - malformed approval == denial;
  - wrong tenant == denial;
  - wrong artifact hash == denial;
  - an approval may not be replayed onto a different artifact (the approval
    id is a domain-separated hash over tenant + action + artifact +
    approver);
  - expired approval == denial (gate consults the clock);
  - revoked approval == denial (revocation is an append-only sidecar
    journal, never an edit of the original record);
  - operator-visible Unicode/zero-width validation stays fail-closed on
    approver identities and justifications;
  - persistence is crash safe (write/fsync/rename + directory fsync,
    single-writer kernel lock, corruption refused on load, duplicate
    records refused);
  - append/audit before privileged effect: every recorded approval is
    journaled as a governance change.
- **Runtime gate**: `Deployment::approval_gate(call, artifact_hash)` is the
  executable "unrecorded approval == denial" check, evaluated
  deterministically against the validated ledger. The approval ledger and
  the set of approval-gated tools are carried in the deployment snapshot, so
  a restart never silently drops either; a corrupt ledger refuses restore.

## Approver identity

Approvals are recorded under the human identity that made the decision (for
this repository: **ZEKRITI Tarek**). The gate never hard-codes a name into
low-level policy logic: any legible, bounded approver identity can be
recorded, and deployments that can prove an authorized approver through
their own identity model may use it.
