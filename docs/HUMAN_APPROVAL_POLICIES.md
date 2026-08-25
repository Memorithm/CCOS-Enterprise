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
- **Where the gate is enforced — read before integrating**: `admit` does
  **not** evaluate the tool-approval gate. This is deliberate and pinned by
  the conformance suite (`tests/human_approval.rs`): an approval authorizes
  one *artifact* (a SHA-256 of what the call would change), and only the
  code that knows the artifact can name it. Enforcement therefore lives at
  each governed mutation site — retention-policy saves, model-allowlist
  switches, Q-Page variant activation — which calls
  `approval_gate(call, &artifact_hash)` *before* its durable effect and
  after every other admission gate has passed. A generic hash over raw
  arguments inside `admit` would either freeze request bytes into the
  approval (breaking retries with identical intent) or weaken the record to
  a per-tool wildcard. If you mark a new tool with `require_approval`, you
  must also invoke `approval_gate` at its effect site: marking alone
  configures policy, it does not enforce it.

## Approver identity

Approvals are recorded under the human identity that made the decision (for
this repository: **ZEKRITI Tarek**). The gate never hard-codes a name into
low-level policy logic: any legible, bounded approver identity can be
recorded, and deployments that can prove an authorized approver through
their own identity model may use it.
