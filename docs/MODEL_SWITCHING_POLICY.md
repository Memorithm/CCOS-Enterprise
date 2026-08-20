# Model Switching Policy

- Switching a tenant's model is a policy-gated administrative action.
- The tenant's **active model is explicit state** and is distinct from the raw
  allowlist. Adding a model to the allowlist does not select it and does not make
  it executable until a governed model-switch transaction commits.
- Switching to a model that is not already allowlisted requires the exact live
  approval record supplied by the operator. The record must use the current
  approval schema, match the tenant/action/artifact exactly, be approved, not be
  revoked, and not be expired at the switch time. A different live approval may
  never make an invalid supplied approval id acceptable.
- Core guarantees state preservation across providers (journal + snapshots are
  provider-independent); Enterprise verifies it per switch: checkpoint the
  target tenant state → select the candidate model → provider transition/replay
  → equivalence check → commit.
- The checkpoint covers the complete Enterprise state owned by the target tenant,
  including model policy and active selection, budget/accounting state, Q-Page
  activations, and tenant cells. Transition failure or replay divergence restores
  that checkpoint before returning failure.
- Divergence is reported, never silently absorbed (benchmark scenario §33.8).
- Every model-switch result is governance-journaled even before the tenant has
  served its first request. The governance entry carries a digest that binds it
  to the complete model-switch record.
- Snapshots persist the active model. Restore fails closed if an explicit active
  model is not allowlisted. A legacy snapshot with no active-model field may be
  migrated only when the selection is unambiguous (zero or one allowlisted
  model); a multi-model legacy snapshot is rejected rather than guessed.
- Provider adapters remain responsible for making their external transition
  callback transaction-safe: an error returned after partially mutating an
  external provider must not leave that provider in an untracked state.
