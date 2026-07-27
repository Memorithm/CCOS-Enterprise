# Model Switching Policy

- Switching a tenant's model is a policy-gated administrative action.
- Core guarantees state preservation across providers (journal + snapshots are
  provider-independent); Enterprise verifies it per switch: pre-switch snapshot
  → switch → replay equivalence check.
- Divergence is reported, never silently absorbed (benchmark scenario §33.8).
