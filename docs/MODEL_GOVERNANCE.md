# Model Governance

- Explicit allowlists per tenant (`ModelAllowlist`): unlisted models denied.
- Budgets and token caps are fail-closed (`TokenBudget.charge`).
- Model identity is journaled for every call (Core event model) — switching
  is policy-visible, state-preserving (MODEL_SWITCHING_POLICY.md).
- Prohibited models are a policy fact, enforceable at the gateway and in CI
  contract tests.
