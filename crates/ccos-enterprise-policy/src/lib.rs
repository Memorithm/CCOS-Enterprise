//! # CCOS Enterprise — Policy
//!
//! Governance policies per tenant and per agent: quotas, budgets, model and
//! tool allowlists, retention (docs/MODEL_GOVERNANCE.md,
//! docs/COGNITIVE_RETENTION_POLICY.md). Foundation slice: the policy decision
//! type and a deterministic budget gate.

use serde::{Deserialize, Serialize};

/// Every policy evaluation yields an explicit, loggable decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    Allow,
    Deny,
    /// Allowed only with a recorded human approval (HUMAN_APPROVAL_POLICIES.md).
    RequireApproval,
}

/// A per-tenant token budget over a rolling window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBudget {
    pub limit: u64,
    pub spent: u64,
}

impl TokenBudget {
    pub fn new(limit: u64) -> Self {
        Self { limit, spent: 0 }
    }

    /// Deterministic gate: deny what would exceed the budget; account what is allowed.
    pub fn charge(&mut self, tokens: u64) -> PolicyDecision {
        if self.spent.saturating_add(tokens) > self.limit {
            return PolicyDecision::Deny;
        }
        self.spent += tokens;
        PolicyDecision::Allow
    }
}

/// Model governance: an explicit allowlist — anything not listed is denied.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelAllowlist(pub std::collections::BTreeSet<String>);

impl ModelAllowlist {
    pub fn evaluate(&self, model: &str) -> PolicyDecision {
        if self.0.contains(model) {
            PolicyDecision::Allow
        } else {
            PolicyDecision::Deny
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_is_fail_closed() {
        let mut b = TokenBudget::new(100);
        assert_eq!(b.charge(60), PolicyDecision::Allow);
        assert_eq!(b.charge(50), PolicyDecision::Deny, "60+50 > 100");
        assert_eq!(b.spent, 60, "denied charge is not accounted");
    }

    #[test]
    fn allowlist_denies_unlisted() {
        let al = ModelAllowlist(["gpt-5".into(), "claude-opus".into()].into_iter().collect());
        assert_eq!(al.evaluate("gpt-5"), PolicyDecision::Allow);
        assert_eq!(al.evaluate("random-model"), PolicyDecision::Deny);
    }
}
