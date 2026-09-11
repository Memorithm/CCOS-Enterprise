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

/// A per-tenant token budget for one explicit billing epoch.
///
/// This is not a wall-clock rolling window. `spent` is monotonic inside an
/// epoch and survives process restart when the deployment snapshot does.
/// Opening a new epoch is an administrative act ([`TokenBudget::reset_epoch`])
/// so a bounce cannot silently refill a quota.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBudget {
    pub limit: u64,
    pub spent: u64,
    /// Billing epoch. Starts at 0; incrementing it is the only supported way
    /// to return `spent` to zero.
    #[serde(default)]
    pub epoch: u64,
}

impl TokenBudget {
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            spent: 0,
            epoch: 0,
        }
    }

    /// Open a new billing epoch: `spent` returns to zero and `epoch` advances.
    pub fn reset_epoch(&mut self) -> u64 {
        self.epoch = self.epoch.saturating_add(1);
        self.spent = 0;
        self.epoch
    }

    /// Deterministic gate: deny what would exceed the budget; account what is allowed.
    pub fn charge(&mut self, tokens: u64) -> PolicyDecision {
        if self.spent.saturating_add(tokens) > self.limit {
            return PolicyDecision::Deny;
        }
        // Saturating on the accounting side too: with `limit == u64::MAX` the
        // guard above cannot catch an overflowing spend, and a wrapping add
        // would silently reset the ledger (fail-open).
        self.spent = self.spent.saturating_add(tokens);
        PolicyDecision::Allow
    }

    /// Give back tokens charged for an effect that did not happen.
    ///
    /// Saturating, so a refund can never take the ledger below zero and hand a
    /// tenant capacity nobody granted — the one direction a quota must not
    /// fail. This is deliberately not a general "credit" operation: it exists
    /// for the caller that charged, discovered its effect was refused
    /// downstream, and must leave the meter as if the call had never been
    /// admitted. Refunding more than was charged is therefore a caller bug,
    /// and clamping at zero is the safe reading of it.
    pub fn refund(&mut self, tokens: u64) {
        self.spent = self.spent.saturating_sub(tokens);
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
    fn unlimited_budget_never_wraps_the_ledger() {
        // With `limit == u64::MAX` every charge is allowed; the accounting
        // must saturate rather than wrap back to a small `spent` (which would
        // silently reopen any downstream reporting based on it).
        let mut b = TokenBudget::new(u64::MAX);
        assert_eq!(b.charge(u64::MAX - 1), PolicyDecision::Allow);
        assert_eq!(b.charge(1_000), PolicyDecision::Allow);
        assert_eq!(b.spent, u64::MAX, "spent saturates instead of wrapping");
        // A finite budget still refuses exactly at the boundary.
        let mut edge = TokenBudget::new(u64::MAX - 1);
        assert_eq!(edge.charge(u64::MAX - 1), PolicyDecision::Allow);
        assert_eq!(edge.charge(1), PolicyDecision::Deny);
        assert_eq!(edge.spent, u64::MAX - 1);
    }

    #[test]
    fn allowlist_denies_unlisted() {
        let al = ModelAllowlist(["gpt-5".into(), "claude-opus".into()].into_iter().collect());
        assert_eq!(al.evaluate("gpt-5"), PolicyDecision::Allow);
        assert_eq!(al.evaluate("random-model"), PolicyDecision::Deny);
    }

    #[test]
    fn reset_epoch_zeros_spent_and_advances_the_watermark() {
        let mut b = TokenBudget::new(100);
        assert_eq!(b.charge(40), PolicyDecision::Allow);
        assert_eq!(b.spent, 40);
        assert_eq!(b.epoch, 0);
        assert_eq!(b.reset_epoch(), 1);
        assert_eq!(b.spent, 0);
        assert_eq!(b.epoch, 1);
        assert_eq!(b.charge(100), PolicyDecision::Allow);
        assert_eq!(b.charge(1), PolicyDecision::Deny);
    }

    #[test]
    fn missing_epoch_field_deserializes_as_zero() {
        let b: TokenBudget = serde_json::from_str(r#"{"limit":10,"spent":3}"#).unwrap();
        assert_eq!(b.epoch, 0);
        assert_eq!(b.spent, 3);
        assert_eq!(b.limit, 10);
    }
}
