//! # CCOS Enterprise — Advanced Q-Pages
//!
//! The ten planned advanced Q-Page variants live here, activated **through
//! policy** (charter §12) — never imposed on Core, which keeps only the
//! standard, stable primitives. Foundation slice: the variant registry with
//! per-tenant activation.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub mod policy;

/// The ten advanced Q-Page variants planned for the product line.
/// Standard primitives are in `ccos-core`; anything here is additive and
/// policy-gated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AdvancedQPageVariant {
    Hierarchical,
    CausalChain,
    Probabilistic,
    MultiTenantFederated,
    TemporalWindowed,
    AuthorityWeighted,
    ConsensusMediated,
    CostBounded,
    ComplianceTagged,
    ExperimentalBridge,
}

/// Per-tenant activation registry. A variant that is not registered is
/// inert — activation is an explicit, auditable tenant decision.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QPageRegistry {
    active: BTreeSet<AdvancedQPageVariant>,
}

impl QPageRegistry {
    pub fn activate(&mut self, v: AdvancedQPageVariant) {
        self.active.insert(v);
    }

    pub fn deactivate(&mut self, v: AdvancedQPageVariant) {
        self.active.remove(&v);
    }

    pub fn is_active(&self, v: AdvancedQPageVariant) -> bool {
        self.active.contains(&v)
    }

    /// The registry's contract with Core: standard primitives work with an
    /// empty registry; every advanced variant is opt-in.
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Every active variant, in declaration order. Activation is documented as
    /// "an explicit, auditable tenant decision", and an auditor cannot compare
    /// two states they cannot enumerate.
    pub fn active(&self) -> Vec<AdvancedQPageVariant> {
        self.active.iter().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_policy_gated() {
        let mut r = QPageRegistry::default();
        assert!(
            !r.is_active(AdvancedQPageVariant::Hierarchical),
            "inert by default"
        );
        r.activate(AdvancedQPageVariant::Hierarchical);
        assert!(r.is_active(AdvancedQPageVariant::Hierarchical));
        assert!(!r.is_active(AdvancedQPageVariant::Probabilistic));
        r.deactivate(AdvancedQPageVariant::Hierarchical);
        assert_eq!(r.active_count(), 0);
    }
}
