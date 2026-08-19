//! Durable, governed activation policy for advanced Q-Page variants.
//!
//! The registry itself is per-tenant state carried in the deployment
//! snapshot. This module adds the *policy* half of "activated through
//! policy" (charter §12):
//!
//! - a per-tenant policy enumerating which variants may be activated;
//! - a variant not permitted by policy is refused (`Denied`), even if the
//!   registry currently holds it — activation is checked against policy, not
//!   merely remembered;
//! - [`AdvancedQPageVariant::ExperimentalBridge`] is special: it is inert by
//!   default (absent from the default policy) and its activation requires a
//!   recorded human approval — the one variant that must never turn on by
//!   accident;
//! - policy evaluation is deterministic and read-only; the caller decides
//!   what to do with the verdict.

use serde::{Deserialize, Serialize};

use crate::AdvancedQPageVariant;

/// The variant that stays inert by default and demands approval to activate.
pub const EXPERIMENTAL_BRIDGE: AdvancedQPageVariant = AdvancedQPageVariant::ExperimentalBridge;

/// Schema tag of the persisted policy.
pub const VARIANT_POLICY_SCHEMA: u32 = 1;

/// The decision of a variant-activation gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationDecision {
    /// The variant is permitted and no approval is needed.
    Allowed,
    /// The variant is permitted but requires a recorded human approval.
    RequiresApproval,
    /// The variant is not permitted by policy.
    Denied,
}

/// Per-tenant variant policy: the set of variants permitted for activation.
///
/// The default policy permits none of the advanced variants — every
/// activation is an explicit operator decision. `ExperimentalBridge` is
/// *never* in the default policy and always requires approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariantPolicy {
    pub schema_version: u32,
    pub permitted: std::collections::BTreeSet<AdvancedQPageVariant>,
    /// Whether the operator has explicitly opted ExperimentalBridge into the
    /// *policy*; the activation gate still requires a recorded approval on
    /// every activation call.
    #[serde(default)]
    pub experimental_bridge_opted_in: bool,
}

impl Default for VariantPolicy {
    fn default() -> Self {
        Self {
            schema_version: VARIANT_POLICY_SCHEMA,
            permitted: std::collections::BTreeSet::new(),
            experimental_bridge_opted_in: false,
        }
    }
}

impl VariantPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != VARIANT_POLICY_SCHEMA {
            return Err(format!(
                "unsupported variant policy schema {}",
                self.schema_version
            ));
        }
        Ok(())
    }

    /// Permit a variant. Refused for `ExperimentalBridge`: that variant is
    /// opted in through [`VariantPolicy::opt_in_experimental_bridge`], which
    /// is the auditable, deliberate path.
    pub fn permit(&mut self, variant: AdvancedQPageVariant) -> bool {
        if variant == EXPERIMENTAL_BRIDGE {
            return false;
        }
        self.permitted.insert(variant)
    }

    /// Withdraw permission for a variant.
    pub fn revoke(&mut self, variant: AdvancedQPageVariant) -> bool {
        self.permitted.remove(&variant)
    }

    /// Explicitly opt the experimental bridge into the policy. This is the
    /// only way `ExperimentalBridge` becomes activatable at all, and it is
    /// separate from `permit` so no typo can slip it in.
    pub fn opt_in_experimental_bridge(&mut self) {
        self.experimental_bridge_opted_in = true;
    }

    /// The gate: what may be activated, and whether approval is required.
    ///
    /// `ExperimentalBridge` is denied entirely unless opted in, and always
    /// requires a recorded approval when opted in. Every other variant is
    /// allowed when permitted, denied otherwise.
    pub fn evaluate(&self, variant: AdvancedQPageVariant) -> ActivationDecision {
        if variant == EXPERIMENTAL_BRIDGE {
            if !self.experimental_bridge_opted_in {
                return ActivationDecision::Denied;
            }
            return ActivationDecision::RequiresApproval;
        }
        if self.permitted.contains(&variant) {
            ActivationDecision::Allowed
        } else {
            ActivationDecision::Denied
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_denies_everything_including_the_bridge() {
        let policy = VariantPolicy::default();
        for variant in [
            AdvancedQPageVariant::Hierarchical,
            AdvancedQPageVariant::CausalChain,
            AdvancedQPageVariant::Probabilistic,
            AdvancedQPageVariant::MultiTenantFederated,
            AdvancedQPageVariant::TemporalWindowed,
            AdvancedQPageVariant::AuthorityWeighted,
            AdvancedQPageVariant::ConsensusMediated,
            AdvancedQPageVariant::CostBounded,
            AdvancedQPageVariant::ComplianceTagged,
            AdvancedQPageVariant::ExperimentalBridge,
        ] {
            assert_eq!(
                policy.evaluate(variant),
                ActivationDecision::Denied,
                "{variant:?} must be inert by default"
            );
        }
    }

    #[test]
    fn permitted_variant_is_allowed_and_revocable() {
        let mut policy = VariantPolicy::default();
        assert!(policy.permit(AdvancedQPageVariant::Hierarchical));
        assert_eq!(
            policy.evaluate(AdvancedQPageVariant::Hierarchical),
            ActivationDecision::Allowed
        );
        assert!(policy.revoke(AdvancedQPageVariant::Hierarchical));
        assert_eq!(
            policy.evaluate(AdvancedQPageVariant::Hierarchical),
            ActivationDecision::Denied
        );
    }

    #[test]
    fn experimental_bridge_cannot_be_permitted_by_typo() {
        let mut policy = VariantPolicy::default();
        // permit() refuses the bridge: the only path is the explicit opt-in.
        assert!(!policy.permit(EXPERIMENTAL_BRIDGE));
        assert_eq!(
            policy.evaluate(EXPERIMENTAL_BRIDGE),
            ActivationDecision::Denied
        );
        policy.opt_in_experimental_bridge();
        assert_eq!(
            policy.evaluate(EXPERIMENTAL_BRIDGE),
            ActivationDecision::RequiresApproval,
            "even opted in, the bridge demands a recorded approval"
        );
    }

    #[test]
    fn unsupported_schema_is_refused() {
        let policy = VariantPolicy {
            schema_version: VARIANT_POLICY_SCHEMA + 1,
            ..Default::default()
        };
        assert!(policy.validate().is_err());
    }
}
