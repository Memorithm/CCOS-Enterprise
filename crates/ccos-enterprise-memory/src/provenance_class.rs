//! Versioned provenance classification for governed memory.
//!
//! Provenance class is orthogonal to trust, similarity and memory stratum.
//! It records *how* an asset arose. In particular, hypothetical/model-proposed
//! state must never become observed or verified merely because its content is
//! similar to trusted material.

use crate::{MemoryAssetDescriptor, MemoryStratum};

/// Origin class for one governed memory asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemoryProvenanceClass {
    /// Accepted real-world/tool/source evidence admitted through governance.
    Observed,
    /// Material derived from governed parent assets with lineage preserved.
    Derived,
    /// Simulation, forecast, imagined continuation or unexecuted proposal.
    Hypothetical,
}

impl MemoryProvenanceClass {
    /// Conservative class inferred from the existing memory shape.
    ///
    /// This exists for migration of assets created before explicit provenance
    /// classes. Evidence roots are observations; all derived strata remain
    /// derived. Hypothetical state is never inferred.
    pub fn inferred(descriptor: &MemoryAssetDescriptor) -> Self {
        match descriptor.stratum {
            MemoryStratum::Evidence => Self::Observed,
            MemoryStratum::Episode | MemoryStratum::Context | MemoryStratum::Pattern => {
                Self::Derived
            }
        }
    }

    /// Validate that a class cannot contradict the structural memory contract.
    pub fn validate_for(
        self,
        descriptor: &MemoryAssetDescriptor,
    ) -> Result<(), MemoryProvenanceError> {
        match (self, descriptor.stratum) {
            (Self::Observed, MemoryStratum::Evidence) => Ok(()),
            (Self::Observed, _) => Err(MemoryProvenanceError::ObservedMustBeEvidence),
            (Self::Derived, MemoryStratum::Evidence) => {
                Err(MemoryProvenanceError::DerivedCannotBeEvidence)
            }
            (Self::Hypothetical, MemoryStratum::Evidence) => {
                Err(MemoryProvenanceError::HypotheticalCannotBeEvidence)
            }
            (Self::Derived | Self::Hypothetical, _) => Ok(()),
        }
    }

    /// Authoritative recall may consider observed/derived assets under the
    /// existing trust and tenant policy. Hypothetical assets are always refused.
    pub const fn eligible_for_authoritative_context(self) -> bool {
        !matches!(self, Self::Hypothetical)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryProvenanceError {
    ObservedMustBeEvidence,
    DerivedCannotBeEvidence,
    HypotheticalCannotBeEvidence,
}

impl std::fmt::Display for MemoryProvenanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ObservedMustBeEvidence => {
                f.write_str("observed provenance requires direct Evidence stratum")
            }
            Self::DerivedCannotBeEvidence => {
                f.write_str("derived provenance cannot relabel direct Evidence")
            }
            Self::HypotheticalCannotBeEvidence => {
                f.write_str("hypothetical provenance cannot relabel direct Evidence")
            }
        }
    }
}

impl std::error::Error for MemoryProvenanceError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MemoryAssetId, MemoryEvidenceRef, MemoryLineage, MemorySpace, MemoryStratum,
    };

    fn id(value: &str) -> MemoryAssetId {
        MemoryAssetId::new(value).unwrap()
    }

    fn observed() -> MemoryAssetDescriptor {
        MemoryAssetDescriptor::new(
            id("source"),
            MemorySpace::Tenant,
            MemoryStratum::Evidence,
            MemoryLineage::root([MemoryEvidenceRef::new("source:1").unwrap()]).unwrap(),
        )
        .unwrap()
    }

    fn derived() -> MemoryAssetDescriptor {
        MemoryAssetDescriptor::new(
            id("episode"),
            MemorySpace::Tenant,
            MemoryStratum::Episode,
            MemoryLineage::derived([id("source")], []).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn migration_inference_never_invents_hypothetical_state() {
        assert_eq!(MemoryProvenanceClass::inferred(&observed()), MemoryProvenanceClass::Observed);
        assert_eq!(MemoryProvenanceClass::inferred(&derived()), MemoryProvenanceClass::Derived);
    }

    #[test]
    fn hypothetical_state_cannot_masquerade_as_direct_evidence() {
        assert_eq!(
            MemoryProvenanceClass::Hypothetical.validate_for(&observed()),
            Err(MemoryProvenanceError::HypotheticalCannotBeEvidence)
        );
    }

    #[test]
    fn authoritative_context_refuses_hypothetical_class_by_definition() {
        assert!(MemoryProvenanceClass::Observed.eligible_for_authoritative_context());
        assert!(MemoryProvenanceClass::Derived.eligible_for_authoritative_context());
        assert!(!MemoryProvenanceClass::Hypothetical.eligible_for_authoritative_context());
    }
}
