//! Provenance gate for already-admitted governed recall.
//!
//! Tenant, lineage and trust admission remains owned by governed recall. This
//! second orthogonal gate prevents hypothetical state from entering an
//! authoritative context and can optionally restrict a consumer to observations.

use crate::{
    AdmittedGovernedRecall, MemoryAssetId, MemoryProvenanceClass, MemoryProvenanceRegistry,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceRecallPolicy {
    ObservedOnly,
    ObservedOrDerived,
}

impl ProvenanceRecallPolicy {
    const fn allows(self, class: MemoryProvenanceClass) -> bool {
        match self {
            Self::ObservedOnly => matches!(class, MemoryProvenanceClass::Observed),
            Self::ObservedOrDerived => matches!(
                class,
                MemoryProvenanceClass::Observed | MemoryProvenanceClass::Derived
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceRecallError {
    MissingClassification(MemoryAssetId),
    Refused {
        asset: MemoryAssetId,
        class: MemoryProvenanceClass,
    },
}

impl std::fmt::Display for ProvenanceRecallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingClassification(id) => write!(
                f,
                "admitted memory asset {} has no provenance classification",
                id.as_str()
            ),
            Self::Refused { asset, class } => write!(
                f,
                "admitted memory asset {} has refused provenance class {class:?}",
                asset.as_str()
            ),
        }
    }
}
impl std::error::Error for ProvenanceRecallError {}

/// Validate provenance for every item in an opaque admitted recall.
///
/// This is an authority-separation gate, not a trust upgrade: successful
/// provenance validation never changes a trust label or observation class.
///
/// This function never repairs, relabels or drops individual items. One missing
/// or forbidden classification rejects the complete batch so a caller cannot
/// silently weaken provenance semantics by accepting a partial context.
pub fn validate_admitted_provenance(
    registry: &MemoryProvenanceRegistry,
    admitted: &AdmittedGovernedRecall,
    policy: ProvenanceRecallPolicy,
) -> Result<(), ProvenanceRecallError> {
    for observation in admitted.observations() {
        let class = registry.class(&observation.asset_id).ok_or_else(|| {
            ProvenanceRecallError::MissingClassification(observation.asset_id.clone())
        })?;
        if !class.eligible_for_authoritative_context() || !policy.allows(class) {
            return Err(ProvenanceRecallError::Refused {
                asset: observation.asset_id.clone(),
                class,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        admit_governed_recall, GovernedMemoryObservation, GovernedMemoryProjection,
        GovernedRecallGate, GovernedRecallTrustPolicy, MemoryAssetDescriptor, MemoryEvidenceRef,
        MemoryLineage, MemoryLineageGraph, MemoryLoadoutBinding, MemoryLoadoutPlan, MemorySpace,
        MemoryStratum, MemoryTrustMetadata, MemoryUsageMode, MemoryValidationState,
    };
    use ccos_enterprise_tenancy::TenantId;
    use std::collections::BTreeMap;

    fn id(value: &str) -> MemoryAssetId {
        MemoryAssetId::new(value).unwrap()
    }

    fn fixture() -> (GovernedMemoryProjection, MemoryProvenanceRegistry) {
        let mut graph = MemoryLineageGraph::new();
        graph
            .register(
                MemoryAssetDescriptor::new(
                    id("source"),
                    MemorySpace::Tenant,
                    MemoryStratum::Evidence,
                    MemoryLineage::root([MemoryEvidenceRef::new("source:1").unwrap()]).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        graph
            .register(
                MemoryAssetDescriptor::new(
                    id("proposal"),
                    MemorySpace::Tenant,
                    MemoryStratum::Episode,
                    MemoryLineage::derived([id("source")], []).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        let registry = MemoryProvenanceRegistry::new(
            &graph,
            [
                (id("source"), MemoryProvenanceClass::Observed),
                (id("proposal"), MemoryProvenanceClass::Hypothetical),
            ],
        )
        .unwrap();
        let trust = BTreeMap::from([
            (
                id("source"),
                MemoryTrustMetadata::new(
                    MemoryValidationState::Verified,
                    1,
                    1,
                    0,
                    ["v:source".to_string()],
                )
                .unwrap(),
            ),
            (
                id("proposal"),
                MemoryTrustMetadata::new(
                    MemoryValidationState::Verified,
                    1,
                    1,
                    0,
                    ["v:proposal".to_string()],
                )
                .unwrap(),
            ),
        ]);
        let projection = GovernedMemoryProjection::new(
            TenantId::new("acme").unwrap(),
            graph,
            trust,
            MemoryLoadoutPlan::new([MemoryLoadoutBinding::new(
                MemorySpace::Tenant,
                1,
                MemoryUsageMode::BootstrapAndOnDemand,
            )
            .unwrap()])
            .unwrap(),
        )
        .unwrap();
        (projection, registry)
    }

    fn admit(projection: &GovernedMemoryProjection, asset: &str) -> AdmittedGovernedRecall {
        let tenant = TenantId::new("acme").unwrap();
        admit_governed_recall(
            GovernedRecallGate {
                expected_tenant: &tenant,
                projection,
                policy: GovernedRecallTrustPolicy::VerifiedOnly,
            },
            [GovernedMemoryObservation {
                asset_id: id(asset),
                space: MemorySpace::Tenant,
                payload: b"payload".to_vec(),
                similarity: 0.9,
            }],
        )
        .unwrap()
    }

    #[test]
    fn hypothetical_asset_is_refused_even_when_trust_is_verified() {
        let (projection, registry) = fixture();
        let admitted = admit(&projection, "proposal");
        assert_eq!(
            validate_admitted_provenance(
                &registry,
                &admitted,
                ProvenanceRecallPolicy::ObservedOrDerived
            ),
            Err(ProvenanceRecallError::Refused {
                asset: id("proposal"),
                class: MemoryProvenanceClass::Hypothetical,
            })
        );
    }

    #[test]
    fn observed_only_policy_accepts_direct_observation() {
        let (projection, registry) = fixture();
        let admitted = admit(&projection, "source");
        assert_eq!(
            validate_admitted_provenance(
                &registry,
                &admitted,
                ProvenanceRecallPolicy::ObservedOnly
            ),
            Ok(())
        );
    }

    #[test]
    fn policy_can_refuse_derived_without_relabeling_it() {
        let (projection, _) = fixture();
        let registry = MemoryProvenanceRegistry::new(
            &projection.graph,
            [
                (id("source"), MemoryProvenanceClass::Observed),
                (id("proposal"), MemoryProvenanceClass::Derived),
            ],
        )
        .unwrap();
        let admitted = admit(&projection, "proposal");
        assert!(matches!(
            validate_admitted_provenance(
                &registry,
                &admitted,
                ProvenanceRecallPolicy::ObservedOnly
            ),
            Err(ProvenanceRecallError::Refused {
                class: MemoryProvenanceClass::Derived,
                ..
            })
        ));
    }
}
