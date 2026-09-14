//! Categorical eligibility metadata for a served memory context.
//!
//! Similarity can order candidates; it cannot establish eligibility. Attestation
//! rechecks asset identity, exact memory space, active lineage and trust metadata.
//! This metadata is not an authorization token, a payload-integrity proof, or a
//! guarantee that a generated answer is true. Tenant and snapshot binding still
//! belong to the surrounding governed request.

use crate::{
    GovernedMemoryContextAssembly, MemoryAssetId, MemoryAssetState, MemoryLineageGraph,
    MemoryTrustMetadata, MemoryValidationState,
};

/// Categorical reason a chunk survived admission. Never a similarity score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryAdmissionReason {
    ActiveAndEligible,
}

/// One attested context item: identity, eligibility and evidence pointers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryContextAttestation {
    pub asset_id: MemoryAssetId,
    pub asset_state: MemoryAssetState,
    pub trust_state: MemoryValidationState,
    pub reason: MemoryAdmissionReason,
    pub parents: Vec<MemoryAssetId>,
    pub evidence: Vec<crate::MemoryEvidenceRef>,
}

/// Attach eligibility metadata to every assembled context chunk.
///
/// Missing descriptors, a space mismatch, inactive lineage or missing/ineligible
/// trust metadata fail closed. The checks are repeated here because the public
/// context assembler also accepts observations not produced by the recall gate.
/// No partial attestation vector is returned when a later chunk is rejected.
pub fn attest_governed_context(
    assembly: &GovernedMemoryContextAssembly,
    graph: &MemoryLineageGraph,
    trust: &std::collections::BTreeMap<MemoryAssetId, MemoryTrustMetadata>,
) -> Result<Vec<MemoryContextAttestation>, crate::MemoryError> {
    let mut out = Vec::with_capacity(assembly.len());
    for chunk in assembly.chunks() {
        let Some(descriptor) = graph.descriptor(&chunk.asset_id) else {
            return Err(crate::MemoryError::InvalidMemoryAssetId);
        };
        if descriptor.space != chunk.space {
            return Err(crate::MemoryError::InvalidConfiguration(
                "context memory space does not match its governed descriptor",
            ));
        }
        let Some(asset_state) = graph.state(&chunk.asset_id) else {
            return Err(crate::MemoryError::InvalidMemoryAssetId);
        };
        if asset_state != MemoryAssetState::Active {
            return Err(crate::MemoryError::InsertRejected);
        }
        let Some(meta) = trust.get(&chunk.asset_id) else {
            return Err(crate::MemoryError::InvalidConfiguration(
                "trust metadata required for attestation",
            ));
        };
        if !meta.recall_eligible() {
            return Err(crate::MemoryError::InsertRejected);
        }
        out.push(MemoryContextAttestation {
            asset_id: chunk.asset_id.clone(),
            asset_state,
            trust_state: meta.state(),
            reason: MemoryAdmissionReason::ActiveAndEligible,
            parents: descriptor.lineage.parents().cloned().collect(),
            evidence: descriptor.lineage.evidence().cloned().collect(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        assemble_governed_bootstrap_context, GovernedMemoryObservation, MemoryAssetDescriptor,
        MemoryContextBudget, MemoryError, MemoryEvidenceRef, MemoryLineage, MemoryLoadoutBinding,
        MemoryLoadoutPlan, MemorySpace, MemoryStratum, MemoryUsageMode,
    };
    use std::collections::BTreeMap;

    fn id(value: &str) -> MemoryAssetId {
        MemoryAssetId::new(value).unwrap()
    }

    fn graph(space: MemorySpace) -> MemoryLineageGraph {
        let mut graph = MemoryLineageGraph::new();
        graph
            .register(
                MemoryAssetDescriptor::new(
                    id("root-1"),
                    space,
                    MemoryStratum::Evidence,
                    MemoryLineage::root([MemoryEvidenceRef::new("audit:root-1").unwrap()])
                        .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        graph
    }

    fn assembly(space: MemorySpace) -> GovernedMemoryContextAssembly {
        let plan = MemoryLoadoutPlan::new([MemoryLoadoutBinding::new(
            space.clone(),
            1,
            MemoryUsageMode::BootstrapAndOnDemand,
        )
        .unwrap()])
        .unwrap();
        assemble_governed_bootstrap_context(
            &plan,
            [GovernedMemoryObservation {
                asset_id: id("root-1"),
                space,
                payload: b"fact".to_vec(),
                similarity: 0.99,
            }],
            MemoryContextBudget::new(8, 1024).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn attestation_carries_evidence_not_similarity() {
        let graph = graph(MemorySpace::Tenant);
        let trust = BTreeMap::from([(id("root-1"), MemoryTrustMetadata::unverified(1))]);
        let assembly = assembly(MemorySpace::Tenant);
        let attested = attest_governed_context(&assembly, &graph, &trust).unwrap();
        assert_eq!(attested.len(), 1);
        assert_eq!(attested[0].reason, MemoryAdmissionReason::ActiveAndEligible);
        assert_eq!(attested[0].evidence[0].as_str(), "audit:root-1");
        assert_eq!(attested[0].trust_state, MemoryValidationState::Unverified);
    }

    #[test]
    fn matching_id_cannot_attest_another_memory_space() {
        let graph = graph(MemorySpace::project("private").unwrap());
        let trust = BTreeMap::from([(id("root-1"), MemoryTrustMetadata::unverified(1))]);
        let assembly = assembly(MemorySpace::Tenant);
        assert_eq!(
            attest_governed_context(&assembly, &graph, &trust),
            Err(MemoryError::InvalidConfiguration(
                "context memory space does not match its governed descriptor"
            ))
        );
    }

    #[test]
    fn unknown_asset_cannot_receive_attestation() {
        let trust = BTreeMap::from([(id("root-1"), MemoryTrustMetadata::unverified(1))]);
        assert_eq!(
            attest_governed_context(
                &assembly(MemorySpace::Tenant),
                &MemoryLineageGraph::new(),
                &trust,
            ),
            Err(MemoryError::InvalidMemoryAssetId)
        );
    }

    #[test]
    fn invalidated_asset_cannot_receive_attestation() {
        let mut graph = graph(MemorySpace::Tenant);
        graph.invalidate(&id("root-1")).unwrap();
        let trust = BTreeMap::from([(id("root-1"), MemoryTrustMetadata::unverified(1))]);
        assert_eq!(
            attest_governed_context(&assembly(MemorySpace::Tenant), &graph, &trust),
            Err(MemoryError::InsertRejected)
        );
    }

    #[test]
    fn missing_trust_cannot_receive_attestation() {
        assert_eq!(
            attest_governed_context(
                &assembly(MemorySpace::Tenant),
                &graph(MemorySpace::Tenant),
                &BTreeMap::new(),
            ),
            Err(MemoryError::InvalidConfiguration(
                "trust metadata required for attestation"
            ))
        );
    }

    #[test]
    fn quarantine_cannot_receive_attestation() {
        let trust = BTreeMap::from([(
            id("root-1"),
            MemoryTrustMetadata::new(
                MemoryValidationState::Quarantined,
                1,
                1,
                0,
                Vec::<String>::new(),
            )
            .unwrap(),
        )]);
        assert_eq!(
            attest_governed_context(
                &assembly(MemorySpace::Tenant),
                &graph(MemorySpace::Tenant),
                &trust,
            ),
            Err(MemoryError::InsertRejected)
        );
    }
}
