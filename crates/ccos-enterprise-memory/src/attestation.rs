//! Why a memory chunk is allowed in a served context.
//!
//! RAG answers "what is nearest in embedding space". CCOS answers "which
//! governed assets may be used, and why". Similarity can order candidates;
//! it cannot mint the attestation. An item without lineage, an active state
//! and a non-quarantined trust row has no reason to be in context.

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

/// Attach a governance attestation to every assembled context chunk.
///
/// Missing descriptor, non-active lineage or missing trust metadata is a
/// caller bug: those chunks should already have been refused by
/// `admit_governed_recall`. This function fails closed rather than inventing
/// a reason.
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
        MemoryContextBudget, MemoryEvidenceRef, MemoryLineage, MemoryLoadoutBinding,
        MemoryLoadoutPlan, MemorySpace, MemoryStratum, MemoryUsageMode,
    };
    use std::collections::BTreeMap;

    fn id(value: &str) -> MemoryAssetId {
        MemoryAssetId::new(value).unwrap()
    }

    #[test]
    fn attestation_carries_evidence_not_similarity() {
        let mut graph = MemoryLineageGraph::new();
        let descriptor = MemoryAssetDescriptor::new(
            id("root-1"),
            MemorySpace::Tenant,
            MemoryStratum::Evidence,
            MemoryLineage::root([MemoryEvidenceRef::new("audit:root-1").unwrap()]).unwrap(),
        )
        .unwrap();
        graph.register(descriptor).unwrap();
        let trust = BTreeMap::from([(id("root-1"), MemoryTrustMetadata::unverified(1))]);
        let plan = MemoryLoadoutPlan::new([MemoryLoadoutBinding::new(
            MemorySpace::Tenant,
            1,
            MemoryUsageMode::BootstrapAndOnDemand,
        )
        .unwrap()])
        .unwrap();
        let assembly = assemble_governed_bootstrap_context(
            &plan,
            [GovernedMemoryObservation {
                asset_id: id("root-1"),
                space: MemorySpace::Tenant,
                payload: b"fact".to_vec(),
                similarity: 0.99,
            }],
            MemoryContextBudget::new(8, 1024).unwrap(),
        )
        .unwrap();
        let attested = attest_governed_context(&assembly, &graph, &trust).unwrap();
        assert_eq!(attested.len(), 1);
        assert_eq!(attested[0].reason, MemoryAdmissionReason::ActiveAndEligible);
        assert_eq!(attested[0].evidence[0].as_str(), "audit:root-1");
        assert_eq!(attested[0].trust_state, MemoryValidationState::Unverified);
    }
}
