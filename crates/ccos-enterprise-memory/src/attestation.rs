//! Cryptographic admission metadata for a served governed-memory context.
//!
//! Similarity may order candidates; it never establishes eligibility. Each
//! attestation names the exact tenant, canonical governance snapshot and payload
//! digest that crossed admission.

use crate::{
    GovernedMemoryContextAssembly, MemoryAssetId, MemoryAssetState, MemorySpace,
    MemoryValidationState,
};

/// Categorical reason a chunk survived admission. Never a similarity score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryAdmissionReason {
    ActiveAndEligible,
}

/// One attested context item bound to tenant, projection and exact payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryContextAttestation {
    pub tenant: ccos_enterprise_tenancy::TenantId,
    pub projection_version: u32,
    pub projection_sha256: String,
    pub asset_id: MemoryAssetId,
    pub space: MemorySpace,
    pub asset_state: MemoryAssetState,
    pub trust_state: MemoryValidationState,
    pub payload_sha256: String,
    pub parents: Vec<MemoryAssetId>,
    pub evidence: Vec<crate::MemoryEvidenceRef>,
    pub reason: MemoryAdmissionReason,
}

/// Project opaque admitted context metadata into an audit-safe attestation.
pub fn attest_governed_context(
    assembly: &GovernedMemoryContextAssembly,
) -> Vec<MemoryContextAttestation> {
    let projection_sha256 = assembly.projection_sha256_hex();
    assembly
        .chunks()
        .iter()
        .map(|chunk| MemoryContextAttestation {
            tenant: assembly.tenant().clone(),
            projection_version: assembly.projection_version(),
            projection_sha256: projection_sha256.clone(),
            asset_id: chunk.asset_id.clone(),
            space: chunk.space.clone(),
            asset_state: chunk.asset_state(),
            trust_state: chunk.trust_state(),
            payload_sha256: chunk.payload_sha256_hex(),
            parents: chunk.parents().to_vec(),
            evidence: chunk.evidence().to_vec(),
            reason: MemoryAdmissionReason::ActiveAndEligible,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        admit_governed_recall, assemble_governed_bootstrap_context, GovernedMemoryObservation,
        GovernedMemoryProjection, GovernedRecallGate, GovernedRecallTrustPolicy,
        MemoryAssetDescriptor, MemoryContextBudget, MemoryEvidenceRef, MemoryLineage,
        MemoryLineageGraph, MemoryLoadoutBinding, MemoryLoadoutPlan, MemoryStratum,
        MemoryTrustMetadata, MemoryUsageMode,
    };
    use ccos_enterprise_tenancy::TenantId;
    use std::collections::BTreeMap;
    fn id(v: &str) -> MemoryAssetId {
        MemoryAssetId::new(v).unwrap()
    }
    #[test]
    fn attestation_carries_tenant_projection_and_payload_digest() {
        let mut graph = MemoryLineageGraph::new();
        graph
            .register(
                MemoryAssetDescriptor::new(
                    id("root"),
                    MemorySpace::Tenant,
                    MemoryStratum::Evidence,
                    MemoryLineage::root([MemoryEvidenceRef::new("audit:root").unwrap()]).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        let trust = BTreeMap::from([(id("root"), MemoryTrustMetadata::unverified(1))]);
        let p = GovernedMemoryProjection::new(
            TenantId::new("acme").unwrap(),
            graph,
            trust,
            MemoryLoadoutPlan::new([MemoryLoadoutBinding::new(
                MemorySpace::Tenant,
                1,
                MemoryUsageMode::Bootstrap,
            )
            .unwrap()])
            .unwrap(),
        )
        .unwrap();
        let tenant = TenantId::new("acme").unwrap();
        let admitted = admit_governed_recall(
            GovernedRecallGate {
                expected_tenant: &tenant,
                projection: &p,
                policy: GovernedRecallTrustPolicy::AnyNonQuarantined,
            },
            [GovernedMemoryObservation {
                asset_id: id("root"),
                space: MemorySpace::Tenant,
                payload: b"fact".to_vec(),
                similarity: 0.9,
            }],
        )
        .unwrap();
        let assembly = assemble_governed_bootstrap_context(
            &p,
            admitted,
            MemoryContextBudget::new(4, 64).unwrap(),
        )
        .unwrap();
        let out = attest_governed_context(&assembly);
        assert_eq!(out[0].tenant.as_str(), "acme");
        assert_eq!(out[0].projection_sha256, assembly.projection_sha256_hex());
        assert_eq!(
            out[0].payload_sha256,
            assembly.chunks()[0].payload_sha256_hex()
        );
        assert_eq!(out[0].trust_state, MemoryValidationState::Unverified);
    }
}
