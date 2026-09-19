use std::collections::BTreeMap;

use crate::{
    governed_recall::projection_fingerprint, AdmittedGovernedMemoryObservation,
    AdmittedGovernedRecall, GovernedMemoryProjection, MemoryContextBudget, MemoryContextError,
};

/// Structured bootstrap context whose chunks retain cryptographically bound
/// admission metadata in addition to their governed asset identity.
#[derive(Debug, Clone, PartialEq)]
pub struct GovernedMemoryContextAssembly {
    tenant: ccos_enterprise_tenancy::TenantId,
    projection_version: u32,
    projection_sha256: [u8; 32],
    chunks: Vec<AdmittedGovernedMemoryObservation>,
    payload_bytes: usize,
}

impl GovernedMemoryContextAssembly {
    pub fn tenant(&self) -> &ccos_enterprise_tenancy::TenantId {
        &self.tenant
    }
    pub const fn projection_version(&self) -> u32 {
        self.projection_version
    }
    pub const fn projection_sha256(&self) -> &[u8; 32] {
        &self.projection_sha256
    }
    pub fn projection_sha256_hex(&self) -> String {
        self.projection_sha256
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
    pub fn chunks(&self) -> &[AdmittedGovernedMemoryObservation] {
        &self.chunks
    }
    pub fn into_chunks(self) -> Vec<AdmittedGovernedMemoryObservation> {
        self.chunks
    }
    pub const fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }
    pub fn len(&self) -> usize {
        self.chunks.len()
    }
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }
}

/// Assemble only observations minted by governed recall admission, and verify
/// that the exact projection used for assembly is the snapshot that minted them.
pub fn assemble_governed_bootstrap_context(
    projection: &GovernedMemoryProjection,
    admitted: AdmittedGovernedRecall,
    budget: MemoryContextBudget,
) -> Result<GovernedMemoryContextAssembly, MemoryContextError> {
    let fingerprint = projection_fingerprint(projection)
        .map_err(|_| MemoryContextError::ProjectionBindingMismatch)?;
    assemble_bound(projection, admitted, budget, fingerprint)
}

pub(crate) fn assemble_bound(
    projection: &GovernedMemoryProjection,
    admitted: AdmittedGovernedRecall,
    budget: MemoryContextBudget,
    fingerprint: [u8; 32],
) -> Result<GovernedMemoryContextAssembly, MemoryContextError> {
    if admitted.tenant() != &projection.tenant
        || admitted.projection_version() != crate::GOVERNED_MEMORY_PROJECTION_VERSION
        || fingerprint != *admitted.projection_sha256()
    {
        return Err(MemoryContextError::ProjectionBindingMismatch);
    }

    let priorities: BTreeMap<_, _> = projection
        .loadout
        .bindings()
        .filter(|binding| binding.usage.allows_bootstrap())
        .map(|binding| (binding.space.clone(), binding.priority))
        .collect();

    let tenant = admitted.tenant().clone();
    let projection_version = admitted.projection_version();
    let projection_sha256 = *admitted.projection_sha256();
    let mut candidates = Vec::new();
    for (input_order, observation) in admitted.into_observations().into_iter().enumerate() {
        let Some(priority) = priorities.get(&observation.space).copied() else {
            return Err(MemoryContextError::ObservationOutsideBootstrapLoadout(
                observation.space.clone(),
            ));
        };
        if !observation.similarity.is_finite() {
            return Err(MemoryContextError::NonFiniteSimilarity);
        }
        candidates.push((priority, input_order, observation));
    }

    candidates.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| right.2.similarity.total_cmp(&left.2.similarity))
            .then_with(|| left.2.space.cmp(&right.2.space))
            .then_with(|| left.2.asset_id.cmp(&right.2.asset_id))
            .then_with(|| left.1.cmp(&right.1))
    });

    let mut chunks = Vec::with_capacity(candidates.len().min(budget.max_items()));
    let mut payload_bytes = 0usize;
    for (_, _, observation) in candidates {
        if chunks.len() >= budget.max_items() {
            break;
        }
        let next_bytes = payload_bytes.saturating_add(observation.payload.len());
        if next_bytes > budget.max_payload_bytes() {
            continue;
        }
        payload_bytes = next_bytes;
        chunks.push(observation);
    }

    Ok(GovernedMemoryContextAssembly {
        tenant,
        projection_version,
        projection_sha256,
        chunks,
        payload_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        admit_governed_recall, GovernedMemoryObservation, GovernedRecallGate,
        GovernedRecallTrustPolicy, MemoryAssetDescriptor, MemoryAssetId, MemoryEvidenceRef,
        MemoryLineage, MemoryLineageGraph, MemoryLoadoutBinding, MemoryLoadoutPlan, MemorySpace,
        MemoryStratum, MemoryTrustMetadata, MemoryUsageMode, MemoryValidationState,
    };
    use ccos_enterprise_tenancy::TenantId;
    use std::collections::BTreeMap;

    fn id(v: &str) -> MemoryAssetId {
        MemoryAssetId::new(v).unwrap()
    }
    fn projection(priority: u16) -> GovernedMemoryProjection {
        let mut graph = MemoryLineageGraph::new();
        for v in ["a", "b"] {
            graph
                .register(
                    MemoryAssetDescriptor::new(
                        id(v),
                        MemorySpace::Tenant,
                        MemoryStratum::Evidence,
                        MemoryLineage::root(
                            [MemoryEvidenceRef::new(format!("audit:{v}")).unwrap()],
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        let trust = BTreeMap::from([("a", "p:a"), ("b", "p:b")].map(|(v, p)| {
            (
                id(v),
                MemoryTrustMetadata::new(MemoryValidationState::Verified, 1, 1, 0, [p.into()])
                    .unwrap(),
            )
        }));
        GovernedMemoryProjection::new(
            TenantId::new("acme").unwrap(),
            graph,
            trust,
            MemoryLoadoutPlan::new([MemoryLoadoutBinding::new(
                MemorySpace::Tenant,
                priority,
                MemoryUsageMode::BootstrapAndOnDemand,
            )
            .unwrap()])
            .unwrap(),
        )
        .unwrap()
    }
    fn admitted(p: &GovernedMemoryProjection, payload: &[u8]) -> AdmittedGovernedRecall {
        let tenant = TenantId::new("acme").unwrap();
        admit_governed_recall(
            GovernedRecallGate {
                expected_tenant: &tenant,
                projection: p,
                policy: GovernedRecallTrustPolicy::VerifiedOnly,
            },
            [GovernedMemoryObservation {
                asset_id: id("a"),
                space: MemorySpace::Tenant,
                payload: payload.to_vec(),
                similarity: 0.5,
            }],
        )
        .unwrap()
    }
    #[test]
    fn assembly_preserves_binding_and_payload_digest() {
        let p = projection(100);
        let a = admitted(&p, b"payload");
        let digest = *a.observations()[0].payload_sha256();
        let c =
            assemble_governed_bootstrap_context(&p, a, MemoryContextBudget::new(4, 64).unwrap())
                .unwrap();
        assert_eq!(c.tenant().as_str(), "acme");
        assert_eq!(c.chunks()[0].asset_id.as_str(), "a");
        assert_eq!(c.chunks()[0].payload_sha256(), &digest);
    }
    #[test]
    fn changed_projection_is_rejected_even_when_asset_is_same() {
        let p1 = projection(100);
        let a = admitted(&p1, b"payload");
        let p2 = projection(99);
        assert_eq!(
            assemble_governed_bootstrap_context(&p2, a, MemoryContextBudget::new(4, 64).unwrap()),
            Err(MemoryContextError::ProjectionBindingMismatch)
        );
    }
    #[test]
    fn non_finite_similarity_fails_closed_after_admission() {
        let p = projection(100);
        let tenant = TenantId::new("acme").unwrap();
        let a = admit_governed_recall(
            GovernedRecallGate {
                expected_tenant: &tenant,
                projection: &p,
                policy: GovernedRecallTrustPolicy::VerifiedOnly,
            },
            [GovernedMemoryObservation {
                asset_id: id("a"),
                space: MemorySpace::Tenant,
                payload: b"x".to_vec(),
                similarity: f32::NAN,
            }],
        )
        .unwrap();
        assert_eq!(
            assemble_governed_bootstrap_context(&p, a, MemoryContextBudget::new(1, 1).unwrap()),
            Err(MemoryContextError::NonFiniteSimilarity)
        );
    }
}
