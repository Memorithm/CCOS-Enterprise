//! Validated immutable authority: hashing is paid once per selected generation.
use ccos_enterprise_tenancy::TenantId;
use sha2::{Digest, Sha256};

use crate::*;

/// Owned, immutable projection with a privately computed canonical fingerprint.
///
/// No caller-supplied digest or mutable projection is accepted. Replacing any
/// authority requires constructing a new snapshot. This caches validation, never
/// authentication or the result of an asset eligibility decision.
#[derive(Debug)]
pub struct GovernedMemorySnapshot {
    projection: GovernedMemoryProjection,
    canonical: Vec<u8>,
    fingerprint: [u8; 32],
}

impl GovernedMemorySnapshot {
    /// Validate and freeze one complete authority projection.
    pub fn new(
        projection: GovernedMemoryProjection,
    ) -> Result<Self, GovernedMemoryProjectionError> {
        let canonical = encode_governed_memory_projection(&projection)?;
        let fingerprint = Sha256::digest(&canonical).into();
        Ok(Self {
            projection,
            canonical,
            fingerprint,
        })
    }

    /// Immutable metadata; mutation requires a new generation and fingerprint.
    pub fn projection(&self) -> &GovernedMemoryProjection {
        &self.projection
    }

    /// Exact validated bytes used in generation/recovery binding.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// Admit observations with the same tenant/space/lineage/trust/payload checks
    /// as `admit_governed_recall`, without rebuilding immutable authority.
    pub fn admit(
        &self,
        expected_tenant: &TenantId,
        policy: GovernedRecallTrustPolicy,
        observations: impl IntoIterator<Item = GovernedMemoryObservation>,
    ) -> Result<AdmittedGovernedRecall, GovernedRecallGateError> {
        crate::governed_recall::admit_bound(
            GovernedRecallGate {
                expected_tenant,
                projection: &self.projection,
                policy,
            },
            observations,
            self.fingerprint,
        )
    }

    /// Assemble only a batch bound to these exact tenant and authority bytes.
    pub fn assemble(
        &self,
        admitted: AdmittedGovernedRecall,
        budget: MemoryContextBudget,
    ) -> Result<GovernedMemoryContextAssembly, MemoryContextError> {
        crate::governed_context::assemble_bound(
            &self.projection,
            admitted,
            budget,
            self.fingerprint,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn projection(tenant: &str) -> GovernedMemoryProjection {
        let id = MemoryAssetId::new("a").unwrap();
        let mut graph = MemoryLineageGraph::new();
        graph
            .register(
                MemoryAssetDescriptor::new(
                    id.clone(),
                    MemorySpace::Tenant,
                    MemoryStratum::Evidence,
                    MemoryLineage::root([MemoryEvidenceRef::new("e").unwrap()]).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        GovernedMemoryProjection::new(
            TenantId::new(tenant).unwrap(),
            graph,
            BTreeMap::from([(id, MemoryTrustMetadata::unverified(1))]),
            MemoryLoadoutPlan::new([MemoryLoadoutBinding::new(
                MemorySpace::Tenant,
                1,
                MemoryUsageMode::BootstrapAndOnDemand,
            )
            .unwrap()])
            .unwrap(),
        )
        .unwrap()
    }
    fn observation() -> GovernedMemoryObservation {
        GovernedMemoryObservation {
            asset_id: MemoryAssetId::new("a").unwrap(),
            space: MemorySpace::Tenant,
            payload: b"exact bytes".to_vec(),
            similarity: 0.5,
        }
    }

    #[test]
    fn cached_path_matches_full_validation_and_rejects_another_snapshot() {
        let p = projection("acme");
        let frozen = GovernedMemorySnapshot::new(p.clone()).unwrap();
        let policy = GovernedRecallTrustPolicy::AnyNonQuarantined;
        let full = admit_governed_recall(
            GovernedRecallGate {
                expected_tenant: &p.tenant,
                projection: &p,
                policy,
            },
            [observation()],
        )
        .unwrap();
        let cached = frozen.admit(&p.tenant, policy, [observation()]).unwrap();
        assert_eq!(full, cached);
        let budget = MemoryContextBudget::new(2, 100).unwrap();
        assert_eq!(
            assemble_governed_bootstrap_context(&p, full, budget).unwrap(),
            frozen.assemble(cached.clone(), budget).unwrap()
        );
        let mut changed = p.clone();
        changed.graph.invalidate(&observation().asset_id).unwrap();
        let newer = GovernedMemorySnapshot::new(changed).unwrap();
        assert!(newer.assemble(cached.clone(), budget).is_err());
        assert!(newer
            .admit(&p.tenant, policy, [observation()])
            .unwrap()
            .is_empty());
        let other = GovernedMemorySnapshot::new(projection("other")).unwrap();
        assert!(other.assemble(cached, budget).is_err());
        assert!(other.admit(&p.tenant, policy, [observation()]).is_err());
    }
}
