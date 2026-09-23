use std::fmt;
use std::ops::Deref;

use ccos_enterprise_tenancy::TenantId;
use sha2::{Digest, Sha256};

use crate::{
    encode_governed_memory_projection, GovernedMemoryObservation, GovernedMemoryProjection,
    MemoryAssetId, MemoryAssetState, MemoryProvenanceClass, MemorySpace, MemoryValidationState,
    GOVERNED_MEMORY_PROJECTION_VERSION,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernedRecallTrustPolicy {
    AnyNonQuarantined,
    CorroboratedOrVerified,
    VerifiedOnly,
}

/// Governance authority used to mint opaque admitted recall values.
#[derive(Debug, Clone, Copy)]
pub struct GovernedRecallGate<'a> {
    pub expected_tenant: &'a TenantId,
    pub projection: &'a GovernedMemoryProjection,
    pub policy: GovernedRecallTrustPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernedRecallGateError {
    TenantMismatch {
        expected: String,
        found: String,
    },
    ProjectionEncoding(String),
    ProviderReturnedUnknownAsset(MemoryAssetId),
    ProviderReturnedMismatchedSpace {
        asset_id: MemoryAssetId,
        expected: MemorySpace,
        observed: MemorySpace,
    },
    MissingTrustMetadata(MemoryAssetId),
    MissingProvenanceMetadata(MemoryAssetId),
}

impl fmt::Display for GovernedRecallGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TenantMismatch { expected, found } => {
                write!(
                    f,
                    "governed recall tenant {found:?} != admitted tenant {expected:?}"
                )
            }
            Self::ProjectionEncoding(error) => {
                write!(f, "governed projection fingerprint: {error}")
            }
            Self::ProviderReturnedUnknownAsset(id) => write!(
                f,
                "governed memory provider returned unknown asset {}",
                id.as_str()
            ),
            Self::ProviderReturnedMismatchedSpace {
                asset_id,
                expected,
                observed,
            } => write!(
                f,
                "governed memory asset {} has space {observed:?}, expected {expected:?}",
                asset_id.as_str()
            ),
            Self::MissingTrustMetadata(id) => write!(
                f,
                "governed memory asset {} has no trust metadata",
                id.as_str()
            ),
            Self::MissingProvenanceMetadata(id) => write!(
                f,
                "governed memory asset {} has no provenance metadata",
                id.as_str()
            ),
        }
    }
}
impl std::error::Error for GovernedRecallGateError {}

/// One observation after tenant/projection/trust admission. Construction is
/// intentionally private to this crate; public provider observations cannot be
/// passed directly to governed context assembly.
#[derive(Debug, Clone, PartialEq)]
pub struct AdmittedGovernedMemoryObservation {
    observation: GovernedMemoryObservation,
    asset_state: MemoryAssetState,
    trust_state: MemoryValidationState,
    provenance_class: MemoryProvenanceClass,
    payload_sha256: [u8; 32],
    parents: Vec<MemoryAssetId>,
    evidence: Vec<crate::MemoryEvidenceRef>,
}

impl AdmittedGovernedMemoryObservation {
    pub const fn asset_state(&self) -> MemoryAssetState {
        self.asset_state
    }
    pub const fn trust_state(&self) -> MemoryValidationState {
        self.trust_state
    }
    pub const fn provenance_class(&self) -> MemoryProvenanceClass {
        self.provenance_class
    }
    pub const fn payload_sha256(&self) -> &[u8; 32] {
        &self.payload_sha256
    }
    pub fn payload_sha256_hex(&self) -> String {
        hex_digest(self.payload_sha256)
    }
    pub fn parents(&self) -> &[MemoryAssetId] {
        &self.parents
    }
    pub fn evidence(&self) -> &[crate::MemoryEvidenceRef] {
        &self.evidence
    }
}
impl Deref for AdmittedGovernedMemoryObservation {
    type Target = GovernedMemoryObservation;
    fn deref(&self) -> &Self::Target {
        &self.observation
    }
}

/// Opaque batch bound to one tenant and one canonical governance snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct AdmittedGovernedRecall {
    tenant: TenantId,
    projection_version: u32,
    projection_sha256: [u8; 32],
    observations: Vec<AdmittedGovernedMemoryObservation>,
}
impl AdmittedGovernedRecall {
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }
    pub const fn projection_version(&self) -> u32 {
        self.projection_version
    }
    pub const fn projection_sha256(&self) -> &[u8; 32] {
        &self.projection_sha256
    }
    pub fn projection_sha256_hex(&self) -> String {
        hex_digest(self.projection_sha256)
    }
    pub fn observations(&self) -> &[AdmittedGovernedMemoryObservation] {
        &self.observations
    }
    pub fn into_observations(self) -> Vec<AdmittedGovernedMemoryObservation> {
        self.observations
    }
}

impl Deref for AdmittedGovernedRecall {
    type Target = [AdmittedGovernedMemoryObservation];
    fn deref(&self) -> &Self::Target {
        &self.observations
    }
}

pub(crate) fn projection_fingerprint(
    projection: &GovernedMemoryProjection,
) -> Result<[u8; 32], GovernedRecallGateError> {
    let bytes = encode_governed_memory_projection(projection)
        .map_err(|error| GovernedRecallGateError::ProjectionEncoding(error.to_string()))?;
    Ok(Sha256::digest(bytes).into())
}

/// Admit provider output against an explicit tenant and canonical projection.
/// Similarity remains ordering data only and cannot mint authority.
pub fn admit_governed_recall(
    gate: GovernedRecallGate<'_>,
    observations: impl IntoIterator<Item = GovernedMemoryObservation>,
) -> Result<AdmittedGovernedRecall, GovernedRecallGateError> {
    if gate.expected_tenant != &gate.projection.tenant {
        return Err(GovernedRecallGateError::TenantMismatch {
            expected: gate.expected_tenant.as_str().to_string(),
            found: gate.projection.tenant.as_str().to_string(),
        });
    }
    let projection_sha256 = projection_fingerprint(gate.projection)?;
    admit_bound(gate, observations, projection_sha256)
}

// Only the validating public path and the immutable snapshot may supply a digest.
pub(crate) fn admit_bound(
    gate: GovernedRecallGate<'_>,
    observations: impl IntoIterator<Item = GovernedMemoryObservation>,
    projection_sha256: [u8; 32],
) -> Result<AdmittedGovernedRecall, GovernedRecallGateError> {
    if gate.expected_tenant != &gate.projection.tenant {
        return Err(GovernedRecallGateError::TenantMismatch {
            expected: gate.expected_tenant.as_str().to_string(),
            found: gate.projection.tenant.as_str().to_string(),
        });
    }
    let mut admitted = Vec::new();
    for observation in observations {
        let descriptor = gate
            .projection
            .graph
            .descriptor(&observation.asset_id)
            .ok_or_else(|| {
                GovernedRecallGateError::ProviderReturnedUnknownAsset(observation.asset_id.clone())
            })?;
        if descriptor.space != observation.space {
            return Err(GovernedRecallGateError::ProviderReturnedMismatchedSpace {
                asset_id: observation.asset_id,
                expected: descriptor.space.clone(),
                observed: observation.space,
            });
        }
        let asset_state = gate
            .projection
            .graph
            .state(&observation.asset_id)
            .ok_or_else(|| {
                GovernedRecallGateError::ProviderReturnedUnknownAsset(observation.asset_id.clone())
            })?;
        if asset_state != MemoryAssetState::Active {
            continue;
        }
        let trust = gate
            .projection
            .trust
            .get(&observation.asset_id)
            .ok_or_else(|| {
                GovernedRecallGateError::MissingTrustMetadata(observation.asset_id.clone())
            })?;
        if !trust.recall_eligible() || !policy_allows(gate.policy, trust.state()) {
            continue;
        }
        let provenance_class = gate
            .projection
            .provenance
            .class(&observation.asset_id)
            .ok_or_else(|| {
                GovernedRecallGateError::MissingProvenanceMetadata(
                    observation.asset_id.clone(),
                )
            })?;
        let payload_sha256 = Sha256::digest(&observation.payload).into();
        admitted.push(AdmittedGovernedMemoryObservation {
            observation,
            asset_state,
            trust_state: trust.state(),
            provenance_class,
            payload_sha256,
            parents: descriptor.lineage.parents().cloned().collect(),
            evidence: descriptor.lineage.evidence().cloned().collect(),
        });
    }
    Ok(AdmittedGovernedRecall {
        tenant: gate.expected_tenant.clone(),
        projection_version: GOVERNED_MEMORY_PROJECTION_VERSION,
        projection_sha256,
        observations: admitted,
    })
}

fn policy_allows(policy: GovernedRecallTrustPolicy, state: MemoryValidationState) -> bool {
    match policy {
        GovernedRecallTrustPolicy::AnyNonQuarantined => {
            !matches!(state, MemoryValidationState::Quarantined)
        }
        GovernedRecallTrustPolicy::CorroboratedOrVerified => matches!(
            state,
            MemoryValidationState::Corroborated | MemoryValidationState::Verified
        ),
        GovernedRecallTrustPolicy::VerifiedOnly => matches!(state, MemoryValidationState::Verified),
    }
}

fn hex_digest(digest: [u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MemoryAssetDescriptor, MemoryEvidenceRef, MemoryLineage, MemoryLineageGraph,
        MemoryLoadoutBinding, MemoryLoadoutPlan, MemoryStratum, MemoryTrustMetadata,
        MemoryUsageMode,
    };
    use std::collections::BTreeMap;

    fn tenant(v: &str) -> TenantId {
        TenantId::new(v).unwrap()
    }
    fn id(v: &str) -> MemoryAssetId {
        MemoryAssetId::new(v).unwrap()
    }
    fn descriptor(v: &str, space: MemorySpace) -> MemoryAssetDescriptor {
        MemoryAssetDescriptor::new(
            id(v),
            space,
            MemoryStratum::Evidence,
            MemoryLineage::root([MemoryEvidenceRef::new(format!("audit:{v}")).unwrap()]).unwrap(),
        )
        .unwrap()
    }
    fn observation(
        v: &str,
        space: MemorySpace,
        payload: &[u8],
        similarity: f32,
    ) -> GovernedMemoryObservation {
        GovernedMemoryObservation {
            asset_id: id(v),
            space,
            payload: payload.to_vec(),
            similarity,
        }
    }
    fn verified() -> MemoryTrustMetadata {
        MemoryTrustMetadata::new(MemoryValidationState::Verified, 1, 1, 0, ["proof:1".into()])
            .unwrap()
    }
    fn projection(
        tenant_id: &str,
        state: Option<MemoryAssetState>,
        trust: Option<MemoryTrustMetadata>,
    ) -> GovernedMemoryProjection {
        let mut graph = MemoryLineageGraph::new();
        graph
            .register(descriptor("known", MemorySpace::Tenant))
            .unwrap();
        if matches!(state, Some(MemoryAssetState::Invalidated)) {
            graph.invalidate(&id("known")).unwrap();
        }
        let trust = trust
            .map(|m| BTreeMap::from([(id("known"), m)]))
            .unwrap_or_default();
        GovernedMemoryProjection::new(
            tenant(tenant_id),
            graph,
            trust,
            MemoryLoadoutPlan::new([MemoryLoadoutBinding::new(
                MemorySpace::Tenant,
                100,
                MemoryUsageMode::BootstrapAndOnDemand,
            )
            .unwrap()])
            .unwrap(),
        )
        .unwrap()
    }
    fn gate<'a>(
        expected: &'a TenantId,
        projection: &'a GovernedMemoryProjection,
    ) -> GovernedRecallGate<'a> {
        GovernedRecallGate {
            expected_tenant: expected,
            projection,
            policy: GovernedRecallTrustPolicy::VerifiedOnly,
        }
    }

    #[test]
    fn tenant_mismatch_fails_closed_before_observation_use() {
        let p = projection("acme", None, Some(verified()));
        let expected = tenant("globex");
        assert!(matches!(
            admit_governed_recall(gate(&expected, &p), []),
            Err(GovernedRecallGateError::TenantMismatch { .. })
        ));
    }
    #[test]
    fn missing_trust_fails_closed() {
        let p = projection("acme", None, None);
        let expected = tenant("acme");
        assert!(
            matches!(admit_governed_recall(gate(&expected,&p), [observation("known",MemorySpace::Tenant,b"x",1.0)]),
            Err(GovernedRecallGateError::MissingTrustMetadata(asset)) if asset.as_str()=="known")
        );
    }
    #[test]
    fn mismatched_space_fails_closed() {
        let p = projection("acme", None, Some(verified()));
        let expected = tenant("acme");
        assert!(matches!(
            admit_governed_recall(
                gate(&expected, &p),
                [observation(
                    "known",
                    MemorySpace::project("p").unwrap(),
                    b"x",
                    1.0
                )]
            ),
            Err(GovernedRecallGateError::ProviderReturnedMismatchedSpace { .. })
        ));
    }
    #[test]
    fn inactive_and_quarantined_are_not_admitted() {
        let p = projection(
            "acme",
            Some(MemoryAssetState::Invalidated),
            Some(verified()),
        );
        let expected = tenant("acme");
        assert!(admit_governed_recall(
            gate(&expected, &p),
            [observation("known", MemorySpace::Tenant, b"x", 1.0)]
        )
        .unwrap()
        .observations()
        .is_empty());
        let q = MemoryTrustMetadata::new(
            MemoryValidationState::Quarantined,
            1,
            1,
            0,
            Vec::<String>::new(),
        )
        .unwrap();
        let p = projection("acme", None, Some(q));
        let gate = GovernedRecallGate {
            expected_tenant: &expected,
            projection: &p,
            policy: GovernedRecallTrustPolicy::AnyNonQuarantined,
        };
        assert!(admit_governed_recall(
            gate,
            [observation("known", MemorySpace::Tenant, b"x", 1.0)]
        )
        .unwrap()
        .observations()
        .is_empty());
    }
    #[test]
    fn admission_binds_projection_and_exact_payload() {
        let p = projection("acme", None, Some(verified()));
        let expected = tenant("acme");
        let a = admit_governed_recall(
            gate(&expected, &p),
            [observation("known", MemorySpace::Tenant, b"payload-a", 0.2)],
        )
        .unwrap();
        let b = admit_governed_recall(
            gate(&expected, &p),
            [observation("known", MemorySpace::Tenant, b"payload-b", 0.9)],
        )
        .unwrap();
        assert_eq!(a.projection_version(), GOVERNED_MEMORY_PROJECTION_VERSION);
        assert_eq!(a.projection_sha256(), b.projection_sha256());
        assert_ne!(
            a.observations()[0].payload_sha256(),
            b.observations()[0].payload_sha256()
        );
        assert_eq!(
            a.observations()[0].trust_state(),
            MemoryValidationState::Verified
        );
        assert_eq!(
            a.observations()[0].provenance_class(),
            MemoryProvenanceClass::Observed
        );
    }
    #[test]
    fn similarity_does_not_change_payload_or_projection_authority() {
        let p = projection("acme", None, Some(verified()));
        let expected = tenant("acme");
        let a = admit_governed_recall(
            gate(&expected, &p),
            [observation("known", MemorySpace::Tenant, b"same", -1.0)],
        )
        .unwrap();
        let b = admit_governed_recall(
            gate(&expected, &p),
            [observation("known", MemorySpace::Tenant, b"same", 99.0)],
        )
        .unwrap();
        assert_eq!(a.projection_sha256(), b.projection_sha256());
        assert_eq!(
            a.observations()[0].payload_sha256(),
            b.observations()[0].payload_sha256()
        );
    }
}
