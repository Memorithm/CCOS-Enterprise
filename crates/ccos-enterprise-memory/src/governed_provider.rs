use ccos_enterprise_tenancy::TenantScope;

use crate::{LoadoutMemoryQuery, MemoryAssetId, MemoryError, MemorySpace};

/// Write one semantically indexed payload while retaining its governed CCOS asset identity.
///
/// The asset id is metadata, not authorization. The provider must still enforce the
/// tenant and memory-space boundary before materialising storage.
#[derive(Debug, Clone, Copy)]
pub struct GovernedMemoryWrite<'a> {
    pub asset_id: &'a MemoryAssetId,
    pub space: &'a MemorySpace,
    pub embedding: &'a [f32],
    pub payload: &'a [u8],
}

/// A semantic-memory observation that preserves the governed asset identity.
///
/// Callers can join this id back to lineage, trust, retention and audit state. The
/// similarity remains only a retrieval signal and never grants authority.
#[derive(Debug, Clone, PartialEq)]
pub struct GovernedMemoryObservation {
    pub asset_id: MemoryAssetId,
    pub space: MemorySpace,
    pub payload: Vec<u8>,
    pub similarity: f32,
}

/// Backend contract for governed semantic memory whose stored observations remain
/// addressable by the CCOS memory-asset identity.
///
/// This trait is deliberately additive to `SemanticMemoryProvider`: existing raw
/// semantic providers remain source-compatible, while governance-aware callers can
/// require identity-preserving storage and retrieval explicitly.
pub trait GovernedSemanticMemoryProvider {
    fn insert_governed(
        &mut self,
        scoped: TenantScope<GovernedMemoryWrite<'_>>,
    ) -> Result<(), MemoryError>;

    fn recall_governed(
        &self,
        scoped: TenantScope<LoadoutMemoryQuery<'_>>,
    ) -> Result<Vec<GovernedMemoryObservation>, MemoryError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observation_identity_is_independent_from_similarity() {
        let id = MemoryAssetId::new("memory:asset:7").unwrap();
        let observation = GovernedMemoryObservation {
            asset_id: id.clone(),
            space: MemorySpace::Tenant,
            payload: b"evidence".to_vec(),
            similarity: -0.25,
        };

        assert_eq!(observation.asset_id, id);
        assert_eq!(observation.payload, b"evidence");
        assert_eq!(observation.similarity, -0.25);
    }
}
