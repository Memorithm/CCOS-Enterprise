//! Governed OctaSoma adapter for CCOS Enterprise.
//!
//! This crate is the only supported direct Enterprise dependency on OctaSoma.
//! CCOS-owned memory domains and provider contracts live in
//! `ccos-enterprise-memory`; this crate only implements those contracts with
//! OctaSoma. Semantic-memory indexes remain physically isolated by tenant and
//! memory space, and similarity remains evidence rather than authorization or
//! causal truth.
//!
//! The legacy tenant-wide API remains available and maps exclusively to the
//! [`MemorySpace::Tenant`] partition. Agent/team/project memories are only
//! reachable through an explicit [`MemoryLoadout`], so an excluded space never
//! participates in candidate generation or ranking.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

pub use ccos_enterprise_memory::{
    GovernedMemoryObservation, GovernedMemoryWrite, GovernedSemanticMemoryProvider,
    LoadoutMemoryQuery, MemoryAssetId, MemoryError as EnterpriseMemoryError, MemoryLoadout,
    MemorySpace, ScopedMemoryObservation, ScopedMemoryWrite, SemanticMemoryProvider,
};
use ccos_enterprise_tenancy::{TenantId, TenantScope};
use octasoma::{HybridMemory, HybridMemoryFactory};

/// A tenant-scoped write into the legacy tenant-wide semantic-memory space.
#[derive(Debug, Clone, Copy)]
pub struct MemoryWrite<'a> {
    pub embedding: &'a [f32],
    pub payload: &'a [u8],
}

/// A tenant-scoped precision recall request for the legacy tenant-wide space.
#[derive(Debug, Clone, Copy)]
pub struct MemoryQuery<'a> {
    pub embedding: &'a [f32],
    pub k: usize,
    pub shortlist: usize,
}

/// An owned semantic-memory observation from the tenant-wide legacy API.
///
/// The payload is copied out of the tenant-local OctaSoma instance so no caller
/// can retain an internal reference that outlives the scoped lookup. The score
/// is a retrieval signal only; Enterprise/CCOS policy remains authoritative.
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryObservation {
    pub payload: Vec<u8>,
    pub similarity: f32,
}

#[derive(Default)]
struct TenantMemory {
    len: usize,
    spaces: BTreeMap<MemorySpace, HybridMemory>,
    governed_spaces: BTreeMap<MemorySpace, HybridMemory>,
    governed_ids: BTreeSet<MemoryAssetId>,
}

/// One isolated collection of OctaSoma indexes per Enterprise tenant.
///
/// Candidate sets, payload arenas and indexes are not shared across tenants or
/// memory spaces. The adapter deliberately exposes no raw OctaSoma handle:
/// callers must cross the typed [`TenantScope`] boundary for every read and
/// write. The configured quota is enforced across all spaces owned by a tenant.
pub struct EnterpriseOctaSoma {
    dim: usize,
    factory: HybridMemoryFactory,
    per_tenant_capacity: usize,
    tenants: BTreeMap<TenantId, TenantMemory>,
}

impl EnterpriseOctaSoma {
    /// Build a deterministic tenant- and space-isolated semantic-memory adapter.
    pub fn new(
        dim: usize,
        bits: usize,
        per_tenant_capacity: usize,
        seed: u64,
    ) -> Result<Self, EnterpriseMemoryError> {
        if dim == 0 {
            return Err(EnterpriseMemoryError::InvalidConfiguration(
                "embedding dimension must be non-zero",
            ));
        }
        if bits == 0 || !bits.is_multiple_of(64) {
            return Err(EnterpriseMemoryError::InvalidConfiguration(
                "SimHash width must be a non-zero multiple of 64",
            ));
        }
        if per_tenant_capacity == 0 {
            return Err(EnterpriseMemoryError::InvalidConfiguration(
                "per-tenant capacity must be non-zero",
            ));
        }
        Ok(Self {
            dim,
            factory: HybridMemoryFactory::new(dim, seed, bits),
            per_tenant_capacity,
            tenants: BTreeMap::new(),
        })
    }

    /// Insert into the legacy tenant-wide partition.
    pub fn insert(
        &mut self,
        scoped: TenantScope<MemoryWrite<'_>>,
    ) -> Result<(), EnterpriseMemoryError> {
        let TenantScope { tenant, inner } = scoped;
        self.insert_inner(tenant, &MemorySpace::Tenant, inner.embedding, inner.payload)
    }

    /// Insert into exactly one tenant and one explicit memory space.
    ///
    /// Scope, embedding and the aggregate per-tenant quota are validated before
    /// any new tenant/space index is materialised.
    pub fn insert_scoped(
        &mut self,
        scoped: TenantScope<ScopedMemoryWrite<'_>>,
    ) -> Result<(), EnterpriseMemoryError> {
        let TenantScope { tenant, inner } = scoped;
        self.insert_inner(tenant, inner.space, inner.embedding, inner.payload)
    }

    /// Insert a governance-aware observation while preserving its stable asset id.
    ///
    /// Governed observations use indexes distinct from the legacy raw API. This keeps
    /// identity-bearing records unambiguous and prevents arbitrary legacy payload bytes
    /// from being interpreted as metadata envelopes.
    pub fn insert_governed(
        &mut self,
        scoped: TenantScope<GovernedMemoryWrite<'_>>,
    ) -> Result<(), EnterpriseMemoryError> {
        let TenantScope { tenant, inner } = scoped;
        validate_tenant(&tenant)?;
        inner.space.validate()?;
        validate_embedding(inner.embedding, self.dim)?;

        if self
            .tenants
            .get(&tenant)
            .is_some_and(|memory| memory.len >= self.per_tenant_capacity)
        {
            return Err(EnterpriseMemoryError::TenantCapacityExceeded {
                limit: self.per_tenant_capacity,
            });
        }

        let factory = self.factory.clone();
        let tenant_memory = self.tenants.entry(tenant).or_default();
        if tenant_memory.governed_ids.contains(inner.asset_id) {
            return Err(EnterpriseMemoryError::InsertRejected);
        }
        let memory = tenant_memory
            .governed_spaces
            .entry(inner.space.clone())
            .or_insert_with(|| factory.create());
        let encoded = encode_governed_payload(inner.asset_id, inner.payload);
        if !memory.insert(inner.embedding, &encoded) {
            return Err(EnterpriseMemoryError::InsertRejected);
        }
        tenant_memory.governed_ids.insert(inner.asset_id.clone());
        tenant_memory.len += 1;
        Ok(())
    }

    fn insert_inner(
        &mut self,
        tenant: TenantId,
        space: &MemorySpace,
        embedding: &[f32],
        payload: &[u8],
    ) -> Result<(), EnterpriseMemoryError> {
        validate_tenant(&tenant)?;
        space.validate()?;
        validate_embedding(embedding, self.dim)?;

        if self
            .tenants
            .get(&tenant)
            .is_some_and(|memory| memory.len >= self.per_tenant_capacity)
        {
            return Err(EnterpriseMemoryError::TenantCapacityExceeded {
                limit: self.per_tenant_capacity,
            });
        }

        let factory = self.factory.clone();
        let tenant_memory = self.tenants.entry(tenant).or_default();
        let memory = tenant_memory
            .spaces
            .entry(space.clone())
            .or_insert_with(|| factory.create());
        if !memory.insert(embedding, payload) {
            return Err(EnterpriseMemoryError::InsertRejected);
        }
        tenant_memory.len += 1;
        Ok(())
    }

    /// Precision recall inside only the legacy tenant-wide candidate pool.
    ///
    /// A missing tenant has no observations. `k == 0` also returns an empty
    /// result without touching the underlying engine.
    pub fn recall(
        &self,
        scoped: TenantScope<MemoryQuery<'_>>,
    ) -> Result<Vec<MemoryObservation>, EnterpriseMemoryError> {
        let TenantScope { tenant, inner } = scoped;
        validate_tenant(&tenant)?;
        validate_embedding(inner.embedding, self.dim)?;
        if inner.k == 0 {
            return Ok(Vec::new());
        }
        let Some(memory) = self
            .tenants
            .get(&tenant)
            .and_then(|tenant| tenant.spaces.get(&MemorySpace::Tenant))
        else {
            return Ok(Vec::new());
        };
        let shortlist = inner.shortlist.max(inner.k).max(1);
        Ok(memory
            .recall(inner.embedding, inner.k, shortlist)
            .into_iter()
            .map(|(payload, similarity)| MemoryObservation {
                payload: payload.to_vec(),
                similarity,
            })
            .collect())
    }

    /// Recall across exactly the spaces listed by the supplied loadout.
    ///
    /// Every space has an independent OctaSoma index. Excluded spaces therefore
    /// cannot affect candidate generation, shortlist ordering or final ranking.
    /// Results are globally ranked by similarity, with deterministic space and
    /// payload tie-breakers, then truncated to `k`.
    pub fn recall_loadout(
        &self,
        scoped: TenantScope<LoadoutMemoryQuery<'_>>,
    ) -> Result<Vec<ScopedMemoryObservation>, EnterpriseMemoryError> {
        let TenantScope { tenant, inner } = scoped;
        validate_tenant(&tenant)?;
        validate_embedding(inner.embedding, self.dim)?;
        if inner.loadout.is_empty() {
            return Err(EnterpriseMemoryError::EmptyMemoryLoadout);
        }
        for space in inner.loadout.spaces() {
            space.validate()?;
        }
        if inner.k == 0 {
            return Ok(Vec::new());
        }
        let Some(tenant_memory) = self.tenants.get(&tenant) else {
            return Ok(Vec::new());
        };

        let shortlist = inner.shortlist.max(inner.k).max(1);
        let mut observations = Vec::new();
        for space in inner.loadout.spaces() {
            let Some(memory) = tenant_memory.spaces.get(space) else {
                continue;
            };
            observations.extend(
                memory
                    .recall(inner.embedding, inner.k, shortlist)
                    .into_iter()
                    .map(|(payload, similarity)| ScopedMemoryObservation {
                        space: space.clone(),
                        payload: payload.to_vec(),
                        similarity,
                    }),
            );
        }
        observations.sort_by(|left, right| {
            right
                .similarity
                .total_cmp(&left.similarity)
                .then_with(|| left.space.cmp(&right.space))
                .then_with(|| left.payload.cmp(&right.payload))
        });
        observations.truncate(inner.k);
        Ok(observations)
    }

    /// Recall only identity-bearing governed observations from the explicit loadout.
    pub fn recall_governed(
        &self,
        scoped: TenantScope<LoadoutMemoryQuery<'_>>,
    ) -> Result<Vec<GovernedMemoryObservation>, EnterpriseMemoryError> {
        let TenantScope { tenant, inner } = scoped;
        validate_tenant(&tenant)?;
        validate_embedding(inner.embedding, self.dim)?;
        if inner.loadout.is_empty() {
            return Err(EnterpriseMemoryError::EmptyMemoryLoadout);
        }
        for space in inner.loadout.spaces() {
            space.validate()?;
        }
        if inner.k == 0 {
            return Ok(Vec::new());
        }
        let Some(tenant_memory) = self.tenants.get(&tenant) else {
            return Ok(Vec::new());
        };

        let shortlist = inner.shortlist.max(inner.k).max(1);
        let mut observations = Vec::new();
        for space in inner.loadout.spaces() {
            let Some(memory) = tenant_memory.governed_spaces.get(space) else {
                continue;
            };
            for (encoded, similarity) in memory.recall(inner.embedding, inner.k, shortlist) {
                let (asset_id, payload) = decode_governed_payload(encoded).ok_or(
                    EnterpriseMemoryError::InvalidConfiguration("corrupt governed memory payload"),
                )?;
                observations.push(GovernedMemoryObservation {
                    asset_id,
                    space: space.clone(),
                    payload: payload.to_vec(),
                    similarity,
                });
            }
        }
        observations.sort_by(|left, right| {
            right
                .similarity
                .total_cmp(&left.similarity)
                .then_with(|| left.space.cmp(&right.space))
                .then_with(|| left.asset_id.cmp(&right.asset_id))
                .then_with(|| left.payload.cmp(&right.payload))
        });
        observations.truncate(inner.k);
        Ok(observations)
    }

    /// Number of governed memories in one exact tenant/space partition.
    pub fn governed_space_len(&self, tenant: &TenantId, space: &MemorySpace) -> usize {
        self.tenants
            .get(tenant)
            .and_then(|memory| memory.governed_spaces.get(space))
            .map_or(0, HybridMemory::len)
    }

    /// Number of memories owned by one tenant across all memory spaces.
    pub fn tenant_len(&self, tenant: &TenantId) -> usize {
        self.tenants.get(tenant).map_or(0, |memory| memory.len)
    }

    /// Number of memories in one exact tenant/space partition.
    pub fn space_len(&self, tenant: &TenantId, space: &MemorySpace) -> usize {
        self.tenants
            .get(tenant)
            .and_then(|memory| memory.spaces.get(space))
            .map_or(0, HybridMemory::len)
    }

    /// Number of tenant-local memory collections currently materialised.
    pub fn tenant_count(&self) -> usize {
        self.tenants.len()
    }

    /// Configured hard item limit for each tenant across all memory spaces.
    pub fn per_tenant_capacity(&self) -> usize {
        self.per_tenant_capacity
    }

    /// Bytes occupied by the one immutable SimHash projector shared by every
    /// tenant/space index created by this adapter.
    pub fn shared_projector_bytes(&self) -> usize {
        self.factory.projector_bytes()
    }
}

impl SemanticMemoryProvider for EnterpriseOctaSoma {
    fn insert_scoped(
        &mut self,
        scoped: TenantScope<ScopedMemoryWrite<'_>>,
    ) -> Result<(), EnterpriseMemoryError> {
        EnterpriseOctaSoma::insert_scoped(self, scoped)
    }

    fn recall_loadout(
        &self,
        scoped: TenantScope<LoadoutMemoryQuery<'_>>,
    ) -> Result<Vec<ScopedMemoryObservation>, EnterpriseMemoryError> {
        EnterpriseOctaSoma::recall_loadout(self, scoped)
    }
}

impl GovernedSemanticMemoryProvider for EnterpriseOctaSoma {
    fn insert_governed(
        &mut self,
        scoped: TenantScope<GovernedMemoryWrite<'_>>,
    ) -> Result<(), EnterpriseMemoryError> {
        EnterpriseOctaSoma::insert_governed(self, scoped)
    }

    fn recall_governed(
        &self,
        scoped: TenantScope<LoadoutMemoryQuery<'_>>,
    ) -> Result<Vec<GovernedMemoryObservation>, EnterpriseMemoryError> {
        EnterpriseOctaSoma::recall_governed(self, scoped)
    }
}

fn encode_governed_payload(asset_id: &MemoryAssetId, payload: &[u8]) -> Vec<u8> {
    let id = asset_id.as_str().as_bytes();
    let id_len = u32::try_from(id.len()).expect("validated memory asset ids fit in u32");
    let mut encoded = Vec::with_capacity(4 + id.len() + payload.len());
    encoded.extend_from_slice(&id_len.to_be_bytes());
    encoded.extend_from_slice(id);
    encoded.extend_from_slice(payload);
    encoded
}

fn decode_governed_payload(encoded: &[u8]) -> Option<(MemoryAssetId, &[u8])> {
    let header: [u8; 4] = encoded.get(..4)?.try_into().ok()?;
    let id_len = u32::from_be_bytes(header) as usize;
    let id_end = 4usize.checked_add(id_len)?;
    let id = std::str::from_utf8(encoded.get(4..id_end)?).ok()?;
    let asset_id = MemoryAssetId::new(id).ok()?;
    Some((asset_id, encoded.get(id_end..)?))
}

fn validate_tenant(tenant: &TenantId) -> Result<(), EnterpriseMemoryError> {
    if tenant.0.trim().is_empty() {
        Err(EnterpriseMemoryError::InvalidTenant)
    } else {
        Ok(())
    }
}

fn validate_embedding(embedding: &[f32], dim: usize) -> Result<(), EnterpriseMemoryError> {
    if embedding.len() != dim {
        return Err(EnterpriseMemoryError::DimensionMismatch {
            expected: dim,
            found: embedding.len(),
        });
    }
    if embedding.iter().any(|x| !x.is_finite()) {
        return Err(EnterpriseMemoryError::NonFiniteEmbedding);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn write<'a>(embedding: &'a [f32], payload: &'a [u8]) -> MemoryWrite<'a> {
        MemoryWrite { embedding, payload }
    }

    fn scoped_write<'a>(
        space: &'a MemorySpace,
        embedding: &'a [f32],
        payload: &'a [u8],
    ) -> ScopedMemoryWrite<'a> {
        ScopedMemoryWrite {
            space,
            embedding,
            payload,
        }
    }

    fn query(embedding: &[f32]) -> MemoryQuery<'_> {
        MemoryQuery {
            embedding,
            k: 1,
            shortlist: 8,
        }
    }

    fn loadout_query<'a>(
        embedding: &'a [f32],
        loadout: &'a MemoryLoadout,
        k: usize,
    ) -> LoadoutMemoryQuery<'a> {
        LoadoutMemoryQuery {
            embedding,
            k,
            shortlist: 8,
            loadout,
        }
    }

    #[test]
    fn recall_never_crosses_tenant_boundary() {
        let mut memory = EnterpriseOctaSoma::new(4, 64, 8, 42).unwrap();
        let v = [1.0, 0.0, 0.0, 0.0];

        memory
            .insert(TenantScope::new(
                TenantId("acme".into()),
                write(&v, b"acme-secret"),
            ))
            .unwrap();
        memory
            .insert(TenantScope::new(
                TenantId("globex".into()),
                write(&v, b"globex-secret"),
            ))
            .unwrap();

        let acme = memory
            .recall(TenantScope::new(TenantId("acme".into()), query(&v)))
            .unwrap();
        let globex = memory
            .recall(TenantScope::new(TenantId("globex".into()), query(&v)))
            .unwrap();

        assert_eq!(acme[0].payload, b"acme-secret");
        assert_eq!(globex[0].payload, b"globex-secret");
        assert_eq!(memory.tenant_count(), 2);
    }

    #[test]
    fn loadout_never_crosses_space_boundary() {
        let mut memory = EnterpriseOctaSoma::new(4, 64, 8, 42).unwrap();
        let tenant = TenantId("acme".into());
        let agent_a = MemorySpace::agent("agent-a").unwrap();
        let agent_b = MemorySpace::agent("agent-b").unwrap();
        let v = [1.0, 0.0, 0.0, 0.0];

        memory
            .insert_scoped(TenantScope::new(
                tenant.clone(),
                scoped_write(&agent_a, &v, b"a-secret"),
            ))
            .unwrap();
        memory
            .insert_scoped(TenantScope::new(
                tenant.clone(),
                scoped_write(&agent_b, &v, b"b-secret"),
            ))
            .unwrap();

        let loadout = MemoryLoadout::new([agent_a.clone()]).unwrap();
        let recalled = memory
            .recall_loadout(TenantScope::new(tenant, loadout_query(&v, &loadout, 4)))
            .unwrap();

        assert_eq!(recalled.len(), 1);
        assert_eq!(recalled[0].space, agent_a);
        assert_eq!(recalled[0].payload, b"a-secret");
    }

    #[test]
    fn loadout_combines_only_explicit_shared_spaces() {
        let mut memory = EnterpriseOctaSoma::new(4, 64, 8, 7).unwrap();
        let tenant = TenantId("acme".into());
        let project = MemorySpace::project("ccos").unwrap();
        let team = MemorySpace::team("runtime").unwrap();
        let excluded = MemorySpace::team("finance").unwrap();
        let v = [1.0, 0.0, 0.0, 0.0];

        for (space, payload) in [
            (&project, b"project".as_slice()),
            (&team, b"team".as_slice()),
            (&excluded, b"excluded".as_slice()),
        ] {
            memory
                .insert_scoped(TenantScope::new(
                    tenant.clone(),
                    scoped_write(space, &v, payload),
                ))
                .unwrap();
        }

        let loadout = MemoryLoadout::new([project.clone(), team.clone()]).unwrap();
        let recalled = memory
            .recall_loadout(TenantScope::new(tenant, loadout_query(&v, &loadout, 8)))
            .unwrap();
        let payloads: BTreeSet<_> = recalled
            .iter()
            .map(|observation| observation.payload.as_slice())
            .collect();

        assert_eq!(
            payloads,
            BTreeSet::from([b"project".as_slice(), b"team".as_slice()])
        );
        assert!(recalled
            .iter()
            .all(|observation| observation.space != excluded));
    }

    #[test]
    fn legacy_api_only_sees_tenant_space() {
        let mut memory = EnterpriseOctaSoma::new(4, 64, 8, 7).unwrap();
        let tenant = TenantId("acme".into());
        let agent = MemorySpace::agent("agent-a").unwrap();
        let v = [1.0, 0.0, 0.0, 0.0];

        memory
            .insert_scoped(TenantScope::new(
                tenant.clone(),
                scoped_write(&agent, &v, b"private"),
            ))
            .unwrap();
        assert!(memory
            .recall(TenantScope::new(tenant.clone(), query(&v)))
            .unwrap()
            .is_empty());

        memory
            .insert(TenantScope::new(tenant.clone(), write(&v, b"tenant-wide")))
            .unwrap();
        assert_eq!(
            memory.recall(TenantScope::new(tenant, query(&v))).unwrap()[0].payload,
            b"tenant-wide"
        );
    }

    #[test]
    fn quota_is_shared_across_all_spaces() {
        let mut memory = EnterpriseOctaSoma::new(4, 64, 1, 7).unwrap();
        let tenant = TenantId("acme".into());
        let agent = MemorySpace::agent("agent-a").unwrap();
        let team = MemorySpace::team("runtime").unwrap();
        let a = [1.0, 0.0, 0.0, 0.0];
        let b = [0.0, 1.0, 0.0, 0.0];

        memory
            .insert_scoped(TenantScope::new(
                tenant.clone(),
                scoped_write(&agent, &a, b"first"),
            ))
            .unwrap();
        assert_eq!(
            memory.insert_scoped(TenantScope::new(
                tenant.clone(),
                scoped_write(&team, &b, b"second"),
            )),
            Err(EnterpriseMemoryError::TenantCapacityExceeded { limit: 1 })
        );
        assert_eq!(memory.tenant_len(&tenant), 1);
        assert_eq!(memory.space_len(&tenant, &agent), 1);
        assert_eq!(memory.space_len(&tenant, &team), 0);
    }

    #[test]
    fn malformed_embedding_is_rejected_before_tenant_creation() {
        let mut memory = EnterpriseOctaSoma::new(4, 64, 8, 9).unwrap();
        let tenant = TenantId("acme".into());
        assert_eq!(
            memory.insert(TenantScope::new(tenant.clone(), write(&[1.0, 2.0], b"bad"),)),
            Err(EnterpriseMemoryError::DimensionMismatch {
                expected: 4,
                found: 2,
            })
        );
        assert_eq!(memory.tenant_count(), 0);

        assert_eq!(
            memory.insert(TenantScope::new(
                tenant,
                write(&[1.0, f32::NAN, 0.0, 0.0], b"nan"),
            )),
            Err(EnterpriseMemoryError::NonFiniteEmbedding)
        );
        assert_eq!(memory.tenant_count(), 0);
    }

    #[test]
    fn invalid_spaces_and_empty_loadouts_fail_closed() {
        assert_eq!(
            MemorySpace::agent("  "),
            Err(EnterpriseMemoryError::InvalidMemorySpace { kind: "agent" })
        );
        assert_eq!(
            MemoryLoadout::new([]),
            Err(EnterpriseMemoryError::EmptyMemoryLoadout)
        );

        let mut memory = EnterpriseOctaSoma::new(4, 64, 8, 11).unwrap();
        let invalid = MemorySpace::Team(String::new());
        let v = [1.0, 0.0, 0.0, 0.0];
        assert_eq!(
            memory.insert_scoped(TenantScope::new(
                TenantId("acme".into()),
                scoped_write(&invalid, &v, b"bad"),
            )),
            Err(EnterpriseMemoryError::InvalidMemorySpace { kind: "team" })
        );
        assert_eq!(memory.tenant_count(), 0);
    }

    #[test]
    fn provider_trait_preserves_explicit_loadout_scope() {
        let mut memory = EnterpriseOctaSoma::new(4, 64, 8, 17).unwrap();
        let tenant = TenantId("acme".into());
        let agent = MemorySpace::agent("agent-a").unwrap();
        let excluded = MemorySpace::agent("agent-b").unwrap();
        let v = [1.0, 0.0, 0.0, 0.0];

        SemanticMemoryProvider::insert_scoped(
            &mut memory,
            TenantScope::new(tenant.clone(), scoped_write(&agent, &v, b"visible")),
        )
        .unwrap();
        SemanticMemoryProvider::insert_scoped(
            &mut memory,
            TenantScope::new(tenant.clone(), scoped_write(&excluded, &v, b"excluded")),
        )
        .unwrap();

        let loadout = MemoryLoadout::new([agent.clone()]).unwrap();
        let recalled = SemanticMemoryProvider::recall_loadout(
            &memory,
            TenantScope::new(tenant, loadout_query(&v, &loadout, 4)),
        )
        .unwrap();

        assert_eq!(recalled.len(), 1);
        assert_eq!(recalled[0].space, agent);
        assert_eq!(recalled[0].payload, b"visible");
    }

    #[test]
    fn empty_or_unknown_tenant_fails_closed() {
        let memory = EnterpriseOctaSoma::new(4, 64, 8, 11).unwrap();
        let v = [1.0, 0.0, 0.0, 0.0];
        assert_eq!(
            memory.recall(TenantScope::new(TenantId(String::new()), query(&v))),
            Err(EnterpriseMemoryError::InvalidTenant)
        );
        assert!(memory
            .recall(TenantScope::new(TenantId("missing".into()), query(&v)))
            .unwrap()
            .is_empty());
    }
}

#[cfg(test)]
mod governed_provider_tests {
    use super::*;

    fn governed_write<'a>(
        asset_id: &'a MemoryAssetId,
        space: &'a MemorySpace,
        embedding: &'a [f32],
        payload: &'a [u8],
    ) -> GovernedMemoryWrite<'a> {
        GovernedMemoryWrite {
            asset_id,
            space,
            embedding,
            payload,
        }
    }

    #[test]
    fn governed_recall_preserves_identity_and_space() {
        let mut memory = EnterpriseOctaSoma::new(4, 64, 8, 42).unwrap();
        let tenant = TenantId("acme".into());
        let space = MemorySpace::team("runtime").unwrap();
        let id = MemoryAssetId::new("memory:runtime:1").unwrap();
        let vector = [1.0, 0.0, 0.0, 0.0];

        memory
            .insert_governed(TenantScope::new(
                tenant.clone(),
                governed_write(&id, &space, &vector, b"governed-payload"),
            ))
            .unwrap();

        let loadout = MemoryLoadout::new([space.clone()]).unwrap();
        let recalled = memory
            .recall_governed(TenantScope::new(
                tenant.clone(),
                LoadoutMemoryQuery {
                    embedding: &vector,
                    k: 4,
                    shortlist: 8,
                    loadout: &loadout,
                },
            ))
            .unwrap();

        assert_eq!(recalled.len(), 1);
        assert_eq!(recalled[0].asset_id, id);
        assert_eq!(recalled[0].space, space);
        assert_eq!(recalled[0].payload, b"governed-payload");
        assert_eq!(memory.governed_space_len(&tenant, &recalled[0].space), 1);
    }

    #[test]
    fn governed_recall_does_not_treat_legacy_payloads_as_identity_envelopes() {
        let mut memory = EnterpriseOctaSoma::new(4, 64, 8, 42).unwrap();
        let tenant = TenantId("acme".into());
        let vector = [1.0, 0.0, 0.0, 0.0];
        memory
            .insert(TenantScope::new(
                tenant.clone(),
                MemoryWrite {
                    embedding: &vector,
                    payload: b"legacy",
                },
            ))
            .unwrap();

        let loadout = MemoryLoadout::tenant_only();
        assert!(memory
            .recall_governed(TenantScope::new(
                tenant,
                LoadoutMemoryQuery {
                    embedding: &vector,
                    k: 4,
                    shortlist: 8,
                    loadout: &loadout,
                },
            ))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn governed_asset_ids_are_unique_per_tenant() {
        let mut memory = EnterpriseOctaSoma::new(4, 64, 8, 42).unwrap();
        let tenant = TenantId("acme".into());
        let first_space = MemorySpace::team("runtime").unwrap();
        let second_space = MemorySpace::project("ccos").unwrap();
        let id = MemoryAssetId::new("memory:unique").unwrap();
        let vector = [1.0, 0.0, 0.0, 0.0];

        memory
            .insert_governed(TenantScope::new(
                tenant.clone(),
                governed_write(&id, &first_space, &vector, b"first"),
            ))
            .unwrap();
        assert_eq!(
            memory.insert_governed(TenantScope::new(
                tenant,
                governed_write(&id, &second_space, &vector, b"duplicate"),
            )),
            Err(EnterpriseMemoryError::InsertRejected)
        );
    }

    #[test]
    fn governed_ids_may_repeat_across_tenants() {
        let mut memory = EnterpriseOctaSoma::new(4, 64, 8, 42).unwrap();
        let space = MemorySpace::Tenant;
        let id = MemoryAssetId::new("memory:tenant-local").unwrap();
        let vector = [1.0, 0.0, 0.0, 0.0];
        for tenant in ["acme", "globex"] {
            memory
                .insert_governed(TenantScope::new(
                    TenantId(tenant.into()),
                    governed_write(&id, &space, &vector, tenant.as_bytes()),
                ))
                .unwrap();
        }
        assert_eq!(memory.tenant_len(&TenantId("acme".into())), 1);
        assert_eq!(memory.tenant_len(&TenantId("globex".into())), 1);
    }
}
