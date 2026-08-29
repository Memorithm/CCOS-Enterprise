//! Governed OctaSoma adapter for CCOS Enterprise.
//!
//! This crate is the only supported direct Enterprise dependency on OctaSoma.
//! It keeps semantic-memory indexes physically isolated by tenant and memory
//! space, enforces a hard per-tenant item quota before mutation, and returns
//! owned recall observations. Similarity is evidence for higher layers; it is
//! never authorization or causal truth.
//!
//! The legacy tenant-wide API remains available and maps exclusively to the
//! [`MemorySpace::Tenant`] partition. Agent/team/project memories are only
//! reachable through an explicit [`MemoryLoadout`], so an excluded space never
//! participates in candidate generation or ranking.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ccos_enterprise_tenancy::{TenantId, TenantScope};
use octasoma::HybridMemory;

/// A physically isolated semantic-memory namespace inside one tenant.
///
/// Spaces are deliberately ordered so loadout recall can use deterministic
/// tie-breaking without depending on insertion order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemorySpace {
    /// Knowledge visible through the legacy tenant-wide API.
    Tenant,
    /// Project-specific shared memory.
    Project(String),
    /// Team-specific shared memory.
    Team(String),
    /// Private memory for one agent identity.
    Agent(String),
}

impl MemorySpace {
    pub fn project(id: impl Into<String>) -> Result<Self, EnterpriseMemoryError> {
        validated_space(Self::Project(id.into()))
    }

    pub fn team(id: impl Into<String>) -> Result<Self, EnterpriseMemoryError> {
        validated_space(Self::Team(id.into()))
    }

    pub fn agent(id: impl Into<String>) -> Result<Self, EnterpriseMemoryError> {
        validated_space(Self::Agent(id.into()))
    }
}

/// Explicit set of memory spaces that may participate in one recall.
///
/// Construction validates every scoped identifier and rejects an empty set.
/// The set is private so callers cannot create an invalid loadout after
/// validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryLoadout {
    spaces: BTreeSet<MemorySpace>,
}

impl MemoryLoadout {
    pub fn new(
        spaces: impl IntoIterator<Item = MemorySpace>,
    ) -> Result<Self, EnterpriseMemoryError> {
        let spaces: BTreeSet<_> = spaces.into_iter().collect();
        if spaces.is_empty() {
            return Err(EnterpriseMemoryError::EmptyMemoryLoadout);
        }
        for space in &spaces {
            validate_space(space)?;
        }
        Ok(Self { spaces })
    }

    /// A loadout containing only the tenant-wide partition.
    pub fn tenant_only() -> Self {
        Self {
            spaces: BTreeSet::from([MemorySpace::Tenant]),
        }
    }

    pub fn spaces(&self) -> impl Iterator<Item = &MemorySpace> {
        self.spaces.iter()
    }

    pub fn len(&self) -> usize {
        self.spaces.len()
    }

    pub fn is_empty(&self) -> bool {
        self.spaces.is_empty()
    }
}

/// A tenant-scoped write into the legacy tenant-wide semantic-memory space.
#[derive(Debug, Clone, Copy)]
pub struct MemoryWrite<'a> {
    pub embedding: &'a [f32],
    pub payload: &'a [u8],
}

/// A tenant-scoped write into one explicit semantic-memory space.
#[derive(Debug, Clone, Copy)]
pub struct ScopedMemoryWrite<'a> {
    pub space: &'a MemorySpace,
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

/// A precision recall request over an explicit memory loadout.
#[derive(Debug, Clone, Copy)]
pub struct LoadoutMemoryQuery<'a> {
    pub embedding: &'a [f32],
    pub k: usize,
    pub shortlist: usize,
    pub loadout: &'a MemoryLoadout,
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

/// An owned observation returned by a loadout recall, including the exact space
/// that produced it for downstream policy/audit decisions.
#[derive(Debug, Clone, PartialEq)]
pub struct ScopedMemoryObservation {
    pub space: MemorySpace,
    pub payload: Vec<u8>,
    pub similarity: f32,
}

/// A fail-closed rejection from the Enterprise memory boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnterpriseMemoryError {
    InvalidConfiguration(&'static str),
    InvalidTenant,
    InvalidMemorySpace { kind: &'static str },
    EmptyMemoryLoadout,
    DimensionMismatch { expected: usize, found: usize },
    NonFiniteEmbedding,
    TenantCapacityExceeded { limit: usize },
    InsertRejected,
}

impl fmt::Display for EnterpriseMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(detail) => {
                write!(f, "invalid memory configuration: {detail}")
            }
            Self::InvalidTenant => write!(f, "tenant id must not be empty"),
            Self::InvalidMemorySpace { kind } => {
                write!(f, "{kind} memory-space id must not be empty")
            }
            Self::EmptyMemoryLoadout => write!(f, "memory loadout must contain at least one space"),
            Self::DimensionMismatch { expected, found } => {
                write!(
                    f,
                    "embedding dimension mismatch: expected {expected}, found {found}"
                )
            }
            Self::NonFiniteEmbedding => write!(f, "embedding contains a non-finite value"),
            Self::TenantCapacityExceeded { limit } => {
                write!(
                    f,
                    "tenant semantic-memory capacity exceeded (limit {limit})"
                )
            }
            Self::InsertRejected => write!(f, "OctaSoma rejected the validated insertion"),
        }
    }
}

impl std::error::Error for EnterpriseMemoryError {}

#[derive(Default)]
struct TenantMemory {
    len: usize,
    spaces: BTreeMap<MemorySpace, HybridMemory>,
}

/// One isolated collection of OctaSoma indexes per Enterprise tenant.
///
/// Candidate sets, payload arenas and indexes are not shared across tenants or
/// memory spaces. The adapter deliberately exposes no raw OctaSoma handle:
/// callers must cross the typed [`TenantScope`] boundary for every read and
/// write. The configured quota is enforced across all spaces owned by a tenant.
pub struct EnterpriseOctaSoma {
    dim: usize,
    seed: u64,
    bits: usize,
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
            seed,
            bits,
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

    fn insert_inner(
        &mut self,
        tenant: TenantId,
        space: &MemorySpace,
        embedding: &[f32],
        payload: &[u8],
    ) -> Result<(), EnterpriseMemoryError> {
        validate_tenant(&tenant)?;
        validate_space(space)?;
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

        let dim = self.dim;
        let seed = self.seed;
        let bits = self.bits;
        let tenant_memory = self.tenants.entry(tenant).or_default();
        let memory = tenant_memory
            .spaces
            .entry(space.clone())
            .or_insert_with(|| HybridMemory::new(dim, seed, bits));
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
            validate_space(space)?;
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
}

fn validated_space(space: MemorySpace) -> Result<MemorySpace, EnterpriseMemoryError> {
    validate_space(&space)?;
    Ok(space)
}

fn validate_space(space: &MemorySpace) -> Result<(), EnterpriseMemoryError> {
    let (kind, id) = match space {
        MemorySpace::Tenant => return Ok(()),
        MemorySpace::Project(id) => ("project", id),
        MemorySpace::Team(id) => ("team", id),
        MemorySpace::Agent(id) => ("agent", id),
    };
    if id.trim().is_empty() {
        Err(EnterpriseMemoryError::InvalidMemorySpace { kind })
    } else {
        Ok(())
    }
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
