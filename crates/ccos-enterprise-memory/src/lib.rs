//! Backend-neutral agent-memory contract for CCOS Enterprise.
//!
//! This crate owns the CCOS vocabulary for composing semantic-memory domains.
//! It deliberately contains no vector index, database, network transport, or
//! vendor-specific implementation. Providers receive an explicit tenant scope
//! and an explicit memory loadout for every operation.
//!
//! The contract is original to CCOS Enterprise. External memory systems may
//! inform product requirements, but their APIs, schemas, storage layouts, and
//! source code are not part of this interface.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;

use ccos_enterprise_tenancy::TenantScope;

mod lineage_graph;
pub use lineage_graph::{
    MemoryAssetState, MemoryGraphError, MemoryInvalidationReport, MemoryLineageGraph,
};

mod loadout_policy;
pub use loadout_policy::{
    MemoryLoadoutBinding, MemoryLoadoutPlan, MemoryLoadoutPlanError, MemoryUsageMode,
    MAX_MEMORY_LOADOUT_BINDINGS,
};

mod recall_budget;
pub use recall_budget::{
    BudgetedMemoryRecall, MemoryRecallBudget, MemoryRecallBudgetError, SemanticMemoryProviderExt,
    MAX_MEMORY_RECALL_ITEMS, MAX_MEMORY_RECALL_PAYLOAD_BYTES, MAX_MEMORY_RECALL_SHORTLIST,
};

/// A semantic-memory namespace inside one tenant.
///
/// The variants model CCOS collaboration boundaries rather than backend
/// partitions. A provider is responsible for enforcing the isolation implied by
/// the selected space before retrieval candidates are produced.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemorySpace {
    /// Tenant-wide shared memory.
    Tenant,
    /// Project-specific shared memory.
    Project(String),
    /// Team-specific shared memory.
    Team(String),
    /// Private memory for one agent identity.
    Agent(String),
}

impl MemorySpace {
    pub fn project(id: impl Into<String>) -> Result<Self, MemoryError> {
        validated_space(Self::Project(id.into()))
    }

    pub fn team(id: impl Into<String>) -> Result<Self, MemoryError> {
        validated_space(Self::Team(id.into()))
    }

    pub fn agent(id: impl Into<String>) -> Result<Self, MemoryError> {
        validated_space(Self::Agent(id.into()))
    }

    /// Revalidate a space constructed through an enum variant directly.
    ///
    /// Provider boundaries call this method so malformed raw variants fail
    /// closed even when a caller bypasses the convenience constructors.
    pub fn validate(&self) -> Result<(), MemoryError> {
        let (kind, id) = match self {
            Self::Tenant => return Ok(()),
            Self::Project(id) => ("project", id),
            Self::Team(id) => ("team", id),
            Self::Agent(id) => ("agent", id),
        };
        if id.trim().is_empty() {
            Err(MemoryError::InvalidMemorySpace { kind })
        } else {
            Ok(())
        }
    }
}

/// Explicit set of memory spaces that may participate in one recall.
///
/// The set is private and validated on construction. Providers still recheck
/// each space at their trust boundary so direct enum construction cannot weaken
/// isolation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryLoadout {
    spaces: BTreeSet<MemorySpace>,
}

impl MemoryLoadout {
    pub fn new(spaces: impl IntoIterator<Item = MemorySpace>) -> Result<Self, MemoryError> {
        let spaces: BTreeSet<_> = spaces.into_iter().collect();
        if spaces.is_empty() {
            return Err(MemoryError::EmptyMemoryLoadout);
        }
        for space in &spaces {
            space.validate()?;
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

/// Semantic distance from direct evidence to increasingly reusable knowledge.
///
/// The names describe CCOS lifecycle intent rather than a storage layout. A
/// backend may index every stratum identically; governance and lineage remain
/// authoritative regardless of retrieval technology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemoryStratum {
    /// Direct observation, tool result, conversation fragment or artifact fact.
    Evidence,
    /// A bounded interaction or task episode derived from evidence.
    Episode,
    /// Reusable situation, project or operational context derived from episodes.
    Context,
    /// Durable generalized pattern that remains linked to its derivation chain.
    Pattern,
}

/// Stable CCOS identity for one governed memory asset.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemoryAssetId(String);

impl MemoryAssetId {
    pub fn new(value: impl Into<String>) -> Result<Self, MemoryError> {
        let value = value.into();
        if value.trim().is_empty() {
            Err(MemoryError::InvalidMemoryAssetId)
        } else {
            Ok(Self(value))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque reference to immutable source evidence outside the memory graph.
///
/// Examples include an audit event id, artifact digest, commit-qualified source
/// location or signed observation id. The contract deliberately does not assign
/// authority to any particular reference syntax.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemoryEvidenceRef(String);

impl MemoryEvidenceRef {
    pub fn new(value: impl Into<String>) -> Result<Self, MemoryError> {
        let value = value.into();
        if value.trim().is_empty() {
            Err(MemoryError::InvalidEvidenceRef)
        } else {
            Ok(Self(value))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Provenance edges retained independently from semantic payloads and indexes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryLineage {
    parents: BTreeSet<MemoryAssetId>,
    evidence: BTreeSet<MemoryEvidenceRef>,
}

impl MemoryLineage {
    /// Lineage for a direct evidence asset.
    pub fn root(
        evidence: impl IntoIterator<Item = MemoryEvidenceRef>,
    ) -> Result<Self, MemoryError> {
        let evidence: BTreeSet<_> = evidence.into_iter().collect();
        if evidence.is_empty() {
            return Err(MemoryError::EvidenceRequiresSource);
        }
        Ok(Self {
            parents: BTreeSet::new(),
            evidence,
        })
    }

    /// Lineage for synthesized memory.
    ///
    /// At least one governed parent is mandatory. Additional direct evidence is
    /// optional and can record corroborating observations discovered during the
    /// synthesis step.
    pub fn derived(
        parents: impl IntoIterator<Item = MemoryAssetId>,
        evidence: impl IntoIterator<Item = MemoryEvidenceRef>,
    ) -> Result<Self, MemoryError> {
        let parents: BTreeSet<_> = parents.into_iter().collect();
        if parents.is_empty() {
            return Err(MemoryError::DerivedMemoryRequiresParent);
        }
        Ok(Self {
            parents,
            evidence: evidence.into_iter().collect(),
        })
    }

    pub fn parents(&self) -> impl Iterator<Item = &MemoryAssetId> {
        self.parents.iter()
    }

    pub fn evidence(&self) -> impl Iterator<Item = &MemoryEvidenceRef> {
        self.evidence.iter()
    }

    pub fn is_root(&self) -> bool {
        self.parents.is_empty()
    }
}

/// Governed metadata for a memory asset, independent from its payload/index.
///
/// This descriptor makes provenance a first-class invariant: evidence assets
/// must point to immutable external evidence, while every synthesized asset must
/// retain at least one parent edge. Self-dependencies are rejected at creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryAssetDescriptor {
    pub id: MemoryAssetId,
    pub space: MemorySpace,
    pub stratum: MemoryStratum,
    pub lineage: MemoryLineage,
}

impl MemoryAssetDescriptor {
    pub fn new(
        id: MemoryAssetId,
        space: MemorySpace,
        stratum: MemoryStratum,
        lineage: MemoryLineage,
    ) -> Result<Self, MemoryError> {
        space.validate()?;
        if lineage.parents.contains(&id) {
            return Err(MemoryError::SelfReferentialLineage);
        }
        match stratum {
            MemoryStratum::Evidence if !lineage.is_root() => {
                return Err(MemoryError::EvidenceCannotHaveParents);
            }
            MemoryStratum::Evidence if lineage.evidence.is_empty() => {
                return Err(MemoryError::EvidenceRequiresSource);
            }
            MemoryStratum::Episode | MemoryStratum::Context | MemoryStratum::Pattern
                if lineage.is_root() =>
            {
                return Err(MemoryError::DerivedMemoryRequiresParent);
            }
            _ => {}
        }
        Ok(Self {
            id,
            space,
            stratum,
            lineage,
        })
    }
}

/// Write request for one exact memory space.
#[derive(Debug, Clone, Copy)]
pub struct ScopedMemoryWrite<'a> {
    pub space: &'a MemorySpace,
    pub embedding: &'a [f32],
    pub payload: &'a [u8],
}

/// Recall request over one explicit memory loadout.
#[derive(Debug, Clone, Copy)]
pub struct LoadoutMemoryQuery<'a> {
    pub embedding: &'a [f32],
    pub k: usize,
    pub shortlist: usize,
    pub loadout: &'a MemoryLoadout,
}

/// Owned provider result with the exact CCOS memory space that produced it.
#[derive(Debug, Clone, PartialEq)]
pub struct ScopedMemoryObservation {
    pub space: MemorySpace,
    pub payload: Vec<u8>,
    pub similarity: f32,
}

/// Normalized failure surface for governed semantic-memory providers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryError {
    InvalidConfiguration(&'static str),
    InvalidTenant,
    InvalidMemorySpace { kind: &'static str },
    InvalidMemoryAssetId,
    InvalidEvidenceRef,
    EmptyMemoryLoadout,
    EvidenceRequiresSource,
    EvidenceCannotHaveParents,
    DerivedMemoryRequiresParent,
    SelfReferentialLineage,
    DimensionMismatch { expected: usize, found: usize },
    NonFiniteEmbedding,
    TenantCapacityExceeded { limit: usize },
    InsertRejected,
}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(detail) => {
                write!(f, "invalid memory configuration: {detail}")
            }
            Self::InvalidTenant => write!(f, "tenant id must not be empty"),
            Self::InvalidMemorySpace { kind } => {
                write!(f, "{kind} memory-space id must not be empty")
            }
            Self::InvalidMemoryAssetId => write!(f, "memory asset id must not be empty"),
            Self::InvalidEvidenceRef => write!(f, "memory evidence reference must not be empty"),
            Self::EmptyMemoryLoadout => write!(f, "memory loadout must contain at least one space"),
            Self::EvidenceRequiresSource => {
                write!(f, "evidence memory must reference at least one source")
            }
            Self::EvidenceCannotHaveParents => {
                write!(f, "evidence memory cannot depend on another memory asset")
            }
            Self::DerivedMemoryRequiresParent => {
                write!(f, "derived memory must retain at least one parent asset")
            }
            Self::SelfReferentialLineage => write!(f, "memory lineage cannot reference itself"),
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
            Self::InsertRejected => write!(f, "semantic-memory provider rejected the insertion"),
        }
    }
}

impl std::error::Error for MemoryError {}

/// Minimal backend contract for CCOS scoped semantic memory.
///
/// The trait intentionally exposes only explicit-space writes and explicit-
/// loadout recalls. Backend-specific convenience APIs may exist separately, but
/// generic CCOS code cannot accidentally perform an unscoped semantic lookup.
pub trait SemanticMemoryProvider {
    fn insert_scoped(
        &mut self,
        scoped: TenantScope<ScopedMemoryWrite<'_>>,
    ) -> Result<(), MemoryError>;

    fn recall_loadout(
        &self,
        scoped: TenantScope<LoadoutMemoryQuery<'_>>,
    ) -> Result<Vec<ScopedMemoryObservation>, MemoryError>;
}

fn validated_space(space: MemorySpace) -> Result<MemorySpace, MemoryError> {
    space.validate()?;
    Ok(space)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset_id(value: &str) -> MemoryAssetId {
        MemoryAssetId::new(value).unwrap()
    }

    fn evidence_ref(value: &str) -> MemoryEvidenceRef {
        MemoryEvidenceRef::new(value).unwrap()
    }

    #[test]
    fn malformed_space_ids_fail_closed() {
        assert_eq!(
            MemorySpace::agent("  "),
            Err(MemoryError::InvalidMemorySpace { kind: "agent" })
        );
        assert_eq!(
            MemorySpace::Project(String::new()).validate(),
            Err(MemoryError::InvalidMemorySpace { kind: "project" })
        );
    }

    #[test]
    fn empty_loadout_is_rejected() {
        assert_eq!(MemoryLoadout::new([]), Err(MemoryError::EmptyMemoryLoadout));
    }

    #[test]
    fn loadout_deduplicates_and_orders_spaces_deterministically() {
        let project = MemorySpace::project("ccos").unwrap();
        let team = MemorySpace::team("runtime").unwrap();
        let loadout =
            MemoryLoadout::new([team.clone(), project.clone(), MemorySpace::Tenant, team]).unwrap();

        assert_eq!(
            loadout.spaces().cloned().collect::<Vec<_>>(),
            vec![
                MemorySpace::Tenant,
                project,
                MemorySpace::team("runtime").unwrap()
            ]
        );
    }

    #[test]
    fn evidence_assets_require_external_source_and_no_parent() {
        assert_eq!(
            MemoryLineage::root([]),
            Err(MemoryError::EvidenceRequiresSource)
        );

        let id = asset_id("mem:evidence:1");
        let lineage =
            MemoryLineage::derived([asset_id("mem:other")], [evidence_ref("audit:7")]).unwrap();
        assert_eq!(
            MemoryAssetDescriptor::new(id, MemorySpace::Tenant, MemoryStratum::Evidence, lineage),
            Err(MemoryError::EvidenceCannotHaveParents)
        );
    }

    #[test]
    fn derived_assets_cannot_drop_parent_lineage() {
        let root = MemoryLineage::root([evidence_ref("artifact:sha256:abc")]).unwrap();
        assert_eq!(
            MemoryAssetDescriptor::new(
                asset_id("mem:episode:1"),
                MemorySpace::Tenant,
                MemoryStratum::Episode,
                root
            ),
            Err(MemoryError::DerivedMemoryRequiresParent)
        );
    }

    #[test]
    fn lineage_is_deduplicated_and_deterministic() {
        let parent_a = asset_id("mem:a");
        let parent_b = asset_id("mem:b");
        let lineage = MemoryLineage::derived(
            [parent_b.clone(), parent_a.clone(), parent_b],
            [evidence_ref("audit:2"), evidence_ref("audit:1")],
        )
        .unwrap();

        assert_eq!(
            lineage.parents().cloned().collect::<Vec<_>>(),
            vec![parent_a, asset_id("mem:b")]
        );
        assert_eq!(
            lineage
                .evidence()
                .map(MemoryEvidenceRef::as_str)
                .collect::<Vec<_>>(),
            vec!["audit:1", "audit:2"]
        );
    }

    #[test]
    fn self_referential_lineage_fails_closed() {
        let id = asset_id("mem:context:1");
        let lineage = MemoryLineage::derived([id.clone()], []).unwrap();
        assert_eq!(
            MemoryAssetDescriptor::new(
                id,
                MemorySpace::project("ccos").unwrap(),
                MemoryStratum::Context,
                lineage
            ),
            Err(MemoryError::SelfReferentialLineage)
        );
    }

    #[test]
    fn valid_derivation_preserves_space_stratum_and_lineage() {
        let parent = asset_id("mem:episode:1");
        let descriptor = MemoryAssetDescriptor::new(
            asset_id("mem:context:1"),
            MemorySpace::project("ccos").unwrap(),
            MemoryStratum::Context,
            MemoryLineage::derived([parent.clone()], [evidence_ref("commit:abc")]).unwrap(),
        )
        .unwrap();

        assert_eq!(descriptor.stratum, MemoryStratum::Context);
        assert_eq!(descriptor.lineage.parents().next(), Some(&parent));
    }
}
