//! Backend-neutral agent-memory contract for CCOS Enterprise.
//!
//! This crate owns the CCOS vocabulary for composing semantic-memory domains.
//! It contains no vector index, network transport, or vendor-specific provider.
//! Providers receive an explicit tenant scope and memory loadout for every
//! operation. The optional use of the projection functions persists governance
//! metadata, not embeddings or provider internals.
//!
//! The contract is original to CCOS Enterprise. External memory systems may
//! inform product requirements, but their APIs, schemas, storage layouts, and
//! source code are not part of this interface.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;

use ccos_enterprise_tenancy::TenantScope;

mod bundle;
pub use bundle::{
    MemoryBundleEntry, MemoryBundleError, MemoryBundleManifest, MemoryBundleVersion,
    MemoryContentDigest, MemoryProviderReference,
};

mod context_budget;
pub use context_budget::{
    assemble_bootstrap_context, MemoryContextAssembly, MemoryContextBudget, MemoryContextError,
    MAX_MEMORY_CONTEXT_ITEMS, MAX_MEMORY_CONTEXT_PAYLOAD_BYTES,
};

mod governed_recall;
pub use governed_recall::{
    admit_governed_recall, GovernedRecallGate, GovernedRecallGateError, GovernedRecallTrustPolicy,
};

mod governed_recall_budget;
pub use governed_recall_budget::GovernedSemanticMemoryProviderExt;

mod governed_context;
pub use governed_context::{assemble_governed_bootstrap_context, GovernedMemoryContextAssembly};

mod governed_provider;
pub use governed_provider::{
    GovernedMemoryObservation, GovernedMemoryWrite, GovernedSemanticMemoryProvider,
};

mod lineage_graph;
pub use lineage_graph::{
    MemoryAssetState, MemoryGraphError, MemoryInvalidationReport, MemoryLineageGraph,
};

mod loadout_policy;
pub use loadout_policy::{
    MemoryLoadoutBinding, MemoryLoadoutPlan, MemoryLoadoutPlanError, MemoryUsageMode,
    MAX_MEMORY_LOADOUT_BINDINGS,
};

mod promotion;
pub use promotion::{evaluate_memory_promotion, MemoryPromotionCandidate, MemoryPromotionError};

mod recall_budget;
pub use recall_budget::{
    BudgetedMemoryRecall, MemoryRecallBudget, MemoryRecallBudgetError, SemanticMemoryProviderExt,
    MAX_MEMORY_RECALL_ITEMS, MAX_MEMORY_RECALL_PAYLOAD_BYTES, MAX_MEMORY_RECALL_SHORTLIST,
};

mod retention;
pub use retention::{
    apply_memory_retention, MemoryRetentionError, MemoryRetentionOutcome, MemoryRetentionPolicy,
};

mod trust;
pub use trust::{MemoryTrustError, MemoryTrustMetadata, MemoryValidationState};

mod projection;
pub use projection::{
    decode_governed_memory_projection, encode_governed_memory_projection,
    load_governed_memory_projection, save_governed_memory_projection, GovernedMemoryProjection,
    GovernedMemoryProjectionError, GovernedMemoryStore, GovernedMemoryStoreError,
    GOVERNED_MEMORY_PROJECTION_FILE, GOVERNED_MEMORY_PROJECTION_VERSION,
    MAX_GOVERNED_MEMORY_PROJECTION_BYTES,
};

mod attestation;
pub use attestation::{attest_governed_context, MemoryAdmissionReason, MemoryContextAttestation};

/// A semantic-memory namespace inside one tenant.
///
/// The variants model CCOS collaboration boundaries rather than backend
/// partitions. A provider is responsible for enforcing the isolation implied by
/// the selected space before retrieval candidates are produced. Space labels
/// are opaque data, not paths; a persistence adapter must never join them to a
/// filesystem root without its own validated path mapping.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemoryStratum {
    Evidence,
    Episode,
    Entity,
    Pattern,
    Procedure,
}

/// Stable identity of a memory asset. It is intentionally independent from the
/// provider's opaque record id so provider migration does not rewrite lineage.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemoryAssetId(String);

impl MemoryAssetId {
    pub fn new(value: impl Into<String>) -> Result<Self, MemoryError> {
        let value = value.into();
        if value.trim().is_empty() {
            Err(MemoryError::EmptyMemoryAssetId)
        } else {
            Ok(Self(value))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MemoryAssetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Stable reference to source evidence, verification material or an immutable
/// audit artifact. This is a reference, not an assertion that the evidence is
/// true or sufficient.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemoryEvidenceRef(String);

impl MemoryEvidenceRef {
    pub fn new(value: impl Into<String>) -> Result<Self, MemoryError> {
        let value = value.into();
        if value.trim().is_empty() {
            Err(MemoryError::EmptyEvidenceReference)
        } else {
            Ok(Self(value))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MemoryEvidenceRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Provenance of a memory asset. A root must point to evidence. A derived asset
/// must point to at least one parent asset and may also retain direct evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryLineage {
    parents: BTreeSet<MemoryAssetId>,
    evidence: BTreeSet<MemoryEvidenceRef>,
}

impl MemoryLineage {
    pub fn root(
        evidence: impl IntoIterator<Item = MemoryEvidenceRef>,
    ) -> Result<Self, MemoryError> {
        let evidence: BTreeSet<_> = evidence.into_iter().collect();
        if evidence.is_empty() {
            return Err(MemoryError::RootMemoryRequiresEvidence);
        }
        Ok(Self {
            parents: BTreeSet::new(),
            evidence,
        })
    }

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
}

/// Canonical metadata for one memory asset.
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
        Ok(Self {
            id,
            space,
            stratum,
            lineage,
        })
    }
}

/// A provider write that is scoped to exactly one memory space.
#[derive(Debug, Clone, Copy)]
pub struct ScopedMemoryWrite<'a> {
    pub space: &'a MemorySpace,
    pub embedding: &'a [f32],
    pub payload: &'a [u8],
}

/// Query across exactly the memory spaces selected by the caller's loadout.
#[derive(Debug, Clone, Copy)]
pub struct LoadoutMemoryQuery<'a> {
    pub embedding: &'a [f32],
    pub loadout: &'a MemoryLoadout,
    pub k: usize,
    pub shortlist: usize,
}

/// A provider observation that preserves the exact space used to produce it.
#[derive(Debug, Clone, PartialEq)]
pub struct ScopedMemoryObservation {
    pub space: MemorySpace,
    pub payload: Vec<u8>,
    pub similarity: f32,
}

pub trait SemanticMemoryProvider {
    fn insert(&mut self, scoped: TenantScope<ScopedMemoryWrite<'_>>) -> Result<(), MemoryError>;

    fn recall(
        &self,
        scoped: TenantScope<LoadoutMemoryQuery<'_>>,
    ) -> Result<Vec<ScopedMemoryObservation>, MemoryError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryError {
    InvalidConfiguration(&'static str),
    InvalidTenant,
    InvalidMemorySpace { kind: &'static str },
    EmptyMemoryLoadout,
    EmptyMemoryAssetId,
    EmptyEvidenceReference,
    RootMemoryRequiresEvidence,
    DerivedMemoryRequiresParent,
    TenantCapacityExceeded { limit: usize },
    InsertRejected,
    ProviderFailure(String),
}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => write!(f, "invalid memory configuration: {message}"),
            Self::InvalidTenant => write!(f, "invalid tenant"),
            Self::InvalidMemorySpace { kind } => write!(f, "invalid {kind} memory space"),
            Self::EmptyMemoryLoadout => write!(f, "memory loadout must contain at least one space"),
            Self::EmptyMemoryAssetId => write!(f, "memory asset id must not be empty"),
            Self::EmptyEvidenceReference => write!(f, "memory evidence reference must not be empty"),
            Self::RootMemoryRequiresEvidence => write!(f, "root memory requires at least one evidence reference"),
            Self::DerivedMemoryRequiresParent => write!(f, "derived memory requires at least one parent asset"),
            Self::TenantCapacityExceeded { limit } => write!(f, "tenant memory capacity {limit} exceeded"),
            Self::InsertRejected => write!(f, "memory provider rejected insertion"),
            Self::ProviderFailure(message) => write!(f, "memory provider failure: {message}"),
        }
    }
}

impl std::error::Error for MemoryError {}

fn validated_space(space: MemorySpace) -> Result<MemorySpace, MemoryError> {
    space.validate()?;
    Ok(space)
}
