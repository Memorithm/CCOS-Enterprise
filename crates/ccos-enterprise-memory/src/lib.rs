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
    load_governed_memory_projection, save_governed_memory_projection, GovernedMemoryProjection,
    GovernedMemoryProjectionError, GOVERNED_MEMORY_PROJECTION_FILE,
    GOVERNED_MEMORY_PROJECTION_VERSION,
};

mod attestation;
pub use attestation::{attest_governed_context, MemoryAdmissionReason, MemoryContextAttestation};

/// Path-safe label for memory asset ids, evidence refs and non-tenant space ids.
///
/// Same alphabet as tenant ids, plus `:` so evidence refs like `audit:evt-1`
/// remain valid. Dots, slashes and `..` stay forbidden because these labels
/// become file components on the durable projection path.
pub fn is_canonical_memory_label(id: &str) -> bool {
    if id.len() > 128 || id.contains("..") {
        return false;
    }
    let mut bytes = id.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_lowercase() || first.is_ascii_digit())
        && bytes.all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-' || b == b':'
        })
}

/// A semantic-memory namespace inside one tenant.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemorySpace {
    Tenant,
    Project(String),
    Team(String),
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
    pub fn validate(&self) -> Result<(), MemoryError> {
        let (kind, id) = match self {
            Self::Tenant => return Ok(()),
            Self::Project(id) => ("project", id),
            Self::Team(id) => ("team", id),
            Self::Agent(id) => ("agent", id),
        };
        if !is_canonical_memory_label(id) {
            Err(MemoryError::InvalidMemorySpace { kind })
        } else {
            Ok(())
        }
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemoryStratum {
    Evidence,
    Episode,
    Context,
    Pattern,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemoryAssetId(String);

impl MemoryAssetId {
    pub fn new(value: impl Into<String>) -> Result<Self, MemoryError> {
        let value = value.into();
        if !is_canonical_memory_label(&value) {
            Err(MemoryError::InvalidMemoryAssetId)
        } else {
            Ok(Self(value))
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemoryEvidenceRef(String);

impl MemoryEvidenceRef {
    pub fn new(value: impl Into<String>) -> Result<Self, MemoryError> {
        let value = value.into();
        if !is_canonical_memory_label(&value) {
            Err(MemoryError::InvalidEvidenceRef)
        } else {
            Ok(Self(value))
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

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
            return Err(MemoryError::EvidenceRequiresSource);
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
    pub fn is_root(&self) -> bool {
        self.parents.is_empty()
    }
}

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

#[derive(Debug, Clone, Copy)]
pub struct ScopedMemoryWrite<'a> {
    pub space: &'a MemorySpace,
    pub embedding: &'a [f32],
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct LoadoutMemoryQuery<'a> {
    pub embedding: &'a [f32],
    pub k: usize,
    pub shortlist: usize,
    pub loadout: &'a MemoryLoadout,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScopedMemoryObservation {
    pub space: MemorySpace,
    pub payload: Vec<u8>,
    pub similarity: f32,
}

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
                write!(f, "{kind} memory-space id is empty or not canonical")
            }
            Self::InvalidMemoryAssetId => {
                write!(f, "memory asset id is empty or not canonical")
            }
            Self::InvalidEvidenceRef => {
                write!(f, "memory evidence reference is empty or not canonical")
            }
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
                write!(f, "embedding dimension mismatch: expected {expected}, found {found}")
            }
            Self::NonFiniteEmbedding => write!(f, "embedding contains a non-finite value"),
            Self::TenantCapacityExceeded { limit } => {
                write!(f, "tenant semantic-memory capacity exceeded (limit {limit})")
            }
            Self::InsertRejected => write!(f, "semantic-memory provider rejected the insertion"),
        }
    }
}

impl std::error::Error for MemoryError {}

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
