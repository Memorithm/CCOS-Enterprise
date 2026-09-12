//! Durable governed-memory projection: lineage, trust and loadout.
//!
//! Embeddings are never stored here. Reconstruction uses public constructors.
//! Similarity is not an authority signal.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use ccos_enterprise_tenancy::TenantId;
use serde::{Deserialize, Serialize};

use crate::{
    MemoryAssetDescriptor, MemoryAssetId, MemoryAssetState, MemoryEvidenceRef, MemoryLineage,
    MemoryLineageGraph, MemoryLoadoutBinding, MemoryLoadoutPlan, MemoryLoadoutPlanError,
    MemorySpace, MemoryStratum, MemoryTrustMetadata, MemoryUsageMode, MemoryValidationState,
};

pub const GOVERNED_MEMORY_PROJECTION_VERSION: u32 = 1;
pub const GOVERNED_MEMORY_PROJECTION_FILE: &str = "governed-memory.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernedMemoryProjection {
    pub tenant: TenantId,
    pub graph: MemoryLineageGraph,
    pub trust: BTreeMap<MemoryAssetId, MemoryTrustMetadata>,
    pub loadout: MemoryLoadoutPlan,
}

#[derive(Debug)]
pub enum GovernedMemoryProjectionError {
    Io { path: PathBuf, source: io::Error },
    Corrupt { path: PathBuf, detail: String },
    UnsupportedVersion(u32),
    TenantMismatch { expected: String, found: String },
    TenantInvalid(String),
    DuplicateAsset(String),
    DuplicateTrust(String),
    DuplicateBinding(String),
    UnknownTrustAsset(String),
    Lineage(crate::MemoryGraphError),
    Trust(crate::MemoryTrustError),
    Memory(crate::MemoryError),
    Loadout(MemoryLoadoutPlanError),
}

impl std::fmt::Display for GovernedMemoryProjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "governed memory projection io {path:?}: {source}"),
            Self::Corrupt { path, detail } => {
                write!(f, "governed memory projection corrupt {path:?}: {detail}")
            }
            Self::UnsupportedVersion(v) => {
                write!(f, "unsupported governed memory projection version {v}")
            }
            Self::TenantMismatch { expected, found } => {
                write!(f, "governed memory projection tenant {found:?} != {expected:?}")
            }
            Self::TenantInvalid(id) => write!(f, "invalid tenant id in projection: {id:?}"),
            Self::DuplicateAsset(id) => write!(f, "duplicate memory asset in projection: {id}"),
            Self::DuplicateTrust(id) => write!(f, "duplicate trust row in projection: {id}"),
            Self::DuplicateBinding(space) => {
                write!(f, "duplicate loadout binding in projection: {space}")
            }
            Self::UnknownTrustAsset(id) => write!(f, "trust metadata names unknown asset {id}"),
            Self::Lineage(error) => write!(f, "governed memory lineage: {error}"),
            Self::Trust(error) => write!(f, "governed memory trust: {error}"),
            Self::Memory(error) => write!(f, "governed memory: {error}"),
            Self::Loadout(error) => write!(f, "governed memory loadout: {error}"),
        }
    }
}

impl std::error::Error for GovernedMemoryProjectionError {}

impl From<crate::MemoryGraphError> for GovernedMemoryProjectionError {
    fn from(value: crate::MemoryGraphError) -> Self {
        Self::Lineage(value)
    }
}
impl From<crate::MemoryTrustError> for GovernedMemoryProjectionError {
    fn from(value: crate::MemoryTrustError) -> Self {
        Self::Trust(value)
    }
}
impl From<crate::MemoryError> for GovernedMemoryProjectionError {
    fn from(value: crate::MemoryError) -> Self {
        Self::Memory(value)
    }
}
impl From<MemoryLoadoutPlanError> for GovernedMemoryProjectionError {
    fn from(value: MemoryLoadoutPlanError) -> Self {
        Self::Loadout(value)
    }
}

#[derive(Serialize, Deserialize)]
struct WireDocument {
    version: u32,
    tenant: String,
    assets: Vec<WireAsset>,
    trust: Vec<WireTrust>,
    loadout: Vec<WireBinding>,
}

#[derive(Serialize, Deserialize)]
struct WireAsset {
    id: String,
    space: String,
    stratum: String,
    parents: Vec<String>,
    evidence: Vec<String>,
    state: String,
}

#[derive(Serialize, Deserialize)]
struct WireTrust {
    asset_id: String,
    state: String,
    source_count: u32,
    independent_source_count: u32,
    contradiction_count: u32,
    verification_refs: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct WireBinding {
    space: String,
    priority: u16,
    usage: String,
}

impl GovernedMemoryProjection {
    pub fn new(
        tenant: TenantId,
        graph: MemoryLineageGraph,
        trust: BTreeMap<MemoryAssetId, MemoryTrustMetadata>,
        loadout: MemoryLoadoutPlan,
    ) -> Result<Self, GovernedMemoryProjectionError> {
        for id in trust.keys() {
            if graph.descriptor(id).is_none() {
                return Err(GovernedMemoryProjectionError::UnknownTrustAsset(
                    id.as_str().to_string(),
                ));
            }
        }
        Ok(Self {
            tenant,
            graph,
            trust,
            loadout,
        })
    }
}
