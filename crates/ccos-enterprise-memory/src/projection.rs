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
    fn from(value: crate::MemoryGraphError) -> Self { Self::Lineage(value) }
}
impl From<crate::MemoryTrustError> for GovernedMemoryProjectionError {
    fn from(value: crate::MemoryTrustError) -> Self { Self::Trust(value) }
}
impl From<crate::MemoryError> for GovernedMemoryProjectionError {
    fn from(value: crate::MemoryError) -> Self { Self::Memory(value) }
}
impl From<MemoryLoadoutPlanError> for GovernedMemoryProjectionError {
    fn from(value: MemoryLoadoutPlanError) -> Self { Self::Loadout(value) }
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
        Ok(Self { tenant, graph, trust, loadout })
    }

    fn to_wire(&self) -> WireDocument {
        let mut assets: Vec<WireAsset> = self
            .graph
            .entries()
            .into_iter()
            .map(|(descriptor, state)| WireAsset {
                id: descriptor.id.as_str().to_string(),
                space: encode_space(&descriptor.space),
                stratum: encode_stratum(descriptor.stratum).to_string(),
                parents: descriptor.lineage.parents().map(|id| id.as_str().to_string()).collect(),
                evidence: descriptor.lineage.evidence().map(|id| id.as_str().to_string()).collect(),
                state: encode_asset_state(state).to_string(),
            })
            .collect();
        assets.sort_by(|a, b| a.id.cmp(&b.id));
        let mut trust: Vec<WireTrust> = self
            .trust
            .iter()
            .map(|(id, meta)| WireTrust {
                asset_id: id.as_str().to_string(),
                state: encode_trust_state(meta.state()).to_string(),
                source_count: meta.source_count(),
                independent_source_count: meta.independent_source_count(),
                contradiction_count: meta.contradiction_count(),
                verification_refs: meta.verification_refs().map(str::to_string).collect(),
            })
            .collect();
        trust.sort_by(|a, b| a.asset_id.cmp(&b.asset_id));
        let loadout = self
            .loadout
            .bindings()
            .map(|binding| WireBinding {
                space: encode_space(&binding.space),
                priority: binding.priority,
                usage: encode_usage(binding.usage).to_string(),
            })
            .collect();
        WireDocument {
            version: GOVERNED_MEMORY_PROJECTION_VERSION,
            tenant: self.tenant.as_str().to_string(),
            assets,
            trust,
            loadout,
        }
    }

    fn from_wire(
        expected_tenant: Option<&TenantId>,
        doc: WireDocument,
    ) -> Result<Self, GovernedMemoryProjectionError> {
        if doc.version != GOVERNED_MEMORY_PROJECTION_VERSION {
            return Err(GovernedMemoryProjectionError::UnsupportedVersion(doc.version));
        }
        let tenant = TenantId::validated(&doc.tenant)
            .ok_or_else(|| GovernedMemoryProjectionError::TenantInvalid(doc.tenant.clone()))?;
        if let Some(expected) = expected_tenant {
            if expected.as_str() != tenant.as_str() {
                return Err(GovernedMemoryProjectionError::TenantMismatch {
                    expected: expected.as_str().to_string(),
                    found: tenant.as_str().to_string(),
                });
            }
        }
        let mut seen_assets = BTreeSet::new();
        let mut descriptors = Vec::new();
        let mut states = Vec::new();
        for asset in doc.assets {
            if !seen_assets.insert(asset.id.clone()) {
                return Err(GovernedMemoryProjectionError::DuplicateAsset(asset.id));
            }
            let id = MemoryAssetId::new(asset.id)?;
            let space = decode_space(&asset.space)?;
            let stratum = decode_stratum(&asset.stratum)?;
            let parents = asset.parents.into_iter().map(MemoryAssetId::new).collect::<Result<Vec<_>, _>>()?;
            let evidence = asset.evidence.into_iter().map(MemoryEvidenceRef::new).collect::<Result<Vec<_>, _>>()?;
            let lineage = if parents.is_empty() {
                MemoryLineage::root(evidence)?
            } else {
                MemoryLineage::derived(parents, evidence)?
            };
            let descriptor = MemoryAssetDescriptor::new(id.clone(), space, stratum, lineage)?;
            states.push((id, decode_asset_state(&asset.state)?));
            descriptors.push(descriptor);
        }
        let graph = MemoryLineageGraph::restore(descriptors, states)?;
        let mut trust = BTreeMap::new();
        for row in doc.trust {
            if trust.keys().any(|id: &MemoryAssetId| id.as_str() == row.asset_id) {
                return Err(GovernedMemoryProjectionError::DuplicateTrust(row.asset_id));
            }
            let id = MemoryAssetId::new(row.asset_id)?;
            if graph.descriptor(&id).is_none() {
                return Err(GovernedMemoryProjectionError::UnknownTrustAsset(id.as_str().to_string()));
            }
            trust.insert(id, MemoryTrustMetadata::new(
                decode_trust_state(&row.state)?,
                row.source_count,
                row.independent_source_count,
                row.contradiction_count,
                row.verification_refs,
            )?);
        }
        let mut seen_spaces = BTreeSet::new();
        let mut bindings = Vec::new();
        for row in doc.loadout {
            if !seen_spaces.insert(row.space.clone()) {
                return Err(GovernedMemoryProjectionError::DuplicateBinding(row.space));
            }
            bindings.push(MemoryLoadoutBinding::new(
                decode_space(&row.space)?,
                row.priority,
                decode_usage(&row.usage)?,
            )?);
        }
        Self::new(tenant, graph, trust, MemoryLoadoutPlan::new(bindings)?)
    }
}

pub fn save_governed_memory_projection(
    root: &Path,
    projection: &GovernedMemoryProjection,
) -> Result<PathBuf, GovernedMemoryProjectionError> {
    fs::create_dir_all(root).map_err(|source| GovernedMemoryProjectionError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    let path = root.join(GOVERNED_MEMORY_PROJECTION_FILE);
    let bytes = serde_json::to_vec_pretty(&projection.to_wire()).map_err(|error| {
        GovernedMemoryProjectionError::Corrupt { path: path.clone(), detail: error.to_string() }
    })?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut file = OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)
            .map_err(|source| GovernedMemoryProjectionError::Io { path: tmp.clone(), source })?;
        file.write_all(&bytes).map_err(|source| GovernedMemoryProjectionError::Io { path: tmp.clone(), source })?;
        file.sync_all().map_err(|source| GovernedMemoryProjectionError::Io { path: tmp.clone(), source })?;
    }
    fs::rename(&tmp, &path).map_err(|source| GovernedMemoryProjectionError::Io { path: path.clone(), source })?;
    if let Some(dir) = path.parent() {
        if let Ok(dirf) = File::open(dir) { let _ = dirf.sync_all(); }
    }
    Ok(path)
}

pub fn load_governed_memory_projection(
    root: &Path,
    expected_tenant: Option<&TenantId>,
) -> Result<Option<GovernedMemoryProjection>, GovernedMemoryProjectionError> {
    let path = root.join(GOVERNED_MEMORY_PROJECTION_FILE);
    match fs::read(&path) {
        Ok(bytes) => {
            let doc: WireDocument = serde_json::from_slice(&bytes).map_err(|error| {
                GovernedMemoryProjectionError::Corrupt { path: path.clone(), detail: error.to_string() }
            })?;
            Ok(Some(GovernedMemoryProjection::from_wire(expected_tenant, doc)?))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(GovernedMemoryProjectionError::Io { path, source }),
    }
}

fn encode_space(space: &MemorySpace) -> String {
    match space {
        MemorySpace::Tenant => "tenant".to_string(),
        MemorySpace::Project(id) => format!("project:{id}"),
        MemorySpace::Team(id) => format!("team:{id}"),
        MemorySpace::Agent(id) => format!("agent:{id}"),
    }
}
fn decode_space(value: &str) -> Result<MemorySpace, GovernedMemoryProjectionError> {
    if value == "tenant" { return Ok(MemorySpace::Tenant); }
    if let Some(id) = value.strip_prefix("project:") { return Ok(MemorySpace::project(id)?); }
    if let Some(id) = value.strip_prefix("team:") { return Ok(MemorySpace::team(id)?); }
    if let Some(id) = value.strip_prefix("agent:") { return Ok(MemorySpace::agent(id)?); }
    Err(GovernedMemoryProjectionError::Corrupt {
        path: PathBuf::from(GOVERNED_MEMORY_PROJECTION_FILE),
        detail: format!("unknown memory space {value:?}"),
    })
}
fn encode_stratum(stratum: MemoryStratum) -> &'static str {
    match stratum {
        MemoryStratum::Evidence => "evidence",
        MemoryStratum::Episode => "episode",
        MemoryStratum::Context => "context",
        MemoryStratum::Pattern => "pattern",
    }
}
fn decode_stratum(value: &str) -> Result<MemoryStratum, crate::MemoryError> {
    match value {
        "evidence" => Ok(MemoryStratum::Evidence),
        "episode" => Ok(MemoryStratum::Episode),
        "context" => Ok(MemoryStratum::Context),
        "pattern" => Ok(MemoryStratum::Pattern),
        _ => Err(crate::MemoryError::InvalidConfiguration("unknown memory stratum")),
    }
}
fn encode_asset_state(state: MemoryAssetState) -> &'static str {
    match state {
        MemoryAssetState::Active => "active",
        MemoryAssetState::Stale => "stale",
        MemoryAssetState::Invalidated => "invalidated",
    }
}
fn decode_asset_state(value: &str) -> Result<MemoryAssetState, crate::MemoryError> {
    match value {
        "active" => Ok(MemoryAssetState::Active),
        "stale" => Ok(MemoryAssetState::Stale),
        "invalidated" => Ok(MemoryAssetState::Invalidated),
        _ => Err(crate::MemoryError::InvalidConfiguration("unknown memory asset state")),
    }
}
fn encode_trust_state(state: MemoryValidationState) -> &'static str {
    match state {
        MemoryValidationState::Unverified => "unverified",
        MemoryValidationState::Corroborated => "corroborated",
        MemoryValidationState::Verified => "verified",
        MemoryValidationState::Disputed => "disputed",
        MemoryValidationState::Quarantined => "quarantined",
    }
}
fn decode_trust_state(value: &str) -> Result<MemoryValidationState, crate::MemoryError> {
    match value {
        "unverified" => Ok(MemoryValidationState::Unverified),
        "corroborated" => Ok(MemoryValidationState::Corroborated),
        "verified" => Ok(MemoryValidationState::Verified),
        "disputed" => Ok(MemoryValidationState::Disputed),
        "quarantined" => Ok(MemoryValidationState::Quarantined),
        _ => Err(crate::MemoryError::InvalidConfiguration("unknown memory trust state")),
    }
}
fn encode_usage(usage: MemoryUsageMode) -> &'static str {
    match usage {
        MemoryUsageMode::Bootstrap => "bootstrap",
        MemoryUsageMode::OnDemand => "on-demand",
        MemoryUsageMode::BootstrapAndOnDemand => "bootstrap-and-on-demand",
    }
}
fn decode_usage(value: &str) -> Result<MemoryUsageMode, crate::MemoryError> {
    match value {
        "bootstrap" => Ok(MemoryUsageMode::Bootstrap),
        "on-demand" => Ok(MemoryUsageMode::OnDemand),
        "bootstrap-and-on-demand" => Ok(MemoryUsageMode::BootstrapAndOnDemand),
        _ => Err(crate::MemoryError::InvalidConfiguration("unknown memory usage mode")),
    }
}
