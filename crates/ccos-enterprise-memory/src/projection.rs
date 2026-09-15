//! Durable governed-memory projection: lineage, trust and loadout.
//!
//! Embeddings are never stored here. Reconstruction uses public constructors.
//! Similarity is not an authority signal. Writers must serialize governance
//! changes externally; atomic file replacement is not a multi-writer transaction
//! or protection against restoring an older, otherwise valid snapshot.

#[path = "projection_store.rs"]
mod store;
pub use store::{GovernedMemoryStore, GovernedMemoryStoreError};

#[path = "projection_codec.rs"]
mod codec;
pub use codec::{decode_governed_memory_projection, encode_governed_memory_projection};

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ccos_enterprise_tenancy::TenantId;
use serde::{Deserialize, Serialize};

use crate::{
    MemoryAssetDescriptor, MemoryAssetId, MemoryAssetState, MemoryEvidenceRef, MemoryLineage,
    MemoryLineageGraph, MemoryLoadoutBinding, MemoryLoadoutPlan, MemoryLoadoutPlanError,
    MemorySpace, MemoryStratum, MemoryTrustMetadata, MemoryUsageMode, MemoryValidationState,
};

pub const GOVERNED_MEMORY_PROJECTION_VERSION: u32 = 1;
pub const GOVERNED_MEMORY_PROJECTION_FILE: &str = "governed-memory.json";
/// Hard byte bound on one encoded governance projection, excluding embeddings.
pub const MAX_GOVERNED_MEMORY_PROJECTION_BYTES: usize = 16 * 1024 * 1024;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

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
            Self::Io { path, source } => {
                write!(f, "governed memory projection io {path:?}: {source}")
            }
            Self::Corrupt { path, detail } => {
                write!(f, "governed memory projection corrupt {path:?}: {detail}")
            }
            Self::UnsupportedVersion(v) => {
                write!(f, "unsupported governed memory projection version {v}")
            }
            Self::TenantMismatch { expected, found } => {
                write!(
                    f,
                    "governed memory projection tenant {found:?} != {expected:?}"
                )
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
#[serde(deny_unknown_fields)]
struct WireDocument {
    version: u32,
    tenant: String,
    assets: Vec<WireAsset>,
    trust: Vec<WireTrust>,
    loadout: Vec<WireBinding>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAsset {
    id: String,
    space: String,
    stratum: String,
    parents: Vec<String>,
    evidence: Vec<String>,
    state: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireTrust {
    asset_id: String,
    state: String,
    source_count: u32,
    independent_source_count: u32,
    contradiction_count: u32,
    verification_refs: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

    fn to_wire(&self) -> WireDocument {
        let mut assets: Vec<WireAsset> = self
            .graph
            .entries()
            .into_iter()
            .map(|(descriptor, state)| WireAsset {
                id: descriptor.id.as_str().to_string(),
                space: encode_space(&descriptor.space),
                stratum: encode_stratum(descriptor.stratum).to_string(),
                parents: descriptor
                    .lineage
                    .parents()
                    .map(|id| id.as_str().to_string())
                    .collect(),
                evidence: descriptor
                    .lineage
                    .evidence()
                    .map(|id| id.as_str().to_string())
                    .collect(),
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
            return Err(GovernedMemoryProjectionError::UnsupportedVersion(
                doc.version,
            ));
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
            let parents = asset
                .parents
                .into_iter()
                .map(MemoryAssetId::new)
                .collect::<Result<Vec<_>, _>>()?;
            let evidence = asset
                .evidence
                .into_iter()
                .map(MemoryEvidenceRef::new)
                .collect::<Result<Vec<_>, _>>()?;
            if parents.iter().collect::<BTreeSet<_>>().len() != parents.len()
                || evidence.iter().collect::<BTreeSet<_>>().len() != evidence.len()
            {
                return Err(projection_corrupt(
                    "duplicate lineage parent or evidence reference",
                ));
            }
            let lineage = if parents.is_empty() {
                MemoryLineage::root(evidence)?
            } else {
                MemoryLineage::derived(parents, evidence)?
            };
            descriptors.push(MemoryAssetDescriptor::new(id, space, stratum, lineage)?);
            states.push(decode_asset_state(&asset.state)?);
        }
        let graph = MemoryLineageGraph::restore(descriptors.into_iter().zip(states))?;
        let mut trust = BTreeMap::new();
        for row in doc.trust {
            let id = MemoryAssetId::new(row.asset_id.clone())?;
            if trust.contains_key(&id) {
                return Err(GovernedMemoryProjectionError::DuplicateTrust(row.asset_id));
            }
            let state = decode_trust_state(&row.state)?;
            let metadata = MemoryTrustMetadata::new(
                state,
                row.source_count,
                row.independent_source_count,
                row.contradiction_count,
                row.verification_refs,
            )?;
            trust.insert(id, metadata);
        }
        let loadout = MemoryLoadoutPlan::new(
            doc.loadout
                .into_iter()
                .map(|binding| {
                    Ok(MemoryLoadoutBinding::new(
                        decode_space(&binding.space)?,
                        binding.priority,
                        decode_usage(&binding.usage)?,
                    )?)
                })
                .collect::<Result<Vec<_>, GovernedMemoryProjectionError>>()?,
        )?;
        GovernedMemoryProjection::new(tenant, graph, trust, loadout)
    }
}

pub fn load_governed_memory_projection(
    root: impl AsRef<Path>,
    expected_tenant: Option<&TenantId>,
) -> Result<Option<GovernedMemoryProjection>, GovernedMemoryProjectionError> {
    let root = root.as_ref();
    let path = root.join(GOVERNED_MEMORY_PROJECTION_FILE);
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(projection_io(&path, error)),
    };
    let mut bytes = Vec::new();
    file.take(MAX_GOVERNED_MEMORY_PROJECTION_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| projection_io(&path, error))?;
    if bytes.len() > MAX_GOVERNED_MEMORY_PROJECTION_BYTES {
        return Err(projection_corrupt("projection exceeds the 16 MiB byte limit"));
    }
    let doc: WireDocument = serde_json::from_slice(&bytes)
        .map_err(|error| projection_corrupt(&error.to_string()))?;
    Ok(Some(GovernedMemoryProjection::from_wire(
        expected_tenant,
        doc,
    )?))
}

pub fn save_governed_memory_projection(
    root: impl AsRef<Path>,
    projection: &GovernedMemoryProjection,
) -> Result<PathBuf, GovernedMemoryProjectionError> {
    let root = root.as_ref();
    if root.as_os_str().is_empty() {
        return Err(projection_io(
            root,
            io::Error::new(io::ErrorKind::InvalidInput, "projection root is empty"),
        ));
    }
    create_projection_root(root)?;
    let root = fs::canonicalize(root).map_err(|error| projection_io(root, error))?;
    let final_path = root.join(GOVERNED_MEMORY_PROJECTION_FILE);
    let current = load_governed_memory_projection(&root, None)?;
    if let Some(current) = current {
        if current.tenant != projection.tenant {
            return Err(GovernedMemoryProjectionError::TenantMismatch {
                expected: current.tenant.as_str().to_string(),
                found: projection.tenant.as_str().to_string(),
            });
        }
    }
    let bytes = encode_governed_memory_projection(projection)?;
    let ordinal = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    let temp_path = root.join(format!(
        ".{GOVERNED_MEMORY_PROJECTION_FILE}.{}.{}.tmp",
        std::process::id(),
        ordinal
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut temp_file = options
        .open(&temp_path)
        .map_err(|error| projection_io(&temp_path, error))?;
    temp_file
        .write_all(&bytes)
        .and_then(|()| temp_file.sync_all())
        .map_err(|error| projection_io(&temp_path, error))?;
    if let Err(error) = fs::rename(&temp_path, &final_path) {
        let _ = fs::remove_file(&temp_path);
        return Err(projection_io(&final_path, error));
    }
    sync_directory(&root).map_err(|error| projection_io(&root, error))?;
    Ok(final_path)
}

pub(crate) fn create_projection_root(root: &Path) -> Result<(), GovernedMemoryProjectionError> {
    match fs::create_dir(root) {
        Ok(()) => sync_directory(root.parent().unwrap_or_else(|| Path::new(".")))
            .map_err(|error| projection_io(root, error)),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(root).map_err(|error| projection_io(root, error))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(projection_io(
                    root,
                    io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "projection root is not a real directory",
                    ),
                ));
            }
            Ok(())
        }
        Err(error) => Err(projection_io(root, error)),
    }
}

pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

pub(crate) fn projection_corrupt(detail: &str) -> GovernedMemoryProjectionError {
    GovernedMemoryProjectionError::Corrupt {
        path: PathBuf::from(GOVERNED_MEMORY_PROJECTION_FILE),
        detail: detail.to_string(),
    }
}

pub(crate) fn projection_io(path: &Path, source: io::Error) -> GovernedMemoryProjectionError {
    GovernedMemoryProjectionError::Io {
        path: path.to_path_buf(),
        source,
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

fn decode_space(raw: &str) -> Result<MemorySpace, GovernedMemoryProjectionError> {
    if raw == "tenant" {
        return Ok(MemorySpace::Tenant);
    }
    let (kind, id) = raw
        .split_once(':')
        .ok_or_else(|| projection_corrupt("memory space must contain a kind prefix"))?;
    match kind {
        "project" => Ok(MemorySpace::project(id.to_string())?),
        "team" => Ok(MemorySpace::team(id.to_string())?),
        "agent" => Ok(MemorySpace::agent(id.to_string())?),
        _ => Err(projection_corrupt("unknown memory space kind")),
    }
}

fn encode_stratum(stratum: MemoryStratum) -> &'static str {
    match stratum {
        MemoryStratum::Evidence => "evidence",
        MemoryStratum::Episode => "episode",
        MemoryStratum::Entity => "entity",
        MemoryStratum::Pattern => "pattern",
        MemoryStratum::Procedure => "procedure",
    }
}

fn decode_stratum(raw: &str) -> Result<MemoryStratum, GovernedMemoryProjectionError> {
    match raw {
        "evidence" => Ok(MemoryStratum::Evidence),
        "episode" => Ok(MemoryStratum::Episode),
        "entity" => Ok(MemoryStratum::Entity),
        "pattern" => Ok(MemoryStratum::Pattern),
        "procedure" => Ok(MemoryStratum::Procedure),
        _ => Err(projection_corrupt("unknown memory stratum")),
    }
}

fn encode_asset_state(state: MemoryAssetState) -> &'static str {
    match state {
        MemoryAssetState::Active => "active",
        MemoryAssetState::Stale => "stale",
        MemoryAssetState::Invalidated => "invalidated",
    }
}

fn decode_asset_state(raw: &str) -> Result<MemoryAssetState, GovernedMemoryProjectionError> {
    match raw {
        "active" => Ok(MemoryAssetState::Active),
        "stale" => Ok(MemoryAssetState::Stale),
        "invalidated" => Ok(MemoryAssetState::Invalidated),
        _ => Err(projection_corrupt("unknown memory asset state")),
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

fn decode_trust_state(raw: &str) -> Result<MemoryValidationState, GovernedMemoryProjectionError> {
    match raw {
        "unverified" => Ok(MemoryValidationState::Unverified),
        "corroborated" => Ok(MemoryValidationState::Corroborated),
        "verified" => Ok(MemoryValidationState::Verified),
        "disputed" => Ok(MemoryValidationState::Disputed),
        "quarantined" => Ok(MemoryValidationState::Quarantined),
        _ => Err(projection_corrupt("unknown trust state")),
    }
}

fn encode_usage(usage: MemoryUsageMode) -> &'static str {
    match usage {
        MemoryUsageMode::Bootstrap => "bootstrap",
        MemoryUsageMode::OnDemand => "on-demand",
    }
}

fn decode_usage(raw: &str) -> Result<MemoryUsageMode, GovernedMemoryProjectionError> {
    match raw {
        "bootstrap" => Ok(MemoryUsageMode::Bootstrap),
        "on-demand" => Ok(MemoryUsageMode::OnDemand),
        _ => Err(projection_corrupt("unknown memory usage mode")),
    }
}
