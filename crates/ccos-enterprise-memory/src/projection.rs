//! Durable governed-memory projection: lineage, trust and loadout.
//!
//! Embeddings are never stored here. Reconstruction uses public constructors.
//! Similarity is not an authority signal. Writers must serialize governance
//! changes externally; atomic file replacement is not a multi-writer transaction
//! or protection against restoring an older, otherwise valid snapshot.

#[path = "projection_store.rs"]
mod store;
pub use store::{GovernedMemoryStore, GovernedMemoryStoreError};

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
            let descriptor = MemoryAssetDescriptor::new(id.clone(), space, stratum, lineage)?;
            states.push((id, decode_asset_state(&asset.state)?));
            descriptors.push(descriptor);
        }
        let graph = MemoryLineageGraph::restore(descriptors, states)?;
        let mut trust = BTreeMap::new();
        for row in doc.trust {
            let id = MemoryAssetId::new(row.asset_id)?;
            if trust.contains_key(&id) {
                return Err(GovernedMemoryProjectionError::DuplicateTrust(
                    id.as_str().to_string(),
                ));
            }
            if graph.descriptor(&id).is_none() {
                return Err(GovernedMemoryProjectionError::UnknownTrustAsset(
                    id.as_str().to_string(),
                ));
            }
            trust.insert(
                id,
                MemoryTrustMetadata::new(
                    decode_trust_state(&row.state)?,
                    row.source_count,
                    row.independent_source_count,
                    row.contradiction_count,
                    row.verification_refs,
                )?,
            );
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

fn projection_corrupt(detail: &str) -> GovernedMemoryProjectionError {
    GovernedMemoryProjectionError::Corrupt {
        path: PathBuf::from(GOVERNED_MEMORY_PROJECTION_FILE),
        detail: detail.to_string(),
    }
}

fn projection_io(path: &Path, source: io::Error) -> GovernedMemoryProjectionError {
    GovernedMemoryProjectionError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn create_projection_root(root: &Path) -> Result<(), GovernedMemoryProjectionError> {
    let mut missing = Vec::new();
    let mut cursor = root;
    while !cursor
        .try_exists()
        .map_err(|error| projection_io(cursor, error))?
    {
        missing.push(cursor.to_path_buf());
        cursor = parent_directory(cursor);
    }
    fs::create_dir_all(root).map_err(|error| projection_io(root, error))?;
    for directory in missing.iter().rev() {
        let parent = parent_directory(directory);
        sync_directory(parent).map_err(|error| projection_io(parent, error))?;
    }
    Ok(())
}

struct TemporaryProjection(PathBuf);

impl Drop for TemporaryProjection {
    fn drop(&mut self) {
        // Only our exclusively created temporary file is eligible for cleanup.
        // Cleanup failure cannot turn a failed publication into success.
        let _ = fs::remove_file(&self.0);
    }
}

fn publish_projection(
    root: &Path,
    path: &Path,
    bytes: &[u8],
    sync_parent: impl FnOnce(&Path) -> io::Result<()>,
) -> Result<(), GovernedMemoryProjectionError> {
    for _ in 0..128 {
        let ordinal = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let tmp = root.join(format!(
            ".governed-memory-{}-{ordinal}.tmp",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = match options.open(&tmp) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(projection_io(&tmp, error)),
        };
        let temporary = TemporaryProjection(tmp);
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| projection_io(&temporary.0, error))?;
        drop(file);
        fs::rename(&temporary.0, path).map_err(|error| projection_io(path, error))?;
        // Publication may already be visible if this fails. Report the error;
        // callers must reload/stop rather than assume rollback or durability.
        sync_parent(root).map_err(|error| projection_io(root, error))?;
        return Ok(());
    }
    Err(projection_io(
        root,
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "temporary projection names exhausted",
        ),
    ))
}

/// Validate and atomically replace one bounded governance projection.
///
/// Temporary files are exclusively created, synced and renamed; directory-sync
/// errors propagate. An error after rename means publication is uncertain, not
/// rolled back. The caller must stop or reload its authority state in that case.
/// The root must be controlled by the deployment, not an untrusted actor.
pub fn save_governed_memory_projection(
    root: &Path,
    projection: &GovernedMemoryProjection,
) -> Result<PathBuf, GovernedMemoryProjectionError> {
    // Public projection fields can be changed after `new`; validate again before
    // touching the filesystem, using exactly the same boundary as restore.
    let checked =
        GovernedMemoryProjection::from_wire(Some(&projection.tenant), projection.to_wire())?;
    let bytes = serde_json::to_vec_pretty(&checked.to_wire())
        .map_err(|error| projection_corrupt(&error.to_string()))?;
    if bytes.len() > MAX_GOVERNED_MEMORY_PROJECTION_BYTES {
        return Err(projection_corrupt(
            "projection exceeds the 16 MiB byte limit",
        ));
    }
    let root = if root.as_os_str().is_empty() {
        Path::new(".")
    } else {
        root
    };
    create_projection_root(root)?;
    let path = root.join(GOVERNED_MEMORY_PROJECTION_FILE);
    publish_projection(root, &path, &bytes, sync_directory)?;
    Ok(path)
}

/// Restore a bounded projection through validating domain constructors.
///
/// Served callers must pass `Some(expected_tenant)`; `None` is intended only for
/// inspection/import before a tenant is selected. A missing file is `None`, never
/// a replacement empty projection after corruption or another I/O error.
pub fn load_governed_memory_projection(
    root: &Path,
    expected_tenant: Option<&TenantId>,
) -> Result<Option<GovernedMemoryProjection>, GovernedMemoryProjectionError> {
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
        return Err(projection_corrupt(
            "projection exceeds the 16 MiB byte limit",
        ));
    }
    let doc: WireDocument =
        serde_json::from_slice(&bytes).map_err(|error| GovernedMemoryProjectionError::Corrupt {
            path,
            detail: error.to_string(),
        })?;
    Ok(Some(GovernedMemoryProjection::from_wire(
        expected_tenant,
        doc,
    )?))
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
    if value == "tenant" {
        return Ok(MemorySpace::Tenant);
    }
    if let Some(id) = value.strip_prefix("project:") {
        return Ok(MemorySpace::project(id)?);
    }
    if let Some(id) = value.strip_prefix("team:") {
        return Ok(MemorySpace::team(id)?);
    }
    if let Some(id) = value.strip_prefix("agent:") {
        return Ok(MemorySpace::agent(id)?);
    }
    Err(projection_corrupt(&format!(
        "unknown memory space {value:?}"
    )))
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
        _ => Err(crate::MemoryError::InvalidConfiguration(
            "unknown memory stratum",
        )),
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
        _ => Err(crate::MemoryError::InvalidConfiguration(
            "unknown memory asset state",
        )),
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
        _ => Err(crate::MemoryError::InvalidConfiguration(
            "unknown memory trust state",
        )),
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
        _ => Err(crate::MemoryError::InvalidConfiguration(
            "unknown memory usage mode",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let ordinal = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "ccos-projection-audit-{}-{ordinal}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn projection() -> GovernedMemoryProjection {
        let id = MemoryAssetId::new("root").unwrap();
        let mut graph = MemoryLineageGraph::new();
        graph
            .register(
                MemoryAssetDescriptor::new(
                    id.clone(),
                    MemorySpace::Tenant,
                    MemoryStratum::Evidence,
                    MemoryLineage::root([MemoryEvidenceRef::new("audit:root").unwrap()]).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        let loadout = MemoryLoadoutPlan::new([MemoryLoadoutBinding::new(
            MemorySpace::Tenant,
            1,
            MemoryUsageMode::Bootstrap,
        )
        .unwrap()])
        .unwrap();
        GovernedMemoryProjection::new(
            TenantId::validated("acme").unwrap(),
            graph,
            BTreeMap::from([(id, MemoryTrustMetadata::unverified(1))]),
            loadout,
        )
        .unwrap()
    }

    #[test]
    fn projection_round_trip_is_deterministic_and_tenant_bound() {
        let dir = TestDirectory::new();
        let mut original = projection();
        original
            .graph
            .invalidate(&MemoryAssetId::new("root").unwrap())
            .unwrap();
        let path = save_governed_memory_projection(&dir.0, &original).unwrap();
        let bytes = fs::read(&path).unwrap();
        assert_eq!(
            load_governed_memory_projection(&dir.0, Some(&original.tenant)).unwrap(),
            Some(original.clone())
        );
        save_governed_memory_projection(&dir.0, &original).unwrap();
        assert_eq!(bytes, fs::read(&path).unwrap());
        assert!(matches!(
            load_governed_memory_projection(&dir.0, Some(&TenantId::validated("other").unwrap())),
            Err(GovernedMemoryProjectionError::TenantMismatch { .. })
        ));
    }

    #[test]
    fn mutated_projection_cannot_replace_a_valid_snapshot() {
        let dir = TestDirectory::new();
        let mut original = projection();
        let path = save_governed_memory_projection(&dir.0, &original).unwrap();
        let before = fs::read(&path).unwrap();
        original.trust.insert(
            MemoryAssetId::new("unknown").unwrap(),
            MemoryTrustMetadata::unverified(1),
        );
        assert!(matches!(
            save_governed_memory_projection(&dir.0, &original),
            Err(GovernedMemoryProjectionError::UnknownTrustAsset(_))
        ));
        assert_eq!(before, fs::read(path).unwrap());
    }

    #[test]
    fn directory_sync_failure_is_not_reported_as_success() {
        let dir = TestDirectory::new();
        let path = dir.0.join(GOVERNED_MEMORY_PROJECTION_FILE);
        let result = publish_projection(&dir.0, &path, b"published", |_| {
            Err(io::Error::other("injected directory sync failure"))
        });
        assert!(matches!(
            result,
            Err(GovernedMemoryProjectionError::Io { .. })
        ));
        // The rename already happened: an error must not be mistaken for rollback.
        assert_eq!(fs::read(path).unwrap(), b"published");
    }

    #[test]
    fn old_shared_temporary_file_is_never_overwritten() {
        let dir = TestDirectory::new();
        let old = dir.0.join("governed-memory.json.tmp");
        fs::write(&old, b"unrelated existing file").unwrap();
        save_governed_memory_projection(&dir.0, &projection()).unwrap();
        assert_eq!(fs::read(old).unwrap(), b"unrelated existing file");
    }

    #[test]
    fn corrupt_and_oversized_documents_fail_closed() {
        let dir = TestDirectory::new();
        let path = dir.0.join(GOVERNED_MEMORY_PROJECTION_FILE);
        fs::write(&path, b"{\"version\":").unwrap();
        assert!(load_governed_memory_projection(&dir.0, None).is_err());
        File::create(&path)
            .unwrap()
            .set_len(MAX_GOVERNED_MEMORY_PROJECTION_BYTES as u64 + 1)
            .unwrap();
        assert!(matches!(
            load_governed_memory_projection(&dir.0, None),
            Err(GovernedMemoryProjectionError::Corrupt { .. })
        ));
    }

    #[test]
    fn unknown_fields_and_duplicate_lineage_are_rejected() {
        let mut value = serde_json::to_value(projection().to_wire()).unwrap();
        value["unexpected_authority"] = serde_json::json!(true);
        assert!(serde_json::from_value::<WireDocument>(value).is_err());
        let mut wire = projection().to_wire();
        wire.assets[0].evidence.push("audit:root".to_string());
        assert!(GovernedMemoryProjection::from_wire(None, wire).is_err());
    }
}
