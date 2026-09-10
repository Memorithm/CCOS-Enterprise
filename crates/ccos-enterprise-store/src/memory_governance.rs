use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use ccos_enterprise_memory::{
    MemoryAssetDescriptor, MemoryAssetId, MemoryAssetState, MemoryEvidenceRef, MemoryLineage,
    MemoryLineageGraph, MemoryLoadoutBinding, MemoryLoadoutPlan, MemorySpace, MemoryStratum,
    MemoryTrustMetadata, MemoryUsageMode, MemoryValidationState,
};
use ccos_enterprise_tenancy::TenantId;
use serde::{Deserialize, Serialize};

use crate::Store;

/// Versioned, tenant-bound governance projection used by the served memory path.
pub const MEMORY_GOVERNANCE_FILE: &str = "memory-governance-v1.json";
const MEMORY_GOVERNANCE_VERSION: u32 = 1;

/// Reconstructed governed-memory authority state.
///
/// This type deliberately contains metadata and policy only: no embeddings,
/// provider handles or semantic payloads. Served recall still has to pass its
/// provider output through the lineage/trust gate before context assembly.
#[derive(Debug)]
pub struct MemoryGovernanceState {
    tenant: TenantId,
    graph: MemoryLineageGraph,
    trust: BTreeMap<MemoryAssetId, MemoryTrustMetadata>,
    loadout: MemoryLoadoutPlan,
}

impl MemoryGovernanceState {
    pub fn new(
        tenant: TenantId,
        graph: MemoryLineageGraph,
        trust: BTreeMap<MemoryAssetId, MemoryTrustMetadata>,
        loadout: MemoryLoadoutPlan,
    ) -> Result<Self, MemoryGovernanceStoreError> {
        validate_tenant(&tenant)?;
        for id in trust.keys() {
            if graph.state(id).is_none() {
                return Err(MemoryGovernanceStoreError::InvalidState(format!(
                    "trust metadata references unknown memory asset {}",
                    id.as_str()
                )));
            }
        }
        Ok(Self {
            tenant,
            graph,
            trust,
            loadout,
        })
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub fn graph(&self) -> &MemoryLineageGraph {
        &self.graph
    }

    pub fn trust(&self) -> &BTreeMap<MemoryAssetId, MemoryTrustMetadata> {
        &self.trust
    }

    pub fn loadout(&self) -> &MemoryLoadoutPlan {
        &self.loadout
    }
}

#[derive(Debug)]
pub enum MemoryGovernanceStoreError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Corrupt {
        path: PathBuf,
        detail: String,
    },
    UnsupportedVersion(u32),
    InvalidTenant(String),
    TenantMismatch {
        expected: String,
        found: String,
    },
    InvalidState(String),
}

impl fmt::Display for MemoryGovernanceStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Corrupt { path, detail } => {
                write!(f, "{}: governed memory snapshot is unreadable: {detail}", path.display())
            }
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported governed memory snapshot version {version}")
            }
            Self::InvalidTenant(tenant) => {
                write!(f, "invalid governed memory tenant id {tenant:?}")
            }
            Self::TenantMismatch { expected, found } => write!(
                f,
                "governed memory snapshot tenant mismatch: expected {expected:?}, found {found:?}"
            ),
            Self::InvalidState(detail) => write!(f, "invalid governed memory state: {detail}"),
        }
    }
}

impl std::error::Error for MemoryGovernanceStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> MemoryGovernanceStoreError + '_ {
    move |source| MemoryGovernanceStoreError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn validate_tenant(tenant: &TenantId) -> Result<(), MemoryGovernanceStoreError> {
    match TenantId::validated(&tenant.0) {
        Some(validated) if validated == *tenant => Ok(()),
        _ => Err(MemoryGovernanceStoreError::InvalidTenant(tenant.0.clone())),
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct VersionProbe {
    version: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct SnapshotV1 {
    version: u32,
    tenant: String,
    assets: Vec<AssetWire>,
    invalidated: Vec<String>,
    trust: Vec<TrustWire>,
    loadout: Vec<LoadoutWire>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AssetWire {
    id: String,
    space: SpaceWire,
    stratum: StratumWire,
    parents: Vec<String>,
    evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
enum SpaceWire {
    Tenant,
    Project(String),
    Team(String),
    Agent(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StratumWire {
    Evidence,
    Episode,
    Context,
    Pattern,
}

#[derive(Debug, Serialize, Deserialize)]
struct TrustWire {
    asset_id: String,
    state: ValidationWire,
    source_count: u32,
    independent_source_count: u32,
    contradiction_count: u32,
    verification_refs: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ValidationWire {
    Unverified,
    Corroborated,
    Verified,
    Disputed,
    Quarantined,
}

#[derive(Debug, Serialize, Deserialize)]
struct LoadoutWire {
    space: SpaceWire,
    priority: u16,
    usage: UsageWire,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum UsageWire {
    Bootstrap,
    OnDemand,
    BootstrapAndOnDemand,
}

impl Store {
    /// Atomically persist the complete governance metadata required by served recall.
    ///
    /// The write uses Core's temp + fsync + atomic-rename primitive, so a crash
    /// leaves either the previous complete snapshot or the new one. Provider
    /// payloads and embeddings are intentionally excluded from this projection.
    pub fn save_memory_governance(
        &self,
        state: &MemoryGovernanceState,
    ) -> Result<(), MemoryGovernanceStoreError> {
        let path = self.root().join(MEMORY_GOVERNANCE_FILE);
        let wire = SnapshotV1::from_state(state)?;
        let bytes = serde_json::to_vec_pretty(&wire).map_err(|error| {
            MemoryGovernanceStoreError::InvalidState(format!(
                "cannot serialize governed memory snapshot: {error}"
            ))
        })?;
        ccos_core::util::write_durable(&path, &bytes).map_err(io(&path))
    }

    /// Reconstruct governed-memory authority state for exactly one tenant.
    ///
    /// Missing state is `Ok(None)` for a deployment that has not configured
    /// governed semantic memory. Existing malformed, cross-tenant or unsupported
    /// state is always refused rather than replaced with defaults.
    pub fn load_memory_governance(
        &self,
        expected_tenant: &TenantId,
    ) -> Result<Option<MemoryGovernanceState>, MemoryGovernanceStoreError> {
        validate_tenant(expected_tenant)?;
        let path = self.root().join(MEMORY_GOVERNANCE_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path).map_err(io(&path))?;
        let probe: VersionProbe = serde_json::from_slice(&bytes).map_err(|error| {
            MemoryGovernanceStoreError::Corrupt {
                path: path.clone(),
                detail: error.to_string(),
            }
        })?;
        if probe.version != MEMORY_GOVERNANCE_VERSION {
            return Err(MemoryGovernanceStoreError::UnsupportedVersion(probe.version));
        }
        let wire: SnapshotV1 = serde_json::from_slice(&bytes).map_err(|error| {
            MemoryGovernanceStoreError::Corrupt {
                path: path.clone(),
                detail: error.to_string(),
            }
        })?;
        let found = TenantId::validated(&wire.tenant)
            .ok_or_else(|| MemoryGovernanceStoreError::InvalidTenant(wire.tenant.clone()))?;
        if &found != expected_tenant {
            return Err(MemoryGovernanceStoreError::TenantMismatch {
                expected: expected_tenant.0.clone(),
                found: found.0,
            });
        }
        wire.into_state()
            .map(Some)
            .map_err(|error| match error {
                MemoryGovernanceStoreError::Corrupt { .. }
                | MemoryGovernanceStoreError::Io { .. } => error,
                other => MemoryGovernanceStoreError::Corrupt {
                    path,
                    detail: other.to_string(),
                },
            })
    }
}

impl SnapshotV1 {
    fn from_state(state: &MemoryGovernanceState) -> Result<Self, MemoryGovernanceStoreError> {
        validate_tenant(&state.tenant)?;

        let assets = state
            .graph
            .descriptors()
            .map(AssetWire::from_descriptor)
            .collect();
        let invalidated = state
            .graph
            .invalidated_asset_ids()
            .map(|id| id.as_str().to_string())
            .collect();
        let trust = state
            .trust
            .iter()
            .map(|(id, metadata)| TrustWire::from_metadata(id, metadata))
            .collect();
        let loadout = state
            .loadout
            .bindings()
            .map(LoadoutWire::from_binding)
            .collect();

        Ok(Self {
            version: MEMORY_GOVERNANCE_VERSION,
            tenant: state.tenant.0.clone(),
            assets,
            invalidated,
            trust,
            loadout,
        })
    }

    fn into_state(self) -> Result<MemoryGovernanceState, MemoryGovernanceStoreError> {
        if self.version != MEMORY_GOVERNANCE_VERSION {
            return Err(MemoryGovernanceStoreError::UnsupportedVersion(self.version));
        }
        let tenant = TenantId::validated(&self.tenant)
            .ok_or_else(|| MemoryGovernanceStoreError::InvalidTenant(self.tenant.clone()))?;

        let mut descriptor_ids = BTreeSet::new();
        let mut descriptors = Vec::with_capacity(self.assets.len());
        for asset in self.assets {
            let descriptor = asset.into_descriptor()?;
            if !descriptor_ids.insert(descriptor.id.clone()) {
                return Err(MemoryGovernanceStoreError::InvalidState(format!(
                    "duplicate memory asset {}",
                    descriptor.id.as_str()
                )));
            }
            descriptors.push(descriptor);
        }
        let mut graph = MemoryLineageGraph::from_active_descriptors(descriptors)
            .map_err(|error| MemoryGovernanceStoreError::InvalidState(error.to_string()))?;

        let mut invalidated_ids = BTreeSet::new();
        for raw in self.invalidated {
            let id = MemoryAssetId::new(raw)
                .map_err(|error| MemoryGovernanceStoreError::InvalidState(error.to_string()))?;
            if !invalidated_ids.insert(id.clone()) {
                return Err(MemoryGovernanceStoreError::InvalidState(format!(
                    "duplicate invalidated memory asset {}",
                    id.as_str()
                )));
            }
            graph
                .invalidate(&id)
                .map_err(|error| MemoryGovernanceStoreError::InvalidState(error.to_string()))?;
        }

        let mut trust = BTreeMap::new();
        for record in self.trust {
            let (id, metadata) = record.into_metadata()?;
            if graph.state(&id).is_none() {
                return Err(MemoryGovernanceStoreError::InvalidState(format!(
                    "trust metadata references unknown memory asset {}",
                    id.as_str()
                )));
            }
            if trust.insert(id.clone(), metadata).is_some() {
                return Err(MemoryGovernanceStoreError::InvalidState(format!(
                    "duplicate trust metadata for memory asset {}",
                    id.as_str()
                )));
            }
        }

        let bindings = self
            .loadout
            .into_iter()
            .map(LoadoutWire::into_binding)
            .collect::<Result<Vec<_>, _>>()?;
        let loadout = MemoryLoadoutPlan::new(bindings)
            .map_err(|error| MemoryGovernanceStoreError::InvalidState(error.to_string()))?;

        MemoryGovernanceState::new(tenant, graph, trust, loadout)
    }
}

impl AssetWire {
    fn from_descriptor(descriptor: &MemoryAssetDescriptor) -> Self {
        Self {
            id: descriptor.id.as_str().to_string(),
            space: SpaceWire::from_space(&descriptor.space),
            stratum: StratumWire::from_stratum(descriptor.stratum),
            parents: descriptor
                .lineage
                .parents()
                .map(|id| id.as_str().to_string())
                .collect(),
            evidence: descriptor
                .lineage
                .evidence()
                .map(|reference| reference.as_str().to_string())
                .collect(),
        }
    }

    fn into_descriptor(self) -> Result<MemoryAssetDescriptor, MemoryGovernanceStoreError> {
        let id = MemoryAssetId::new(self.id)
            .map_err(|error| MemoryGovernanceStoreError::InvalidState(error.to_string()))?;
        let space = self.space.into_space()?;
        let stratum = self.stratum.into_stratum();
        let parents = self
            .parents
            .into_iter()
            .map(|raw| {
                MemoryAssetId::new(raw)
                    .map_err(|error| MemoryGovernanceStoreError::InvalidState(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let evidence = self
            .evidence
            .into_iter()
            .map(|raw| {
                MemoryEvidenceRef::new(raw)
                    .map_err(|error| MemoryGovernanceStoreError::InvalidState(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let lineage = match stratum {
            MemoryStratum::Evidence => {
                if !parents.is_empty() {
                    return Err(MemoryGovernanceStoreError::InvalidState(format!(
                        "evidence memory asset {} cannot carry parents",
                        id.as_str()
                    )));
                }
                MemoryLineage::root(evidence)
            }
            MemoryStratum::Episode | MemoryStratum::Context | MemoryStratum::Pattern => {
                MemoryLineage::derived(parents, evidence)
            }
        }
        .map_err(|error| MemoryGovernanceStoreError::InvalidState(error.to_string()))?;
        MemoryAssetDescriptor::new(id, space, stratum, lineage)
            .map_err(|error| MemoryGovernanceStoreError::InvalidState(error.to_string()))
    }
}

impl SpaceWire {
    fn from_space(space: &MemorySpace) -> Self {
        match space {
            MemorySpace::Tenant => Self::Tenant,
            MemorySpace::Project(id) => Self::Project(id.clone()),
            MemorySpace::Team(id) => Self::Team(id.clone()),
            MemorySpace::Agent(id) => Self::Agent(id.clone()),
        }
    }

    fn into_space(self) -> Result<MemorySpace, MemoryGovernanceStoreError> {
        match self {
            Self::Tenant => Ok(MemorySpace::Tenant),
            Self::Project(id) => MemorySpace::project(id),
            Self::Team(id) => MemorySpace::team(id),
            Self::Agent(id) => MemorySpace::agent(id),
        }
        .map_err(|error| MemoryGovernanceStoreError::InvalidState(error.to_string()))
    }
}

impl StratumWire {
    fn from_stratum(stratum: MemoryStratum) -> Self {
        match stratum {
            MemoryStratum::Evidence => Self::Evidence,
            MemoryStratum::Episode => Self::Episode,
            MemoryStratum::Context => Self::Context,
            MemoryStratum::Pattern => Self::Pattern,
        }
    }

    fn into_stratum(self) -> MemoryStratum {
        match self {
            Self::Evidence => MemoryStratum::Evidence,
            Self::Episode => MemoryStratum::Episode,
            Self::Context => MemoryStratum::Context,
            Self::Pattern => MemoryStratum::Pattern,
        }
    }
}

impl TrustWire {
    fn from_metadata(id: &MemoryAssetId, metadata: &MemoryTrustMetadata) -> Self {
        Self {
            asset_id: id.as_str().to_string(),
            state: ValidationWire::from_state(metadata.state()),
            source_count: metadata.source_count(),
            independent_source_count: metadata.independent_source_count(),
            contradiction_count: metadata.contradiction_count(),
            verification_refs: metadata
                .verification_refs()
                .map(str::to_string)
                .collect(),
        }
    }

    fn into_metadata(
        self,
    ) -> Result<(MemoryAssetId, MemoryTrustMetadata), MemoryGovernanceStoreError> {
        let id = MemoryAssetId::new(self.asset_id)
            .map_err(|error| MemoryGovernanceStoreError::InvalidState(error.to_string()))?;
        let metadata = MemoryTrustMetadata::new(
            self.state.into_state(),
            self.source_count,
            self.independent_source_count,
            self.contradiction_count,
            self.verification_refs,
        )
        .map_err(|error| MemoryGovernanceStoreError::InvalidState(error.to_string()))?;
        Ok((id, metadata))
    }
}

impl ValidationWire {
    fn from_state(state: MemoryValidationState) -> Self {
        match state {
            MemoryValidationState::Unverified => Self::Unverified,
            MemoryValidationState::Corroborated => Self::Corroborated,
            MemoryValidationState::Verified => Self::Verified,
            MemoryValidationState::Disputed => Self::Disputed,
            MemoryValidationState::Quarantined => Self::Quarantined,
        }
    }

    fn into_state(self) -> MemoryValidationState {
        match self {
            Self::Unverified => MemoryValidationState::Unverified,
            Self::Corroborated => MemoryValidationState::Corroborated,
            Self::Verified => MemoryValidationState::Verified,
            Self::Disputed => MemoryValidationState::Disputed,
            Self::Quarantined => MemoryValidationState::Quarantined,
        }
    }
}

impl LoadoutWire {
    fn from_binding(binding: &MemoryLoadoutBinding) -> Self {
        Self {
            space: SpaceWire::from_space(&binding.space),
            priority: binding.priority,
            usage: UsageWire::from_usage(binding.usage),
        }
    }

    fn into_binding(self) -> Result<MemoryLoadoutBinding, MemoryGovernanceStoreError> {
        MemoryLoadoutBinding::new(
            self.space.into_space()?,
            self.priority,
            self.usage.into_usage(),
        )
        .map_err(|error| MemoryGovernanceStoreError::InvalidState(error.to_string()))
    }
}

impl UsageWire {
    fn from_usage(usage: MemoryUsageMode) -> Self {
        match usage {
            MemoryUsageMode::Bootstrap => Self::Bootstrap,
            MemoryUsageMode::OnDemand => Self::OnDemand,
            MemoryUsageMode::BootstrapAndOnDemand => Self::BootstrapAndOnDemand,
        }
    }

    fn into_usage(self) -> MemoryUsageMode {
        match self {
            Self::Bootstrap => MemoryUsageMode::Bootstrap,
            Self::OnDemand => MemoryUsageMode::OnDemand,
            Self::BootstrapAndOnDemand => MemoryUsageMode::BootstrapAndOnDemand,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn id(value: &str) -> MemoryAssetId {
        MemoryAssetId::new(value).unwrap()
    }

    fn descriptor(
        value: &str,
        stratum: MemoryStratum,
        parents: impl IntoIterator<Item = MemoryAssetId>,
    ) -> MemoryAssetDescriptor {
        let lineage = if stratum == MemoryStratum::Evidence {
            MemoryLineage::root([MemoryEvidenceRef::new(format!("audit:{value}")).unwrap()])
                .unwrap()
        } else {
            MemoryLineage::derived(parents, []).unwrap()
        };
        MemoryAssetDescriptor::new(id(value), MemorySpace::Tenant, stratum, lineage).unwrap()
    }

    fn state() -> MemoryGovernanceState {
        let mut graph = MemoryLineageGraph::new();
        graph
            .register(descriptor("root", MemoryStratum::Evidence, []))
            .unwrap();
        graph
            .register(descriptor(
                "episode",
                MemoryStratum::Episode,
                [id("root")],
            ))
            .unwrap();
        graph.invalidate(&id("root")).unwrap();

        let trust = BTreeMap::from([
            (
                id("root"),
                MemoryTrustMetadata::new(
                    MemoryValidationState::Verified,
                    1,
                    1,
                    0,
                    ["proof:root".into()],
                )
                .unwrap(),
            ),
            (id("episode"), MemoryTrustMetadata::unverified(1)),
        ]);
        let loadout = MemoryLoadoutPlan::new([
            MemoryLoadoutBinding::new(
                MemorySpace::Tenant,
                100,
                MemoryUsageMode::BootstrapAndOnDemand,
            )
            .unwrap(),
            MemoryLoadoutBinding::new(
                MemorySpace::project("ccos").unwrap(),
                50,
                MemoryUsageMode::OnDemand,
            )
            .unwrap(),
        ])
        .unwrap();
        MemoryGovernanceState::new(TenantId::validated("acme").unwrap(), graph, trust, loadout)
            .unwrap()
    }

    fn temp_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "ccos-memory-governance-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn round_trip_preserves_lineage_state_trust_and_loadout() {
        let root = temp_root("roundtrip");
        let store = Store::open(&root).unwrap();
        let state = state();
        store.save_memory_governance(&state).unwrap();
        let loaded = store
            .load_memory_governance(&TenantId::validated("acme").unwrap())
            .unwrap()
            .unwrap();

        assert_eq!(
            loaded.graph().state(&id("root")),
            Some(MemoryAssetState::Invalidated)
        );
        assert_eq!(
            loaded.graph().state(&id("episode")),
            Some(MemoryAssetState::Stale)
        );
        assert_eq!(
            loaded.trust()[&id("root")].state(),
            MemoryValidationState::Verified
        );
        assert_eq!(loaded.loadout().len(), 2);
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn encoding_is_deterministic() {
        let root = temp_root("deterministic");
        let store = Store::open(&root).unwrap();
        let state = state();
        store.save_memory_governance(&state).unwrap();
        let path = root.join(MEMORY_GOVERNANCE_FILE);
        let first = std::fs::read(&path).unwrap();
        store.save_memory_governance(&state).unwrap();
        let second = std::fs::read(&path).unwrap();
        assert_eq!(first, second);
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_or_truncated_snapshot_is_refused() {
        let root = temp_root("truncated");
        let store = Store::open(&root).unwrap();
        std::fs::write(root.join(MEMORY_GOVERNANCE_FILE), b"{\"version\":1,\"tenant\":\"acme\"")
            .unwrap();
        assert!(matches!(
            store.load_memory_governance(&TenantId::validated("acme").unwrap()),
            Err(MemoryGovernanceStoreError::Corrupt { .. })
        ));
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unsupported_version_and_tenant_mismatch_fail_closed() {
        let root = temp_root("version-tenant");
        let store = Store::open(&root).unwrap();
        std::fs::write(
            root.join(MEMORY_GOVERNANCE_FILE),
            br#"{"version":2,"tenant":"acme"}"#,
        )
        .unwrap();
        assert!(matches!(
            store.load_memory_governance(&TenantId::validated("acme").unwrap()),
            Err(MemoryGovernanceStoreError::UnsupportedVersion(2))
        ));

        let state = state();
        store.save_memory_governance(&state).unwrap();
        assert!(matches!(
            store.load_memory_governance(&TenantId::validated("globex").unwrap()),
            Err(MemoryGovernanceStoreError::TenantMismatch { .. })
        ));
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }
}
