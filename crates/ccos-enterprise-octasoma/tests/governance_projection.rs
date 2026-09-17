//! Cross-crate tests using the real OctaSoma adapter, not a synthetic provider.
//!
//! Only governance metadata is restored here; the provider stays in memory.
//! These tests do not claim durable vector-index reconstruction or MCP serving.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ccos_enterprise_memory::{
    admit_governed_recall, assemble_governed_bootstrap_context, attest_governed_context,
    load_governed_memory_projection, save_governed_memory_projection, GovernedMemoryProjection,
    GovernedMemoryWrite, GovernedRecallGate, GovernedRecallTrustPolicy, LoadoutMemoryQuery,
    MemoryAssetDescriptor, MemoryAssetId, MemoryAssetState, MemoryContextBudget, MemoryEvidenceRef,
    MemoryLineage, MemoryLineageGraph, MemoryLoadoutBinding, MemoryLoadoutPlan, MemorySpace,
    MemoryStratum, MemoryTrustMetadata, MemoryUsageMode,
};
use ccos_enterprise_octasoma::EnterpriseOctaSoma;
use ccos_enterprise_tenancy::{TenantId, TenantScope};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
const EVIDENCE: &str = "https://example.invalid/Repo/blob/abc/src/Main.rs#L12";

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let ordinal = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ccos-octa-projection-{}-{ordinal}",
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

fn fixture() -> (EnterpriseOctaSoma, GovernedMemoryProjection, MemoryAssetId) {
    let tenant = TenantId::validated("acme").unwrap();
    let asset = MemoryAssetId::new("Memory:Case/42").unwrap();
    let mut provider = EnterpriseOctaSoma::new(2, 64, 8, 7).unwrap();
    provider
        .insert_governed(TenantScope::new(
            tenant.clone(),
            GovernedMemoryWrite {
                asset_id: &asset,
                space: &MemorySpace::Tenant,
                embedding: &[1.0, 0.0],
                payload: b"observed evidence",
            },
        ))
        .unwrap();
    let mut graph = MemoryLineageGraph::new();
    graph
        .register(
            MemoryAssetDescriptor::new(
                asset.clone(),
                MemorySpace::Tenant,
                MemoryStratum::Evidence,
                MemoryLineage::root([MemoryEvidenceRef::new(EVIDENCE).unwrap()]).unwrap(),
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
    let projection = GovernedMemoryProjection::new(
        tenant,
        graph,
        BTreeMap::from([(asset.clone(), MemoryTrustMetadata::unverified(1))]),
        loadout,
    )
    .unwrap();
    (provider, projection, asset)
}

#[test]
fn restored_projection_preserves_real_provider_identity_space_and_evidence() {
    let dir = TestDirectory::new();
    let (provider, projection, asset) = fixture();
    save_governed_memory_projection(&dir.0, &projection).unwrap();
    let restored = load_governed_memory_projection(&dir.0, Some(&projection.tenant))
        .unwrap()
        .unwrap();
    let loadout = restored.loadout.bootstrap_loadout().unwrap().unwrap();
    let observations = provider
        .recall_governed(TenantScope::new(
            restored.tenant.clone(),
            LoadoutMemoryQuery {
                embedding: &[1.0, 0.0],
                k: 4,
                shortlist: 8,
                loadout: &loadout,
            },
        ))
        .unwrap();
    assert_eq!(observations.len(), 1);
    let admitted = admit_governed_recall(
        GovernedRecallGate {
            expected_tenant: &restored.tenant,
            projection: &restored,
            policy: GovernedRecallTrustPolicy::AnyNonQuarantined,
        },
        observations,
    )
    .unwrap();
    let assembly = assemble_governed_bootstrap_context(
        &restored,
        admitted,
        MemoryContextBudget::new(4, 1024).unwrap(),
    )
    .unwrap();
    let attestations = attest_governed_context(&assembly);
    assert_eq!(assembly.len(), 1);
    assert_eq!(assembly.chunks()[0].asset_id, asset);
    assert_eq!(assembly.chunks()[0].space, MemorySpace::Tenant);
    assert_eq!(assembly.chunks()[0].payload, b"observed evidence");
    assert_eq!(attestations.len(), 1);
    assert_eq!(attestations[0].evidence[0].as_str(), EVIDENCE);
}

#[test]
fn restored_invalidation_blocks_a_still_retrievable_provider_record() {
    let dir = TestDirectory::new();
    let (provider, mut projection, asset) = fixture();
    projection.graph.invalidate(&asset).unwrap();
    save_governed_memory_projection(&dir.0, &projection).unwrap();
    let restored = load_governed_memory_projection(&dir.0, Some(&projection.tenant))
        .unwrap()
        .unwrap();
    assert_eq!(
        restored.graph.state(&asset),
        Some(MemoryAssetState::Invalidated)
    );
    let loadout = restored.loadout.bootstrap_loadout().unwrap().unwrap();
    let observations = provider
        .recall_governed(TenantScope::new(
            restored.tenant.clone(),
            LoadoutMemoryQuery {
                embedding: &[1.0, 0.0],
                k: 4,
                shortlist: 8,
                loadout: &loadout,
            },
        ))
        .unwrap();
    // The real provider still retrieves it; only restored governance rejects it.
    assert_eq!(observations.len(), 1);
    let admitted = admit_governed_recall(
        GovernedRecallGate {
            expected_tenant: &restored.tenant,
            projection: &restored,
            policy: GovernedRecallTrustPolicy::AnyNonQuarantined,
        },
        observations,
    )
    .unwrap();
    assert!(admitted.is_empty());
}
