use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ccos_enterprise_memory::{
    GovernedMemoryProjection, MemoryAssetDescriptor, MemoryAssetId, MemoryEvidenceRef,
    MemoryLineage, MemoryLineageGraph, MemoryLoadoutBinding, MemoryLoadoutPlan, MemorySpace,
    MemoryStratum, MemoryTrustMetadata, MemoryUsageMode, MemoryValidationState,
};
use ccos_enterprise_octasoma::generation::{
    ProviderGenerationStore, GOVERNANCE_GENERATIONS_DIR, PROVIDER_GENERATIONS_DIR,
};
use ccos_enterprise_octasoma::recovery::{RecoveryConfig, RecoveryRecord};
use ccos_enterprise_tenancy::TenantId;

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ccos-generation-retry-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn tenant() -> TenantId {
    TenantId::validated("acme").unwrap()
}

fn asset() -> MemoryAssetId {
    MemoryAssetId::new("asset-1").unwrap()
}

fn authority() -> GovernedMemoryProjection {
    let mut graph = MemoryLineageGraph::new();
    graph
        .register(
            MemoryAssetDescriptor::new(
                asset(),
                MemorySpace::Tenant,
                MemoryStratum::Evidence,
                MemoryLineage::root([MemoryEvidenceRef::new("audit:asset-1").unwrap()]).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    GovernedMemoryProjection::new(
        tenant(),
        graph,
        BTreeMap::from([(
            asset(),
            MemoryTrustMetadata::new(
                MemoryValidationState::Verified,
                1,
                1,
                0,
                ["proof:asset-1".to_string()],
            )
            .unwrap(),
        )]),
        MemoryLoadoutPlan::new([MemoryLoadoutBinding::new(
            MemorySpace::Tenant,
            100,
            MemoryUsageMode::Bootstrap,
        )
        .unwrap()])
        .unwrap(),
    )
    .unwrap()
}

fn config() -> RecoveryConfig {
    RecoveryConfig {
        dimension: 2,
        simhash_bits: 64,
        per_tenant_capacity: 4,
        seed: 42,
    }
}

fn records() -> Vec<RecoveryRecord> {
    vec![RecoveryRecord {
        asset_id: asset(),
        embedding: vec![1.0, 0.0],
        payload: b"stable input".to_vec(),
        forgotten: false,
    }]
}

#[test]
fn exact_orphans_from_a_preselector_crash_are_safe_to_reuse_on_retry() {
    let dir = Directory::new();
    let store =
        ProviderGenerationStore::initialize(&dir.0, authority(), config(), &records()).unwrap();

    let provider_dir = dir.0.join(PROVIDER_GENERATIONS_DIR);
    let governance_dir = dir.0.join(GOVERNANCE_GENERATIONS_DIR);
    fs::copy(
        provider_dir.join("generation-00000000000000000000.json"),
        provider_dir.join("generation-00000000000000000001.json"),
    )
    .unwrap();
    fs::copy(
        governance_dir.join("generation-00000000000000000000.governance.json"),
        governance_dir.join("generation-00000000000000000001.governance.json"),
    )
    .unwrap();

    let store = store.advance(authority(), config(), &records()).unwrap();
    assert_eq!(store.generation(), 1);
    assert_eq!(store.recovered().stored_records(), 1);

    drop(store);
    let reopened = ProviderGenerationStore::open(&dir.0, tenant()).unwrap();
    assert_eq!(reopened.generation(), 1);
    assert_eq!(reopened.recovered().stored_records(), 1);
}
