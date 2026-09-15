use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ccos_enterprise_memory::{
    BudgetedMemoryRecall, GovernedMemoryProjection, GovernedRecallTrustPolicy,
    MemoryAssetDescriptor, MemoryAssetId, MemoryContextBudget, MemoryEvidenceRef, MemoryLineage,
    MemoryLineageGraph, MemoryLoadoutBinding, MemoryLoadoutPlan, MemoryRecallBudget, MemorySpace,
    MemoryStratum, MemoryTrustMetadata, MemoryUsageMode, MemoryValidationState,
};
use ccos_enterprise_octasoma::generation::{
    ProviderGenerationError, ProviderGenerationStore, PROVIDER_SELECTOR_FILE,
};
use ccos_enterprise_octasoma::recovery::{RecoveryConfig, RecoveryRecord};
use ccos_enterprise_tenancy::{TenantId, TenantScope};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ccos-generation-selector-{}-{}",
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

fn id() -> MemoryAssetId {
    MemoryAssetId::new("asset-1").unwrap()
}

fn projection() -> GovernedMemoryProjection {
    let mut graph = MemoryLineageGraph::new();
    graph
        .register(
            MemoryAssetDescriptor::new(
                id(),
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
            id(),
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
        asset_id: id(),
        embedding: vec![1.0, 0.0],
        payload: b"verified context".to_vec(),
        forgotten: false,
    }]
}

#[test]
fn explicit_initialization_reopens_and_reconstructs_the_real_provider() {
    let dir = Directory::new();
    let store =
        ProviderGenerationStore::initialize(&dir.0, projection(), config(), &records()).unwrap();
    assert_eq!(store.generation(), 0);
    assert_eq!(store.config(), config());
    assert_eq!(store.recovered().stored_records(), 1);

    let loadout = store
        .governance()
        .loadout
        .bootstrap_loadout()
        .unwrap()
        .unwrap();
    let admitted = store
        .recovered()
        .recall(
            store.governance(),
            TenantScope::new(
                tenant(),
                BudgetedMemoryRecall {
                    embedding: &[1.0, 0.0],
                    loadout: &loadout,
                    budget: MemoryRecallBudget::new(4, 8, 1024).unwrap(),
                },
            ),
            GovernedRecallTrustPolicy::VerifiedOnly,
        )
        .unwrap();
    assert_eq!(admitted.len(), 1);
    assert_eq!(admitted[0].asset_id, id());
    assert_eq!(admitted[0].payload, b"verified context");
    let _ = MemoryContextBudget::new(4, 1024).unwrap();

    assert!(matches!(
        ProviderGenerationStore::open(&dir.0, tenant()),
        Err(ProviderGenerationError::AlreadyOpen { .. })
    ));
    drop(store);
    let reopened = ProviderGenerationStore::open(&dir.0, tenant()).unwrap();
    assert_eq!(reopened.recovered().stored_records(), 1);
}

#[test]
fn selector_governance_digest_is_independent_and_fail_closed() {
    let dir = Directory::new();
    let store =
        ProviderGenerationStore::initialize(&dir.0, projection(), config(), &records()).unwrap();
    drop(store);
    let path = dir.0.join(PROVIDER_SELECTOR_FILE);
    let mut selector: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    selector["governance_sha256"] = serde_json::Value::String("00".repeat(32));
    fs::write(&path, serde_json::to_vec_pretty(&selector).unwrap()).unwrap();
    assert!(matches!(
        ProviderGenerationStore::open(&dir.0, tenant()),
        Err(ProviderGenerationError::GovernanceMismatch)
    ));
}

#[test]
fn selector_cannot_choose_an_arbitrary_path_or_tenant() {
    let dir = Directory::new();
    let store =
        ProviderGenerationStore::initialize(&dir.0, projection(), config(), &records()).unwrap();
    drop(store);
    let path = dir.0.join(PROVIDER_SELECTOR_FILE);
    let original = fs::read(&path).unwrap();

    let mut selector: serde_json::Value = serde_json::from_slice(&original).unwrap();
    selector["image_file"] = serde_json::Value::String("../escape.json".into());
    fs::write(&path, serde_json::to_vec_pretty(&selector).unwrap()).unwrap();
    assert!(matches!(
        ProviderGenerationStore::open(&dir.0, tenant()),
        Err(ProviderGenerationError::Invalid(
            "non-canonical image filename"
        ))
    ));

    fs::write(&path, &original).unwrap();
    let other = TenantId::validated("other").unwrap();
    assert!(ProviderGenerationStore::open(&dir.0, other).is_err());
}

#[test]
fn provisioning_never_overwrites_existing_selector_state() {
    let dir = Directory::new();
    fs::write(dir.0.join(PROVIDER_SELECTOR_FILE), b"operator-owned").unwrap();
    assert!(matches!(
        ProviderGenerationStore::initialize(&dir.0, projection(), config(), &records()),
        Err(ProviderGenerationError::AlreadyInitialized { .. })
    ));
    assert_eq!(
        fs::read(dir.0.join(PROVIDER_SELECTOR_FILE)).unwrap(),
        b"operator-owned"
    );
}
