use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ccos_enterprise_memory::{
    encode_governed_memory_projection, BudgetedMemoryRecall, GovernedMemoryProjection,
    GovernedMemoryStore, GovernedRecallTrustPolicy, MemoryAssetDescriptor, MemoryAssetId,
    MemoryContextBudget, MemoryEvidenceRef, MemoryLineage, MemoryLineageGraph,
    MemoryLoadoutBinding, MemoryLoadoutPlan, MemoryRecallBudget, MemorySpace, MemoryStratum,
    MemoryTrustMetadata, MemoryUsageMode, MemoryValidationState,
};
use ccos_enterprise_octasoma::generation::{
    ProviderGenerationError, ProviderGenerationStore, GENERATION_SELECTOR_VERSION, GOVERNANCE_DIR,
    GOVERNANCE_GENERATIONS_DIR, PROVIDER_GENERATIONS_DIR, PROVIDER_SELECTOR_FILE,
};
use ccos_enterprise_octasoma::recovery::{RecoveryConfig, RecoveryImage, RecoveryRecord};
use ccos_enterprise_tenancy::{TenantId, TenantScope};
use sha2::{Digest, Sha256};

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
    records_with(b"verified context")
}

fn records_with(payload: &[u8]) -> Vec<RecoveryRecord> {
    vec![RecoveryRecord {
        asset_id: id(),
        embedding: vec![1.0, 0.0],
        payload: payload.to_vec(),
        forgotten: false,
    }]
}

fn recalled_payload(store: &ProviderGenerationStore) -> Vec<u8> {
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
    admitted[0].payload.clone()
}

fn raw_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    raw_hex(&Sha256::digest(bytes))
}

#[test]
fn explicit_initialization_publishes_v2_and_reconstructs_the_real_provider() {
    let dir = Directory::new();
    let store =
        ProviderGenerationStore::initialize(&dir.0, projection(), config(), &records()).unwrap();
    assert_eq!(store.generation(), 0);
    assert_eq!(store.config(), config());
    assert_eq!(store.recovered().stored_records(), 1);
    assert_eq!(recalled_payload(&store), b"verified context");
    let _ = MemoryContextBudget::new(4, 1024).unwrap();

    let selector: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.0.join(PROVIDER_SELECTOR_FILE)).unwrap()).unwrap();
    assert_eq!(selector["version"], GENERATION_SELECTOR_VERSION);
    assert_eq!(
        selector["governance_file"],
        "generation-00000000000000000000.governance.json"
    );

    assert!(matches!(
        ProviderGenerationStore::open(&dir.0, tenant()),
        Err(ProviderGenerationError::AlreadyOpen { .. })
    ));
    drop(store);
    let reopened = ProviderGenerationStore::open(&dir.0, tenant()).unwrap();
    assert_eq!(reopened.recovered().stored_records(), 1);
    assert_eq!(recalled_payload(&reopened), b"verified context");
}

#[test]
fn legacy_v1_selector_remains_readable() {
    let dir = Directory::new();
    let provider_dir = dir.0.join(PROVIDER_GENERATIONS_DIR);
    fs::create_dir(&provider_dir).unwrap();
    let governance =
        GovernedMemoryStore::initialize(dir.0.join(GOVERNANCE_DIR), projection()).unwrap();
    let current = governance.projection_for(&tenant()).unwrap();
    let governance_bytes = encode_governed_memory_projection(current).unwrap();
    let image = RecoveryImage::capture(current, config(), &records()).unwrap();
    let image_file = "generation-00000000000000000000.json";
    image.write_new(provider_dir.join(image_file)).unwrap();
    let selector = serde_json::json!({
        "version": 1,
        "tenant": "acme",
        "generation": 0,
        "image_file": image_file,
        "image_sha256": raw_hex(&image.digest()),
        "governance_sha256": sha256_hex(&governance_bytes),
        "config": config(),
    });
    fs::write(
        dir.0.join(PROVIDER_SELECTOR_FILE),
        serde_json::to_vec_pretty(&selector).unwrap(),
    )
    .unwrap();
    drop(governance);

    let opened = ProviderGenerationStore::open(&dir.0, tenant()).unwrap();
    assert_eq!(opened.generation(), 0);
    assert_eq!(recalled_payload(&opened), b"verified context");
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
fn selector_cannot_choose_arbitrary_provider_or_governance_paths() {
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

    let mut selector: serde_json::Value = serde_json::from_slice(&original).unwrap();
    selector["governance_file"] = serde_json::Value::String("../escape.json".into());
    fs::write(&path, serde_json::to_vec_pretty(&selector).unwrap()).unwrap();
    assert!(matches!(
        ProviderGenerationStore::open(&dir.0, tenant()),
        Err(ProviderGenerationError::Invalid(
            "non-canonical governance filename"
        ))
    ));

    fs::write(&path, &original).unwrap();
    let other = TenantId::validated("other").unwrap();
    assert!(ProviderGenerationStore::open(&dir.0, other).is_err());
}

#[test]
fn advance_publishes_both_artifacts_before_switching_generation() {
    let dir = Directory::new();
    let store =
        ProviderGenerationStore::initialize(&dir.0, projection(), config(), &records()).unwrap();
    let store = store
        .advance(projection(), config(), &records_with(b"next generation"))
        .unwrap();
    assert_eq!(store.generation(), 1);
    assert_eq!(recalled_payload(&store), b"next generation");
    assert!(dir
        .0
        .join(PROVIDER_GENERATIONS_DIR)
        .join("generation-00000000000000000000.json")
        .is_file());
    assert!(dir
        .0
        .join(PROVIDER_GENERATIONS_DIR)
        .join("generation-00000000000000000001.json")
        .is_file());
    assert!(dir
        .0
        .join(GOVERNANCE_GENERATIONS_DIR)
        .join("generation-00000000000000000001.governance.json")
        .is_file());
    drop(store);
    let reopened = ProviderGenerationStore::open(&dir.0, tenant()).unwrap();
    assert_eq!(reopened.generation(), 1);
    assert_eq!(recalled_payload(&reopened), b"next generation");
}

#[test]
fn inert_orphan_artifacts_do_not_advance_the_selector() {
    let dir = Directory::new();
    let store =
        ProviderGenerationStore::initialize(&dir.0, projection(), config(), &records()).unwrap();
    drop(store);
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

    let reopened = ProviderGenerationStore::open(&dir.0, tenant()).unwrap();
    assert_eq!(reopened.generation(), 0);
    assert_eq!(recalled_payload(&reopened), b"verified context");
}

#[test]
fn failed_advance_before_selector_publication_preserves_previous_authority() {
    let dir = Directory::new();
    let store =
        ProviderGenerationStore::initialize(&dir.0, projection(), config(), &records()).unwrap();
    let selector_path = dir.0.join(PROVIDER_SELECTOR_FILE);
    let before = fs::read(&selector_path).unwrap();
    fs::write(
        dir.0
            .join(GOVERNANCE_GENERATIONS_DIR)
            .join("generation-00000000000000000001.governance.json"),
        b"operator collision",
    )
    .unwrap();

    assert!(store
        .advance(projection(), config(), &records_with(b"must not publish"))
        .is_err());
    assert_eq!(fs::read(&selector_path).unwrap(), before);
    let reopened = ProviderGenerationStore::open(&dir.0, tenant()).unwrap();
    assert_eq!(reopened.generation(), 0);
    assert_eq!(recalled_payload(&reopened), b"verified context");
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
