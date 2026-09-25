use super::*;
use crate::accepted_write::AcceptedEvidenceWrite;
use ccos_enterprise_memory::{
    MemoryAssetDescriptor, MemoryEvidenceRef, MemoryLineage, MemoryLineageGraph,
    MemoryLoadoutBinding, MemoryLoadoutPlan, MemoryProvenanceClass, MemorySpace, MemoryStratum,
    MemoryTrustMetadata, MemoryUsageMode,
};
use std::collections::BTreeMap;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "ccos-purge-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
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
fn id(name: &str) -> MemoryAssetId {
    MemoryAssetId::new(name).unwrap()
}

fn initialize(path: &Path) -> ProviderGenerationStore {
    let mut graph = MemoryLineageGraph::new();
    let mut trust = BTreeMap::new();
    let mut records = Vec::new();
    for name in ["root", "child", "survivor"] {
        let lineage = if name == "child" {
            MemoryLineage::derived([id("root")], []).unwrap()
        } else {
            MemoryLineage::root([MemoryEvidenceRef::new(format!("e:{name}")).unwrap()]).unwrap()
        };
        graph
            .register(
                MemoryAssetDescriptor::new(
                    id(name),
                    MemorySpace::Tenant,
                    if name == "child" {
                        MemoryStratum::Episode
                    } else {
                        MemoryStratum::Evidence
                    },
                    lineage,
                )
                .unwrap(),
            )
            .unwrap();
        trust.insert(id(name), MemoryTrustMetadata::unverified(1));
        records.push(RecoveryRecord {
            asset_id: id(name),
            embedding: vec![1.0, 0.0],
            payload: format!("sensitive payload {name}").into_bytes(),
            forgotten: false,
        });
    }
    let authority = GovernedMemoryProjection::new(
        tenant(),
        graph,
        trust,
        MemoryLoadoutPlan::new([MemoryLoadoutBinding::new(
            MemorySpace::Tenant,
            100,
            MemoryUsageMode::BootstrapAndOnDemand,
        )
        .unwrap()])
        .unwrap(),
    )
    .unwrap();
    ProviderGenerationStore::initialize(
        path,
        authority,
        RecoveryConfig {
            dimension: 2,
            simhash_bits: 64,
            per_tenant_capacity: 3,
            seed: 42,
        },
        &records,
    )
    .unwrap()
}

fn assert_purged(store: &ProviderGenerationStore) {
    assert_eq!(store.generation(), 1);
    let rows = store.recovered.source_records();
    assert_eq!(rows.len(), 3);
    for row in rows {
        if row.asset_id == id("survivor") {
            assert_eq!(row.payload, b"sensitive payload survivor");
            assert!(!row.forgotten);
        } else {
            assert!(row.is_physically_purged());
            assert_ne!(
                store.governance().graph.state(&row.asset_id),
                Some(MemoryAssetState::Active)
            );
        }
    }
    assert_eq!(
        store.governance().provenance.class(&id("root")),
        Some(MemoryProvenanceClass::Observed)
    );
    assert_eq!(
        store.governance().provenance.class(&id("child")),
        Some(MemoryProvenanceClass::Derived)
    );
    assert_eq!(
        store.governance().provenance.class(&id("survivor")),
        Some(MemoryProvenanceClass::Observed)
    );
    for dir in [PROVIDER_GENERATIONS_DIR, GOVERNANCE_GENERATIONS_DIR] {
        assert_eq!(fs::read_dir(store.root.join(dir)).unwrap().count(), 1);
    }
    assert!(!store.root.join(INTENT).exists());
    assert!(store.root.join(FLOOR).exists());
}

#[test]
fn purge_reclaims_capacity_and_keeps_ids_reserved_across_restart() {
    let dir = Directory::new();
    let store = initialize(&dir.0);
    let prepared = store.prepare_purge(&tenant(), id("root")).unwrap();
    // Unselected generations can also retain sensitive bytes and must be retired.
    fs::copy(
        dir.0
            .join(PROVIDER_GENERATIONS_DIR)
            .join(provider_generation_filename(0)),
        dir.0
            .join(PROVIDER_GENERATIONS_DIR)
            .join(provider_generation_filename(99)),
    )
    .unwrap();
    let (store, receipt) = store.commit_prepared_purge(prepared).unwrap();
    assert_purged(&store);
    assert!(store.matches_purge_receipt(&receipt));
    let write = |name: &str| AcceptedEvidenceWrite {
        asset_id: id(name),
        evidence: MemoryEvidenceRef::new("e:new").unwrap(),
        embedding: vec![0.0, 1.0],
        payload: b"new payload".to_vec(),
    };
    assert!(store.prepare_unverified_evidence(write("root")).is_err());
    let prepared = store
        .prepare_unverified_evidence(write("replacement"))
        .unwrap();
    let (store, _) = store.commit_prepared_evidence(prepared).unwrap();
    assert_eq!(store.recovered.source_records().len(), 4); // more metadata than provider capacity
    drop(store);
    let store = ProviderGenerationStore::open(&dir.0, tenant()).unwrap();
    assert_eq!(tombstones(store.recovered.source_records()).len(), 2);
    assert!(store.prepare_unverified_evidence(write("child")).is_err());
}

#[test]
fn authorization_tenant_and_unknown_id_fail_before_intent() {
    let dir = Directory::new();
    let store = initialize(&dir.0);
    assert!(store
        .prepare_purge(&TenantId::validated("other").unwrap(), id("root"))
        .is_err());
    assert!(store.prepare_purge(&tenant(), id("unknown")).is_err());
    assert!(!dir.0.join(INTENT).exists());
}

#[test]
fn ordinary_generation_cannot_resurrect_or_drop_purge_history() {
    let dir = Directory::new();
    let store = initialize(&dir.0);
    let old_authority = store.governance().clone();
    let old_records = store.recovered.source_records().to_vec();
    let prepared = store.prepare_purge(&tenant(), id("root")).unwrap();
    let (store, _) = store.commit_prepared_purge(prepared).unwrap();
    let config = store.config;
    assert!(store.advance(old_authority, config, &old_records).is_err());
    let store = ProviderGenerationStore::open(&dir.0, tenant()).unwrap();
    assert_purged(&store);
}

#[test]
fn old_selector_and_old_artifacts_cannot_bypass_retained_floor() {
    let dir = Directory::new();
    let store = initialize(&dir.0);
    let selector = fs::read(dir.0.join(PROVIDER_SELECTOR_FILE)).unwrap();
    let provider_name = provider_generation_filename(0);
    let governance_name = governance_generation_filename(0);
    let provider = fs::read(dir.0.join(PROVIDER_GENERATIONS_DIR).join(&provider_name)).unwrap();
    let governance = fs::read(
        dir.0
            .join(GOVERNANCE_GENERATIONS_DIR)
            .join(&governance_name),
    )
    .unwrap();
    let prepared = store.prepare_purge(&tenant(), id("root")).unwrap();
    let (store, _) = store.commit_prepared_purge(prepared).unwrap();
    drop(store);
    fs::write(dir.0.join(PROVIDER_SELECTOR_FILE), selector).unwrap();
    fs::write(
        dir.0.join(PROVIDER_GENERATIONS_DIR).join(provider_name),
        provider,
    )
    .unwrap();
    fs::write(
        dir.0.join(GOVERNANCE_GENERATIONS_DIR).join(governance_name),
        governance,
    )
    .unwrap();
    assert!(ProviderGenerationStore::open(&dir.0, tenant()).is_err());
}

#[test]
fn missing_floor_or_active_tombstone_fails_closed() {
    let dir = Directory::new();
    let store = initialize(&dir.0);
    let mut records = store.recovered.source_records().to_vec();
    records[0] = RecoveryRecord::physical_tombstone(id("root"));
    assert!(RecoveryImage::capture(store.governance(), store.config, &records).is_err());
    let prepared = store.prepare_purge(&tenant(), id("root")).unwrap();
    let (store, _) = store.commit_prepared_purge(prepared).unwrap();
    drop(store);
    fs::remove_file(dir.0.join(FLOOR)).unwrap();
    assert!(ProviderGenerationStore::open(&dir.0, tenant()).is_err());
}

#[test]
fn altered_intent_never_returns_the_old_serving_owner() {
    let dir = Directory::new();
    let store = initialize(&dir.0);
    let mut prepared = store.prepare_purge(&tenant(), id("root")).unwrap();
    prepared.intent.next_digest = "0".repeat(64);
    write_metadata(&dir.0, INTENT, &prepared.intent, None).unwrap();
    drop(store);
    assert!(ProviderGenerationStore::open(&dir.0, tenant()).is_err());
    assert!(dir.0.join(INTENT).exists());
}

#[cfg(unix)]
#[test]
fn cleanup_never_follows_a_generation_symlink() {
    let dir = Directory::new();
    let outside = Directory::new();
    let protected = outside.0.join("protected");
    fs::write(&protected, b"untouched").unwrap();
    let store = initialize(&dir.0);
    std::os::unix::fs::symlink(
        &protected,
        dir.0
            .join(PROVIDER_GENERATIONS_DIR)
            .join(provider_generation_filename(99)),
    )
    .unwrap();
    let prepared = store.prepare_purge(&tenant(), id("root")).unwrap();
    assert!(store.commit_prepared_purge(prepared).is_err());
    assert!(ProviderGenerationStore::open(&dir.0, tenant()).is_err());
    assert_eq!(fs::read(&protected).unwrap(), b"untouched");
}

#[test]
#[ignore = "child process entry point"]
fn crash_worker() {
    let dir = std::env::var_os("CCOS_PURGE_TEST_ROOT").unwrap();
    let store = ProviderGenerationStore::open(PathBuf::from(dir), tenant()).unwrap();
    let prepared = store.prepare_purge(&tenant(), id("root")).unwrap();
    store.commit_prepared_purge(prepared).unwrap();
    panic!("configured crash checkpoint was not reached");
}

#[test]
fn process_death_at_each_durable_boundary_rolls_forward_without_resurrection() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    for stage in ["intent", "artifacts", "selector", "cleanup", "floor"] {
        let dir = Directory::new();
        drop(initialize(&dir.0));
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "generation::purge::tests::crash_worker",
                "--ignored",
            ])
            .env("CCOS_PURGE_TEST_ROOT", &dir.0)
            .env("CCOS_PURGE_TEST_STAGE", stage)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let started = Instant::now();
        while !dir.0.join("test-ready").exists() && started.elapsed() < Duration::from_secs(20) {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let ready = dir.0.join("test-ready").exists();
        let _ = child.kill();
        child.wait().unwrap();
        assert!(ready, "child did not reach {stage}");
        if stage == "intent" {
            // A torn, unselected output is repairable only under the verified intent.
            fs::write(
                dir.0
                    .join(PROVIDER_GENERATIONS_DIR)
                    .join(provider_generation_filename(1)),
                b"{partial",
            )
            .unwrap();
        }
        let store = ProviderGenerationStore::open(&dir.0, tenant()).unwrap();
        assert_purged(&store);
        drop(store);
        assert_purged(&ProviderGenerationStore::open(&dir.0, tenant()).unwrap());
    }
}
