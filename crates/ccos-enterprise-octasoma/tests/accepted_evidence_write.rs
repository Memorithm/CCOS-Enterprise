use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ccos_enterprise_memory::{
    BudgetedMemoryRecall, GovernedMemoryProjection, GovernedRecallTrustPolicy,
    MemoryAssetDescriptor, MemoryAssetId, MemoryEvidenceRef, MemoryLineage, MemoryLineageGraph,
    MemoryLoadoutBinding, MemoryLoadoutPlan, MemoryProvenanceClass, MemoryRecallBudget,
    MemorySpace, MemoryStratum, MemoryTrustMetadata, MemoryUsageMode, MemoryValidationState,
};
use ccos_enterprise_octasoma::accepted_write::{
    AcceptedEvidenceWrite, AcceptedEvidenceWriteError, EvidenceGenerationReceipt,
};
use ccos_enterprise_octasoma::generation::ProviderGenerationStore;
use ccos_enterprise_octasoma::recovery::{RecoveryConfig, RecoveryRecord};
use ccos_enterprise_tenancy::{TenantId, TenantScope};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ccos-accepted-evidence-{}-{}",
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
fn id(value: &str) -> MemoryAssetId {
    MemoryAssetId::new(value).unwrap()
}
fn evidence(value: &str) -> MemoryEvidenceRef {
    MemoryEvidenceRef::new(value).unwrap()
}
fn config() -> RecoveryConfig {
    RecoveryConfig {
        dimension: 2,
        simhash_bits: 64,
        per_tenant_capacity: 8,
        seed: 42,
    }
}

fn initial_projection() -> GovernedMemoryProjection {
    let mut graph = MemoryLineageGraph::new();
    graph
        .register(
            MemoryAssetDescriptor::new(
                id("verified-root"),
                MemorySpace::Tenant,
                MemoryStratum::Evidence,
                MemoryLineage::root([evidence("audit:verified-root")]).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    GovernedMemoryProjection::new(
        tenant(),
        graph,
        BTreeMap::from([(
            id("verified-root"),
            MemoryTrustMetadata::new(
                MemoryValidationState::Verified,
                1,
                1,
                0,
                ["proof:verified-root".to_string()],
            )
            .unwrap(),
        )]),
        MemoryLoadoutPlan::new([MemoryLoadoutBinding::new(
            MemorySpace::Tenant,
            100,
            MemoryUsageMode::BootstrapAndOnDemand,
        )
        .unwrap()])
        .unwrap(),
    )
    .unwrap()
}

fn initial_records() -> Vec<RecoveryRecord> {
    vec![RecoveryRecord {
        asset_id: id("verified-root"),
        embedding: vec![1.0, 0.0],
        payload: b"verified old evidence".to_vec(),
        forgotten: false,
    }]
}

fn write(asset: &str, payload: &[u8], embedding: [f32; 2]) -> AcceptedEvidenceWrite {
    AcceptedEvidenceWrite {
        asset_id: id(asset),
        evidence: evidence(&format!("audit:{asset}")),
        embedding: embedding.to_vec(),
        payload: payload.to_vec(),
    }
}

#[test]
fn accepted_evidence_advances_generation_but_stays_out_of_verified_context() {
    let dir = Directory::new();
    let store = ProviderGenerationStore::initialize(
        &dir.0,
        initial_projection(),
        config(),
        &initial_records(),
    )
    .unwrap();
    assert_eq!(store.generation(), 0);

    let prepared = store
        .prepare_unverified_evidence(write(
            "fresh-unverified",
            b"new direct evidence",
            [0.0, 1.0],
        ))
        .unwrap();
    assert_eq!(
        store.generation(),
        0,
        "preparation must be side-effect free"
    );

    let (store, receipt) = store.commit_prepared_evidence(prepared).unwrap();
    assert_eq!(store.generation(), 1);
    assert_eq!(receipt.generation, 1);
    assert_eq!(receipt.asset_id, id("fresh-unverified"));
    assert!(store.matches_evidence_receipt(&receipt));
    assert_eq!(store.recovered().stored_records(), 2);

    let descriptor = store
        .governance()
        .graph
        .descriptor(&id("fresh-unverified"))
        .unwrap();
    assert_eq!(descriptor.space, MemorySpace::Tenant);
    assert_eq!(descriptor.stratum, MemoryStratum::Evidence);
    assert!(descriptor.lineage.parents().next().is_none());
    assert_eq!(
        descriptor.lineage.evidence().next().unwrap().as_str(),
        "audit:fresh-unverified"
    );
    assert_eq!(
        store.governance().trust[&id("fresh-unverified")].state(),
        MemoryValidationState::Unverified
    );
    assert_eq!(
        store.governance().provenance.class(&id("fresh-unverified")),
        Some(MemoryProvenanceClass::Observed)
    );

    let loadout = store
        .governance()
        .loadout
        .bootstrap_loadout()
        .unwrap()
        .unwrap();
    let recalled = store
        .recovered()
        .recall(
            store.governance(),
            TenantScope::new(
                tenant(),
                BudgetedMemoryRecall {
                    embedding: &[0.0, 1.0],
                    loadout: &loadout,
                    budget: MemoryRecallBudget::new(8, 8, 4096).unwrap(),
                },
            ),
            GovernedRecallTrustPolicy::VerifiedOnly,
        )
        .unwrap();
    assert!(recalled
        .iter()
        .all(|observation| observation.asset_id != id("fresh-unverified")));

    let wrong = EvidenceGenerationReceipt {
        generation: 2,
        asset_id: receipt.asset_id.clone(),
        image_digest: receipt.image_digest,
    };
    assert!(!store.matches_evidence_receipt(&wrong));
}

#[test]
fn duplicate_asset_is_refused_before_any_generation_side_effect() {
    let dir = Directory::new();
    let store = ProviderGenerationStore::initialize(
        &dir.0,
        initial_projection(),
        config(),
        &initial_records(),
    )
    .unwrap();
    let error = store
        .prepare_unverified_evidence(write("verified-root", b"duplicate", [1.0, 0.0]))
        .unwrap_err();
    assert!(matches!(
        error,
        AcceptedEvidenceWriteError::DuplicateAsset(ref asset)
            if asset == &id("verified-root")
    ));
    assert_eq!(store.generation(), 0);
    assert_eq!(store.recovered().stored_records(), 1);
}

#[test]
fn prepared_population_is_bound_to_its_base_generation_and_digest() {
    let dir = Directory::new();
    let store = ProviderGenerationStore::initialize(
        &dir.0,
        initial_projection(),
        config(),
        &initial_records(),
    )
    .unwrap();
    let stale = store
        .prepare_unverified_evidence(write("stale", b"stale", [0.0, 1.0]))
        .unwrap();
    let current = store
        .prepare_unverified_evidence(write("current", b"current", [0.5, 0.5]))
        .unwrap();
    let (store, _) = store.commit_prepared_evidence(current).unwrap();
    assert_eq!(store.generation(), 1);
    assert!(matches!(
        store.commit_prepared_evidence(stale),
        Err(AcceptedEvidenceWriteError::StalePreparation)
    ));
}
