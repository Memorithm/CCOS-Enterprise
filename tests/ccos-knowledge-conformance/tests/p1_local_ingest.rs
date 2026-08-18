use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ccos_enterprise_ingest::{IngestLimits, KnowledgeSource, LocalTreeSource};
use ccos_enterprise_knowledge::model::{
    AssertionKind, EntityId, EntityRecord, SourceTrust, TenantId,
};
use ccos_enterprise_knowledge::{JournalEntry, KnowledgeOp};
use ccos_enterprise_knowledge_store::KnowledgeStore;

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let ordinal = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ccos-ingest-conformance-{label}-{}-{ordinal}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn local_artifact_reaches_canonical_journal_only_through_source_and_evidence() {
    let dataset = TestDir::new("dataset");
    let store_dir = TestDir::new("store");
    std::fs::write(dataset.0.join("company.json"), br#"{"name":"Acme"}"#).unwrap();

    let ingest = LocalTreeSource::new(
        TenantId("acme".into()),
        "company-data",
        &dataset.0,
        IngestLimits::default(),
    )
    .unwrap();
    let descriptor = ingest.enumerate().unwrap().remove(0);
    let artifact = ingest.fetch(&descriptor).unwrap();
    let source = artifact.source_record(SourceTrust::External);
    let evidence = artifact.whole_artifact_evidence();

    let mut store = KnowledgeStore::open(&store_dir.0).unwrap();
    store
        .append(&[
            JournalEntry::new(0, KnowledgeOp::RegisterSource(source.clone())),
            JournalEntry::new(1, KnowledgeOp::AddEvidence(evidence.clone())),
            JournalEntry::new(
                2,
                KnowledgeOp::AddEntity(EntityRecord {
                    id: EntityId::from("entity:acme"),
                    tenant: TenantId("acme".into()),
                    namespace: None,
                    entity_type: "company".into(),
                    label: Some("Acme".into()),
                    evidence: BTreeSet::from([evidence.id.clone()]),
                    kind: AssertionKind::Observation,
                }),
            ),
        ])
        .unwrap();

    let partition = store.state().tenant(&TenantId("acme".into())).unwrap();
    assert_eq!(partition.sources.len(), 1);
    assert_eq!(partition.evidence.len(), 1);
    assert_eq!(partition.entities.len(), 1);
    assert_eq!(
        partition.sources[&source.id].locator,
        "fs://company-data/company.json"
    );
    assert_eq!(
        partition.entities[&EntityId::from("entity:acme")].kind,
        AssertionKind::Observation
    );
}

#[test]
fn same_dataset_mounted_elsewhere_produces_same_canonical_source_identity() {
    let left = TestDir::new("left");
    let right = TestDir::new("right");
    std::fs::create_dir_all(left.0.join("nested")).unwrap();
    std::fs::create_dir_all(right.0.join("nested")).unwrap();
    std::fs::write(left.0.join("nested/fact.txt"), b"same").unwrap();
    std::fs::write(right.0.join("nested/fact.txt"), b"same").unwrap();

    let left_source = LocalTreeSource::new(
        TenantId("acme".into()),
        "dataset",
        &left.0,
        IngestLimits::default(),
    )
    .unwrap();
    let right_source = LocalTreeSource::new(
        TenantId("acme".into()),
        "dataset",
        &right.0,
        IngestLimits::default(),
    )
    .unwrap();

    let left_descriptor = left_source.enumerate().unwrap().remove(0);
    let right_descriptor = right_source.enumerate().unwrap().remove(0);
    assert_eq!(left_descriptor.source_id(), right_descriptor.source_id());
    let left_artifact = left_source.fetch(&left_descriptor).unwrap();
    let right_artifact = right_source.fetch(&right_descriptor).unwrap();
    assert_eq!(left_artifact.content_hash, right_artifact.content_hash);
}
