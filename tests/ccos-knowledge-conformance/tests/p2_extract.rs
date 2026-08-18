use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ccos_enterprise_extract::{extract, ExtractedValue};
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
            "ccos-extract-conformance-{label}-{}-{ordinal}",
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
fn structural_candidate_enters_canonical_state_only_after_explicit_observation_write() {
    let dataset = TestDir::new("dataset");
    let journal = TestDir::new("journal");
    std::fs::write(
        dataset.0.join("companies.ndjson"),
        b"{\"name\":\"Acme\",\"sector\":\"industrial\"}\r\n{\"name\":\"Globex\"}\r\n",
    )
    .unwrap();

    let source = LocalTreeSource::new(
        TenantId("tenant-a".into()),
        "companies",
        &dataset.0,
        IngestLimits::default(),
    )
    .unwrap();
    let descriptor = source.enumerate().unwrap().remove(0);
    let raw = source.fetch(&descriptor).unwrap();
    let source_record = raw.source_record(SourceTrust::External);
    let batch = extract(&raw).unwrap();
    assert_eq!(batch.candidates.len(), 2);
    assert_eq!(
        batch.candidates[0].attributes["name"],
        ExtractedValue::String("Acme".into())
    );
    assert_eq!(batch.candidates[0].kind, AssertionKind::Observation);

    let evidence = batch.candidates[0].evidence.clone();
    let locator = evidence.locator.clone().unwrap();
    let span = locator.strip_prefix("bytes:").unwrap();
    let (start, end) = span.split_once('-').unwrap();
    let start: usize = start.parse().unwrap();
    let end: usize = end.parse().unwrap();
    assert_eq!(
        &raw.bytes[start..end],
        b"{\"name\":\"Acme\",\"sector\":\"industrial\"}"
    );

    let mut store = KnowledgeStore::open(&journal.0).unwrap();
    store
        .append(&[
            JournalEntry::new(0, KnowledgeOp::RegisterSource(source_record)),
            JournalEntry::new(1, KnowledgeOp::AddEvidence(evidence.clone())),
            JournalEntry::new(
                2,
                KnowledgeOp::AddEntity(EntityRecord {
                    id: EntityId::from("entity:pending-resolution:acme"),
                    tenant: TenantId("tenant-a".into()),
                    namespace: None,
                    entity_type: "record-candidate".into(),
                    label: Some("Acme".into()),
                    evidence: BTreeSet::from([evidence.id]),
                    kind: AssertionKind::Observation,
                }),
            ),
        ])
        .unwrap();

    let entity = &store
        .state()
        .tenant(&TenantId("tenant-a".into()))
        .unwrap()
        .entities[&EntityId::from("entity:pending-resolution:acme")];
    assert_eq!(entity.kind, AssertionKind::Observation);
}
