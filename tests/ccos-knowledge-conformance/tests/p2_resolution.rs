use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ccos_enterprise_extract::extract;
use ccos_enterprise_ingest::{IngestLimits, KnowledgeSource, LocalTreeSource};
use ccos_enterprise_knowledge::model::{AssertionKind, SourceTrust, TenantId};
use ccos_enterprise_knowledge::{JournalEntry, KnowledgeOp};
use ccos_enterprise_knowledge_store::KnowledgeStore;
use ccos_enterprise_resolution::{resolve_batches, IdentityNormalization, ResolutionSchema};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let ordinal = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ccos-resolution-conformance-{label}-{}-{ordinal}",
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
fn two_sources_resolve_to_one_observation_only_after_explicit_journal_write() {
    let crm_dir = TestDir::new("crm");
    let erp_dir = TestDir::new("erp");
    let journal = TestDir::new("journal");
    std::fs::write(
        crm_dir.0.join("company.json"),
        br#"{"company_id":"C-7","name":"Acme","country":"FR"}"#,
    )
    .unwrap();
    std::fs::write(
        erp_dir.0.join("company.json"),
        br#"{"company_id":"C-7","name":"Acme","employees":42}"#,
    )
    .unwrap();

    let ingest = |root: &PathBuf, namespace: &str| {
        LocalTreeSource::new(
            TenantId("tenant-a".into()),
            namespace,
            root,
            IngestLimits::default(),
        )
        .unwrap()
    };
    let crm = ingest(&crm_dir.0, "crm");
    let erp = ingest(&erp_dir.0, "erp");
    let crm_raw = crm.fetch(&crm.enumerate().unwrap().remove(0)).unwrap();
    let erp_raw = erp.fetch(&erp.enumerate().unwrap().remove(0)).unwrap();
    let crm_batch = extract(&crm_raw).unwrap();
    let erp_batch = extract(&erp_raw).unwrap();
    let crm_evidence = crm_batch.candidates[0].evidence.clone();
    let erp_evidence = erp_batch.candidates[0].evidence.clone();

    let schema = ResolutionSchema::new(
        "company",
        ["company_id"],
        Some("name".into()),
        IdentityNormalization::Exact,
    )
    .unwrap();
    let resolved = resolve_batches(&[crm_batch, erp_batch], &schema).unwrap();
    assert_eq!(resolved.proposals.len(), 1);
    let proposal = resolved.proposals.values().next().unwrap();
    assert_eq!(proposal.evidence.len(), 2);
    let entity = proposal.entity_observation().unwrap();
    assert_eq!(entity.kind, AssertionKind::Observation);

    let mut store = KnowledgeStore::open(&journal.0).unwrap();
    store
        .append(&[
            JournalEntry::new(
                0,
                KnowledgeOp::RegisterSource(crm_raw.source_record(SourceTrust::External)),
            ),
            JournalEntry::new(1, KnowledgeOp::AddEvidence(crm_evidence)),
            JournalEntry::new(
                2,
                KnowledgeOp::RegisterSource(erp_raw.source_record(SourceTrust::External)),
            ),
            JournalEntry::new(3, KnowledgeOp::AddEvidence(erp_evidence)),
            JournalEntry::new(4, KnowledgeOp::AddEntity(entity.clone())),
        ])
        .unwrap();

    let partition = store.state().tenant(&TenantId("tenant-a".into())).unwrap();
    assert_eq!(partition.entities.len(), 1);
    assert_eq!(partition.entities[&entity.id].evidence.len(), 2);
    assert_eq!(
        partition.entities[&entity.id].kind,
        AssertionKind::Observation
    );
}
