use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ccos_enterprise_knowledge::model::{
    AssertionKind, EntityId, EntityRecord, EvidenceId, EvidenceRecord, FactAssertion, FactId,
    FactObject, SourceId, SourceRecord, SourceTrust, TenantId, UnixMillis, ValidityInterval,
};
use ccos_enterprise_knowledge::{JournalEntry, KnowledgeError, KnowledgeOp};
use ccos_enterprise_knowledge_store::{KnowledgeStore, StoreError};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let ordinal = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ccos-knowledge-conformance-{}-{ordinal}",
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

fn tenant(id: &str) -> TenantId {
    TenantId(id.to_owned())
}

fn evidence(id: &str) -> BTreeSet<EvidenceId> {
    BTreeSet::from([EvidenceId::from(id)])
}

fn source(sequence: u64, tenant_id: &str, id: &str) -> JournalEntry {
    JournalEntry::new(
        sequence,
        KnowledgeOp::RegisterSource(SourceRecord {
            id: SourceId::from(id),
            tenant: tenant(tenant_id),
            locator: format!("file:///{tenant_id}/{id}"),
            content_hash: Some(format!("sha256:{tenant_id}:{id}")),
            trust: SourceTrust::Authoritative,
        }),
    )
}

fn evidence_record(sequence: u64, tenant_id: &str, id: &str, source_id: &str) -> JournalEntry {
    JournalEntry::new(
        sequence,
        KnowledgeOp::AddEvidence(EvidenceRecord {
            id: EvidenceId::from(id),
            tenant: tenant(tenant_id),
            source: SourceId::from(source_id),
            locator: Some("$.record".into()),
            content_hash: None,
        }),
    )
}

fn entity(sequence: u64, tenant_id: &str, evidence_id: &str) -> JournalEntry {
    JournalEntry::new(
        sequence,
        KnowledgeOp::AddEntity(EntityRecord {
            id: EntityId::from("entity:company"),
            tenant: tenant(tenant_id),
            namespace: None,
            entity_type: "company".into(),
            label: Some("Acme".into()),
            evidence: evidence(evidence_id),
            kind: AssertionKind::Authoritative,
        }),
    )
}

fn ceo(sequence: u64, id: &str, value: &str) -> JournalEntry {
    JournalEntry::new(
        sequence,
        KnowledgeOp::AssertFact(FactAssertion {
            id: FactId::from(id),
            tenant: tenant("acme"),
            subject: EntityId::from("entity:company"),
            predicate: "ceo".into(),
            object: FactObject::Literal(value.into()),
            validity: ValidityInterval {
                valid_from: Some(UnixMillis(1_000)),
                valid_until: None,
            },
            evidence: evidence("evidence:acme"),
            kind: AssertionKind::Authoritative,
        }),
    )
}

#[test]
fn durable_conflict_provenance_and_bitemporal_state_survive_restart() {
    let dir = TestDir::new();
    let expected_hash;
    {
        let mut store = KnowledgeStore::open(&dir.0).unwrap();
        store
            .append(&[
                source(0, "acme", "source:acme"),
                evidence_record(1, "acme", "evidence:acme", "source:acme"),
                entity(2, "acme", "evidence:acme"),
                ceo(3, "fact:alice", "Alice"),
                ceo(4, "fact:bob", "Bob"),
            ])
            .unwrap();

        let partition = store.state().tenant(&tenant("acme")).unwrap();
        assert_eq!(partition.facts.len(), 2);
        assert_eq!(partition.conflicts.len(), 1);
        assert_eq!(
            store
                .state()
                .facts_at(&tenant("acme"), UnixMillis(1_001), 4)
                .unwrap()
                .len(),
            2
        );
        let provenance = store
            .state()
            .fact_provenance(&tenant("acme"), &FactId::from("fact:alice"))
            .unwrap();
        assert_eq!(provenance.evidence.len(), 1);
        assert_eq!(provenance.sources[0].id, SourceId::from("source:acme"));
        expected_hash = store.state().canonical_hash().unwrap();
    }

    let loaded = KnowledgeStore::load(&dir.0).unwrap();
    assert_eq!(loaded.torn_tail, 0);
    assert_eq!(loaded.entries.len(), 5);
    assert_eq!(loaded.state.canonical_hash().unwrap(), expected_hash);
    let partition = loaded.state.tenant(&tenant("acme")).unwrap();
    assert_eq!(partition.facts.len(), 2);
    assert_eq!(partition.conflicts.len(), 1);
}

#[test]
fn cross_tenant_reference_is_refused_without_advancing_durable_journal() {
    let dir = TestDir::new();
    let mut store = KnowledgeStore::open(&dir.0).unwrap();
    store
        .append(&[
            source(0, "acme", "source:acme"),
            evidence_record(1, "acme", "evidence:acme-secret", "source:acme"),
            source(2, "globex", "source:globex"),
            evidence_record(3, "globex", "evidence:globex", "source:globex"),
        ])
        .unwrap();

    let result = store.append(&[entity(4, "globex", "evidence:acme-secret")]);
    assert!(matches!(
        result,
        Err(StoreError::Knowledge(KnowledgeError::UnknownEvidence(id)))
            if id == EvidenceId::from("evidence:acme-secret")
    ));
    assert_eq!(store.next_sequence(), 4);
    drop(store);

    let loaded = KnowledgeStore::load(&dir.0).unwrap();
    assert_eq!(loaded.entries.len(), 4);
    assert_eq!(loaded.state.next_sequence(), 4);
}
