use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ccos_enterprise_auth::ActorId;
use ccos_enterprise_decision::{
    DecisionDraft, DecisionError, DecisionJournalEntry, DecisionOp, DecisionOutcomeDraft,
    KnowledgeAnchor, OutcomeStatus, TraversalLimits,
};
use ccos_enterprise_decision_store::{DecisionStore, StoreError, JOURNAL_FILE};
use ccos_enterprise_knowledge::{JournalEntry, KnowledgeOp, KnowledgeState};
use ccos_enterprise_knowledge_model::{
    AssertionKind, DecisionId, EntityId, EntityRecord, EvidenceId, EvidenceRecord, FactAssertion,
    FactId, FactObject, RuleId, SourceId, SourceRecord, SourceTrust, TenantId, ValidityInterval,
};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let ordinal = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ccos-p5b-decision-store-{}-{ordinal}",
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

fn tenant() -> TenantId {
    TenantId("acme".into())
}

fn evidence() -> BTreeSet<EvidenceId> {
    BTreeSet::from([EvidenceId::from("evidence:policy")])
}

fn knowledge() -> KnowledgeState {
    let tenant = tenant();
    KnowledgeState::replay(vec![
        JournalEntry::new(
            0,
            KnowledgeOp::RegisterSource(SourceRecord {
                id: SourceId::from("source:policy"),
                tenant: tenant.clone(),
                locator: "file:///acme/policy.json".into(),
                content_hash: Some("sha256:policy".into()),
                trust: SourceTrust::Authoritative,
            }),
        ),
        JournalEntry::new(
            1,
            KnowledgeOp::AddEvidence(EvidenceRecord {
                id: EvidenceId::from("evidence:policy"),
                tenant: tenant.clone(),
                source: SourceId::from("source:policy"),
                locator: Some("$.approval".into()),
                content_hash: Some("sha256:approval".into()),
            }),
        ),
        JournalEntry::new(
            2,
            KnowledgeOp::AddEntity(EntityRecord {
                id: EntityId::from("entity:request"),
                tenant: tenant.clone(),
                namespace: None,
                entity_type: "deployment_request".into(),
                label: Some("Acme deployment".into()),
                evidence: evidence(),
                kind: AssertionKind::Authoritative,
            }),
        ),
        JournalEntry::new(
            3,
            KnowledgeOp::AssertFact(FactAssertion {
                id: FactId::from("fact:eligible"),
                tenant,
                subject: EntityId::from("entity:request"),
                predicate: "eligible".into(),
                object: FactObject::Literal("true".into()),
                validity: ValidityInterval::unbounded(),
                evidence: evidence(),
                kind: AssertionKind::Authoritative,
            }),
        ),
    ])
    .unwrap()
}

fn draft(id: &str, knowledge: &KnowledgeState) -> DecisionDraft {
    DecisionDraft {
        id: DecisionId::from(id),
        tenant: tenant(),
        actor: ActorId("agent-7".into()),
        question: "Should this deployment proceed?".into(),
        selected: "approve".into(),
        rationale: "The authoritative eligibility fact and approval rule support this action."
            .into(),
        facts: BTreeSet::from([FactId::from("fact:eligible")]),
        relations: BTreeSet::new(),
        evidence: evidence(),
        rules: BTreeSet::from([RuleId::from("rule:approval")]),
        precedents: BTreeSet::new(),
        knowledge: KnowledgeAnchor::capture(knowledge).unwrap(),
    }
}

#[test]
fn durable_decision_journal_survives_restart_and_keeps_accountable_views() {
    let dir = TestDir::new();
    let knowledge = knowledge();

    {
        let mut store = DecisionStore::open(&dir.0).unwrap();
        store
            .append(
                &[DecisionJournalEntry::new(
                    0,
                    DecisionOp::Record(draft("decision:approve", &knowledge)),
                )],
                &knowledge,
            )
            .unwrap();
        assert_eq!(store.next_sequence(), 1);
    }

    let expected_hash;
    {
        let mut store = DecisionStore::open(&dir.0).unwrap();
        assert_eq!(
            store.next_sequence(),
            1,
            "restart must resume journal order"
        );

        let mut deployment = draft("decision:deploy", &knowledge);
        deployment
            .precedents
            .insert(DecisionId::from("decision:approve"));
        store
            .append(
                &[DecisionJournalEntry::new(1, DecisionOp::Record(deployment))],
                &knowledge,
            )
            .unwrap();
        store
            .append(
                &[DecisionJournalEntry::new(
                    2,
                    DecisionOp::RecordOutcome {
                        tenant: tenant(),
                        decision: DecisionId::from("decision:deploy"),
                        outcome: DecisionOutcomeDraft {
                            status: OutcomeStatus::Succeeded,
                            summary: "Deployment completed under the approved policy.".into(),
                            evidence: evidence(),
                            knowledge: KnowledgeAnchor::capture(&knowledge).unwrap(),
                        },
                    },
                )],
                &knowledge,
            )
            .unwrap();
        expected_hash = store.state().canonical_hash().unwrap();
    }

    let loaded = DecisionStore::load(&dir.0).unwrap();
    assert_eq!(loaded.entries.len(), 3);
    assert_eq!(loaded.torn_tail, 0);
    assert_eq!(loaded.state.canonical_hash().unwrap(), expected_hash);
    assert_eq!(
        loaded
            .state
            .causal_ancestry(
                &tenant(),
                &DecisionId::from("decision:deploy"),
                TraversalLimits::default(),
            )
            .unwrap(),
        vec![DecisionId::from("decision:approve")]
    );
    assert_eq!(
        loaded
            .state
            .decision(&tenant(), &DecisionId::from("decision:deploy"))
            .unwrap()
            .outcome
            .as_ref()
            .unwrap()
            .status,
        OutcomeStatus::Succeeded
    );
}

#[test]
fn a_decision_cannot_be_persisted_against_a_different_knowledge_snapshot() {
    let dir = TestDir::new();
    let original = knowledge();
    let entry = DecisionJournalEntry::new(
        0,
        DecisionOp::Record(draft("decision:stale-anchor", &original)),
    );

    let mut advanced = original.clone();
    advanced
        .apply(JournalEntry::new(
            4,
            KnowledgeOp::RegisterSource(SourceRecord {
                id: SourceId::from("source:new"),
                tenant: tenant(),
                locator: "file:///acme/new.json".into(),
                content_hash: Some("sha256:new".into()),
                trust: SourceTrust::Internal,
            }),
        ))
        .unwrap();

    let mut store = DecisionStore::open(&dir.0).unwrap();
    let error = store.append(&[entry], &advanced).unwrap_err();
    assert!(matches!(
        error,
        StoreError::Decision(DecisionError::KnowledgeAnchorMismatch)
    ));
    assert_eq!(store.next_sequence(), 0);
    drop(store);
    assert!(std::fs::read(dir.0.join(JOURNAL_FILE)).unwrap().is_empty());
}
