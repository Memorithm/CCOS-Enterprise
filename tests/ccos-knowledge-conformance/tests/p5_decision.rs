use std::collections::BTreeSet;

use ccos_enterprise_auth::ActorId;
use ccos_enterprise_decision::{
    DecisionDraft, DecisionJournalEntry, DecisionOp, DecisionOutcomeDraft, DecisionState,
    KnowledgeAnchor, OutcomeStatus, SimilarDecisionQuery, TraversalLimits,
};
use ccos_enterprise_knowledge::{JournalEntry, KnowledgeOp, KnowledgeState};
use ccos_enterprise_knowledge_model::{
    AssertionKind, DecisionId, EntityId, EntityRecord, EvidenceId, EvidenceRecord, FactAssertion,
    FactId, FactObject, RuleId, SourceId, SourceRecord, SourceTrust, TenantId, ValidityInterval,
};

fn tenant(name: &str) -> TenantId {
    TenantId(name.to_owned())
}

fn evidence() -> BTreeSet<EvidenceId> {
    BTreeSet::from([EvidenceId::from("evidence:policy")])
}

fn knowledge() -> KnowledgeState {
    let mut entries = Vec::new();
    let mut sequence = 0_u64;
    for name in ["acme", "globex"] {
        let tenant = tenant(name);
        entries.push(JournalEntry::new(
            sequence,
            KnowledgeOp::RegisterSource(SourceRecord {
                id: SourceId::from("source:policy"),
                tenant: tenant.clone(),
                locator: format!("file:///{name}/policy.json"),
                content_hash: Some(format!("sha256:{name}")),
                trust: SourceTrust::Authoritative,
            }),
        ));
        sequence += 1;
        entries.push(JournalEntry::new(
            sequence,
            KnowledgeOp::AddEvidence(EvidenceRecord {
                id: EvidenceId::from("evidence:policy"),
                tenant: tenant.clone(),
                source: SourceId::from("source:policy"),
                locator: Some("$.approval".into()),
                content_hash: Some(format!("sha256:{name}:approval")),
            }),
        ));
        sequence += 1;
        entries.push(JournalEntry::new(
            sequence,
            KnowledgeOp::AddEntity(EntityRecord {
                id: EntityId::from("entity:request"),
                tenant: tenant.clone(),
                namespace: None,
                entity_type: "deployment_request".into(),
                label: Some(format!("{name} deployment")),
                evidence: evidence(),
                kind: AssertionKind::Authoritative,
            }),
        ));
        sequence += 1;
        entries.push(JournalEntry::new(
            sequence,
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
        ));
        sequence += 1;
    }
    KnowledgeState::replay(entries).unwrap()
}

fn draft(
    tenant_name: &str,
    id: &str,
    question: &str,
    selected: &str,
    knowledge: &KnowledgeState,
) -> DecisionDraft {
    DecisionDraft {
        id: DecisionId::from(id),
        tenant: tenant(tenant_name),
        actor: ActorId("agent-7".into()),
        question: question.into(),
        selected: selected.into(),
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
fn decisions_are_searchable_causal_replayable_and_exportable() {
    let knowledge = knowledge();
    let mut state = DecisionState::new();
    let mut journal = Vec::new();

    let first = DecisionJournalEntry::new(
        0,
        DecisionOp::Record(draft(
            "acme",
            "decision:approve",
            "Should this request be approved?",
            "approve",
            &knowledge,
        )),
    );
    state.apply(first.clone(), &knowledge).unwrap();
    journal.push(first);

    let mut second_draft = draft(
        "acme",
        "decision:deploy",
        "Should the approved request proceed to deployment?",
        "deploy",
        &knowledge,
    );
    second_draft
        .precedents
        .insert(DecisionId::from("decision:approve"));
    let second = DecisionJournalEntry::new(1, DecisionOp::Record(second_draft));
    state.apply(second.clone(), &knowledge).unwrap();
    journal.push(second);

    let outcome = DecisionJournalEntry::new(
        2,
        DecisionOp::RecordOutcome {
            tenant: tenant("acme"),
            decision: DecisionId::from("decision:deploy"),
            outcome: DecisionOutcomeDraft {
                status: OutcomeStatus::Succeeded,
                summary: "Deployment completed under the approved policy.".into(),
                evidence: evidence(),
                knowledge: KnowledgeAnchor::capture(&knowledge).unwrap(),
            },
        },
    );
    state.apply(outcome.clone(), &knowledge).unwrap();
    journal.push(outcome);

    let matches = state
        .similar_decisions(&SimilarDecisionQuery {
            tenant: tenant("acme"),
            question: "Should this request be approved?".into(),
            facts: BTreeSet::from([FactId::from("fact:eligible")]),
            relations: BTreeSet::new(),
            rules: BTreeSet::from([RuleId::from("rule:approval")]),
            exclude: None,
            limit: 8,
        })
        .unwrap();
    assert_eq!(matches[0].decision, DecisionId::from("decision:approve"));
    assert!(matches[0].score.weighted_total() > 0);

    let limits = TraversalLimits::default();
    assert_eq!(
        state
            .causal_ancestry(
                &tenant("acme"),
                &DecisionId::from("decision:deploy"),
                limits,
            )
            .unwrap(),
        vec![DecisionId::from("decision:approve")]
    );
    assert_eq!(
        state
            .causal_dependents(
                &tenant("acme"),
                &DecisionId::from("decision:approve"),
                limits,
            )
            .unwrap(),
        vec![DecisionId::from("decision:deploy")]
    );

    let impact = state
        .impact_analysis(
            &tenant("acme"),
            &DecisionId::from("decision:approve"),
            limits,
        )
        .unwrap();
    assert_eq!(
        impact.dependent_decisions,
        vec![DecisionId::from("decision:deploy")]
    );
    assert!(impact.facts.contains(&FactId::from("fact:eligible")));
    assert!(impact.rules.contains(&RuleId::from("rule:approval")));

    let trail = state
        .regulatory_trail(
            &tenant("acme"),
            &DecisionId::from("decision:deploy"),
            limits,
        )
        .unwrap();
    assert_eq!(trail.records.len(), 2);
    assert_eq!(trail.records[0].id, DecisionId::from("decision:approve"));
    assert_eq!(trail.records[1].id, DecisionId::from("decision:deploy"));
    assert_eq!(
        trail.records[1].outcome.as_ref().unwrap().status,
        OutcomeStatus::Succeeded
    );
    assert_eq!(
        trail.canonical_json().unwrap(),
        trail.canonical_json().unwrap()
    );
    assert_eq!(
        trail.canonical_hash().unwrap(),
        trail.canonical_hash().unwrap()
    );

    let replayed = DecisionState::replay(journal).unwrap();
    assert_eq!(
        state.canonical_hash().unwrap(),
        replayed.canonical_hash().unwrap(),
        "admitted decision journals must replay bit-stably"
    );
}

#[test]
fn a_tenant_cannot_cite_another_tenants_precedent() {
    let knowledge = knowledge();
    let mut state = DecisionState::new();
    state
        .apply(
            DecisionJournalEntry::new(
                0,
                DecisionOp::Record(draft(
                    "acme",
                    "decision:acme-secret",
                    "Should Acme approve?",
                    "approve",
                    &knowledge,
                )),
            ),
            &knowledge,
        )
        .unwrap();

    let mut foreign = draft(
        "globex",
        "decision:globex",
        "Should Globex approve?",
        "approve",
        &knowledge,
    );
    foreign
        .precedents
        .insert(DecisionId::from("decision:acme-secret"));
    let error = state
        .apply(
            DecisionJournalEntry::new(1, DecisionOp::Record(foreign)),
            &knowledge,
        )
        .unwrap_err();
    assert_eq!(
        error,
        ccos_enterprise_decision::DecisionError::UnknownPrecedent(DecisionId::from(
            "decision:acme-secret"
        ))
    );
    assert_eq!(state.next_sequence(), 1);
    assert!(state.tenant(&tenant("globex")).is_none());
}

#[test]
fn invalidated_knowledge_cannot_become_a_new_decision_basis() {
    let mut knowledge = knowledge();
    knowledge
        .apply(JournalEntry::new(
            8,
            KnowledgeOp::InvalidateFact {
                tenant: tenant("acme"),
                fact: FactId::from("fact:eligible"),
            },
        ))
        .unwrap();

    let mut state = DecisionState::new();
    let error = state
        .apply(
            DecisionJournalEntry::new(
                0,
                DecisionOp::Record(draft(
                    "acme",
                    "decision:stale",
                    "Should stale evidence be trusted?",
                    "approve",
                    &knowledge,
                )),
            ),
            &knowledge,
        )
        .unwrap_err();
    assert_eq!(
        error,
        ccos_enterprise_decision::DecisionError::StaleFact(FactId::from("fact:eligible"))
    );
    assert_eq!(state.next_sequence(), 0);
}
