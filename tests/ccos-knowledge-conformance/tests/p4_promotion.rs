use std::collections::BTreeSet;

use ccos_enterprise_extract::{CandidateId, ExtractedValue};
use ccos_enterprise_knowledge::{JournalEntry, KnowledgeOp, KnowledgeState};
use ccos_enterprise_knowledge_model::{
    AssertionKind, CanonicalLiteral, EvidenceId, EvidenceRecord, FactObject, SourceId,
    SourceRecord, SourceTrust, TenantId, ValidityInterval,
};
use ccos_enterprise_ontology::{EntitySchema, Ontology, PropertySpec, ValueType};
use ccos_enterprise_promotion::plan_observation_promotion;
use ccos_enterprise_resolution::{EntityProposal, FactProposal};

fn ontology() -> Ontology {
    Ontology::new(
        TenantId("tenant-a".into()),
        "company-v1",
        [EntitySchema::new(
            "company",
            [
                PropertySpec::new("company_id", ValueType::String, true).unwrap(),
                PropertySpec::new("active", ValueType::Bool, true).unwrap(),
                PropertySpec::new("employees", ValueType::Number, false).unwrap(),
            ],
            false,
        )
        .unwrap()],
    )
    .unwrap()
}

fn proposal() -> EntityProposal {
    let left = CandidateId("candidate:crm".into());
    let right = CandidateId("candidate:erp".into());
    let evidence_left = EvidenceId::from("evidence:crm");
    let evidence_right = EvidenceId::from("evidence:erp");
    EntityProposal {
        id: "entity:company:acme-7".into(),
        tenant: TenantId("tenant-a".into()),
        entity_type: "company".into(),
        candidates: BTreeSet::from([left.clone(), right.clone()]),
        evidence: BTreeSet::from([evidence_left.clone(), evidence_right.clone()]),
        labels: BTreeSet::from(["Acme".into()]),
        facts: vec![
            FactProposal {
                candidate: left.clone(),
                predicate: "company_id".into(),
                value: ExtractedValue::String("ACME-7".into()),
                evidence: evidence_left.clone(),
            },
            FactProposal {
                candidate: right.clone(),
                predicate: "company_id".into(),
                value: ExtractedValue::String("ACME-7".into()),
                evidence: evidence_right.clone(),
            },
            FactProposal {
                candidate: left,
                predicate: "active".into(),
                value: ExtractedValue::Bool(true),
                evidence: evidence_left,
            },
            FactProposal {
                candidate: right,
                predicate: "employees".into(),
                value: ExtractedValue::Number("42".into()),
                evidence: evidence_right,
            },
        ],
    }
}

#[test]
fn schema_gated_plan_enters_canonical_state_only_through_journal() {
    let ontology = ontology();
    let plan =
        plan_observation_promotion(&ontology, &proposal(), ValidityInterval::unbounded()).unwrap();

    assert_eq!(plan.ontology_version, "company-v1");
    assert_eq!(plan.ontology_fingerprint, ontology.fingerprint());
    assert!(plan.plan_hash.starts_with("sha256:"));
    assert_eq!(plan.entity.kind, AssertionKind::Observation);
    assert!(plan
        .facts
        .iter()
        .all(|fact| fact.kind == AssertionKind::Observation));

    let tenant = TenantId("tenant-a".into());
    let source_crm = SourceId::from("source:crm");
    let source_erp = SourceId::from("source:erp");
    let evidence_crm = EvidenceId::from("evidence:crm");
    let evidence_erp = EvidenceId::from("evidence:erp");

    let mut journal = vec![
        JournalEntry::new(
            0,
            KnowledgeOp::RegisterSource(SourceRecord {
                id: source_crm.clone(),
                tenant: tenant.clone(),
                locator: "db://crm/company/7".into(),
                content_hash: Some("sha256:crm".into()),
                trust: SourceTrust::Internal,
            }),
        ),
        JournalEntry::new(
            1,
            KnowledgeOp::RegisterSource(SourceRecord {
                id: source_erp.clone(),
                tenant: tenant.clone(),
                locator: "db://erp/company/7".into(),
                content_hash: Some("sha256:erp".into()),
                trust: SourceTrust::Internal,
            }),
        ),
        JournalEntry::new(
            2,
            KnowledgeOp::AddEvidence(EvidenceRecord {
                id: evidence_crm,
                tenant: tenant.clone(),
                source: source_crm,
                locator: Some("row:7".into()),
                content_hash: Some("sha256:crm-row".into()),
            }),
        ),
        JournalEntry::new(
            3,
            KnowledgeOp::AddEvidence(EvidenceRecord {
                id: evidence_erp,
                tenant: tenant.clone(),
                source: source_erp,
                locator: Some("row:7".into()),
                content_hash: Some("sha256:erp-row".into()),
            }),
        ),
    ];

    for operation in plan.operations() {
        journal.push(JournalEntry::new(journal.len() as u64, operation));
    }

    let state = KnowledgeState::replay(journal.clone()).unwrap();
    let partition = state.tenant(&tenant).unwrap();
    assert_eq!(partition.entities.len(), 1);
    assert_eq!(partition.facts.len(), 3);
    assert!(partition.facts.values().any(|fact| matches!(
        fact.assertion.object,
        FactObject::Typed(CanonicalLiteral::Bool(true))
    )));
    assert!(partition.facts.values().any(|fact| matches!(
        fact.assertion.object,
        FactObject::Typed(CanonicalLiteral::Number(ref value)) if value.as_str() == "42"
    )));

    let replayed = KnowledgeState::replay(journal).unwrap();
    assert_eq!(
        state.canonical_hash().unwrap(),
        replayed.canonical_hash().unwrap()
    );
}
