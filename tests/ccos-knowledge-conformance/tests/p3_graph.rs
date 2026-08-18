use std::collections::BTreeSet;

use ccos_enterprise_kg::{GraphLimits, GraphView};
use ccos_enterprise_knowledge::model::{
    AssertionKind, EntityId, EntityRecord, EvidenceId, EvidenceRecord, RelationAssertion,
    RelationId, SourceId, SourceRecord, SourceTrust, TenantId, UnixMillis, ValidityInterval,
};
use ccos_enterprise_knowledge::{JournalEntry, KnowledgeOp, KnowledgeState};

fn evidence() -> BTreeSet<EvidenceId> {
    BTreeSet::from([EvidenceId::from("evidence:1")])
}

#[test]
fn graph_view_is_tenant_scoped_rebuildable_and_valid_time_aware() {
    let acme = TenantId("acme".into());
    let globex = TenantId("globex".into());
    let mut entries = Vec::new();
    let mut sequence = 0_u64;

    for tenant in [&acme, &globex] {
        entries.push(JournalEntry::new(
            sequence,
            KnowledgeOp::RegisterSource(SourceRecord {
                id: SourceId::from("source:1"),
                tenant: tenant.clone(),
                locator: format!("memory://{}", tenant.0),
                content_hash: Some("sha256:test".into()),
                trust: SourceTrust::Internal,
            }),
        ));
        sequence += 1;
        entries.push(JournalEntry::new(
            sequence,
            KnowledgeOp::AddEvidence(EvidenceRecord {
                id: EvidenceId::from("evidence:1"),
                tenant: tenant.clone(),
                source: SourceId::from("source:1"),
                locator: Some("bytes:0-1".into()),
                content_hash: Some("sha256:test".into()),
            }),
        ));
        sequence += 1;
        for id in ["service", "db", "archive"] {
            entries.push(JournalEntry::new(
                sequence,
                KnowledgeOp::AddEntity(EntityRecord {
                    id: EntityId::from(id),
                    tenant: tenant.clone(),
                    namespace: None,
                    entity_type: "component".into(),
                    label: Some(id.into()),
                    evidence: evidence(),
                    kind: AssertionKind::Observation,
                }),
            ));
            sequence += 1;
        }
    }

    entries.push(JournalEntry::new(
        sequence,
        KnowledgeOp::AssertRelation(RelationAssertion {
            id: RelationId::from("r:service-db"),
            tenant: acme.clone(),
            from: EntityId::from("service"),
            relation: "depends_on".into(),
            to: EntityId::from("db"),
            validity: ValidityInterval::unbounded(),
            evidence: evidence(),
            kind: AssertionKind::Observation,
        }),
    ));
    sequence += 1;
    entries.push(JournalEntry::new(
        sequence,
        KnowledgeOp::AssertRelation(RelationAssertion {
            id: RelationId::from("r:db-archive"),
            tenant: acme.clone(),
            from: EntityId::from("db"),
            relation: "depends_on".into(),
            to: EntityId::from("archive"),
            validity: ValidityInterval {
                valid_from: Some(UnixMillis(0)),
                valid_until: Some(UnixMillis(100)),
            },
            evidence: evidence(),
            kind: AssertionKind::Observation,
        }),
    ));

    let state = KnowledgeState::replay(entries.clone()).unwrap();
    let acme_view = GraphView::new(&state, &acme, UnixMillis(50), GraphLimits::default()).unwrap();
    let path = acme_view
        .shortest_path(
            &EntityId::from("service"),
            &EntityId::from("archive"),
            Some("depends_on"),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        path.entities
            .iter()
            .map(EntityId::as_str)
            .collect::<Vec<_>>(),
        vec!["service", "db", "archive"]
    );

    let later = GraphView::new(&state, &acme, UnixMillis(150), GraphLimits::default()).unwrap();
    assert!(later
        .shortest_path(
            &EntityId::from("service"),
            &EntityId::from("archive"),
            Some("depends_on"),
        )
        .unwrap()
        .is_none());

    let globex_view =
        GraphView::new(&state, &globex, UnixMillis(50), GraphLimits::default()).unwrap();
    assert!(globex_view
        .outgoing(&EntityId::from("service"), None)
        .unwrap()
        .is_empty());

    // No projection database is needed to rebuild the same graph semantics.
    let replayed = KnowledgeState::replay(entries).unwrap();
    let replayed_view =
        GraphView::new(&replayed, &acme, UnixMillis(50), GraphLimits::default()).unwrap();
    assert_eq!(
        replayed_view
            .descendants(&EntityId::from("service"), Some("depends_on"))
            .unwrap(),
        vec![EntityId::from("archive"), EntityId::from("db")]
    );
}
