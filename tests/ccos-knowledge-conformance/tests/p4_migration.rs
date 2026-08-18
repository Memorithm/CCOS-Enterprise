use std::collections::BTreeSet;

use ccos_enterprise_extract::{CandidateId, ExtractedValue};
use ccos_enterprise_knowledge_model::{EntityId, EvidenceId, TenantId, ValidityInterval};
use ccos_enterprise_ontology::{EntitySchema, Ontology, PropertySpec, ValueType};
use ccos_enterprise_ontology_migration::{MigrationStep, OntologyMigration};
use ccos_enterprise_promotion::plan_observation_promotion;
use ccos_enterprise_resolution::{EntityProposal, FactProposal};

fn v1() -> Ontology {
    Ontology::new(
        TenantId("tenant-a".into()),
        "company-v1",
        [EntitySchema::new(
            "company",
            [
                PropertySpec::new("id", ValueType::String, true).unwrap(),
                PropertySpec::new("legal_name", ValueType::String, true).unwrap(),
            ],
            false,
        )
        .unwrap()],
    )
    .unwrap()
}

fn v2() -> Ontology {
    Ontology::new(
        TenantId("tenant-a".into()),
        "organization-v2",
        [EntitySchema::new(
            "organization",
            [
                PropertySpec::new("id", ValueType::String, true).unwrap(),
                PropertySpec::new("name", ValueType::String, true).unwrap(),
            ],
            false,
        )
        .unwrap()],
    )
    .unwrap()
}

fn proposal() -> EntityProposal {
    let candidate = CandidateId("candidate:crm:7".into());
    let evidence = EvidenceId::from("evidence:crm:7");
    EntityProposal {
        id: EntityId::new("entity:company:7"),
        tenant: TenantId("tenant-a".into()),
        entity_type: "company".into(),
        candidates: BTreeSet::from([candidate.clone()]),
        evidence: BTreeSet::from([evidence.clone()]),
        labels: BTreeSet::from(["Acme".into()]),
        facts: vec![
            FactProposal {
                candidate: candidate.clone(),
                predicate: "id".into(),
                value: ExtractedValue::String("C-7".into()),
                evidence: evidence.clone(),
            },
            FactProposal {
                candidate,
                predicate: "legal_name".into(),
                value: ExtractedValue::String("Acme".into()),
                evidence,
            },
        ],
    }
}

#[test]
fn migration_is_lossless_before_target_promotion() {
    let from = v1();
    let to = v2();
    let migration = OntologyMigration::new(
        "company-v1-to-organization-v2",
        &from,
        &to,
        vec![
            MigrationStep::RenameEntityType {
                from: "company".into(),
                to: "organization".into(),
            },
            MigrationStep::RenameProperty {
                entity_type: "organization".into(),
                from: "legal_name".into(),
                to: "name".into(),
            },
        ],
    )
    .unwrap();

    let original = proposal();
    let migrated = migration.apply(&from, &to, &original).unwrap();
    assert_eq!(migrated.receipt.from_fingerprint, from.fingerprint());
    assert_eq!(migrated.receipt.to_fingerprint, to.fingerprint());
    assert_ne!(
        migrated.receipt.before_proposal_hash,
        migrated.receipt.after_proposal_hash
    );

    let promoted =
        plan_observation_promotion(&to, &migrated.proposal, ValidityInterval::unbounded()).unwrap();
    assert_eq!(promoted.ontology_fingerprint, to.fingerprint());
    assert!(promoted.facts.iter().any(|fact| fact.predicate == "name"));

    let inverse = migration.inverse(&from, &to).unwrap();
    let restored = inverse
        .apply(&to, &from, &migrated.proposal)
        .unwrap()
        .proposal;
    assert_eq!(restored, original);
}
