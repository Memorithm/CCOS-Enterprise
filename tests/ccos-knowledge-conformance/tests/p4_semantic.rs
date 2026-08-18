use std::collections::BTreeSet;

use ccos_enterprise_extract::{CandidateId, ExtractedValue};
use ccos_enterprise_knowledge_model::{EntityId, EvidenceId, TenantId};
use ccos_enterprise_ontology::{EntitySchema, Ontology, PropertySpec, ValueType};
use ccos_enterprise_resolution::{EntityProposal, FactProposal};
use ccos_enterprise_semantic::{
    ontology_schema_rdf, ontology_schema_shacl, proposal_json_ld, proposal_rdf, SemanticError,
    SemanticNamespace,
};

fn ontology() -> Ontology {
    Ontology::new(
        TenantId("tenant-a".into()),
        "company-v1",
        [EntitySchema::new(
            "company",
            [
                PropertySpec::new("id", ValueType::String, true).unwrap(),
                PropertySpec::new("active", ValueType::Bool, false).unwrap(),
                PropertySpec::new("metadata", ValueType::Json, false).unwrap(),
            ],
            false,
        )
        .unwrap()],
    )
    .unwrap()
}

fn proposal(reverse: bool) -> EntityProposal {
    let candidate = CandidateId("candidate:crm:7".into());
    let evidence = EvidenceId::from("evidence:crm:7");
    let mut facts = vec![
        FactProposal {
            candidate: candidate.clone(),
            predicate: "id".into(),
            value: ExtractedValue::String("ACME-7".into()),
            evidence: evidence.clone(),
        },
        FactProposal {
            candidate: candidate.clone(),
            predicate: "active".into(),
            value: ExtractedValue::Bool(true),
            evidence: evidence.clone(),
        },
        FactProposal {
            candidate: candidate.clone(),
            predicate: "metadata".into(),
            value: ExtractedValue::Json("{\"z\":1,\"a\":2}".into()),
            evidence: evidence.clone(),
        },
    ];
    if reverse {
        facts.reverse();
    }
    EntityProposal {
        id: EntityId::new("company/7"),
        tenant: TenantId("tenant-a".into()),
        entity_type: "company".into(),
        candidates: BTreeSet::from([candidate]),
        evidence: BTreeSet::from([evidence]),
        labels: BTreeSet::from(["Acme".into()]),
        facts,
    }
}

#[test]
fn rdf_jsonld_and_shacl_projections_are_deterministic_and_tenant_scoped() {
    let ontology = ontology();
    let namespace = SemanticNamespace::new("https://example.test/ccos/").unwrap();

    let schema_rdf = ontology_schema_rdf(&ontology, "company", &namespace)
        .unwrap()
        .to_ntriples();
    let shacl = ontology_schema_shacl(&ontology, "company", &namespace)
        .unwrap()
        .to_ntriples();
    let rdf = proposal_rdf(&ontology, &proposal(false), &namespace)
        .unwrap()
        .to_ntriples();
    let rdf_reordered = proposal_rdf(&ontology, &proposal(true), &namespace)
        .unwrap()
        .to_ntriples();
    let json_ld = proposal_json_ld(&ontology, &proposal(false), &namespace).unwrap();
    let json_ld_reordered = proposal_json_ld(&ontology, &proposal(true), &namespace).unwrap();

    assert_eq!(rdf, rdf_reordered);
    assert_eq!(json_ld, json_ld_reordered);
    assert!(schema_rdf.contains("http://www.w3.org/2000/01/rdf-schema#Class"));
    assert!(schema_rdf.contains("http://www.w3.org/2000/01/rdf-schema#range"));
    assert!(shacl.contains("http://www.w3.org/ns/shacl#NodeShape"));
    assert!(shacl.contains("http://www.w3.org/ns/shacl#targetClass"));
    assert!(shacl.contains("http://www.w3.org/ns/shacl#minCount"));
    assert!(rdf.contains("entity/tenant-a/company%2F7"));
    assert!(rdf.contains("http://www.w3.org/2001/XMLSchema#boolean"));
    assert!(json_ld.as_str().contains("\"@context\""));
    assert!(json_ld.as_str().contains("\"@type\":\"@json\""));
    assert!(json_ld
        .as_str()
        .contains("https://example.test/ccos/entity/tenant-a/company%2F7"));
}

#[test]
fn invalid_tenant_cannot_be_exported_as_semantic_data() {
    let ontology = ontology();
    let namespace = SemanticNamespace::new("https://example.test/ccos/").unwrap();
    let mut foreign = proposal(false);
    foreign.tenant = TenantId("tenant-b".into());

    assert!(matches!(
        proposal_rdf(&ontology, &foreign, &namespace),
        Err(SemanticError::SchemaViolations(_))
    ));
    assert!(matches!(
        proposal_json_ld(&ontology, &foreign, &namespace),
        Err(SemanticError::SchemaViolations(_))
    ));
}
