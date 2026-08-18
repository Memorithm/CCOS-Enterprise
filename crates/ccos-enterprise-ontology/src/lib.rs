//! Deterministic tenant-scoped ontology validation for Knowledge Plane proposals.
//!
//! The ontology layer validates resolved Observation proposals. It deliberately has no
//! dependency on the canonical Knowledge store and therefore cannot promote facts or
//! mutate authoritative state. Promotion remains a later governed operation.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ccos_enterprise_extract::ExtractedValue;
use ccos_enterprise_knowledge_model::TenantId;
use ccos_enterprise_resolution::EntityProposal;
use sha2::{Digest, Sha256};

pub const ONTOLOGY_CONTRACT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValueType {
    Null,
    Bool,
    Number,
    String,
    Json,
}

impl ValueType {
    fn matches(self, value: &ExtractedValue) -> bool {
        matches!(
            (self, value),
            (Self::Null, ExtractedValue::Null)
                | (Self::Bool, ExtractedValue::Bool(_))
                | (Self::Number, ExtractedValue::Number(_))
                | (Self::String, ExtractedValue::String(_))
                | (Self::Json, ExtractedValue::Json(_))
        )
    }

    fn tag(self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool => "bool",
            Self::Number => "number",
            Self::String => "string",
            Self::Json => "json",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertySpec {
    pub name: String,
    pub value_type: ValueType,
    pub required: bool,
}

impl PropertySpec {
    pub fn new(
        name: impl Into<String>,
        value_type: ValueType,
        required: bool,
    ) -> Result<Self, OntologyError> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(OntologyError::InvalidPropertyName);
        }
        Ok(Self {
            name,
            value_type,
            required,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntitySchema {
    pub entity_type: String,
    pub properties: BTreeMap<String, PropertySpec>,
    pub allow_extra_properties: bool,
}

impl EntitySchema {
    pub fn new<I>(
        entity_type: impl Into<String>,
        properties: I,
        allow_extra_properties: bool,
    ) -> Result<Self, OntologyError>
    where
        I: IntoIterator<Item = PropertySpec>,
    {
        let entity_type = entity_type.into();
        if entity_type.trim().is_empty() {
            return Err(OntologyError::InvalidEntityType);
        }

        let mut indexed = BTreeMap::new();
        for property in properties {
            let name = property.name.clone();
            if indexed.insert(name.clone(), property).is_some() {
                return Err(OntologyError::DuplicateProperty {
                    entity_type,
                    property: name,
                });
            }
        }

        Ok(Self {
            entity_type,
            properties: indexed,
            allow_extra_properties,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ontology {
    tenant: TenantId,
    version: String,
    entities: BTreeMap<String, EntitySchema>,
    fingerprint: String,
}

impl Ontology {
    pub fn new<I>(
        tenant: TenantId,
        version: impl Into<String>,
        entities: I,
    ) -> Result<Self, OntologyError>
    where
        I: IntoIterator<Item = EntitySchema>,
    {
        if tenant.0.trim().is_empty() {
            return Err(OntologyError::InvalidTenant);
        }
        let version = version.into();
        if version.trim().is_empty() {
            return Err(OntologyError::InvalidVersion);
        }

        let mut indexed = BTreeMap::new();
        for entity in entities {
            let entity_type = entity.entity_type.clone();
            if indexed.insert(entity_type.clone(), entity).is_some() {
                return Err(OntologyError::DuplicateEntityType(entity_type));
            }
        }
        if indexed.is_empty() {
            return Err(OntologyError::EmptyOntology);
        }

        let fingerprint = ontology_fingerprint(&tenant, &version, &indexed);
        Ok(Self {
            tenant,
            version,
            entities: indexed,
            fingerprint,
        })
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn entity_schema(&self, entity_type: &str) -> Option<&EntitySchema> {
        self.entities.get(entity_type)
    }

    pub fn validate_proposal(&self, proposal: &EntityProposal) -> ValidationReport {
        let mut violations = Vec::new();

        // Stop before schema lookup for another tenant. Besides being fail-closed, this
        // avoids using validation errors as an oracle for another tenant's schema.
        if proposal.tenant != self.tenant {
            violations.push(Violation::TenantMismatch {
                expected: self.tenant.0.clone(),
                actual: proposal.tenant.0.clone(),
            });
            return ValidationReport::new(self, violations);
        }

        let Some(schema) = self.entities.get(&proposal.entity_type) else {
            violations.push(Violation::UnknownEntityType(proposal.entity_type.clone()));
            return ValidationReport::new(self, violations);
        };

        if proposal.evidence.is_empty() {
            violations.push(Violation::MissingEntityEvidence);
        }
        if proposal.labels.len() > 1 {
            violations.push(Violation::ConflictingLabels(
                proposal.labels.iter().cloned().collect(),
            ));
        }

        let mut present = BTreeSet::new();
        for fact in &proposal.facts {
            present.insert(fact.predicate.clone());

            if !proposal.candidates.contains(&fact.candidate) {
                violations.push(Violation::ForeignCandidateReference {
                    predicate: fact.predicate.clone(),
                    candidate: fact.candidate.0.clone(),
                });
            }
            if !proposal.evidence.contains(&fact.evidence) {
                violations.push(Violation::ForeignEvidenceReference {
                    predicate: fact.predicate.clone(),
                    evidence: fact.evidence.0.clone(),
                });
            }

            match schema.properties.get(&fact.predicate) {
                Some(spec) if !spec.value_type.matches(&fact.value) => {
                    violations.push(Violation::TypeMismatch {
                        property: fact.predicate.clone(),
                        expected: spec.value_type,
                        actual: value_type_of(&fact.value),
                    });
                }
                Some(_) => {}
                None if !schema.allow_extra_properties => {
                    violations.push(Violation::UnknownProperty(fact.predicate.clone()));
                }
                None => {}
            }
        }

        for spec in schema.properties.values() {
            if spec.required && !present.contains(&spec.name) {
                violations.push(Violation::MissingRequiredProperty(spec.name.clone()));
            }
        }

        violations.sort();
        violations.dedup();
        ValidationReport::new(self, violations)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Violation {
    TenantMismatch {
        expected: String,
        actual: String,
    },
    UnknownEntityType(String),
    MissingEntityEvidence,
    ConflictingLabels(Vec<String>),
    MissingRequiredProperty(String),
    UnknownProperty(String),
    TypeMismatch {
        property: String,
        expected: ValueType,
        actual: ValueType,
    },
    ForeignCandidateReference {
        predicate: String,
        candidate: String,
    },
    ForeignEvidenceReference {
        predicate: String,
        evidence: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    pub contract_version: u32,
    pub ontology_version: String,
    pub ontology_fingerprint: String,
    pub violations: Vec<Violation>,
}

impl ValidationReport {
    fn new(ontology: &Ontology, violations: Vec<Violation>) -> Self {
        Self {
            contract_version: ONTOLOGY_CONTRACT_VERSION,
            ontology_version: ontology.version.clone(),
            ontology_fingerprint: ontology.fingerprint.clone(),
            violations,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.violations.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OntologyError {
    InvalidTenant,
    InvalidVersion,
    EmptyOntology,
    InvalidEntityType,
    InvalidPropertyName,
    DuplicateEntityType(String),
    DuplicateProperty {
        entity_type: String,
        property: String,
    },
}

impl fmt::Display for OntologyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTenant => f.write_str("ontology tenant must be non-empty"),
            Self::InvalidVersion => f.write_str("ontology version must be non-empty"),
            Self::EmptyOntology => f.write_str("ontology must declare at least one entity type"),
            Self::InvalidEntityType => f.write_str("entity type must be non-empty"),
            Self::InvalidPropertyName => f.write_str("property name must be non-empty"),
            Self::DuplicateEntityType(entity_type) => {
                write!(f, "entity type {entity_type:?} is declared more than once")
            }
            Self::DuplicateProperty {
                entity_type,
                property,
            } => write!(
                f,
                "property {property:?} is declared more than once for entity type {entity_type:?}"
            ),
        }
    }
}

impl std::error::Error for OntologyError {}

fn value_type_of(value: &ExtractedValue) -> ValueType {
    match value {
        ExtractedValue::Null => ValueType::Null,
        ExtractedValue::Bool(_) => ValueType::Bool,
        ExtractedValue::Number(_) => ValueType::Number,
        ExtractedValue::String(_) => ValueType::String,
        ExtractedValue::Json(_) => ValueType::Json,
    }
}

fn ontology_fingerprint(
    tenant: &TenantId,
    version: &str,
    entities: &BTreeMap<String, EntitySchema>,
) -> String {
    let mut hasher = Sha256::new();
    hash_part(&mut hasher, &ONTOLOGY_CONTRACT_VERSION.to_le_bytes());
    hash_part(&mut hasher, tenant.0.as_bytes());
    hash_part(&mut hasher, version.as_bytes());
    for (entity_type, schema) in entities {
        hash_part(&mut hasher, entity_type.as_bytes());
        hash_part(&mut hasher, &[u8::from(schema.allow_extra_properties)]);
        for (name, property) in &schema.properties {
            hash_part(&mut hasher, name.as_bytes());
            hash_part(&mut hasher, property.value_type.tag().as_bytes());
            hash_part(&mut hasher, &[u8::from(property.required)]);
        }
    }
    format!("sha256:{}", hex_lower(&hasher.finalize()))
}

fn hash_part(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use ccos_enterprise_extract::{CandidateId, ExtractedValue};
    use ccos_enterprise_knowledge_model::{EntityId, EvidenceId};
    use ccos_enterprise_resolution::FactProposal;

    fn schema(order_reversed: bool) -> Ontology {
        let mut properties = vec![
            PropertySpec::new("id", ValueType::String, true).unwrap(),
            PropertySpec::new("active", ValueType::Bool, false).unwrap(),
        ];
        if order_reversed {
            properties.reverse();
        }
        Ontology::new(
            TenantId("tenant-a".into()),
            "v1",
            [EntitySchema::new("company", properties, false).unwrap()],
        )
        .unwrap()
    }

    fn proposal() -> EntityProposal {
        let candidate = CandidateId("candidate:1".into());
        let evidence = EvidenceId::from("evidence:1");
        EntityProposal {
            id: EntityId::new("entity:1"),
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
                    predicate: "active".into(),
                    value: ExtractedValue::Bool(true),
                    evidence,
                },
            ],
        }
    }

    #[test]
    fn schema_order_does_not_change_fingerprint() {
        assert_eq!(schema(false).fingerprint(), schema(true).fingerprint());
    }

    #[test]
    fn valid_proposal_passes_without_promoting_authority() {
        let report = schema(false).validate_proposal(&proposal());
        assert!(report.is_valid());
        assert!(report.ontology_fingerprint.starts_with("sha256:"));
    }

    #[test]
    fn wrong_tenant_stops_before_schema_details() {
        let ontology = schema(false);
        let mut proposal = proposal();
        proposal.tenant = TenantId("tenant-b".into());
        let report = ontology.validate_proposal(&proposal);
        assert_eq!(report.violations.len(), 1);
        assert!(matches!(
            report.violations.first(),
            Some(Violation::TenantMismatch { .. })
        ));
    }

    #[test]
    fn type_and_required_property_violations_are_deterministic() {
        let ontology = schema(false);
        let mut proposal = proposal();
        proposal.facts.retain(|fact| fact.predicate != "id");
        proposal.facts[0].value = ExtractedValue::String("yes".into());
        let report = ontology.validate_proposal(&proposal);
        assert_eq!(
            report.violations,
            vec![
                Violation::MissingRequiredProperty("id".into()),
                Violation::TypeMismatch {
                    property: "active".into(),
                    expected: ValueType::Bool,
                    actual: ValueType::String,
                },
            ]
        );
    }

    #[test]
    fn duplicate_schema_members_fail_closed() {
        let duplicate = EntitySchema::new(
            "company",
            [
                PropertySpec::new("id", ValueType::String, true).unwrap(),
                PropertySpec::new("id", ValueType::Number, true).unwrap(),
            ],
            false,
        );
        assert!(matches!(
            duplicate,
            Err(OntologyError::DuplicateProperty { .. })
        ));
    }
}
