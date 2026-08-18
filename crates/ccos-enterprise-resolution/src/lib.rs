//! Deterministic exact-key entity resolution for structural observation candidates.
//!
//! Resolution produces proposals. It never merges canonical entities and never writes to
//! the Knowledge journal. A proposal can be materialized only as an Observation entity;
//! contradictory labels are surfaced instead of choosing a winner silently.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ccos_enterprise_extract::{CandidateId, ExtractedValue, ExtractionBatch, RecordCandidate};
use ccos_enterprise_knowledge_model::{
    AssertionKind, EntityId, EntityRecord, EvidenceId, TenantId,
};
use sha2::{Digest, Sha256};

pub const RESOLUTION_CONTRACT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityNormalization {
    Exact,
    Trim,
    TrimAsciiCaseFold,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionSchema {
    entity_type: String,
    identity_fields: BTreeSet<String>,
    label_field: Option<String>,
    normalization: IdentityNormalization,
}

impl ResolutionSchema {
    pub fn new<I, S>(
        entity_type: impl Into<String>,
        identity_fields: I,
        label_field: Option<String>,
        normalization: IdentityNormalization,
    ) -> Result<Self, ResolutionError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let entity_type = entity_type.into();
        if entity_type.trim().is_empty() {
            return Err(ResolutionError::InvalidEntityType);
        }
        let identity_fields: BTreeSet<String> =
            identity_fields.into_iter().map(Into::into).collect();
        if identity_fields.is_empty() || identity_fields.iter().any(|field| field.trim().is_empty())
        {
            return Err(ResolutionError::InvalidIdentityFields);
        }
        if label_field
            .as_ref()
            .is_some_and(|field| field.trim().is_empty())
        {
            return Err(ResolutionError::InvalidLabelField);
        }
        Ok(Self {
            entity_type,
            identity_fields,
            label_field,
            normalization,
        })
    }

    pub fn entity_type(&self) -> &str {
        &self.entity_type
    }

    pub fn identity_fields(&self) -> &BTreeSet<String> {
        &self.identity_fields
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FactProposal {
    pub candidate: CandidateId,
    pub predicate: String,
    pub value: ExtractedValue,
    pub evidence: EvidenceId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityProposal {
    pub id: EntityId,
    pub tenant: TenantId,
    pub entity_type: String,
    pub candidates: BTreeSet<CandidateId>,
    pub evidence: BTreeSet<EvidenceId>,
    pub labels: BTreeSet<String>,
    pub facts: Vec<FactProposal>,
}

impl EntityProposal {
    /// Materialization remains an Observation. A later governed promotion can choose a
    /// stronger authority class, but exact-key resolution itself has no such authority.
    pub fn entity_observation(&self) -> Result<EntityRecord, ResolutionError> {
        if self.labels.len() > 1 {
            return Err(ResolutionError::LabelConflict {
                entity: self.id.clone(),
                labels: self.labels.clone(),
            });
        }
        Ok(EntityRecord {
            id: self.id.clone(),
            tenant: self.tenant.clone(),
            namespace: None,
            entity_type: self.entity_type.clone(),
            label: self.labels.iter().next().cloned(),
            evidence: self.evidence.clone(),
            kind: AssertionKind::Observation,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionBatch {
    pub contract_version: u32,
    pub tenant: TenantId,
    pub entity_type: String,
    pub proposals: BTreeMap<EntityId, EntityProposal>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionError {
    InvalidEntityType,
    InvalidIdentityFields,
    InvalidLabelField,
    EmptyInput,
    MixedTenant,
    CandidateScopeMismatch(CandidateId),
    NonObservationCandidate(CandidateId),
    MissingIdentityField {
        candidate: CandidateId,
        field: String,
    },
    UnsupportedIdentityValue {
        candidate: CandidateId,
        field: String,
    },
    LabelNotString {
        candidate: CandidateId,
        field: String,
    },
    DuplicateCandidate(CandidateId),
    LabelConflict {
        entity: EntityId,
        labels: BTreeSet<String>,
    },
}

impl fmt::Display for ResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEntityType => f.write_str("entity type must be non-empty"),
            Self::InvalidIdentityFields => {
                f.write_str("at least one non-empty identity field is required")
            }
            Self::InvalidLabelField => f.write_str("label field must be non-empty when provided"),
            Self::EmptyInput => {
                f.write_str("entity resolution requires at least one extraction batch")
            }
            Self::MixedTenant => f.write_str("one resolution pass cannot mix tenants"),
            Self::CandidateScopeMismatch(id) => {
                write!(
                    f,
                    "candidate {id} does not match its extraction batch scope"
                )
            }
            Self::NonObservationCandidate(id) => {
                write!(f, "candidate {id} is not an Observation")
            }
            Self::MissingIdentityField { candidate, field } => {
                write!(
                    f,
                    "candidate {candidate} is missing identity field {field:?}"
                )
            }
            Self::UnsupportedIdentityValue { candidate, field } => write!(
                f,
                "candidate {candidate} has unsupported identity value in {field:?}"
            ),
            Self::LabelNotString { candidate, field } => write!(
                f,
                "candidate {candidate} label field {field:?} is not a string"
            ),
            Self::DuplicateCandidate(id) => {
                write!(
                    f,
                    "candidate {id} appears more than once in the resolution input"
                )
            }
            Self::LabelConflict { entity, labels } => {
                write!(
                    f,
                    "resolved entity {entity} has conflicting labels: {labels:?}"
                )
            }
        }
    }
}

impl std::error::Error for ResolutionError {}

pub fn resolve_batches(
    batches: &[ExtractionBatch],
    schema: &ResolutionSchema,
) -> Result<ResolutionBatch, ResolutionError> {
    let Some(first) = batches.first() else {
        return Err(ResolutionError::EmptyInput);
    };
    let tenant = first.tenant.clone();
    if batches.iter().any(|batch| batch.tenant != tenant) {
        return Err(ResolutionError::MixedTenant);
    }

    let mut proposals: BTreeMap<EntityId, EntityProposal> = BTreeMap::new();
    let mut seen_candidates = BTreeSet::new();
    for batch in batches {
        for candidate in &batch.candidates {
            validate_candidate_scope(batch, candidate)?;
            if candidate.kind != AssertionKind::Observation {
                return Err(ResolutionError::NonObservationCandidate(
                    candidate.id.clone(),
                ));
            }
            if !seen_candidates.insert(candidate.id.clone()) {
                return Err(ResolutionError::DuplicateCandidate(candidate.id.clone()));
            }

            let entity_id = entity_id(&tenant, candidate, schema)?;
            let label = candidate_label(candidate, schema)?;
            let proposal = proposals
                .entry(entity_id.clone())
                .or_insert_with(|| EntityProposal {
                    id: entity_id,
                    tenant: tenant.clone(),
                    entity_type: schema.entity_type.clone(),
                    candidates: BTreeSet::new(),
                    evidence: BTreeSet::new(),
                    labels: BTreeSet::new(),
                    facts: Vec::new(),
                });
            proposal.candidates.insert(candidate.id.clone());
            proposal.evidence.insert(candidate.evidence.id.clone());
            if let Some(label) = label {
                proposal.labels.insert(label);
            }
            for (predicate, value) in &candidate.attributes {
                proposal.facts.push(FactProposal {
                    candidate: candidate.id.clone(),
                    predicate: predicate.clone(),
                    value: value.clone(),
                    evidence: candidate.evidence.id.clone(),
                });
            }
        }
    }

    for proposal in proposals.values_mut() {
        proposal.facts.sort();
    }

    Ok(ResolutionBatch {
        contract_version: RESOLUTION_CONTRACT_VERSION,
        tenant,
        entity_type: schema.entity_type.clone(),
        proposals,
    })
}

fn validate_candidate_scope(
    batch: &ExtractionBatch,
    candidate: &RecordCandidate,
) -> Result<(), ResolutionError> {
    if candidate.tenant != batch.tenant
        || candidate.source_id != batch.source_id
        || candidate.evidence.tenant != batch.tenant
        || candidate.evidence.source != batch.source_id
    {
        Err(ResolutionError::CandidateScopeMismatch(
            candidate.id.clone(),
        ))
    } else {
        Ok(())
    }
}

fn entity_id(
    tenant: &TenantId,
    candidate: &RecordCandidate,
    schema: &ResolutionSchema,
) -> Result<EntityId, ResolutionError> {
    let mut hasher = Sha256::new();
    hash_part(&mut hasher, tenant.0.as_bytes());
    hash_part(&mut hasher, schema.entity_type.as_bytes());
    for field in &schema.identity_fields {
        let value = candidate.attributes.get(field).ok_or_else(|| {
            ResolutionError::MissingIdentityField {
                candidate: candidate.id.clone(),
                field: field.clone(),
            }
        })?;
        hash_part(&mut hasher, field.as_bytes());
        hash_part(
            &mut hasher,
            identity_value(value, schema.normalization, candidate, field)?.as_bytes(),
        );
    }
    Ok(EntityId::new(format!(
        "entity:resolved:{}",
        hex_lower(&hasher.finalize())
    )))
}

fn identity_value(
    value: &ExtractedValue,
    normalization: IdentityNormalization,
    candidate: &RecordCandidate,
    field: &str,
) -> Result<String, ResolutionError> {
    match value {
        ExtractedValue::String(value) => {
            let normalized = match normalization {
                IdentityNormalization::Exact => value.clone(),
                IdentityNormalization::Trim => value.trim().to_owned(),
                IdentityNormalization::TrimAsciiCaseFold => value.trim().to_ascii_lowercase(),
            };
            Ok(format!("s:{normalized}"))
        }
        ExtractedValue::Bool(value) => Ok(format!("b:{}", u8::from(*value))),
        ExtractedValue::Number(value) => Ok(format!("n:{value}")),
        ExtractedValue::Null | ExtractedValue::Json(_) => {
            Err(ResolutionError::UnsupportedIdentityValue {
                candidate: candidate.id.clone(),
                field: field.to_owned(),
            })
        }
    }
}

fn candidate_label(
    candidate: &RecordCandidate,
    schema: &ResolutionSchema,
) -> Result<Option<String>, ResolutionError> {
    let Some(field) = &schema.label_field else {
        return Ok(None);
    };
    let Some(value) = candidate.attributes.get(field) else {
        return Ok(None);
    };
    match value {
        ExtractedValue::String(value) => Ok(Some(value.clone())),
        _ => Err(ResolutionError::LabelNotString {
            candidate: candidate.id.clone(),
            field: field.clone(),
        }),
    }
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
    use ccos_enterprise_extract::extract;
    use ccos_enterprise_ingest::RawArtifact;
    use ccos_enterprise_knowledge_model::{SourceId, TenantId};

    fn raw(source: &str, bytes: &[u8]) -> RawArtifact {
        let digest = Sha256::digest(bytes);
        RawArtifact {
            tenant: TenantId("acme".into()),
            source_id: SourceId::from(source),
            virtual_uri: format!("fs://dataset/{source}.json"),
            media_type: "application/json".into(),
            content_hash: format!("sha256:{}", hex_lower(&digest)),
            bytes: bytes.to_vec(),
        }
    }

    fn schema() -> ResolutionSchema {
        ResolutionSchema::new(
            "company",
            ["company_id"],
            Some("name".into()),
            IdentityNormalization::TrimAsciiCaseFold,
        )
        .unwrap()
    }

    #[test]
    fn exact_identity_merges_sources_but_preserves_evidence_and_facts() {
        let left = extract(&raw(
            "source:crm",
            br#"{"company_id":" ACME-7 ","name":"Acme","country":"FR"}"#,
        ))
        .unwrap();
        let right = extract(&raw(
            "source:erp",
            br#"{"company_id":"acme-7","name":"Acme","employees":42}"#,
        ))
        .unwrap();
        let resolved = resolve_batches(&[left, right], &schema()).unwrap();
        assert_eq!(resolved.proposals.len(), 1);
        let proposal = resolved.proposals.values().next().unwrap();
        assert_eq!(proposal.candidates.len(), 2);
        assert_eq!(proposal.evidence.len(), 2);
        assert_eq!(proposal.facts.len(), 6);
        assert_eq!(
            proposal.entity_observation().unwrap().kind,
            AssertionKind::Observation
        );
    }

    #[test]
    fn input_order_does_not_change_resolution_output() {
        let left = extract(&raw("source:left", br#"{"company_id":"7","name":"Acme"}"#)).unwrap();
        let right = extract(&raw("source:right", br#"{"company_id":"7","name":"Acme"}"#)).unwrap();
        assert_eq!(
            resolve_batches(&[left.clone(), right.clone()], &schema()).unwrap(),
            resolve_batches(&[right, left], &schema()).unwrap()
        );
    }

    #[test]
    fn conflicting_labels_are_not_silently_selected() {
        let left = extract(&raw("source:left", br#"{"company_id":"7","name":"Acme"}"#)).unwrap();
        let right = extract(&raw(
            "source:right",
            br#"{"company_id":"7","name":"ACME Corp"}"#,
        ))
        .unwrap();
        let resolved = resolve_batches(&[left, right], &schema()).unwrap();
        let proposal = resolved.proposals.values().next().unwrap();
        assert!(matches!(
            proposal.entity_observation(),
            Err(ResolutionError::LabelConflict { .. })
        ));
    }

    #[test]
    fn nested_json_cannot_be_an_identity_key() {
        let batch = extract(&raw(
            "source:left",
            br#"{"company_id":{"nested":7},"name":"Acme"}"#,
        ))
        .unwrap();
        assert!(matches!(
            resolve_batches(&[batch], &schema()),
            Err(ResolutionError::UnsupportedIdentityValue { .. })
        ));
    }

    #[test]
    fn fact_proposals_retain_json_types_before_ontology_typing() {
        let batch = extract(&raw(
            "source:left",
            br#"{"company_id":"7","name":"Acme","active":true,"employees":42}"#,
        ))
        .unwrap();
        let resolved = resolve_batches(&[batch], &schema()).unwrap();
        let proposal = resolved.proposals.values().next().unwrap();
        assert!(proposal.facts.iter().any(|fact| {
            fact.predicate == "active" && fact.value == ExtractedValue::Bool(true)
        }));
        assert!(proposal.facts.iter().any(|fact| {
            fact.predicate == "employees" && fact.value == ExtractedValue::Number("42".into())
        }));
    }
}
