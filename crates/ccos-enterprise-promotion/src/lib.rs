//! Schema-gated canonical promotion plans for resolved Knowledge Plane observations.
//!
//! Promotion here means promotion into the canonical event-sourced Knowledge state, not
//! promotion of authority. P4b always emits [`AssertionKind::Observation`]. A caller must
//! still submit the returned [`KnowledgeOp`] values through `KnowledgeState::apply`; this
//! crate has no direct state mutation path.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ccos_enterprise_extract::ExtractedValue;
use ccos_enterprise_knowledge::KnowledgeOp;
use ccos_enterprise_knowledge_model::{
    AssertionKind, CanonicalJson, CanonicalLiteral, CanonicalNumber, EntityRecord, EvidenceId,
    FactAssertion, FactId, FactObject, TenantId, ValidityInterval,
};
use ccos_enterprise_ontology::{Ontology, Violation};
use ccos_enterprise_resolution::{EntityProposal, ResolutionError};
use sha2::{Digest, Sha256};

pub const PROMOTION_CONTRACT_VERSION: u32 = 1;

/// Immutable, deterministic materialization plan.
///
/// The ontology fingerprint is bound into every generated fact ID and the plan hash, so
/// changing the schema version/fingerprint changes the resulting canonical identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionPlan {
    pub contract_version: u32,
    pub tenant: TenantId,
    pub ontology_version: String,
    pub ontology_fingerprint: String,
    pub plan_hash: String,
    pub entity: EntityRecord,
    pub facts: Vec<FactAssertion>,
}

impl PromotionPlan {
    /// Return journal operations in the only valid creation order: entity first, then facts.
    /// Applying them remains the responsibility of the canonical Knowledge journal.
    pub fn operations(&self) -> Vec<KnowledgeOp> {
        let mut operations = Vec::with_capacity(self.facts.len() + 1);
        operations.push(KnowledgeOp::AddEntity(self.entity.clone()));
        operations.extend(self.facts.iter().cloned().map(KnowledgeOp::AssertFact));
        operations
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromotionError {
    InvalidValidity,
    SchemaViolations(Vec<Violation>),
    Resolution(String),
    InvalidNumber(String),
    InvalidJson(String),
    EmptyPromotion,
}

impl fmt::Display for PromotionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidValidity => f.write_str("promotion valid-time interval is invalid"),
            Self::SchemaViolations(violations) => {
                write!(f, "ontology rejected proposal: {violations:?}")
            }
            Self::Resolution(detail) => write!(f, "proposal cannot materialize: {detail}"),
            Self::InvalidNumber(value) => write!(f, "invalid canonical number {value:?}"),
            Self::InvalidJson(value) => write!(f, "invalid canonical JSON {value:?}"),
            Self::EmptyPromotion => f.write_str("validated proposal produced no canonical facts"),
        }
    }
}

impl std::error::Error for PromotionError {}

/// Validate a resolved proposal against one exact ontology snapshot and build canonical
/// Observation records without mutating Knowledge state.
pub fn plan_observation_promotion(
    ontology: &Ontology,
    proposal: &EntityProposal,
    validity: ValidityInterval,
) -> Result<PromotionPlan, PromotionError> {
    validity
        .validate()
        .map_err(|_| PromotionError::InvalidValidity)?;

    let report = ontology.validate_proposal(proposal);
    if !report.is_valid() {
        return Err(PromotionError::SchemaViolations(report.violations));
    }

    let entity = proposal.entity_observation().map_err(resolution_error)?;
    debug_assert_eq!(entity.kind, AssertionKind::Observation);

    // Independent sources asserting the same typed value collapse into one canonical fact
    // whose evidence set is the union. Different typed values remain separate facts and the
    // P0 journal will surface them as an explicit conflict when their valid time overlaps.
    let mut grouped: BTreeMap<(String, CanonicalLiteral), BTreeSet<EvidenceId>> = BTreeMap::new();
    for fact in &proposal.facts {
        let literal = canonical_literal(&fact.value)?;
        grouped
            .entry((fact.predicate.clone(), literal))
            .or_default()
            .insert(fact.evidence.clone());
    }

    if grouped.is_empty() {
        return Err(PromotionError::EmptyPromotion);
    }

    let mut facts = Vec::with_capacity(grouped.len());
    for ((predicate, literal), evidence) in grouped {
        let id = promoted_fact_id(
            &proposal.tenant,
            &proposal.id,
            &predicate,
            &literal,
            validity,
            &evidence,
            &report.ontology_fingerprint,
        );
        facts.push(FactAssertion {
            id,
            tenant: proposal.tenant.clone(),
            subject: proposal.id.clone(),
            predicate,
            object: FactObject::Typed(literal),
            validity,
            evidence,
            kind: AssertionKind::Observation,
        });
    }
    facts.sort_by(|left, right| left.id.cmp(&right.id));

    let plan_hash = promotion_plan_hash(
        &proposal.tenant,
        &proposal.id,
        &report.ontology_fingerprint,
        &facts,
    );

    Ok(PromotionPlan {
        contract_version: PROMOTION_CONTRACT_VERSION,
        tenant: proposal.tenant.clone(),
        ontology_version: report.ontology_version,
        ontology_fingerprint: report.ontology_fingerprint,
        plan_hash,
        entity,
        facts,
    })
}

fn resolution_error(error: ResolutionError) -> PromotionError {
    PromotionError::Resolution(error.to_string())
}

fn canonical_literal(value: &ExtractedValue) -> Result<CanonicalLiteral, PromotionError> {
    match value {
        ExtractedValue::Null => Ok(CanonicalLiteral::Null),
        ExtractedValue::Bool(value) => Ok(CanonicalLiteral::Bool(*value)),
        ExtractedValue::Number(value) => CanonicalNumber::new(value.clone())
            .map(CanonicalLiteral::Number)
            .map_err(|_| PromotionError::InvalidNumber(value.clone())),
        ExtractedValue::String(value) => Ok(CanonicalLiteral::String(value.clone())),
        ExtractedValue::Json(value) => CanonicalJson::new(value.clone())
            .map(CanonicalLiteral::Json)
            .map_err(|_| PromotionError::InvalidJson(value.clone())),
    }
}

fn promoted_fact_id(
    tenant: &TenantId,
    entity: &ccos_enterprise_knowledge_model::EntityId,
    predicate: &str,
    literal: &CanonicalLiteral,
    validity: ValidityInterval,
    evidence: &BTreeSet<EvidenceId>,
    ontology_fingerprint: &str,
) -> FactId {
    let mut hasher = Sha256::new();
    hash_part(&mut hasher, tenant.0.as_bytes());
    hash_part(&mut hasher, entity.as_str().as_bytes());
    hash_part(&mut hasher, predicate.as_bytes());
    hash_literal(&mut hasher, literal);
    hash_optional_time(&mut hasher, validity.valid_from.map(|time| time.0));
    hash_optional_time(&mut hasher, validity.valid_until.map(|time| time.0));
    for evidence_id in evidence {
        hash_part(&mut hasher, evidence_id.as_str().as_bytes());
    }
    hash_part(&mut hasher, ontology_fingerprint.as_bytes());
    FactId::new(format!("fact:promoted:{}", hex_lower(&hasher.finalize())))
}

fn promotion_plan_hash(
    tenant: &TenantId,
    entity: &ccos_enterprise_knowledge_model::EntityId,
    ontology_fingerprint: &str,
    facts: &[FactAssertion],
) -> String {
    let mut hasher = Sha256::new();
    hash_part(&mut hasher, &PROMOTION_CONTRACT_VERSION.to_le_bytes());
    hash_part(&mut hasher, tenant.0.as_bytes());
    hash_part(&mut hasher, entity.as_str().as_bytes());
    hash_part(&mut hasher, ontology_fingerprint.as_bytes());
    for fact in facts {
        hash_part(&mut hasher, fact.id.as_str().as_bytes());
    }
    format!("sha256:{}", hex_lower(&hasher.finalize()))
}

fn hash_literal(hasher: &mut Sha256, literal: &CanonicalLiteral) {
    match literal {
        CanonicalLiteral::Null => hash_part(hasher, b"null"),
        CanonicalLiteral::Bool(value) => {
            hash_part(hasher, b"bool");
            hash_part(hasher, &[u8::from(*value)]);
        }
        CanonicalLiteral::Number(value) => {
            hash_part(hasher, b"number");
            hash_part(hasher, value.as_str().as_bytes());
        }
        CanonicalLiteral::String(value) => {
            hash_part(hasher, b"string");
            hash_part(hasher, value.as_bytes());
        }
        CanonicalLiteral::Json(value) => {
            hash_part(hasher, b"json");
            hash_part(hasher, value.as_str().as_bytes());
        }
    }
}

fn hash_optional_time(hasher: &mut Sha256, value: Option<i64>) {
    match value {
        Some(value) => {
            hash_part(hasher, b"some");
            hash_part(hasher, &value.to_le_bytes());
        }
        None => hash_part(hasher, b"none"),
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
    use ccos_enterprise_extract::{CandidateId, ExtractedValue};
    use ccos_enterprise_knowledge_model::{EntityId, EvidenceId};
    use ccos_enterprise_ontology::{EntitySchema, PropertySpec, ValueType};
    use ccos_enterprise_resolution::FactProposal;

    fn ontology() -> Ontology {
        Ontology::new(
            TenantId("tenant-a".into()),
            "v1",
            [EntitySchema::new(
                "company",
                [
                    PropertySpec::new("id", ValueType::String, true).unwrap(),
                    PropertySpec::new("active", ValueType::Bool, true).unwrap(),
                    PropertySpec::new("employees", ValueType::Number, false).unwrap(),
                    PropertySpec::new("metadata", ValueType::Json, false).unwrap(),
                ],
                false,
            )
            .unwrap()],
        )
        .unwrap()
    }

    fn proposal() -> EntityProposal {
        let candidate_a = CandidateId("candidate:a".into());
        let candidate_b = CandidateId("candidate:b".into());
        let evidence_a = EvidenceId::from("evidence:a");
        let evidence_b = EvidenceId::from("evidence:b");
        EntityProposal {
            id: EntityId::new("entity:company:7"),
            tenant: TenantId("tenant-a".into()),
            entity_type: "company".into(),
            candidates: BTreeSet::from([candidate_a.clone(), candidate_b.clone()]),
            evidence: BTreeSet::from([evidence_a.clone(), evidence_b.clone()]),
            labels: BTreeSet::from(["Acme".into()]),
            facts: vec![
                FactProposal {
                    candidate: candidate_a.clone(),
                    predicate: "id".into(),
                    value: ExtractedValue::String("C-7".into()),
                    evidence: evidence_a.clone(),
                },
                FactProposal {
                    candidate: candidate_b.clone(),
                    predicate: "id".into(),
                    value: ExtractedValue::String("C-7".into()),
                    evidence: evidence_b.clone(),
                },
                FactProposal {
                    candidate: candidate_a.clone(),
                    predicate: "active".into(),
                    value: ExtractedValue::Bool(true),
                    evidence: evidence_a.clone(),
                },
                FactProposal {
                    candidate: candidate_b.clone(),
                    predicate: "employees".into(),
                    value: ExtractedValue::Number("42".into()),
                    evidence: evidence_b.clone(),
                },
                FactProposal {
                    candidate: candidate_a,
                    predicate: "metadata".into(),
                    value: ExtractedValue::Json("{\"z\":1,\"a\":2}".into()),
                    evidence: evidence_a,
                },
            ],
        }
    }

    #[test]
    fn promotion_preserves_types_and_unions_equal_evidence() {
        let plan =
            plan_observation_promotion(&ontology(), &proposal(), ValidityInterval::unbounded())
                .unwrap();
        assert_eq!(plan.entity.kind, AssertionKind::Observation);
        assert_eq!(plan.facts.len(), 4);
        let id = plan
            .facts
            .iter()
            .find(|fact| fact.predicate == "id")
            .unwrap();
        assert_eq!(id.evidence.len(), 2);
        assert!(matches!(
            id.object,
            FactObject::Typed(CanonicalLiteral::String(ref value)) if value == "C-7"
        ));
        assert!(plan
            .facts
            .iter()
            .any(|fact| matches!(fact.object, FactObject::Typed(CanonicalLiteral::Bool(true)))));
        assert!(plan.facts.iter().any(|fact| matches!(
            fact.object,
            FactObject::Typed(CanonicalLiteral::Number(ref value)) if value.as_str() == "42"
        )));
        assert!(plan.facts.iter().any(|fact| matches!(
            fact.object,
            FactObject::Typed(CanonicalLiteral::Json(ref value)) if value.as_str() == "{\"a\":2,\"z\":1}"
        )));
    }

    #[test]
    fn invalid_schema_never_produces_operations() {
        let mut proposal = proposal();
        proposal
            .facts
            .retain(|fact| fact.predicate.as_str() != "active");
        assert!(matches!(
            plan_observation_promotion(&ontology(), &proposal, ValidityInterval::unbounded()),
            Err(PromotionError::SchemaViolations(_))
        ));
    }

    #[test]
    fn plan_is_deterministic_for_fact_input_order() {
        let mut reversed = proposal();
        reversed.facts.reverse();
        let left =
            plan_observation_promotion(&ontology(), &proposal(), ValidityInterval::unbounded())
                .unwrap();
        let right =
            plan_observation_promotion(&ontology(), &reversed, ValidityInterval::unbounded())
                .unwrap();
        assert_eq!(left, right);
    }
}
