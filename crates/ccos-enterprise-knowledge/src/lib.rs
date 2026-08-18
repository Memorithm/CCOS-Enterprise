//! Deterministic, event-sourced canonical state for the CCOS Enterprise Knowledge Plane.
//!
//! External graph/vector/RDF stores are projections of this state. They are never the
//! authority. The only mutation API is [`KnowledgeState::apply`], which consumes a dense,
//! monotonically sequenced [`JournalEntry`]. Replaying the same entries yields the same
//! canonical hash.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub use ccos_enterprise_knowledge_model as model;
use model::{
    ConflictId, ConflictReason, ConflictRecord, ConflictResolution, EntityId, EntityRecord,
    EvidenceId, EvidenceRecord, FactAssertion, FactId, FactObject, FactRecord, RelationAssertion,
    RelationId, RelationRecord, SourceId, SourceRecord, TenantId, UnixMillis,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KnowledgeOp {
    RegisterSource(SourceRecord),
    AddEvidence(EvidenceRecord),
    AddEntity(EntityRecord),
    AssertFact(FactAssertion),
    InvalidateFact {
        tenant: TenantId,
        fact: FactId,
    },
    AssertRelation(RelationAssertion),
    InvalidateRelation {
        tenant: TenantId,
        relation: RelationId,
    },
    ResolveConflict {
        tenant: TenantId,
        conflict: ConflictId,
        resolution: ConflictResolution,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    pub sequence: u64,
    pub op: KnowledgeOp,
}

impl JournalEntry {
    pub fn new(sequence: u64, op: KnowledgeOp) -> Self {
        Self { sequence, op }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TenantKnowledge {
    pub sources: BTreeMap<SourceId, SourceRecord>,
    pub evidence: BTreeMap<EvidenceId, EvidenceRecord>,
    pub entities: BTreeMap<EntityId, EntityRecord>,
    pub facts: BTreeMap<FactId, FactRecord>,
    pub relations: BTreeMap<RelationId, RelationRecord>,
    pub conflicts: BTreeMap<ConflictId, ConflictRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct KnowledgeState {
    next_sequence: u64,
    tenants: BTreeMap<TenantId, TenantKnowledge>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KnowledgeError {
    JournalDiscontinuity { expected: u64, found: u64 },
    InvalidIdentifier { kind: &'static str },
    InvalidPredicate,
    MissingEvidence,
    Duplicate { kind: &'static str, id: String },
    UnknownTenant,
    UnknownSource(SourceId),
    UnknownEvidence(EvidenceId),
    UnknownEntity(EntityId),
    UnknownFact(FactId),
    UnknownRelation(RelationId),
    UnknownConflict(ConflictId),
    AlreadyInvalidated { kind: &'static str, id: String },
    InvalidTemporalRange,
    ResolutionFactNotInConflict(FactId),
    ResolutionFactNotCurrent(FactId),
    Serialization(String),
}

impl fmt::Display for KnowledgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JournalDiscontinuity { expected, found } => {
                write!(f, "journal sequence {found} does not continue {expected}")
            }
            Self::InvalidIdentifier { kind } => write!(f, "{kind} identifier is empty"),
            Self::InvalidPredicate => f.write_str("predicate/relation name is empty"),
            Self::MissingEvidence => f.write_str("knowledge assertion has no evidence"),
            Self::Duplicate { kind, id } => write!(f, "duplicate {kind} id {id}"),
            Self::UnknownTenant => f.write_str("tenant knowledge partition does not exist"),
            Self::UnknownSource(id) => write!(f, "unknown source {id}"),
            Self::UnknownEvidence(id) => write!(f, "unknown evidence {id}"),
            Self::UnknownEntity(id) => write!(f, "unknown entity {id}"),
            Self::UnknownFact(id) => write!(f, "unknown fact {id}"),
            Self::UnknownRelation(id) => write!(f, "unknown relation {id}"),
            Self::UnknownConflict(id) => write!(f, "unknown conflict {id}"),
            Self::AlreadyInvalidated { kind, id } => {
                write!(f, "{kind} {id} is already invalidated")
            }
            Self::InvalidTemporalRange => f.write_str("invalid valid-time interval"),
            Self::ResolutionFactNotInConflict(id) => {
                write!(f, "resolution fact {id} is not a member of the conflict")
            }
            Self::ResolutionFactNotCurrent(id) => {
                write!(f, "resolution fact {id} is not current")
            }
            Self::Serialization(detail) => write!(f, "canonical serialization failed: {detail}"),
        }
    }
}

impl std::error::Error for KnowledgeError {}

impl KnowledgeState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub fn tenant(&self, tenant: &TenantId) -> Option<&TenantKnowledge> {
        self.tenants.get(tenant)
    }

    pub fn apply(&mut self, entry: JournalEntry) -> Result<(), KnowledgeError> {
        if entry.sequence != self.next_sequence {
            return Err(KnowledgeError::JournalDiscontinuity {
                expected: self.next_sequence,
                found: entry.sequence,
            });
        }

        match entry.op {
            KnowledgeOp::RegisterSource(source) => self.register_source(source)?,
            KnowledgeOp::AddEvidence(evidence) => self.add_evidence(evidence)?,
            KnowledgeOp::AddEntity(entity) => self.add_entity(entity)?,
            KnowledgeOp::AssertFact(assertion) => {
                self.assert_fact(assertion, entry.sequence)?;
            }
            KnowledgeOp::InvalidateFact { tenant, fact } => {
                self.invalidate_fact(&tenant, &fact, entry.sequence)?;
            }
            KnowledgeOp::AssertRelation(assertion) => {
                self.assert_relation(assertion, entry.sequence)?;
            }
            KnowledgeOp::InvalidateRelation { tenant, relation } => {
                self.invalidate_relation(&tenant, &relation, entry.sequence)?;
            }
            KnowledgeOp::ResolveConflict {
                tenant,
                conflict,
                resolution,
            } => self.resolve_conflict(&tenant, &conflict, resolution, entry.sequence)?,
        }

        self.next_sequence += 1;
        Ok(())
    }

    pub fn replay(entries: impl IntoIterator<Item = JournalEntry>) -> Result<Self, KnowledgeError> {
        let mut state = Self::new();
        for entry in entries {
            state.apply(entry)?;
        }
        Ok(state)
    }

    pub fn replay_at(
        entries: impl IntoIterator<Item = JournalEntry>,
        transaction_sequence: u64,
    ) -> Result<Self, KnowledgeError> {
        let mut state = Self::new();
        for entry in entries {
            if entry.sequence != state.next_sequence {
                return Err(KnowledgeError::JournalDiscontinuity {
                    expected: state.next_sequence,
                    found: entry.sequence,
                });
            }
            if entry.sequence > transaction_sequence {
                break;
            }
            state.apply(entry)?;
        }
        Ok(state)
    }

    /// SHA-256 of the canonical state. BTree-backed collections make serialization order stable.
    pub fn canonical_hash(&self) -> Result<[u8; 32], KnowledgeError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|error| KnowledgeError::Serialization(error.to_string()))?;
        let digest = Sha256::digest(bytes);
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&digest);
        Ok(hash)
    }

    pub fn facts_at(
        &self,
        tenant: &TenantId,
        valid_time: UnixMillis,
        transaction_sequence: u64,
    ) -> Result<Vec<&FactRecord>, KnowledgeError> {
        let partition = self
            .tenants
            .get(tenant)
            .ok_or(KnowledgeError::UnknownTenant)?;
        Ok(partition
            .facts
            .values()
            .filter(|fact| fact.visible_at(valid_time, transaction_sequence))
            .collect())
    }

    pub fn fact_provenance(
        &self,
        tenant: &TenantId,
        fact: &FactId,
    ) -> Result<FactProvenance<'_>, KnowledgeError> {
        let partition = self
            .tenants
            .get(tenant)
            .ok_or(KnowledgeError::UnknownTenant)?;
        let fact = partition
            .facts
            .get(fact)
            .ok_or_else(|| KnowledgeError::UnknownFact(fact.clone()))?;

        let mut evidence = Vec::with_capacity(fact.assertion.evidence.len());
        let mut source_ids = BTreeSet::new();
        for evidence_id in &fact.assertion.evidence {
            let item = partition
                .evidence
                .get(evidence_id)
                .ok_or_else(|| KnowledgeError::UnknownEvidence(evidence_id.clone()))?;
            source_ids.insert(item.source.clone());
            evidence.push(item);
        }

        let mut sources = Vec::with_capacity(source_ids.len());
        for source_id in source_ids {
            sources.push(
                partition
                    .sources
                    .get(&source_id)
                    .ok_or(KnowledgeError::UnknownSource(source_id))?,
            );
        }

        Ok(FactProvenance {
            fact,
            evidence,
            sources,
        })
    }

    fn register_source(&mut self, source: SourceRecord) -> Result<(), KnowledgeError> {
        require_id("source", source.id.as_str())?;
        require_id("tenant", &source.tenant.0)?;
        if source.locator.trim().is_empty() {
            return Err(KnowledgeError::InvalidIdentifier {
                kind: "source locator",
            });
        }
        let partition = self.tenants.entry(source.tenant.clone()).or_default();
        if partition.sources.contains_key(&source.id) {
            return Err(KnowledgeError::Duplicate {
                kind: "source",
                id: source.id.to_string(),
            });
        }
        partition.sources.insert(source.id.clone(), source);
        Ok(())
    }

    fn add_evidence(&mut self, evidence: EvidenceRecord) -> Result<(), KnowledgeError> {
        require_id("evidence", evidence.id.as_str())?;
        let partition = self
            .tenants
            .get_mut(&evidence.tenant)
            .ok_or(KnowledgeError::UnknownTenant)?;
        if !partition.sources.contains_key(&evidence.source) {
            return Err(KnowledgeError::UnknownSource(evidence.source));
        }
        if partition.evidence.contains_key(&evidence.id) {
            return Err(KnowledgeError::Duplicate {
                kind: "evidence",
                id: evidence.id.to_string(),
            });
        }
        partition.evidence.insert(evidence.id.clone(), evidence);
        Ok(())
    }

    fn add_entity(&mut self, entity: EntityRecord) -> Result<(), KnowledgeError> {
        require_id("entity", entity.id.as_str())?;
        if entity.entity_type.trim().is_empty() {
            return Err(KnowledgeError::InvalidIdentifier {
                kind: "entity type",
            });
        }
        require_evidence(&entity.evidence)?;
        let partition = self
            .tenants
            .get_mut(&entity.tenant)
            .ok_or(KnowledgeError::UnknownTenant)?;
        validate_evidence(partition, &entity.evidence)?;
        if partition.entities.contains_key(&entity.id) {
            return Err(KnowledgeError::Duplicate {
                kind: "entity",
                id: entity.id.to_string(),
            });
        }
        partition.entities.insert(entity.id.clone(), entity);
        Ok(())
    }

    fn assert_fact(
        &mut self,
        assertion: FactAssertion,
        sequence: u64,
    ) -> Result<(), KnowledgeError> {
        require_id("fact", assertion.id.as_str())?;
        require_predicate(&assertion.predicate)?;
        require_evidence(&assertion.evidence)?;
        assertion
            .validity
            .validate()
            .map_err(|_| KnowledgeError::InvalidTemporalRange)?;

        let tenant = assertion.tenant.clone();
        let partition = self
            .tenants
            .get_mut(&tenant)
            .ok_or(KnowledgeError::UnknownTenant)?;
        validate_evidence(partition, &assertion.evidence)?;
        validate_entity(partition, &assertion.subject)?;
        if let FactObject::Entity(target) = &assertion.object {
            validate_entity(partition, target)?;
        }
        if partition.facts.contains_key(&assertion.id) {
            return Err(KnowledgeError::Duplicate {
                kind: "fact",
                id: assertion.id.to_string(),
            });
        }

        let competing: Vec<FactId> = partition
            .facts
            .values()
            .filter(|existing| {
                existing.invalidated_at.is_none()
                    && existing.assertion.subject == assertion.subject
                    && existing.assertion.predicate == assertion.predicate
                    && existing.assertion.object != assertion.object
                    && existing.assertion.validity.overlaps(assertion.validity)
            })
            .map(|fact| fact.assertion.id.clone())
            .collect();

        let fact_id = assertion.id.clone();
        let subject = assertion.subject.clone();
        let predicate = assertion.predicate.clone();
        partition.facts.insert(
            fact_id.clone(),
            FactRecord {
                assertion,
                asserted_at: sequence,
                invalidated_at: None,
            },
        );

        if !competing.is_empty() {
            let conflict_id = conflict_id(&tenant, &subject, &predicate);
            let conflict = partition
                .conflicts
                .entry(conflict_id.clone())
                .or_insert_with(|| ConflictRecord {
                    id: conflict_id,
                    tenant: tenant.clone(),
                    facts: BTreeSet::new(),
                    reason: ConflictReason::CompetingObjects {
                        subject: subject.clone(),
                        predicate: predicate.clone(),
                    },
                    detected_at: sequence,
                    resolution: None,
                    resolved_at: None,
                });
            conflict.facts.extend(competing);
            conflict.facts.insert(fact_id);
            // A new competing assertion re-opens a previously resolved conflict set.
            conflict.resolution = None;
            conflict.resolved_at = None;
        }
        Ok(())
    }

    fn invalidate_fact(
        &mut self,
        tenant: &TenantId,
        fact: &FactId,
        sequence: u64,
    ) -> Result<(), KnowledgeError> {
        let partition = self
            .tenants
            .get_mut(tenant)
            .ok_or(KnowledgeError::UnknownTenant)?;
        let record = partition
            .facts
            .get_mut(fact)
            .ok_or_else(|| KnowledgeError::UnknownFact(fact.clone()))?;
        if record.invalidated_at.is_some() {
            return Err(KnowledgeError::AlreadyInvalidated {
                kind: "fact",
                id: fact.to_string(),
            });
        }
        record.invalidated_at = Some(sequence);
        Ok(())
    }

    fn assert_relation(
        &mut self,
        assertion: RelationAssertion,
        sequence: u64,
    ) -> Result<(), KnowledgeError> {
        require_id("relation", assertion.id.as_str())?;
        require_predicate(&assertion.relation)?;
        require_evidence(&assertion.evidence)?;
        assertion
            .validity
            .validate()
            .map_err(|_| KnowledgeError::InvalidTemporalRange)?;
        let partition = self
            .tenants
            .get_mut(&assertion.tenant)
            .ok_or(KnowledgeError::UnknownTenant)?;
        validate_evidence(partition, &assertion.evidence)?;
        validate_entity(partition, &assertion.from)?;
        validate_entity(partition, &assertion.to)?;
        if partition.relations.contains_key(&assertion.id) {
            return Err(KnowledgeError::Duplicate {
                kind: "relation",
                id: assertion.id.to_string(),
            });
        }
        partition.relations.insert(
            assertion.id.clone(),
            RelationRecord {
                assertion,
                asserted_at: sequence,
                invalidated_at: None,
            },
        );
        Ok(())
    }

    fn invalidate_relation(
        &mut self,
        tenant: &TenantId,
        relation: &RelationId,
        sequence: u64,
    ) -> Result<(), KnowledgeError> {
        let partition = self
            .tenants
            .get_mut(tenant)
            .ok_or(KnowledgeError::UnknownTenant)?;
        let record = partition
            .relations
            .get_mut(relation)
            .ok_or_else(|| KnowledgeError::UnknownRelation(relation.clone()))?;
        if record.invalidated_at.is_some() {
            return Err(KnowledgeError::AlreadyInvalidated {
                kind: "relation",
                id: relation.to_string(),
            });
        }
        record.invalidated_at = Some(sequence);
        Ok(())
    }

    fn resolve_conflict(
        &mut self,
        tenant: &TenantId,
        conflict: &ConflictId,
        resolution: ConflictResolution,
        sequence: u64,
    ) -> Result<(), KnowledgeError> {
        let partition = self
            .tenants
            .get_mut(tenant)
            .ok_or(KnowledgeError::UnknownTenant)?;
        let preferred = match &resolution {
            ConflictResolution::PreferFact(id) | ConflictResolution::SupersededBy(id) => Some(id),
            ConflictResolution::Dismissed { .. } => None,
        };

        if let Some(id) = preferred {
            let conflict_record = partition
                .conflicts
                .get(conflict)
                .ok_or_else(|| KnowledgeError::UnknownConflict(conflict.clone()))?;
            if !conflict_record.facts.contains(id) {
                return Err(KnowledgeError::ResolutionFactNotInConflict(id.clone()));
            }
            let fact = partition
                .facts
                .get(id)
                .ok_or_else(|| KnowledgeError::UnknownFact(id.clone()))?;
            if fact.invalidated_at.is_some() {
                return Err(KnowledgeError::ResolutionFactNotCurrent(id.clone()));
            }
        }

        let conflict_record = partition
            .conflicts
            .get_mut(conflict)
            .ok_or_else(|| KnowledgeError::UnknownConflict(conflict.clone()))?;
        conflict_record.resolution = Some(resolution);
        conflict_record.resolved_at = Some(sequence);
        Ok(())
    }
}

pub struct FactProvenance<'a> {
    pub fact: &'a FactRecord,
    pub evidence: Vec<&'a EvidenceRecord>,
    pub sources: Vec<&'a SourceRecord>,
}

fn require_id(kind: &'static str, value: &str) -> Result<(), KnowledgeError> {
    if value.trim().is_empty() {
        Err(KnowledgeError::InvalidIdentifier { kind })
    } else {
        Ok(())
    }
}

fn require_predicate(value: &str) -> Result<(), KnowledgeError> {
    if value.trim().is_empty() {
        Err(KnowledgeError::InvalidPredicate)
    } else {
        Ok(())
    }
}

fn require_evidence(evidence: &BTreeSet<EvidenceId>) -> Result<(), KnowledgeError> {
    if evidence.is_empty() {
        Err(KnowledgeError::MissingEvidence)
    } else {
        Ok(())
    }
}

fn validate_evidence(
    partition: &TenantKnowledge,
    evidence: &BTreeSet<EvidenceId>,
) -> Result<(), KnowledgeError> {
    for id in evidence {
        if !partition.evidence.contains_key(id) {
            // Deliberately indistinguishable from a missing ID in every other tenant:
            // existence in another tenant is not information this partition may reveal.
            return Err(KnowledgeError::UnknownEvidence(id.clone()));
        }
    }
    Ok(())
}

fn validate_entity(partition: &TenantKnowledge, id: &EntityId) -> Result<(), KnowledgeError> {
    if partition.entities.contains_key(id) {
        Ok(())
    } else {
        Err(KnowledgeError::UnknownEntity(id.clone()))
    }
}

fn conflict_id(tenant: &TenantId, subject: &EntityId, predicate: &str) -> ConflictId {
    let mut hasher = Sha256::new();
    hasher.update(tenant.0.as_bytes());
    hasher.update([0]);
    hasher.update(subject.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(predicate.as_bytes());
    let digest = hasher.finalize();
    ConflictId::new(format!("conflict:{}", hex_lower(&digest)))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use model::{AssertionKind, SourceTrust, ValidityInterval};

    fn tenant(value: &str) -> TenantId {
        TenantId(value.to_owned())
    }

    fn evidence_set(value: &str) -> BTreeSet<EvidenceId> {
        BTreeSet::from([EvidenceId::from(value)])
    }

    fn bootstrap(tenant_id: &str) -> Vec<JournalEntry> {
        let tenant = tenant(tenant_id);
        vec![
            JournalEntry::new(
                0,
                KnowledgeOp::RegisterSource(SourceRecord {
                    id: SourceId::from("source:1"),
                    tenant: tenant.clone(),
                    locator: "file:///authoritative.json".into(),
                    content_hash: Some("sha256:abc".into()),
                    trust: SourceTrust::Authoritative,
                }),
            ),
            JournalEntry::new(
                1,
                KnowledgeOp::AddEvidence(EvidenceRecord {
                    id: EvidenceId::from("evidence:1"),
                    tenant: tenant.clone(),
                    source: SourceId::from("source:1"),
                    locator: Some("$.rows[0]".into()),
                    content_hash: None,
                }),
            ),
            JournalEntry::new(
                2,
                KnowledgeOp::AddEntity(EntityRecord {
                    id: EntityId::from("entity:company"),
                    tenant,
                    namespace: None,
                    entity_type: "company".into(),
                    label: Some("Acme".into()),
                    evidence: evidence_set("evidence:1"),
                    kind: AssertionKind::Authoritative,
                }),
            ),
        ]
    }

    fn ceo_fact(tenant_id: &str, id: &str, person: &str, valid_from: i64) -> FactAssertion {
        FactAssertion {
            id: FactId::from(id),
            tenant: tenant(tenant_id),
            subject: EntityId::from("entity:company"),
            predicate: "ceo".into(),
            object: FactObject::Literal(person.into()),
            validity: ValidityInterval {
                valid_from: Some(UnixMillis(valid_from)),
                valid_until: None,
            },
            evidence: evidence_set("evidence:1"),
            kind: AssertionKind::Authoritative,
        }
    }

    #[test]
    fn replay_is_bit_stable_at_the_canonical_hash() {
        let mut log = bootstrap("acme");
        log.push(JournalEntry::new(
            3,
            KnowledgeOp::AssertFact(ceo_fact("acme", "fact:alice", "Alice", 10)),
        ));
        let left = KnowledgeState::replay(log.clone()).unwrap();
        let right = KnowledgeState::replay(log).unwrap();
        assert_eq!(
            left.canonical_hash().unwrap(),
            right.canonical_hash().unwrap()
        );
    }

    #[test]
    fn journal_gaps_are_refused_without_advancing_state() {
        let mut state = KnowledgeState::new();
        let result = state.apply(JournalEntry::new(
            1,
            KnowledgeOp::RegisterSource(SourceRecord {
                id: SourceId::from("s"),
                tenant: tenant("acme"),
                locator: "file:///x".into(),
                content_hash: None,
                trust: SourceTrust::Internal,
            }),
        ));
        assert_eq!(
            result,
            Err(KnowledgeError::JournalDiscontinuity {
                expected: 0,
                found: 1,
            })
        );
        assert_eq!(state.next_sequence(), 0);
    }

    #[test]
    fn competing_facts_are_preserved_and_flagged() {
        let mut state = KnowledgeState::replay(bootstrap("acme")).unwrap();
        state
            .apply(JournalEntry::new(
                3,
                KnowledgeOp::AssertFact(ceo_fact("acme", "fact:alice", "Alice", 10)),
            ))
            .unwrap();
        state
            .apply(JournalEntry::new(
                4,
                KnowledgeOp::AssertFact(ceo_fact("acme", "fact:bob", "Bob", 10)),
            ))
            .unwrap();

        let partition = state.tenant(&tenant("acme")).unwrap();
        assert_eq!(
            partition.facts.len(),
            2,
            "contradictions must never overwrite"
        );
        let conflict = partition.conflicts.values().next().unwrap();
        assert_eq!(
            conflict.facts,
            BTreeSet::from([FactId::from("fact:alice"), FactId::from("fact:bob")])
        );
        assert!(conflict.resolution.is_none());
    }

    #[test]
    fn cross_tenant_evidence_is_not_visible() {
        let mut state = KnowledgeState::replay(bootstrap("acme")).unwrap();
        state
            .apply(JournalEntry::new(
                3,
                KnowledgeOp::AddEvidence(EvidenceRecord {
                    id: EvidenceId::from("evidence:acme-secret"),
                    tenant: tenant("acme"),
                    source: SourceId::from("source:1"),
                    locator: Some("$.secret".into()),
                    content_hash: None,
                }),
            ))
            .unwrap();

        let mut globex = bootstrap("globex");
        for entry in &mut globex {
            entry.sequence += 4;
        }
        for entry in globex {
            state.apply(entry).unwrap();
        }

        let result = state.apply(JournalEntry::new(
            7,
            KnowledgeOp::AddEntity(EntityRecord {
                id: EntityId::from("entity:leak"),
                tenant: tenant("globex"),
                namespace: None,
                entity_type: "test".into(),
                label: None,
                evidence: BTreeSet::from([EvidenceId::from("evidence:acme-secret")]),
                kind: AssertionKind::Observation,
            }),
        ));
        assert_eq!(
            result,
            Err(KnowledgeError::UnknownEvidence(EvidenceId::from(
                "evidence:acme-secret"
            )))
        );
        assert_eq!(state.next_sequence(), 7);
    }

    #[test]
    fn bitemporal_query_separates_valid_and_transaction_time() {
        let mut state = KnowledgeState::replay(bootstrap("acme")).unwrap();
        state
            .apply(JournalEntry::new(
                3,
                KnowledgeOp::AssertFact(ceo_fact("acme", "fact:alice", "Alice", 10)),
            ))
            .unwrap();
        state
            .apply(JournalEntry::new(
                4,
                KnowledgeOp::InvalidateFact {
                    tenant: tenant("acme"),
                    fact: FactId::from("fact:alice"),
                },
            ))
            .unwrap();

        assert_eq!(
            state
                .facts_at(&tenant("acme"), UnixMillis(11), 3)
                .unwrap()
                .len(),
            1
        );
        assert!(state
            .facts_at(&tenant("acme"), UnixMillis(11), 4)
            .unwrap()
            .is_empty());
        assert!(state
            .facts_at(&tenant("acme"), UnixMillis(9), 3)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn provenance_reaches_registered_source() {
        let mut state = KnowledgeState::replay(bootstrap("acme")).unwrap();
        state
            .apply(JournalEntry::new(
                3,
                KnowledgeOp::AssertFact(ceo_fact("acme", "fact:alice", "Alice", 10)),
            ))
            .unwrap();
        let trace = state
            .fact_provenance(&tenant("acme"), &FactId::from("fact:alice"))
            .unwrap();
        assert_eq!(trace.evidence.len(), 1);
        assert_eq!(trace.sources.len(), 1);
        assert_eq!(trace.sources[0].id, SourceId::from("source:1"));
    }
}
