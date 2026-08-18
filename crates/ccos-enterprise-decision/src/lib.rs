//! Deterministic, tenant-scoped Decision Intelligence for the CCOS Enterprise Knowledge Plane.
//!
//! Decisions are not model chain-of-thought. They are compact accountable records of what was
//! decided, by which authenticated actor, against which canonical knowledge snapshot, using which
//! facts/relations/evidence/rules and which earlier decisions as precedents.
//!
//! The crate deliberately owns no LLM, vector store or graph database. Similarity, ancestry,
//! dependent-impact analysis and regulatory export are deterministic views over a BTree-backed
//! decision journal. A decision may cite only knowledge that is current in the exact canonical
//! snapshot whose sequence and SHA-256 hash it records.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use ccos_enterprise_auth::{is_canonical_identity, ActorId};
use ccos_enterprise_knowledge::KnowledgeState;
use ccos_enterprise_knowledge_model::{
    DecisionId, EvidenceId, FactId, RelationId, RuleId, TenantId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const DECISION_CONTRACT_VERSION: u32 = 1;

/// Exact canonical Knowledge Plane snapshot against which a decision or outcome was admitted.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct KnowledgeAnchor {
    /// Last applied Knowledge Plane journal sequence.
    pub sequence: u64,
    /// Lower-case SHA-256 of the canonical KnowledgeState serialization.
    pub canonical_hash: String,
}

impl KnowledgeAnchor {
    pub fn capture(knowledge: &KnowledgeState) -> Result<Self, DecisionError> {
        let sequence = knowledge
            .next_sequence()
            .checked_sub(1)
            .ok_or(DecisionError::EmptyKnowledgeState)?;
        let hash = knowledge
            .canonical_hash()
            .map_err(|error| DecisionError::Knowledge(error.to_string()))?;
        Ok(Self {
            sequence,
            canonical_hash: hex_lower(&hash),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OutcomeStatus {
    Succeeded,
    Partial,
    Failed,
    Reversed,
}

/// User/application supplied decision before the journal assigns transaction order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionDraft {
    pub id: DecisionId,
    pub tenant: TenantId,
    pub actor: ActorId,
    pub question: String,
    pub selected: String,
    pub rationale: String,
    pub facts: BTreeSet<FactId>,
    pub relations: BTreeSet<RelationId>,
    pub evidence: BTreeSet<EvidenceId>,
    pub rules: BTreeSet<RuleId>,
    /// Existing decisions in the same tenant that materially informed this decision.
    pub precedents: BTreeSet<DecisionId>,
    pub knowledge: KnowledgeAnchor,
}

/// Outcome before the journal assigns transaction order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionOutcomeDraft {
    pub status: OutcomeStatus,
    pub summary: String,
    pub evidence: BTreeSet<EvidenceId>,
    pub knowledge: KnowledgeAnchor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionOutcomeRecord {
    pub status: OutcomeStatus,
    pub summary: String,
    pub evidence: BTreeSet<EvidenceId>,
    pub knowledge: KnowledgeAnchor,
    /// Decision-journal sequence at which the outcome became part of the audit trail.
    pub recorded_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub id: DecisionId,
    pub tenant: TenantId,
    pub actor: ActorId,
    pub question: String,
    pub selected: String,
    pub rationale: String,
    pub facts: BTreeSet<FactId>,
    pub relations: BTreeSet<RelationId>,
    pub evidence: BTreeSet<EvidenceId>,
    pub rules: BTreeSet<RuleId>,
    pub precedents: BTreeSet<DecisionId>,
    pub knowledge: KnowledgeAnchor,
    /// Decision-journal sequence at which the decision became visible.
    pub decided_at: u64,
    /// Immutable once recorded. A changed/reversed decision is a new decision citing this one.
    pub outcome: Option<DecisionOutcomeRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionOp {
    Record(DecisionDraft),
    RecordOutcome {
        tenant: TenantId,
        decision: DecisionId,
        outcome: DecisionOutcomeDraft,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionJournalEntry {
    pub sequence: u64,
    pub op: DecisionOp,
}

impl DecisionJournalEntry {
    pub fn new(sequence: u64, op: DecisionOp) -> Self {
        Self { sequence, op }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TenantDecisions {
    pub decisions: BTreeMap<DecisionId, DecisionRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DecisionState {
    next_sequence: u64,
    tenants: BTreeMap<TenantId, TenantDecisions>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionError {
    JournalDiscontinuity { expected: u64, found: u64 },
    EmptyKnowledgeState,
    Knowledge(String),
    KnowledgeAnchorMismatch,
    InvalidField(&'static str),
    MissingDecisionBasis,
    DuplicateDecision(DecisionId),
    UnknownTenant,
    UnknownDecision(DecisionId),
    UnknownPrecedent(DecisionId),
    UnknownFact(FactId),
    StaleFact(FactId),
    UnknownRelation(RelationId),
    StaleRelation(RelationId),
    UnknownEvidence(EvidenceId),
    OutcomeAlreadyRecorded(DecisionId),
    InvalidTraversalLimits,
    TraversalLimitExceeded { limit: usize },
    InvalidSearchLimit,
    Serialization(String),
}

impl fmt::Display for DecisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JournalDiscontinuity { expected, found } => {
                write!(
                    f,
                    "decision journal sequence {found} does not continue {expected}"
                )
            }
            Self::EmptyKnowledgeState => f.write_str("cannot anchor a decision to empty knowledge"),
            Self::Knowledge(detail) => write!(f, "knowledge state error: {detail}"),
            Self::KnowledgeAnchorMismatch => {
                f.write_str("decision knowledge anchor does not match the supplied canonical state")
            }
            Self::InvalidField(field) => write!(f, "decision field {field} is empty or invalid"),
            Self::MissingDecisionBasis => {
                f.write_str("decision cites no fact, relation, evidence, rule or precedent")
            }
            Self::DuplicateDecision(id) => write!(f, "duplicate decision id {id}"),
            Self::UnknownTenant => f.write_str("tenant decision partition does not exist"),
            Self::UnknownDecision(id) => write!(f, "unknown decision {id}"),
            Self::UnknownPrecedent(id) => write!(f, "unknown precedent decision {id}"),
            Self::UnknownFact(id) => write!(f, "unknown fact {id}"),
            Self::StaleFact(id) => write!(f, "fact {id} is invalidated in the anchored snapshot"),
            Self::UnknownRelation(id) => write!(f, "unknown relation {id}"),
            Self::StaleRelation(id) => {
                write!(f, "relation {id} is invalidated in the anchored snapshot")
            }
            Self::UnknownEvidence(id) => write!(f, "unknown evidence {id}"),
            Self::OutcomeAlreadyRecorded(id) => write!(f, "decision {id} already has an outcome"),
            Self::InvalidTraversalLimits => {
                f.write_str("decision traversal limits must both be greater than zero")
            }
            Self::TraversalLimitExceeded { limit } => {
                write!(f, "decision traversal exceeded {limit}-result bound")
            }
            Self::InvalidSearchLimit => {
                f.write_str("decision search limit must be greater than zero")
            }
            Self::Serialization(detail) => write!(f, "decision serialization failed: {detail}"),
        }
    }
}

impl std::error::Error for DecisionError {}

impl DecisionState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub fn tenant(&self, tenant: &TenantId) -> Option<&TenantDecisions> {
        self.tenants.get(tenant)
    }

    pub fn decision(
        &self,
        tenant: &TenantId,
        decision: &DecisionId,
    ) -> Result<&DecisionRecord, DecisionError> {
        self.tenants
            .get(tenant)
            .ok_or(DecisionError::UnknownTenant)?
            .decisions
            .get(decision)
            .ok_or_else(|| DecisionError::UnknownDecision(decision.clone()))
    }

    /// Production mutation path. Knowledge references and the exact snapshot anchor are checked
    /// before the structurally deterministic journal transition is applied.
    pub fn apply(
        &mut self,
        entry: DecisionJournalEntry,
        knowledge: &KnowledgeState,
    ) -> Result<(), DecisionError> {
        self.require_sequence(entry.sequence)?;
        match &entry.op {
            DecisionOp::Record(draft) => {
                validate_anchor(&draft.knowledge, knowledge)?;
                validate_draft(draft, knowledge)?;
            }
            DecisionOp::RecordOutcome {
                tenant, outcome, ..
            } => {
                validate_anchor(&outcome.knowledge, knowledge)?;
                validate_outcome(tenant, outcome, knowledge)?;
            }
        }
        self.apply_admitted(entry)
    }

    /// Replay a journal whose entries were already admitted through [`Self::apply`].
    ///
    /// External knowledge projections are intentionally not consulted during replay: the stored
    /// KnowledgeAnchor is the immutable proof of which canonical snapshot was checked when the
    /// entry was admitted. Persistence can hash-chain these entries without making replay depend
    /// on a live graph/vector backend.
    pub fn replay(
        entries: impl IntoIterator<Item = DecisionJournalEntry>,
    ) -> Result<Self, DecisionError> {
        let mut state = Self::new();
        for entry in entries {
            state.require_sequence(entry.sequence)?;
            state.apply_admitted(entry)?;
        }
        Ok(state)
    }

    pub fn canonical_hash(&self) -> Result<[u8; 32], DecisionError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|error| DecisionError::Serialization(error.to_string()))?;
        let digest = Sha256::digest(bytes);
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&digest);
        Ok(hash)
    }

    pub fn similar_decisions(
        &self,
        query: &SimilarDecisionQuery,
    ) -> Result<Vec<DecisionMatch>, DecisionError> {
        if query.limit == 0 {
            return Err(DecisionError::InvalidSearchLimit);
        }
        let partition = self
            .tenants
            .get(&query.tenant)
            .ok_or(DecisionError::UnknownTenant)?;
        let query_terms = terms(&query.question);
        let mut matches = Vec::new();

        for record in partition.decisions.values() {
            if query.exclude.as_ref().is_some_and(|id| id == &record.id) {
                continue;
            }
            let record_terms = terms(&format!(
                "{} {} {}",
                record.question, record.selected, record.rationale
            ));
            let score = DecisionSimilarity {
                shared_facts: intersection_len(&query.facts, &record.facts),
                shared_relations: intersection_len(&query.relations, &record.relations),
                shared_rules: intersection_len(&query.rules, &record.rules),
                shared_terms: intersection_len(&query_terms, &record_terms),
            };
            if score.weighted_total() == 0 {
                continue;
            }
            matches.push(DecisionMatch {
                decision: record.id.clone(),
                score,
            });
        }

        matches.sort_by(|left, right| {
            right
                .score
                .weighted_total()
                .cmp(&left.score.weighted_total())
                .then_with(|| right.score.cmp(&left.score))
                .then_with(|| left.decision.cmp(&right.decision))
        });
        matches.truncate(query.limit);
        Ok(matches)
    }

    /// Breadth-first causal ancestry through explicit precedent edges.
    pub fn causal_ancestry(
        &self,
        tenant: &TenantId,
        decision: &DecisionId,
        limits: TraversalLimits,
    ) -> Result<Vec<DecisionId>, DecisionError> {
        limits.validate()?;
        let partition = self
            .tenants
            .get(tenant)
            .ok_or(DecisionError::UnknownTenant)?;
        let root = partition
            .decisions
            .get(decision)
            .ok_or_else(|| DecisionError::UnknownDecision(decision.clone()))?;
        let mut queue: VecDeque<(DecisionId, usize)> =
            root.precedents.iter().cloned().map(|id| (id, 1)).collect();
        let mut visited = BTreeSet::new();
        let mut output = Vec::new();

        while let Some((current, depth)) = queue.pop_front() {
            if depth > limits.max_depth || !visited.insert(current.clone()) {
                continue;
            }
            output.push(current.clone());
            if output.len() > limits.max_results {
                return Err(DecisionError::TraversalLimitExceeded {
                    limit: limits.max_results,
                });
            }
            if depth == limits.max_depth {
                continue;
            }
            let record = partition
                .decisions
                .get(&current)
                .ok_or_else(|| DecisionError::UnknownPrecedent(current.clone()))?;
            for precedent in &record.precedents {
                queue.push_back((precedent.clone(), depth + 1));
            }
        }
        Ok(output)
    }

    /// Breadth-first reverse traversal: every later decision that explicitly depends on `decision`.
    pub fn causal_dependents(
        &self,
        tenant: &TenantId,
        decision: &DecisionId,
        limits: TraversalLimits,
    ) -> Result<Vec<DecisionId>, DecisionError> {
        limits.validate()?;
        let partition = self
            .tenants
            .get(tenant)
            .ok_or(DecisionError::UnknownTenant)?;
        if !partition.decisions.contains_key(decision) {
            return Err(DecisionError::UnknownDecision(decision.clone()));
        }

        let mut queue = VecDeque::from([(decision.clone(), 0_usize)]);
        let mut visited = BTreeSet::from([decision.clone()]);
        let mut output = Vec::new();
        while let Some((current, depth)) = queue.pop_front() {
            if depth >= limits.max_depth {
                continue;
            }
            for record in partition.decisions.values() {
                if !record.precedents.contains(&current) || !visited.insert(record.id.clone()) {
                    continue;
                }
                output.push(record.id.clone());
                if output.len() > limits.max_results {
                    return Err(DecisionError::TraversalLimitExceeded {
                        limit: limits.max_results,
                    });
                }
                queue.push_back((record.id.clone(), depth + 1));
            }
        }
        Ok(output)
    }

    /// Transitive blast radius of changing/reversing a decision, including the knowledge/rule
    /// footprint of all decisions downstream of it.
    pub fn impact_analysis(
        &self,
        tenant: &TenantId,
        decision: &DecisionId,
        limits: TraversalLimits,
    ) -> Result<ImpactReport, DecisionError> {
        let dependents = self.causal_dependents(tenant, decision, limits)?;
        let partition = self
            .tenants
            .get(tenant)
            .ok_or(DecisionError::UnknownTenant)?;
        let mut ids = Vec::with_capacity(dependents.len() + 1);
        ids.push(decision.clone());
        ids.extend(dependents.iter().cloned());

        let mut facts = BTreeSet::new();
        let mut relations = BTreeSet::new();
        let mut evidence = BTreeSet::new();
        let mut rules = BTreeSet::new();
        for id in ids {
            let record = partition
                .decisions
                .get(&id)
                .ok_or_else(|| DecisionError::UnknownDecision(id.clone()))?;
            facts.extend(record.facts.iter().cloned());
            relations.extend(record.relations.iter().cloned());
            evidence.extend(record.evidence.iter().cloned());
            rules.extend(record.rules.iter().cloned());
            if let Some(outcome) = &record.outcome {
                evidence.extend(outcome.evidence.iter().cloned());
            }
        }

        Ok(ImpactReport {
            decision: decision.clone(),
            dependent_decisions: dependents,
            facts,
            relations,
            evidence,
            rules,
        })
    }

    /// Chronological, deterministic audit bundle containing the selected decision and all explicit
    /// precedent ancestors. It intentionally exports accountable records, never hidden reasoning.
    pub fn regulatory_trail(
        &self,
        tenant: &TenantId,
        decision: &DecisionId,
        limits: TraversalLimits,
    ) -> Result<RegulatoryTrail, DecisionError> {
        let partition = self
            .tenants
            .get(tenant)
            .ok_or(DecisionError::UnknownTenant)?;
        let mut ids = self.causal_ancestry(tenant, decision, limits)?;
        ids.push(decision.clone());
        let mut records = Vec::with_capacity(ids.len());
        for id in ids {
            records.push(
                partition
                    .decisions
                    .get(&id)
                    .ok_or_else(|| DecisionError::UnknownDecision(id.clone()))?
                    .clone(),
            );
        }
        records.sort_by(|left, right| {
            left.decided_at
                .cmp(&right.decided_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(RegulatoryTrail {
            contract_version: DECISION_CONTRACT_VERSION,
            tenant: tenant.clone(),
            decision: decision.clone(),
            records,
        })
    }

    fn require_sequence(&self, found: u64) -> Result<(), DecisionError> {
        if found != self.next_sequence {
            Err(DecisionError::JournalDiscontinuity {
                expected: self.next_sequence,
                found,
            })
        } else {
            Ok(())
        }
    }

    fn apply_admitted(&mut self, entry: DecisionJournalEntry) -> Result<(), DecisionError> {
        match entry.op {
            DecisionOp::Record(draft) => self.record(draft, entry.sequence)?,
            DecisionOp::RecordOutcome {
                tenant,
                decision,
                outcome,
            } => self.record_outcome(&tenant, &decision, outcome, entry.sequence)?,
        }
        self.next_sequence += 1;
        Ok(())
    }

    fn record(&mut self, draft: DecisionDraft, sequence: u64) -> Result<(), DecisionError> {
        validate_structural_draft(&draft)?;
        if let Some(existing) = self.tenants.get(&draft.tenant) {
            if existing.decisions.contains_key(&draft.id) {
                return Err(DecisionError::DuplicateDecision(draft.id));
            }
            for precedent in &draft.precedents {
                if !existing.decisions.contains_key(precedent) {
                    return Err(DecisionError::UnknownPrecedent(precedent.clone()));
                }
            }
        } else if let Some(precedent) = draft.precedents.iter().next() {
            return Err(DecisionError::UnknownPrecedent(precedent.clone()));
        }
        let partition = self.tenants.entry(draft.tenant.clone()).or_default();
        partition.decisions.insert(
            draft.id.clone(),
            DecisionRecord {
                id: draft.id,
                tenant: draft.tenant,
                actor: draft.actor,
                question: draft.question,
                selected: draft.selected,
                rationale: draft.rationale,
                facts: draft.facts,
                relations: draft.relations,
                evidence: draft.evidence,
                rules: draft.rules,
                precedents: draft.precedents,
                knowledge: draft.knowledge,
                decided_at: sequence,
                outcome: None,
            },
        );
        Ok(())
    }

    fn record_outcome(
        &mut self,
        tenant: &TenantId,
        decision: &DecisionId,
        outcome: DecisionOutcomeDraft,
        sequence: u64,
    ) -> Result<(), DecisionError> {
        validate_structural_outcome(&outcome)?;
        let record = self
            .tenants
            .get_mut(tenant)
            .ok_or(DecisionError::UnknownTenant)?
            .decisions
            .get_mut(decision)
            .ok_or_else(|| DecisionError::UnknownDecision(decision.clone()))?;
        if record.outcome.is_some() {
            return Err(DecisionError::OutcomeAlreadyRecorded(decision.clone()));
        }
        record.outcome = Some(DecisionOutcomeRecord {
            status: outcome.status,
            summary: outcome.summary,
            evidence: outcome.evidence,
            knowledge: outcome.knowledge,
            recorded_at: sequence,
        });
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimilarDecisionQuery {
    pub tenant: TenantId,
    pub question: String,
    pub facts: BTreeSet<FactId>,
    pub relations: BTreeSet<RelationId>,
    pub rules: BTreeSet<RuleId>,
    pub exclude: Option<DecisionId>,
    pub limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DecisionSimilarity {
    pub shared_facts: u64,
    pub shared_relations: u64,
    pub shared_rules: u64,
    pub shared_terms: u64,
}

impl DecisionSimilarity {
    /// Integer-only weighting keeps ranking bit-stable and avoids floating-point ties.
    pub fn weighted_total(self) -> u64 {
        self.shared_facts
            .saturating_mul(16)
            .saturating_add(self.shared_relations.saturating_mul(8))
            .saturating_add(self.shared_rules.saturating_mul(8))
            .saturating_add(self.shared_terms)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionMatch {
    pub decision: DecisionId,
    pub score: DecisionSimilarity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraversalLimits {
    pub max_depth: usize,
    pub max_results: usize,
}

impl Default for TraversalLimits {
    fn default() -> Self {
        Self {
            max_depth: 32,
            max_results: 1_000,
        }
    }
}

impl TraversalLimits {
    fn validate(self) -> Result<(), DecisionError> {
        if self.max_depth == 0 || self.max_results == 0 {
            Err(DecisionError::InvalidTraversalLimits)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImpactReport {
    pub decision: DecisionId,
    pub dependent_decisions: Vec<DecisionId>,
    pub facts: BTreeSet<FactId>,
    pub relations: BTreeSet<RelationId>,
    pub evidence: BTreeSet<EvidenceId>,
    pub rules: BTreeSet<RuleId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegulatoryTrail {
    pub contract_version: u32,
    pub tenant: TenantId,
    pub decision: DecisionId,
    pub records: Vec<DecisionRecord>,
}

impl RegulatoryTrail {
    pub fn canonical_json(&self) -> Result<String, DecisionError> {
        serde_json::to_string(self).map_err(|error| DecisionError::Serialization(error.to_string()))
    }

    pub fn canonical_hash(&self) -> Result<[u8; 32], DecisionError> {
        let json = self.canonical_json()?;
        let digest = Sha256::digest(json.as_bytes());
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&digest);
        Ok(hash)
    }
}

fn validate_anchor(
    anchor: &KnowledgeAnchor,
    knowledge: &KnowledgeState,
) -> Result<(), DecisionError> {
    if anchor == &KnowledgeAnchor::capture(knowledge)? {
        Ok(())
    } else {
        Err(DecisionError::KnowledgeAnchorMismatch)
    }
}

fn validate_draft(draft: &DecisionDraft, knowledge: &KnowledgeState) -> Result<(), DecisionError> {
    validate_structural_draft(draft)?;
    let partition = knowledge
        .tenant(&draft.tenant)
        .ok_or(DecisionError::UnknownTenant)?;
    for id in &draft.facts {
        let record = partition
            .facts
            .get(id)
            .ok_or_else(|| DecisionError::UnknownFact(id.clone()))?;
        if record.invalidated_at.is_some() {
            return Err(DecisionError::StaleFact(id.clone()));
        }
    }
    for id in &draft.relations {
        let record = partition
            .relations
            .get(id)
            .ok_or_else(|| DecisionError::UnknownRelation(id.clone()))?;
        if record.invalidated_at.is_some() {
            return Err(DecisionError::StaleRelation(id.clone()));
        }
    }
    for id in &draft.evidence {
        if !partition.evidence.contains_key(id) {
            return Err(DecisionError::UnknownEvidence(id.clone()));
        }
    }
    Ok(())
}

fn validate_outcome(
    tenant: &TenantId,
    outcome: &DecisionOutcomeDraft,
    knowledge: &KnowledgeState,
) -> Result<(), DecisionError> {
    validate_structural_outcome(outcome)?;
    let partition = knowledge
        .tenant(tenant)
        .ok_or(DecisionError::UnknownTenant)?;
    for id in &outcome.evidence {
        if !partition.evidence.contains_key(id) {
            return Err(DecisionError::UnknownEvidence(id.clone()));
        }
    }
    Ok(())
}

fn validate_structural_draft(draft: &DecisionDraft) -> Result<(), DecisionError> {
    require_text("decision id", draft.id.as_str())?;
    require_text("tenant", &draft.tenant.0)?;
    if !is_canonical_identity(&draft.actor.0) {
        return Err(DecisionError::InvalidField("actor"));
    }
    require_text("question", &draft.question)?;
    require_text("selected", &draft.selected)?;
    require_text("rationale", &draft.rationale)?;
    if draft.facts.is_empty()
        && draft.relations.is_empty()
        && draft.evidence.is_empty()
        && draft.rules.is_empty()
        && draft.precedents.is_empty()
    {
        return Err(DecisionError::MissingDecisionBasis);
    }
    Ok(())
}

fn validate_structural_outcome(outcome: &DecisionOutcomeDraft) -> Result<(), DecisionError> {
    require_text("outcome summary", &outcome.summary)?;
    if outcome.evidence.is_empty() {
        return Err(DecisionError::InvalidField("outcome evidence"));
    }
    Ok(())
}

fn require_text(field: &'static str, value: &str) -> Result<(), DecisionError> {
    if value.trim().is_empty() {
        Err(DecisionError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn terms(text: &str) -> BTreeSet<String> {
    text.split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|term| term.len() > 1)
        .map(|term| term.to_ascii_lowercase())
        .collect()
}

fn intersection_len<T: Ord>(left: &BTreeSet<T>, right: &BTreeSet<T>) -> u64 {
    left.intersection(right).count() as u64
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
    use ccos_enterprise_knowledge::{JournalEntry, KnowledgeOp};
    use ccos_enterprise_knowledge_model::{
        AssertionKind, EntityId, EntityRecord, EvidenceRecord, FactAssertion, FactObject, SourceId,
        SourceRecord, SourceTrust, ValidityInterval,
    };

    fn tenant() -> TenantId {
        TenantId("acme".into())
    }

    fn knowledge() -> KnowledgeState {
        let tenant = tenant();
        KnowledgeState::replay(vec![
            JournalEntry::new(
                0,
                KnowledgeOp::RegisterSource(SourceRecord {
                    id: SourceId::from("source:policy"),
                    tenant: tenant.clone(),
                    locator: "file:///policy.json".into(),
                    content_hash: Some("sha256:abc".into()),
                    trust: SourceTrust::Authoritative,
                }),
            ),
            JournalEntry::new(
                1,
                KnowledgeOp::AddEvidence(EvidenceRecord {
                    id: EvidenceId::from("evidence:policy"),
                    tenant: tenant.clone(),
                    source: SourceId::from("source:policy"),
                    locator: Some("$.rule".into()),
                    content_hash: Some("sha256:def".into()),
                }),
            ),
            JournalEntry::new(
                2,
                KnowledgeOp::AddEntity(EntityRecord {
                    id: EntityId::from("entity:request"),
                    tenant: tenant.clone(),
                    namespace: None,
                    entity_type: "request".into(),
                    label: Some("Deployment request".into()),
                    evidence: BTreeSet::from([EvidenceId::from("evidence:policy")]),
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
                    evidence: BTreeSet::from([EvidenceId::from("evidence:policy")]),
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
            question: "Should this request be approved?".into(),
            selected: "approve".into(),
            rationale: "Eligibility is authoritative and current.".into(),
            facts: BTreeSet::from([FactId::from("fact:eligible")]),
            relations: BTreeSet::new(),
            evidence: BTreeSet::from([EvidenceId::from("evidence:policy")]),
            rules: BTreeSet::from([RuleId::from("rule:approval")]),
            precedents: BTreeSet::new(),
            knowledge: KnowledgeAnchor::capture(knowledge).unwrap(),
        }
    }

    #[test]
    fn replay_is_deterministic_and_precedents_form_a_dag_by_construction() {
        let knowledge = knowledge();
        let mut state = DecisionState::new();
        let first =
            DecisionJournalEntry::new(0, DecisionOp::Record(draft("decision:1", &knowledge)));
        state.apply(first.clone(), &knowledge).unwrap();
        let mut second = draft("decision:2", &knowledge);
        second.precedents.insert(DecisionId::from("decision:1"));
        let second = DecisionJournalEntry::new(1, DecisionOp::Record(second));
        state.apply(second.clone(), &knowledge).unwrap();

        let replayed = DecisionState::replay([first, second]).unwrap();
        assert_eq!(
            state.canonical_hash().unwrap(),
            replayed.canonical_hash().unwrap()
        );
        assert_eq!(
            state
                .causal_ancestry(
                    &tenant(),
                    &DecisionId::from("decision:2"),
                    TraversalLimits::default()
                )
                .unwrap(),
            vec![DecisionId::from("decision:1")]
        );
    }

    #[test]
    fn an_anchor_must_name_the_exact_knowledge_snapshot() {
        let knowledge = knowledge();
        let mut wrong = draft("decision:1", &knowledge);
        wrong.knowledge.canonical_hash.push('x');
        let mut state = DecisionState::new();
        assert_eq!(
            state.apply(
                DecisionJournalEntry::new(0, DecisionOp::Record(wrong)),
                &knowledge
            ),
            Err(DecisionError::KnowledgeAnchorMismatch)
        );
        assert_eq!(state.next_sequence(), 0);
    }

    #[test]
    fn outcomes_are_append_only() {
        let knowledge = knowledge();
        let mut state = DecisionState::new();
        state
            .apply(
                DecisionJournalEntry::new(0, DecisionOp::Record(draft("decision:1", &knowledge))),
                &knowledge,
            )
            .unwrap();
        let outcome = DecisionOutcomeDraft {
            status: OutcomeStatus::Succeeded,
            summary: "Request deployed without policy violation.".into(),
            evidence: BTreeSet::from([EvidenceId::from("evidence:policy")]),
            knowledge: KnowledgeAnchor::capture(&knowledge).unwrap(),
        };
        state
            .apply(
                DecisionJournalEntry::new(
                    1,
                    DecisionOp::RecordOutcome {
                        tenant: tenant(),
                        decision: DecisionId::from("decision:1"),
                        outcome: outcome.clone(),
                    },
                ),
                &knowledge,
            )
            .unwrap();
        assert!(matches!(
            state.apply(
                DecisionJournalEntry::new(
                    2,
                    DecisionOp::RecordOutcome {
                        tenant: tenant(),
                        decision: DecisionId::from("decision:1"),
                        outcome,
                    },
                ),
                &knowledge,
            ),
            Err(DecisionError::OutcomeAlreadyRecorded(_))
        ));
        assert_eq!(state.next_sequence(), 2);
    }
}
