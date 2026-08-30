//! Fail-closed bridge from immutable external research evidence into the
//! event-sourced CCOS Knowledge Plane.
//!
//! This module does not interpret an external system's scientific result and
//! does not grant policy authority. It only packages exact source/evidence
//! provenance and an explicitly observational assertion into ordinary
//! [`JournalEntry`] values. [`KnowledgeState::apply`](crate::KnowledgeState::apply)
//! remains the sole mutation boundary and revalidates every operation.

use std::collections::BTreeSet;
use std::fmt;

use crate::{JournalEntry, KnowledgeOp};
use crate::model::{
    AssertionKind, EntityId, EntityRecord, EvidenceId, EvidenceRecord, FactAssertion, FactId,
    FactObject, SourceId, SourceRecord, SourceTrust, TenantId, ValidityInterval,
};

/// One immutable external observation ready to enter CCOS provenance.
///
/// IDs are supplied by the caller so CCOS does not fabricate identity for an
/// external artifact. The source and evidence hashes are mandatory: this
/// bridge is for immutable evidence, not mutable URLs or latest-state aliases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalObservation {
    pub tenant: TenantId,
    pub source_id: SourceId,
    pub source_locator: String,
    pub source_content_hash: String,
    /// May be Internal, External, or Untrusted. Authoritative is rejected.
    pub source_trust: SourceTrust,
    pub evidence_id: EvidenceId,
    pub evidence_locator: String,
    pub evidence_content_hash: String,
    pub entity_id: EntityId,
    pub entity_type: String,
    pub entity_label: Option<String>,
    pub fact_id: FactId,
    pub predicate: String,
    pub object: FactObject,
    pub validity: ValidityInterval,
}

/// Structural failures caught before journal entries are emitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalObservationError {
    /// Research evidence cannot enter through this bridge as an authoritative source.
    AuthoritativeSourceForbidden,
    /// An immutable provenance locator must be non-empty.
    EmptyLocator(&'static str),
    /// An immutable provenance hash must be non-empty.
    EmptyContentHash(&'static str),
    /// Four dense journal sequence numbers could not be represented.
    SequenceOverflow,
}

impl fmt::Display for ExternalObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthoritativeSourceForbidden => formatter.write_str(
                "external research observations cannot be registered as authoritative sources",
            ),
            Self::EmptyLocator(field) => write!(formatter, "{field} locator must not be empty"),
            Self::EmptyContentHash(field) => {
                write!(formatter, "{field} content hash must not be empty")
            }
            Self::SequenceOverflow => {
                formatter.write_str("external observation journal sequence overflows u64")
            }
        }
    }
}

impl std::error::Error for ExternalObservationError {}

impl ExternalObservation {
    /// Convert this external observation into the canonical CCOS mutation path.
    ///
    /// The returned entries are exactly, in order:
    ///
    /// 1. register the non-authoritative source;
    /// 2. register immutable evidence tied to that source;
    /// 3. add an entity classified as [`AssertionKind::Observation`];
    /// 4. assert a fact classified as [`AssertionKind::Observation`].
    ///
    /// The function does not apply the entries. Callers must append/apply them
    /// through the normal event-sourced journal boundary.
    ///
    /// # Errors
    ///
    /// Fails closed for authoritative source trust, empty provenance fields, or
    /// sequence overflow. Normal knowledge invariants (IDs, predicates,
    /// temporal ranges, duplicates, tenant/source/evidence existence) remain
    /// enforced by [`crate::KnowledgeState::apply`].
    pub fn into_journal_entries(
        self,
        start_sequence: u64,
    ) -> Result<[JournalEntry; 4], ExternalObservationError> {
        self.validate()?;
        let evidence_sequence = start_sequence
            .checked_add(1)
            .ok_or(ExternalObservationError::SequenceOverflow)?;
        let entity_sequence = start_sequence
            .checked_add(2)
            .ok_or(ExternalObservationError::SequenceOverflow)?;
        let fact_sequence = start_sequence
            .checked_add(3)
            .ok_or(ExternalObservationError::SequenceOverflow)?;

        let Self {
            tenant,
            source_id,
            source_locator,
            source_content_hash,
            source_trust,
            evidence_id,
            evidence_locator,
            evidence_content_hash,
            entity_id,
            entity_type,
            entity_label,
            fact_id,
            predicate,
            object,
            validity,
        } = self;

        let source = SourceRecord {
            id: source_id.clone(),
            tenant: tenant.clone(),
            locator: source_locator,
            content_hash: Some(source_content_hash),
            trust: source_trust,
        };
        let evidence = EvidenceRecord {
            id: evidence_id.clone(),
            tenant: tenant.clone(),
            source: source_id,
            locator: Some(evidence_locator),
            content_hash: Some(evidence_content_hash),
        };
        let evidence_set = BTreeSet::from([evidence_id]);
        let entity = EntityRecord {
            id: entity_id.clone(),
            tenant: tenant.clone(),
            namespace: None,
            entity_type,
            label: entity_label,
            evidence: evidence_set.clone(),
            kind: AssertionKind::Observation,
        };
        let fact = FactAssertion {
            id: fact_id,
            tenant,
            subject: entity_id,
            predicate,
            object,
            validity,
            evidence: evidence_set,
            kind: AssertionKind::Observation,
        };

        Ok([
            JournalEntry::new(start_sequence, KnowledgeOp::RegisterSource(source)),
            JournalEntry::new(evidence_sequence, KnowledgeOp::AddEvidence(evidence)),
            JournalEntry::new(entity_sequence, KnowledgeOp::AddEntity(entity)),
            JournalEntry::new(fact_sequence, KnowledgeOp::AssertFact(fact)),
        ])
    }

    fn validate(&self) -> Result<(), ExternalObservationError> {
        if self.source_trust == SourceTrust::Authoritative {
            return Err(ExternalObservationError::AuthoritativeSourceForbidden);
        }
        for (field, value) in [
            ("source", self.source_locator.as_str()),
            ("evidence", self.evidence_locator.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(ExternalObservationError::EmptyLocator(field));
            }
        }
        for (field, value) in [
            ("source", self.source_content_hash.as_str()),
            ("evidence", self.evidence_content_hash.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(ExternalObservationError::EmptyContentHash(field));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KnowledgeState;
    use crate::model::{CanonicalLiteral, EntityId, FactObject, UnixMillis};

    fn observation(trust: SourceTrust) -> ExternalObservation {
        ExternalObservation {
            tenant: TenantId("tenant-a".into()),
            source_id: SourceId::new("source:flat:run-42"),
            source_locator: "artifact://flat/run-42".into(),
            source_content_hash: "sha256:source42".into(),
            source_trust: trust,
            evidence_id: EvidenceId::new("evidence:flat:run-42:query-7"),
            evidence_locator: "query:7".into(),
            evidence_content_hash: "sha256:evidence42".into(),
            entity_id: EntityId::new("research-observation:run-42:query-7"),
            entity_type: "research_observation".into(),
            entity_label: Some("external attention diagnostic".into()),
            fact_id: FactId::new("fact:run-42:query-7:entropy"),
            predicate: "attention.normalized_entropy".into(),
            object: FactObject::Typed(CanonicalLiteral::String("0.8125".into())),
            validity: ValidityInterval {
                valid_from: Some(UnixMillis(1_000)),
                valid_until: Some(UnixMillis(2_000)),
            },
        }
    }

    #[test]
    fn emits_dense_non_authoritative_observation_journal() {
        let entries = observation(SourceTrust::External)
            .into_journal_entries(0)
            .unwrap();
        assert_eq!(entries.map(|entry| entry.sequence), [0, 1, 2, 3]);

        let mut state = KnowledgeState::new();
        for entry in entries {
            state.apply(entry).unwrap();
        }
        let tenant = state.tenant(&TenantId("tenant-a".into())).unwrap();
        let source = tenant.sources.values().next().unwrap();
        assert_eq!(source.trust, SourceTrust::External);
        let entity = tenant.entities.values().next().unwrap();
        assert_eq!(entity.kind, AssertionKind::Observation);
        let fact = tenant.facts.values().next().unwrap();
        assert_eq!(fact.assertion.kind, AssertionKind::Observation);
        assert_eq!(fact.asserted_at, 3);
    }

    #[test]
    fn fact_provenance_reaches_exact_external_source_and_evidence() {
        let entries = observation(SourceTrust::Internal)
            .into_journal_entries(0)
            .unwrap();
        let state = KnowledgeState::replay(entries).unwrap();
        let tenant = TenantId("tenant-a".into());
        let provenance = state
            .fact_provenance(&tenant, &FactId::new("fact:run-42:query-7:entropy"))
            .unwrap();
        assert_eq!(provenance.evidence.len(), 1);
        assert_eq!(provenance.sources.len(), 1);
        assert_eq!(provenance.sources[0].locator, "artifact://flat/run-42");
        assert_eq!(
            provenance.evidence[0].locator.as_deref(),
            Some("query:7")
        );
    }

    #[test]
    fn authoritative_source_is_rejected_before_journal_emission() {
        assert_eq!(
            observation(SourceTrust::Authoritative).into_journal_entries(0),
            Err(ExternalObservationError::AuthoritativeSourceForbidden)
        );
    }

    #[test]
    fn empty_hash_and_sequence_overflow_fail_closed() {
        let mut item = observation(SourceTrust::External);
        item.evidence_content_hash.clear();
        assert_eq!(
            item.into_journal_entries(0),
            Err(ExternalObservationError::EmptyContentHash("evidence"))
        );

        assert_eq!(
            observation(SourceTrust::External).into_journal_entries(u64::MAX - 2),
            Err(ExternalObservationError::SequenceOverflow)
        );
    }
}
