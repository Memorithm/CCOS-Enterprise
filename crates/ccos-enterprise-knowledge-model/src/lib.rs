//! Canonical, backend-independent data model for the CCOS Enterprise Knowledge Plane.
//!
//! The model deliberately contains no storage, network, vector or graph-database code.
//! Every object is tenant-scoped and serializable so the journal can replay into the
//! same canonical state regardless of the projection backends attached later.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;

pub use ccos_enterprise_tenancy::TenantId;
use serde::{Deserialize, Serialize};

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        pub struct $name(pub String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_owned())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

id_type!(EntityId);
id_type!(FactId);
id_type!(RelationId);
id_type!(SourceId);
id_type!(EvidenceId);
id_type!(ConflictId);
id_type!(RuleId);
id_type!(InferenceId);
id_type!(DecisionId);
id_type!(NamespaceId);

/// Milliseconds since the Unix epoch, used only for world/source time.
///
/// Replay ordering never relies on wall-clock time; transaction time is the journal
/// sequence carried by [`FactRecord::asserted_at`] and related records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UnixMillis(pub i64);

/// Half-open valid-time interval `[valid_from, valid_until)`.
/// `None` means unbounded on that side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ValidityInterval {
    pub valid_from: Option<UnixMillis>,
    pub valid_until: Option<UnixMillis>,
}

impl ValidityInterval {
    pub const fn unbounded() -> Self {
        Self {
            valid_from: None,
            valid_until: None,
        }
    }

    pub fn validate(self) -> Result<(), TemporalError> {
        if let (Some(from), Some(until)) = (self.valid_from, self.valid_until) {
            if from >= until {
                return Err(TemporalError::EmptyOrNegativeInterval { from, until });
            }
        }
        Ok(())
    }

    pub fn contains(self, at: UnixMillis) -> bool {
        self.valid_from.is_none_or(|from| at >= from)
            && self.valid_until.is_none_or(|until| at < until)
    }

    pub fn overlaps(self, other: Self) -> bool {
        let self_before_other = match (self.valid_until, other.valid_from) {
            (Some(until), Some(from)) => until <= from,
            _ => false,
        };
        let other_before_self = match (other.valid_until, self.valid_from) {
            (Some(until), Some(from)) => until <= from,
            _ => false,
        };
        !self_before_other && !other_before_self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemporalError {
    EmptyOrNegativeInterval { from: UnixMillis, until: UnixMillis },
}

impl fmt::Display for TemporalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyOrNegativeInterval { from, until } => write!(
                f,
                "valid-time interval is empty or negative: {}..{}",
                from.0, until.0
            ),
        }
    }
}

impl std::error::Error for TemporalError {}

/// Trust is a property of the source, not a claim that every assertion from it is true.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceTrust {
    Authoritative,
    Internal,
    External,
    Untrusted,
}

/// Separates authoritative knowledge from observations and model-produced material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssertionKind {
    Authoritative,
    Observation,
    Inference,
    LlmOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRecord {
    pub id: SourceId,
    pub tenant: TenantId,
    pub locator: String,
    pub content_hash: Option<String>,
    pub trust: SourceTrust,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub id: EvidenceId,
    pub tenant: TenantId,
    pub source: SourceId,
    pub locator: Option<String>,
    pub content_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityRecord {
    pub id: EntityId,
    pub tenant: TenantId,
    pub namespace: Option<NamespaceId>,
    pub entity_type: String,
    pub label: Option<String>,
    pub evidence: BTreeSet<EvidenceId>,
    pub kind: AssertionKind,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FactObject {
    Entity(EntityId),
    Literal(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactAssertion {
    pub id: FactId,
    pub tenant: TenantId,
    pub subject: EntityId,
    pub predicate: String,
    pub object: FactObject,
    pub validity: ValidityInterval,
    pub evidence: BTreeSet<EvidenceId>,
    pub kind: AssertionKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactRecord {
    pub assertion: FactAssertion,
    /// Transaction time: journal sequence at which the assertion became visible.
    pub asserted_at: u64,
    /// Transaction time: journal sequence at which the assertion stopped being current.
    pub invalidated_at: Option<u64>,
}

impl FactRecord {
    pub fn visible_at_transaction(&self, sequence: u64) -> bool {
        self.asserted_at <= sequence && self.invalidated_at.is_none_or(|at| sequence < at)
    }

    pub fn visible_at(&self, valid_time: UnixMillis, transaction_sequence: u64) -> bool {
        self.visible_at_transaction(transaction_sequence)
            && self.assertion.validity.contains(valid_time)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationAssertion {
    pub id: RelationId,
    pub tenant: TenantId,
    pub from: EntityId,
    pub relation: String,
    pub to: EntityId,
    pub validity: ValidityInterval,
    pub evidence: BTreeSet<EvidenceId>,
    pub kind: AssertionKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationRecord {
    pub assertion: RelationAssertion,
    pub asserted_at: u64,
    pub invalidated_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictReason {
    CompetingObjects {
        subject: EntityId,
        predicate: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictResolution {
    PreferFact(FactId),
    SupersededBy(FactId),
    Dismissed { justification: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictRecord {
    pub id: ConflictId,
    pub tenant: TenantId,
    pub facts: BTreeSet<FactId>,
    pub reason: ConflictReason,
    pub detected_at: u64,
    pub resolution: Option<ConflictResolution>,
    pub resolved_at: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validity_is_half_open() {
        let interval = ValidityInterval {
            valid_from: Some(UnixMillis(10)),
            valid_until: Some(UnixMillis(20)),
        };
        assert!(interval.contains(UnixMillis(10)));
        assert!(interval.contains(UnixMillis(19)));
        assert!(!interval.contains(UnixMillis(20)));
    }

    #[test]
    fn touching_intervals_do_not_overlap() {
        let left = ValidityInterval {
            valid_from: Some(UnixMillis(0)),
            valid_until: Some(UnixMillis(10)),
        };
        let right = ValidityInterval {
            valid_from: Some(UnixMillis(10)),
            valid_until: Some(UnixMillis(20)),
        };
        assert!(!left.overlaps(right));
    }

    #[test]
    fn invalid_interval_is_refused() {
        let interval = ValidityInterval {
            valid_from: Some(UnixMillis(10)),
            valid_until: Some(UnixMillis(10)),
        };
        assert!(interval.validate().is_err());
    }
}
