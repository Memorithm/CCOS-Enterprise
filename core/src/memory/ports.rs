//! Backend-neutral memory ports for CCOS.
//!
//! CCOS owns causal truth, event sourcing, replay and hard policy. External
//! semantic/episodic stores may provide candidate observations through these
//! traits, but they never become causal authority merely by implementing a port.
//!
//! This module deliberately contains no backend-specific type, feature flag or
//! dependency. In particular, adapters for semantic-memory engines live outside
//! `ccos-core` and translate their native records into these structures.

use std::collections::BTreeMap;
use std::fmt;

/// Stable identifier used at the CCOS boundary for an external memory record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemoryRecordId(String);

impl MemoryRecordId {
    /// Creates a non-empty record identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, MemoryPortError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(MemoryPortError::InvalidInput(
                "memory record id must not be empty".into(),
            ));
        }
        Ok(Self(value))
    }

    /// Returns the stable textual identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MemoryRecordId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Opaque scope selected by the CCOS caller.
///
/// Enterprise adapters may map this to tenant/workspace/agent isolation. Core
/// intentionally does not know how a product decomposes or authorises scopes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemoryScope(String);

impl MemoryScope {
    /// Creates a non-empty scope.
    pub fn new(value: impl Into<String>) -> Result<Self, MemoryPortError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(MemoryPortError::InvalidInput(
                "memory scope must not be empty".into(),
            ));
        }
        Ok(Self(value))
    }

    /// Returns the opaque scope value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Backend-neutral record submitted to an external semantic/episodic provider.
#[derive(Debug, Clone, PartialEq)]
pub struct ExternalMemoryRecord {
    /// Stable logical id; physical index locations must never escape the adapter.
    pub id: MemoryRecordId,
    /// Product-selected isolation scope.
    pub scope: MemoryScope,
    /// Textual content from which a semantic representation may be derived.
    pub content: String,
    /// Optional CCOS causal region used only as a narrowing hint.
    pub causal_region: Option<String>,
    /// Stable provenance label or URI supplied by the caller.
    pub provenance: Option<String>,
    /// Caller-supplied logical/event time; Core does not read the wall clock here.
    pub timestamp: u64,
    /// Backend-neutral metadata. Adapters must not inject backend implementation
    /// details into this map.
    pub metadata: BTreeMap<String, String>,
}

/// A semantic-recall request sent through a memory port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticQuery {
    /// Isolation scope to search.
    pub scope: MemoryScope,
    /// Free-text semantic query.
    pub text: String,
    /// Maximum number of observations requested.
    pub limit: usize,
    /// Optional causal region chosen by CCOS before semantic recall.
    pub causal_region: Option<String>,
}

impl SemanticQuery {
    /// Validates the two hard request invariants shared by every adapter.
    pub fn validate(&self) -> Result<(), MemoryPortError> {
        if self.text.trim().is_empty() {
            return Err(MemoryPortError::InvalidInput(
                "semantic query must not be empty".into(),
            ));
        }
        if self.limit == 0 {
            return Err(MemoryPortError::InvalidInput(
                "semantic query limit must be greater than zero".into(),
            ));
        }
        Ok(())
    }
}

/// One untrusted observation returned by an external memory provider.
///
/// `score` is a ranking signal only. CCOS must never interpret it as authority,
/// probability, causal weight or permission to bypass deterministic hard gates.
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryObservation {
    pub id: MemoryRecordId,
    pub content: String,
    pub score: f32,
    pub provenance: Option<String>,
    pub causal_region: Option<String>,
}

/// Backend-neutral failure surfaced at the adapter boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemoryPortError {
    InvalidInput(String),
    NotFound(String),
    Conflict(String),
    Unavailable(String),
    Backend(String),
}

impl fmt::Display for MemoryPortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => write!(f, "invalid memory-port input: {message}"),
            Self::NotFound(message) => write!(f, "memory record not found: {message}"),
            Self::Conflict(message) => write!(f, "memory-port conflict: {message}"),
            Self::Unavailable(message) => write!(f, "memory provider unavailable: {message}"),
            Self::Backend(message) => write!(f, "memory provider error: {message}"),
        }
    }
}

impl std::error::Error for MemoryPortError {}

/// Port for semantic candidate storage and recall.
///
/// Implementations are adapters. Their results are observations that CCOS may
/// combine with its own causal state; implementations do not own causal truth.
pub trait SemanticMemoryProvider {
    /// Inserts or replaces a logical record.
    fn upsert(&mut self, record: &ExternalMemoryRecord) -> Result<(), MemoryPortError>;

    /// Removes a logical record from the active view.
    fn delete(&mut self, scope: &MemoryScope, id: &MemoryRecordId) -> Result<(), MemoryPortError>;

    /// Returns ranked semantic observations for a validated query.
    fn recall(&self, query: &SemanticQuery) -> Result<Vec<MemoryObservation>, MemoryPortError>;
}

/// Port for append-oriented episodic memory.
///
/// The episode order is supplied by the caller (`timestamp`/event sequence), so
/// deterministic CCOS code does not delegate clock semantics to a backend.
pub trait EpisodicProvider {
    /// Appends or idempotently records one episode.
    fn append_episode(&mut self, record: &ExternalMemoryRecord) -> Result<(), MemoryPortError>;

    /// Recalls up to `limit` episodes for the scope, newest/relevant ordering being
    /// part of the adapter's documented contract.
    fn recall_episodes(
        &self,
        scope: &MemoryScope,
        limit: usize,
    ) -> Result<Vec<MemoryObservation>, MemoryPortError>;
}

/// Optional lifecycle capabilities exposed by an adapter.
///
/// Product policies such as retention periods, tenant key destruction and legal
/// right-to-forget orchestration remain outside Core; this port only exposes the
/// primitive operations needed to enforce such policies.
pub trait MemoryLifecycleProvider {
    /// Makes a record non-recallable while retaining a tombstone/audit marker.
    fn tombstone(
        &mut self,
        scope: &MemoryScope,
        id: &MemoryRecordId,
    ) -> Result<(), MemoryPortError>;

    /// Physically purges a record where the backend supports irreversible purge.
    fn purge(&mut self, scope: &MemoryScope, id: &MemoryRecordId) -> Result<(), MemoryPortError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_scopes_reject_empty_values() {
        assert!(MemoryRecordId::new(" ").is_err());
        assert!(MemoryScope::new("").is_err());
    }

    #[test]
    fn semantic_query_enforces_non_empty_text_and_positive_limit() {
        let scope = MemoryScope::new("workspace:demo").unwrap();
        assert!(SemanticQuery {
            scope: scope.clone(),
            text: "".into(),
            limit: 1,
            causal_region: None,
        }
        .validate()
        .is_err());
        assert!(SemanticQuery {
            scope,
            text: "query".into(),
            limit: 0,
            causal_region: None,
        }
        .validate()
        .is_err());
    }
}
