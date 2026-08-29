//! Backend-neutral agent-memory contract for CCOS Enterprise.
//!
//! This crate owns the CCOS vocabulary for composing semantic-memory domains.
//! It deliberately contains no vector index, database, network transport, or
//! vendor-specific implementation. Providers receive an explicit tenant scope
//! and an explicit memory loadout for every operation.
//!
//! The contract is original to CCOS Enterprise. External memory systems may
//! inform product requirements, but their APIs, schemas, storage layouts, and
//! source code are not part of this interface.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;

use ccos_enterprise_tenancy::TenantScope;

/// A semantic-memory namespace inside one tenant.
///
/// The variants model CCOS collaboration boundaries rather than backend
/// partitions. A provider is responsible for enforcing the isolation implied by
/// the selected space before retrieval candidates are produced.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemorySpace {
    /// Tenant-wide shared memory.
    Tenant,
    /// Project-specific shared memory.
    Project(String),
    /// Team-specific shared memory.
    Team(String),
    /// Private memory for one agent identity.
    Agent(String),
}

impl MemorySpace {
    pub fn project(id: impl Into<String>) -> Result<Self, MemoryError> {
        validated_space(Self::Project(id.into()))
    }

    pub fn team(id: impl Into<String>) -> Result<Self, MemoryError> {
        validated_space(Self::Team(id.into()))
    }

    pub fn agent(id: impl Into<String>) -> Result<Self, MemoryError> {
        validated_space(Self::Agent(id.into()))
    }

    /// Revalidate a space constructed through an enum variant directly.
    ///
    /// Provider boundaries call this method so malformed raw variants fail
    /// closed even when a caller bypasses the convenience constructors.
    pub fn validate(&self) -> Result<(), MemoryError> {
        let (kind, id) = match self {
            Self::Tenant => return Ok(()),
            Self::Project(id) => ("project", id),
            Self::Team(id) => ("team", id),
            Self::Agent(id) => ("agent", id),
        };
        if id.trim().is_empty() {
            Err(MemoryError::InvalidMemorySpace { kind })
        } else {
            Ok(())
        }
    }
}

/// Explicit set of memory spaces that may participate in one recall.
///
/// The set is private and validated on construction. Providers still recheck
/// each space at their trust boundary so direct enum construction cannot weaken
/// isolation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryLoadout {
    spaces: BTreeSet<MemorySpace>,
}

impl MemoryLoadout {
    pub fn new(spaces: impl IntoIterator<Item = MemorySpace>) -> Result<Self, MemoryError> {
        let spaces: BTreeSet<_> = spaces.into_iter().collect();
        if spaces.is_empty() {
            return Err(MemoryError::EmptyMemoryLoadout);
        }
        for space in &spaces {
            space.validate()?;
        }
        Ok(Self { spaces })
    }

    /// A loadout containing only the tenant-wide partition.
    pub fn tenant_only() -> Self {
        Self {
            spaces: BTreeSet::from([MemorySpace::Tenant]),
        }
    }

    pub fn spaces(&self) -> impl Iterator<Item = &MemorySpace> {
        self.spaces.iter()
    }

    pub fn len(&self) -> usize {
        self.spaces.len()
    }

    pub fn is_empty(&self) -> bool {
        self.spaces.is_empty()
    }
}

/// Write request for one exact memory space.
#[derive(Debug, Clone, Copy)]
pub struct ScopedMemoryWrite<'a> {
    pub space: &'a MemorySpace,
    pub embedding: &'a [f32],
    pub payload: &'a [u8],
}

/// Recall request over one explicit memory loadout.
#[derive(Debug, Clone, Copy)]
pub struct LoadoutMemoryQuery<'a> {
    pub embedding: &'a [f32],
    pub k: usize,
    pub shortlist: usize,
    pub loadout: &'a MemoryLoadout,
}

/// Owned provider result with the exact CCOS memory space that produced it.
#[derive(Debug, Clone, PartialEq)]
pub struct ScopedMemoryObservation {
    pub space: MemorySpace,
    pub payload: Vec<u8>,
    pub similarity: f32,
}

/// Normalized failure surface for governed semantic-memory providers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryError {
    InvalidConfiguration(&'static str),
    InvalidTenant,
    InvalidMemorySpace { kind: &'static str },
    EmptyMemoryLoadout,
    DimensionMismatch { expected: usize, found: usize },
    NonFiniteEmbedding,
    TenantCapacityExceeded { limit: usize },
    InsertRejected,
}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(detail) => {
                write!(f, "invalid memory configuration: {detail}")
            }
            Self::InvalidTenant => write!(f, "tenant id must not be empty"),
            Self::InvalidMemorySpace { kind } => {
                write!(f, "{kind} memory-space id must not be empty")
            }
            Self::EmptyMemoryLoadout => write!(f, "memory loadout must contain at least one space"),
            Self::DimensionMismatch { expected, found } => {
                write!(
                    f,
                    "embedding dimension mismatch: expected {expected}, found {found}"
                )
            }
            Self::NonFiniteEmbedding => write!(f, "embedding contains a non-finite value"),
            Self::TenantCapacityExceeded { limit } => {
                write!(
                    f,
                    "tenant semantic-memory capacity exceeded (limit {limit})"
                )
            }
            Self::InsertRejected => write!(f, "semantic-memory provider rejected the insertion"),
        }
    }
}

impl std::error::Error for MemoryError {}

/// Minimal backend contract for CCOS scoped semantic memory.
///
/// The trait intentionally exposes only explicit-space writes and explicit-
/// loadout recalls. Backend-specific convenience APIs may exist separately, but
/// generic CCOS code cannot accidentally perform an unscoped semantic lookup.
pub trait SemanticMemoryProvider {
    fn insert_scoped(
        &mut self,
        scoped: TenantScope<ScopedMemoryWrite<'_>>,
    ) -> Result<(), MemoryError>;

    fn recall_loadout(
        &self,
        scoped: TenantScope<LoadoutMemoryQuery<'_>>,
    ) -> Result<Vec<ScopedMemoryObservation>, MemoryError>;
}

fn validated_space(space: MemorySpace) -> Result<MemorySpace, MemoryError> {
    space.validate()?;
    Ok(space)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_space_ids_fail_closed() {
        assert_eq!(
            MemorySpace::agent("  "),
            Err(MemoryError::InvalidMemorySpace { kind: "agent" })
        );
        assert_eq!(
            MemorySpace::Project(String::new()).validate(),
            Err(MemoryError::InvalidMemorySpace { kind: "project" })
        );
    }

    #[test]
    fn empty_loadout_is_rejected() {
        assert_eq!(MemoryLoadout::new([]), Err(MemoryError::EmptyMemoryLoadout));
    }

    #[test]
    fn loadout_deduplicates_and_orders_spaces_deterministically() {
        let project = MemorySpace::project("ccos").unwrap();
        let team = MemorySpace::team("runtime").unwrap();
        let loadout = MemoryLoadout::new([
            team.clone(),
            project.clone(),
            MemorySpace::Tenant,
            team,
        ])
        .unwrap();

        assert_eq!(
            loadout.spaces().cloned().collect::<Vec<_>>(),
            vec![MemorySpace::Tenant, project, MemorySpace::team("runtime").unwrap()]
        );
    }
}
