//! Governed OctaSoma adapter for CCOS Enterprise.
//!
//! This crate is the only supported direct Enterprise dependency on OctaSoma.
//! It keeps one independent semantic-memory instance per [`TenantId`], enforces
//! a hard item quota before mutation, and returns owned recall observations.
//! Similarity is evidence for higher layers; it is never authorization or causal
//! truth.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;

use ccos_enterprise_tenancy::{TenantId, TenantScope};
use octasoma::HybridMemory;

/// A tenant-scoped write into semantic/episodic memory.
#[derive(Debug, Clone, Copy)]
pub struct MemoryWrite<'a> {
    pub embedding: &'a [f32],
    pub payload: &'a [u8],
}

/// A tenant-scoped precision recall request.
#[derive(Debug, Clone, Copy)]
pub struct MemoryQuery<'a> {
    pub embedding: &'a [f32],
    pub k: usize,
    pub shortlist: usize,
}

/// An owned semantic-memory observation.
///
/// The payload is copied out of the tenant-local OctaSoma instance so no caller
/// can retain an internal reference that outlives the scoped lookup. The score
/// is a retrieval signal only; Enterprise/CCOS policy remains authoritative.
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryObservation {
    pub payload: Vec<u8>,
    pub similarity: f32,
}

/// A fail-closed rejection from the Enterprise memory boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnterpriseMemoryError {
    InvalidConfiguration(&'static str),
    InvalidTenant,
    DimensionMismatch { expected: usize, found: usize },
    NonFiniteEmbedding,
    TenantCapacityExceeded { limit: usize },
    InsertRejected,
}

impl fmt::Display for EnterpriseMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(detail) => {
                write!(f, "invalid memory configuration: {detail}")
            }
            Self::InvalidTenant => write!(f, "tenant id must not be empty"),
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
            Self::InsertRejected => write!(f, "OctaSoma rejected the validated insertion"),
        }
    }
}

impl std::error::Error for EnterpriseMemoryError {}

/// One isolated OctaSoma [`HybridMemory`] per Enterprise tenant.
///
/// No candidate set, payload arena or index is shared across tenants. The
/// adapter deliberately exposes no raw OctaSoma handle: callers must cross the
/// typed [`TenantScope`] boundary for every read and write.
pub struct EnterpriseOctaSoma {
    dim: usize,
    seed: u64,
    bits: usize,
    per_tenant_capacity: usize,
    tenants: BTreeMap<TenantId, HybridMemory>,
}

impl EnterpriseOctaSoma {
    /// Build a deterministic tenant-isolated semantic-memory adapter.
    pub fn new(
        dim: usize,
        bits: usize,
        per_tenant_capacity: usize,
        seed: u64,
    ) -> Result<Self, EnterpriseMemoryError> {
        if dim == 0 {
            return Err(EnterpriseMemoryError::InvalidConfiguration(
                "embedding dimension must be non-zero",
            ));
        }
        if bits == 0 || !bits.is_multiple_of(64) {
            return Err(EnterpriseMemoryError::InvalidConfiguration(
                "SimHash width must be a non-zero multiple of 64",
            ));
        }
        if per_tenant_capacity == 0 {
            return Err(EnterpriseMemoryError::InvalidConfiguration(
                "per-tenant capacity must be non-zero",
            ));
        }
        Ok(Self {
            dim,
            seed,
            bits,
            per_tenant_capacity,
            tenants: BTreeMap::new(),
        })
    }

    /// Insert into exactly one tenant's memory, failing before mutation when the
    /// request violates scope, embedding or quota invariants.
    pub fn insert(
        &mut self,
        scoped: TenantScope<MemoryWrite<'_>>,
    ) -> Result<(), EnterpriseMemoryError> {
        let TenantScope { tenant, inner } = scoped;
        validate_tenant(&tenant)?;
        validate_embedding(inner.embedding, self.dim)?;

        let memory = self
            .tenants
            .entry(tenant)
            .or_insert_with(|| HybridMemory::new(self.dim, self.seed, self.bits));
        if memory.len() >= self.per_tenant_capacity {
            return Err(EnterpriseMemoryError::TenantCapacityExceeded {
                limit: self.per_tenant_capacity,
            });
        }
        if !memory.insert(inner.embedding, inner.payload) {
            return Err(EnterpriseMemoryError::InsertRejected);
        }
        Ok(())
    }

    /// Precision recall inside exactly one tenant's candidate pool.
    ///
    /// A missing tenant has no observations. `k == 0` also returns an empty
    /// result without touching the underlying engine.
    pub fn recall(
        &self,
        scoped: TenantScope<MemoryQuery<'_>>,
    ) -> Result<Vec<MemoryObservation>, EnterpriseMemoryError> {
        let TenantScope { tenant, inner } = scoped;
        validate_tenant(&tenant)?;
        validate_embedding(inner.embedding, self.dim)?;
        if inner.k == 0 {
            return Ok(Vec::new());
        }
        let Some(memory) = self.tenants.get(&tenant) else {
            return Ok(Vec::new());
        };
        let shortlist = inner.shortlist.max(inner.k).max(1);
        Ok(memory
            .recall(inner.embedding, inner.k, shortlist)
            .into_iter()
            .map(|(payload, similarity)| MemoryObservation {
                payload: payload.to_vec(),
                similarity,
            })
            .collect())
    }

    /// Number of memories visible in one tenant scope.
    pub fn tenant_len(&self, tenant: &TenantId) -> usize {
        self.tenants.get(tenant).map_or(0, HybridMemory::len)
    }

    /// Number of tenant-local indexes currently materialised.
    pub fn tenant_count(&self) -> usize {
        self.tenants.len()
    }

    /// Configured hard item limit for each tenant.
    pub fn per_tenant_capacity(&self) -> usize {
        self.per_tenant_capacity
    }
}

fn validate_tenant(tenant: &TenantId) -> Result<(), EnterpriseMemoryError> {
    if tenant.0.trim().is_empty() {
        Err(EnterpriseMemoryError::InvalidTenant)
    } else {
        Ok(())
    }
}

fn validate_embedding(embedding: &[f32], dim: usize) -> Result<(), EnterpriseMemoryError> {
    if embedding.len() != dim {
        return Err(EnterpriseMemoryError::DimensionMismatch {
            expected: dim,
            found: embedding.len(),
        });
    }
    if embedding.iter().any(|x| !x.is_finite()) {
        return Err(EnterpriseMemoryError::NonFiniteEmbedding);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write<'a>(embedding: &'a [f32], payload: &'a [u8]) -> MemoryWrite<'a> {
        MemoryWrite { embedding, payload }
    }

    fn query(embedding: &[f32]) -> MemoryQuery<'_> {
        MemoryQuery {
            embedding,
            k: 1,
            shortlist: 8,
        }
    }

    #[test]
    fn recall_never_crosses_tenant_boundary() {
        let mut memory = EnterpriseOctaSoma::new(4, 64, 8, 42).unwrap();
        let v = [1.0, 0.0, 0.0, 0.0];

        memory
            .insert(TenantScope::new(
                TenantId("acme".into()),
                write(&v, b"acme-secret"),
            ))
            .unwrap();
        memory
            .insert(TenantScope::new(
                TenantId("globex".into()),
                write(&v, b"globex-secret"),
            ))
            .unwrap();

        let acme = memory
            .recall(TenantScope::new(TenantId("acme".into()), query(&v)))
            .unwrap();
        let globex = memory
            .recall(TenantScope::new(TenantId("globex".into()), query(&v)))
            .unwrap();

        assert_eq!(acme[0].payload, b"acme-secret");
        assert_eq!(globex[0].payload, b"globex-secret");
        assert_eq!(memory.tenant_count(), 2);
    }

    #[test]
    fn quota_rejects_before_mutating_tenant_index() {
        let mut memory = EnterpriseOctaSoma::new(4, 64, 1, 7).unwrap();
        let a = [1.0, 0.0, 0.0, 0.0];
        let b = [0.0, 1.0, 0.0, 0.0];
        let tenant = TenantId("acme".into());

        memory
            .insert(TenantScope::new(tenant.clone(), write(&a, b"first")))
            .unwrap();
        assert_eq!(
            memory.insert(TenantScope::new(tenant.clone(), write(&b, b"second"))),
            Err(EnterpriseMemoryError::TenantCapacityExceeded { limit: 1 })
        );
        assert_eq!(memory.tenant_len(&tenant), 1);
    }

    #[test]
    fn malformed_embedding_is_rejected_before_tenant_creation() {
        let mut memory = EnterpriseOctaSoma::new(4, 64, 8, 9).unwrap();
        let tenant = TenantId("acme".into());
        assert_eq!(
            memory.insert(TenantScope::new(tenant.clone(), write(&[1.0, 2.0], b"bad"),)),
            Err(EnterpriseMemoryError::DimensionMismatch {
                expected: 4,
                found: 2,
            })
        );
        assert_eq!(memory.tenant_count(), 0);

        assert_eq!(
            memory.insert(TenantScope::new(
                tenant,
                write(&[1.0, f32::NAN, 0.0, 0.0], b"nan"),
            )),
            Err(EnterpriseMemoryError::NonFiniteEmbedding)
        );
        assert_eq!(memory.tenant_count(), 0);
    }

    #[test]
    fn empty_or_unknown_tenant_fails_closed() {
        let memory = EnterpriseOctaSoma::new(4, 64, 8, 11).unwrap();
        let v = [1.0, 0.0, 0.0, 0.0];
        assert_eq!(
            memory.recall(TenantScope::new(TenantId(String::new()), query(&v))),
            Err(EnterpriseMemoryError::InvalidTenant)
        );
        assert!(memory
            .recall(TenantScope::new(TenantId("missing".into()), query(&v)))
            .unwrap()
            .is_empty());
    }
}
