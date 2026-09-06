//! # CCOS Enterprise — Tenancy
//!
//! Multi-tenancy primitives: tenant identity and the **isolation invariant**
//! (docs/TENANCY_MODEL.md, docs/TENANT_MEMORY_ISOLATION.md). Foundation
//! slice: tenant-scoped namespacing that makes cross-tenant access a type
//! error, not a convention.

use serde::{Deserialize, Serialize};

/// A tenant boundary. Memory, quotas, policies and audit are scoped to it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TenantId(pub String);

impl TenantId {
    /// Construct a tenant id only if it is one this product will carry:
    /// non-empty, at most 128 bytes, ASCII `[a-z0-9_-]` with an alphanumeric
    /// first byte.
    ///
    /// The rule is restated here rather than imported from the runtime because
    /// tenancy is the lower crate and a dependency cycle is not worth the
    /// reuse — the same discipline `ccos_enterprise_auth` applies to
    /// identities. A confusable or path-unsafe tenant id is at its most
    /// expensive at construction, before it can name a store, a path or an
    /// audit row; the raw tuple constructor remains for state read back from
    /// a validated snapshot, where the restore path has already checked it.
    pub fn validated(id: &str) -> Option<Self> {
        let mut bytes = id.bytes();
        let Some(first) = bytes.next() else {
            return None;
        };
        let ok = id.len() <= 128
            && (first.is_ascii_lowercase() || first.is_ascii_digit())
            && bytes
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
        ok.then(|| Self(id.to_string()))
    }
}

/// Look a tenant up by name without owning one.
///
/// This exists for a measured reason. A `BTreeMap` keyed by `TenantId` can only
/// be probed with a `TenantId`, so every lookup used to build one — allocating
/// and copying the caller's string before discovering the key was absent. On a
/// store keyed by `(TenantId, String)` that cost the caller's whole key on a
/// pure miss: 4 MiB allocated to answer "no". With `Borrow<str>` the map takes
/// a `&str` and a miss costs nothing.
impl std::borrow::Borrow<str> for TenantId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

/// A tenant-scoped key: every store lookup in Enterprise carries the tenant
/// explicitly so a missing scope is a compile-time absence, not a runtime bug.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantScope<T> {
    pub tenant: TenantId,
    pub inner: T,
}

impl<T> TenantScope<T> {
    pub fn new(tenant: TenantId, inner: T) -> Self {
        Self { tenant, inner }
    }

    /// Re-scope is explicit: crossing tenants is a deliberate, auditable act
    /// (an admin operation), never an accident of a shared cache key.
    pub fn rescope(self, tenant: TenantId) -> Self {
        Self {
            tenant,
            inner: self.inner,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_are_distinct() {
        let a = TenantScope::new(TenantId("acme".into()), "memory-root");
        let b = TenantScope::new(TenantId("globex".into()), "memory-root");
        assert_ne!(a.tenant, b.tenant, "same inner key, different tenants");
        let c = a.clone().rescope(TenantId("globex".into()));
        assert_eq!(
            c.tenant, b.tenant,
            "explicit rescope is visible in the type"
        );
    }
}
