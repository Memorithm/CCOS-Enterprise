//! # CCOS Enterprise — Tenancy
//!
//! Multi-tenancy primitives: tenant, workspace and agent identity plus the
//! isolation invariant (docs/TENANCY_MODEL.md, docs/TENANT_MEMORY_ISOLATION.md).
//! Scope is carried in the type so cross-boundary access is explicit rather
//! than an unreviewed string convention.

use serde::{Deserialize, Serialize};

/// A tenant boundary. Memory, quotas, policies and audit are scoped to it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TenantId(pub String);

/// A workspace boundary nested inside one tenant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct WorkspaceId(pub String);

/// An agent boundary nested inside one workspace.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AgentId(pub String);

/// Look a tenant up by name without owning one.
impl std::borrow::Borrow<str> for TenantId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl std::borrow::Borrow<str> for WorkspaceId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl std::borrow::Borrow<str> for AgentId {
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

/// A workspace-scoped value. The tenant is always carried alongside the
/// workspace id; a workspace id alone is not a global namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceScope<T> {
    pub tenant: TenantId,
    pub workspace: WorkspaceId,
    pub inner: T,
}

impl<T> WorkspaceScope<T> {
    pub fn new(tenant: TenantId, workspace: WorkspaceId, inner: T) -> Self {
        Self {
            tenant,
            workspace,
            inner,
        }
    }

    /// Narrows this workspace value to one agent without dropping either parent
    /// isolation boundary.
    pub fn for_agent(self, agent: AgentId) -> AgentScope<T> {
        AgentScope {
            tenant: self.tenant,
            workspace: self.workspace,
            agent,
            inner: self.inner,
        }
    }
}

/// The narrowest standard Enterprise memory scope: Tenant → Workspace → Agent.
///
/// Adapters may encode this into an opaque backend scope, but the backend never
/// becomes authoritative for tenancy semantics or access decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentScope<T> {
    pub tenant: TenantId,
    pub workspace: WorkspaceId,
    pub agent: AgentId,
    pub inner: T,
}

impl<T> AgentScope<T> {
    pub fn new(tenant: TenantId, workspace: WorkspaceId, agent: AgentId, inner: T) -> Self {
        Self {
            tenant,
            workspace,
            agent,
            inner,
        }
    }

    /// Change only the agent inside the same tenant/workspace boundary.
    pub fn for_agent(self, agent: AgentId) -> Self {
        Self {
            tenant: self.tenant,
            workspace: self.workspace,
            agent,
            inner: self.inner,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_scopes_are_distinct() {
        let a = TenantScope::new(TenantId("acme".into()), "memory-root");
        let b = TenantScope::new(TenantId("globex".into()), "memory-root");
        assert_ne!(a.tenant, b.tenant, "same inner key, different tenants");
        let c = a.clone().rescope(TenantId("globex".into()));
        assert_eq!(
            c.tenant, b.tenant,
            "explicit rescope is visible in the type"
        );
    }

    #[test]
    fn workspace_scope_preserves_tenant_boundary() {
        let a = WorkspaceScope::new(
            TenantId("acme".into()),
            WorkspaceId("research".into()),
            "memory",
        );
        let b = WorkspaceScope::new(
            TenantId("globex".into()),
            WorkspaceId("research".into()),
            "memory",
        );
        assert_ne!(a, b);
    }

    #[test]
    fn agent_scope_preserves_all_parent_boundaries() {
        let workspace = WorkspaceScope::new(
            TenantId("acme".into()),
            WorkspaceId("ws-a".into()),
            "memory",
        );
        let a = workspace.clone().for_agent(AgentId("agent-a".into()));
        let b = workspace.for_agent(AgentId("agent-b".into()));

        assert_eq!(a.tenant, b.tenant);
        assert_eq!(a.workspace, b.workspace);
        assert_ne!(a.agent, b.agent);
        assert_ne!(a, b);
    }
}
