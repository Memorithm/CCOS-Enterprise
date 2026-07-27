//! # CCOS Enterprise — RBAC
//!
//! Role-based access control over CCOS capabilities (see docs/RBAC_MODEL.md).
//! Foundation slice: roles, permissions, and a deterministic grant check.
//! ABAC extensions arrive when justified by a real tenant requirement.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A governed capability (MCP tool class, admin action, data class).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Permission(pub String);

/// A named role: an ordered set of permissions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    pub permissions: BTreeSet<Permission>,
}

/// Role assignments per actor.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoleBook {
    roles: BTreeMap<String, Role>,
    assignments: BTreeMap<String, BTreeSet<String>>,
}

impl RoleBook {
    pub fn add_role(&mut self, role: Role) {
        self.roles.insert(role.name.clone(), role);
    }

    pub fn assign(&mut self, actor: &str, role: &str) -> bool {
        if !self.roles.contains_key(role) {
            return false; // fail closed: unknown roles cannot be granted
        }
        self.assignments
            .entry(actor.into())
            .or_default()
            .insert(role.into());
        true
    }

    /// Deterministic permission check: allowed iff any assigned role grants it.
    pub fn allows(&self, actor: &str, permission: &Permission) -> bool {
        self.assignments
            .get(actor)
            .into_iter()
            .flatten()
            .filter_map(|r| self.roles.get(r))
            .any(|role| role.permissions.contains(permission))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_and_deny() {
        let mut book = RoleBook::default();
        let mut reader = Role {
            name: "reader".into(),
            ..Default::default()
        };
        reader.permissions.insert(Permission("memory.read".into()));
        book.add_role(reader);
        assert!(book.assign("alice", "reader"));
        assert!(!book.assign("alice", "admin")); // unknown role refused
        assert!(book.allows("alice", &Permission("memory.read".into())));
        assert!(!book.allows("alice", &Permission("memory.write".into())));
        assert!(!book.allows("bob", &Permission("memory.read".into())));
    }
}
