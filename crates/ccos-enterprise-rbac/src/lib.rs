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
    /// Define a role that does not exist yet. Returns `false` — changing
    /// nothing — if the name is empty or already taken.
    ///
    /// It used to be an unconditional `insert`, which made redefinition a
    /// **silent mass privilege change**: every actor already holding the name
    /// gained or lost whatever the new permission set changed, with no return
    /// value to notice it by and no record anywhere. Escalating every `reader`
    /// to `policy.admin` was one call that looked like provisioning.
    ///
    /// Redefinition is still possible, deliberately, through
    /// [`redefine_role`](Self::redefine_role) — which says what it does and
    /// reports what it hit.
    pub fn add_role(&mut self, role: Role) -> bool {
        if role.name.is_empty() || self.roles.contains_key(&role.name) {
            return false;
        }
        self.roles.insert(role.name.clone(), role);
        true
    }

    /// Replace an existing role's permission set. Returns whether a role of
    /// that name existed.
    ///
    /// Every holder is affected immediately — that is what a role *is* — so
    /// this is the operation an administrative surface should demand a
    /// justification for. It is separate from [`add_role`](Self::add_role) so
    /// that a mass privilege change cannot be reached by a typo in a
    /// provisioning script.
    pub fn redefine_role(&mut self, role: Role) -> bool {
        if role.name.is_empty() {
            return false;
        }
        self.roles.insert(role.name.clone(), role).is_some()
    }

    /// Remove a role **and every grant of it**. Returns whether it existed.
    ///
    /// Purging the assignments is the whole point. Leaving them behind would
    /// mean a later role of the same name silently re-grants everyone who once
    /// held it: a de-provisioned actor coming back to life because somebody
    /// re-created an unrelated role. `allows` tolerates a dangling grant, so
    /// the resurrection would be invisible until it mattered.
    pub fn remove_role(&mut self, name: &str) -> bool {
        let existed = self.roles.remove(name).is_some();
        for grants in self.assignments.values_mut() {
            grants.remove(name);
        }
        self.assignments.retain(|_, grants| !grants.is_empty());
        existed
    }

    /// Withdraw one role from one actor. Returns whether the grant existed.
    pub fn unassign(&mut self, actor: &str, role: &str) -> bool {
        let Some(grants) = self.assignments.get_mut(actor) else {
            return false;
        };
        let removed = grants.remove(role);
        if grants.is_empty() {
            self.assignments.remove(actor);
        }
        removed
    }

    /// Withdraw every role from one actor — de-provisioning a principal.
    /// Returns whether the actor held anything.
    pub fn remove_actor(&mut self, actor: &str) -> bool {
        self.assignments.remove(actor).is_some()
    }

    /// Grant a role to an actor. Fails closed on an unknown role, and refuses
    /// the empty string for either side: `""` is not a principal and not a
    /// role, however willing a `BTreeMap` is to hold one.
    pub fn assign(&mut self, actor: &str, role: &str) -> bool {
        if actor.is_empty() || role.is_empty() {
            return false;
        }
        if !self.roles.contains_key(role) {
            return false; // fail closed: unknown roles cannot be granted
        }
        self.assignments
            .entry(actor.into())
            .or_default()
            .insert(role.into());
        true
    }

    /// Whether a role of this name is defined.
    pub fn has_role(&self, name: &str) -> bool {
        self.roles.contains_key(name)
    }

    /// The roles this actor holds, in name order.
    pub fn roles_of(&self, actor: &str) -> Vec<&str> {
        self.assignments
            .get(actor)
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect()
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
