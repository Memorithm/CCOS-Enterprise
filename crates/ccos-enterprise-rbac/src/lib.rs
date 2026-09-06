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

/// Role assignments per principal.
///
/// Assignments are keyed by **`(org, actor)`**, not by the bare actor name.
/// A `RoleBook` used to key on the actor string alone, which made the book
/// deployment-global across organizations: every org's `agent-7` shared one
/// assignment row, so provisioning `agent-7` in org A granted org B's
/// `agent-7` whatever org A's administrator intended. Identities are proved
/// as `(org, actor)` pairs — [`ccos_enterprise_auth::AuthenticatedActor`]
/// carries both — and the book keys on both or it keys on a name.
///
/// The wire form is a **row list**, not a map keyed by the tuple: JSON object
/// keys must be strings, and a snapshot that cannot be written is worse than
/// one that needs a few lines more. [`Deserialize`] still reads the legacy
/// `actor → roles` map shape so pre-org snapshots load — see
/// [`AssignmentRows::Legacy`] for the deliberate fail-closed reading of those
/// rows.
#[derive(Debug, Clone, Default)]
pub struct RoleBook {
    roles: BTreeMap<String, Role>,
    assignments: BTreeMap<(String, String), BTreeSet<String>>,
}

/// One assignment row, as persisted.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AssignmentRow {
    org: String,
    actor: String,
    roles: BTreeSet<String>,
}

/// The two assignment encodings this type reads.
///
/// [`AssignmentRows::Scoped`] is the current form: one row per principal,
/// organization named. [`AssignmentRows::Legacy`] is what every snapshot
/// written before the org-scoped key carried: a map keyed by the bare actor
/// name. Those rows record **no organization**, so they are restored under
/// the empty org — which authorizes nobody, because `allows` keys on the
/// proved `(org, actor)` pair and no credential proves an empty org. That is
/// the fail-closed reading: a row whose org was never recorded cannot be
/// safely attributed, so it grants nothing until an operator re-provisions
/// the principal explicitly with `assign(org, actor, role)`. Silently
/// re-attaching the grants to whichever single org the deployment happens to
/// serve would be exactly the cross-tenant bleed this key exists to close.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(untagged)]
enum AssignmentRows {
    Scoped(Vec<AssignmentRow>),
    Legacy(BTreeMap<String, BTreeSet<String>>),
}

impl Default for AssignmentRows {
    fn default() -> Self {
        Self::Scoped(Vec::new())
    }
}

impl serde::Serialize for RoleBook {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("RoleBook", 2)?;
        state.serialize_field("roles", &self.roles)?;
        // Empty grant sets are a state `assign` never produces (the entry is
        // created only when a role is granted), so they are not written.
        let rows: Vec<AssignmentRow> = self
            .assignments
            .iter()
            .filter(|(_, grants)| !grants.is_empty())
            .map(|((org, actor), grants)| AssignmentRow {
                org: org.clone(),
                actor: actor.clone(),
                roles: grants.clone(),
            })
            .collect();
        state.serialize_field("assignments", &rows)?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for RoleBook {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(default)]
            roles: BTreeMap<String, Role>,
            #[serde(default)]
            assignments: AssignmentRows,
        }
        let raw = Raw::deserialize(deserializer)?;
        let mut book = RoleBook {
            roles: raw.roles,
            assignments: BTreeMap::new(),
        };
        match raw.assignments {
            AssignmentRows::Scoped(rows) => {
                for row in rows {
                    if !row.roles.is_empty() {
                        book.assignments.insert((row.org, row.actor), row.roles);
                    }
                }
            }
            AssignmentRows::Legacy(map) => {
                for (actor, grants) in map {
                    if !grants.is_empty() {
                        book.assignments
                            .entry((String::new(), actor))
                            .or_default()
                            .extend(grants);
                    }
                }
            }
        }
        Ok(book)
    }
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
    pub fn unassign(&mut self, org: &str, actor: &str, role: &str) -> bool {
        let Some(grants) = self
            .assignments
            .get_mut(&(org.to_string(), actor.to_string()))
        else {
            return false;
        };
        let removed = grants.remove(role);
        if grants.is_empty() {
            self.assignments
                .remove(&(org.to_string(), actor.to_string()));
        }
        removed
    }

    /// Withdraw every role from one actor — de-provisioning a principal.
    /// Returns whether the actor held anything.
    pub fn remove_actor(&mut self, org: &str, actor: &str) -> bool {
        self.assignments
            .remove(&(org.to_string(), actor.to_string()))
            .is_some()
    }

    /// Grant a role to an actor. Fails closed on an unknown role, and refuses
    /// the empty string for any side: `""` is not an organization, a principal
    /// or a role, however willing a `BTreeMap` is to hold one.
    pub fn assign(&mut self, org: &str, actor: &str, role: &str) -> bool {
        if org.is_empty() || actor.is_empty() || role.is_empty() {
            return false;
        }
        if !self.roles.contains_key(role) {
            return false; // fail closed: unknown roles cannot be granted
        }
        self.assignments
            .entry((org.to_string(), actor.to_string()))
            .or_default()
            .insert(role.into());
        true
    }

    /// Whether a role of this name is defined.
    pub fn has_role(&self, name: &str) -> bool {
        self.roles.contains_key(name)
    }

    /// The permissions a role grants, in name order; empty for an unknown role.
    ///
    /// A governance journal that records "the role changed" without recording
    /// *what it changed to* is not evidence, so this exists for the caller that
    /// has to write the before/after down.
    pub fn permissions_of(&self, name: &str) -> Vec<&str> {
        self.roles
            .get(name)
            .into_iter()
            .flat_map(|r| r.permissions.iter())
            .map(|p| p.0.as_str())
            .collect()
    }

    /// Every actor currently holding this role, as `org/actor` strings in
    /// key order.
    ///
    /// The blast radius of a redefinition or a removal: without it a journal
    /// can say a role was rewritten but not whose rights moved. The org is
    /// part of the answer — `acme/agent-7` and `globex/agent-7` are different
    /// principals and an auditor must be able to tell them apart.
    pub fn holders_of(&self, name: &str) -> Vec<String> {
        self.assignments
            .iter()
            .filter(|(_, grants)| grants.contains(name))
            .map(|((org, actor), _)| format!("{org}/{actor}"))
            .collect()
    }

    /// The roles this actor holds, in name order.
    pub fn roles_of(&self, org: &str, actor: &str) -> Vec<&str> {
        self.assignments
            .get(&(org.to_string(), actor.to_string()))
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect()
    }

    /// Deterministic permission check: allowed iff any assigned role grants
    /// it. Keyed on the **proved** `(org, actor)` pair — the same pair the
    /// credential carries — so a name collision across organizations reaches
    /// nothing.
    pub fn allows(&self, org: &str, actor: &str, permission: &Permission) -> bool {
        self.assignments
            .get(&(org.to_string(), actor.to_string()))
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
        assert!(book.assign("acme", "alice", "reader"));
        assert!(!book.assign("acme", "alice", "admin")); // unknown role refused
        assert!(book.allows("acme", "alice", &Permission("memory.read".into())));
        assert!(!book.allows("acme", "alice", &Permission("memory.write".into())));
        assert!(!book.allows("acme", "bob", &Permission("memory.read".into())));
    }

    #[test]
    fn the_same_actor_name_in_two_organizations_holds_nothing_in_common() {
        // The defect this key closes: the book was keyed by the bare actor
        // name, so `agent-7` provisioned in `acme` carried `globex`'s grants —
        // and vice versa. Identity is a `(org, actor)` pair; the book keys on
        // the pair or it keys on a name.
        let mut book = RoleBook::default();
        let mut writer = Role {
            name: "writer".into(),
            ..Default::default()
        };
        writer.permissions.insert(Permission("memory.write".into()));
        book.add_role(writer);

        assert!(book.assign("acme", "agent-7", "writer"));

        // Same name, other organization: denied by default, and the grant is
        // invisible from both directions.
        assert!(!book.allows("globex", "agent-7", &Permission("memory.write".into())));
        assert!(book.roles_of("globex", "agent-7").is_empty());
        assert!(!book.remove_actor("globex", "agent-7"));

        // De-provisioning one org's principal leaves the other untouched.
        assert!(book.remove_actor("acme", "agent-7"));
        assert!(!book.allows("acme", "agent-7", &Permission("memory.write".into())));
        assert!(book.holders_of("writer").is_empty());

        // Holders are named with their organization.
        assert!(book.assign("acme", "agent-7", "writer"));
        assert!(book.assign("globex", "agent-7", "writer"));
        assert_eq!(
            book.holders_of("writer"),
            vec!["acme/agent-7".to_string(), "globex/agent-7".to_string()]
        );
    }

    #[test]
    fn empty_orgs_actors_and_roles_are_refused() {
        let mut book = RoleBook::default();
        let mut reader = Role {
            name: "reader".into(),
            ..Default::default()
        };
        reader.permissions.insert(Permission("memory.read".into()));
        book.add_role(reader);
        assert!(!book.assign("", "alice", "reader"));
        assert!(!book.assign("acme", "", "reader"));
        assert!(!book.assign("acme", "alice", ""));
    }
}
