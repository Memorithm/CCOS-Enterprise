//! # CCOS Enterprise — Authentication
//!
//! Agent/user identity primitives. Foundation slice: opaque, hashable
//! identity types — authentication *mechanisms* (tokens, OIDC, mTLS) land on
//! top of these in later milestones (see docs/AGENT_IDENTITY_MODEL.md).

use serde::{Deserialize, Serialize};

/// A verified actor identity (user, agent, or service) inside an
/// organization. Opaque string, never an email, never a token.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActorId(pub String);

/// An organization boundary — the outermost administrative scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OrgId(pub String);

/// Proof strength attached to an authenticated actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuthStrength {
    /// Identity asserted but not cryptographically verified.
    Anonymous,
    /// Shared-secret or token verified.
    Token,
    /// Strong proof (mTLS, hardware-backed key).
    Strong,
}

/// An authenticated actor in an organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedActor {
    pub org: OrgId,
    pub actor: ActorId,
    pub strength: AuthStrength,
}

impl AuthenticatedActor {
    /// Whether the actor may be considered for sensitive operations
    /// (license administration, tenant policy changes).
    pub fn is_strongly_authenticated(&self) -> bool {
        self.strength == AuthStrength::Strong
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strength_ordering() {
        let a = AuthenticatedActor {
            org: OrgId("memorithm".into()),
            actor: ActorId("agent-7".into()),
            strength: AuthStrength::Strong,
        };
        assert!(a.is_strongly_authenticated());
        assert!(AuthStrength::Strong > AuthStrength::Token);
        assert!(AuthStrength::Token > AuthStrength::Anonymous);
    }
}
