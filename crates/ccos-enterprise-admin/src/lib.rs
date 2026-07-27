//! # CCOS Enterprise — Administration
//!
//! Operator-facing administration surface (org/tenant/user lifecycle).
//! Foundation slice: the administrative action log — every admin act is an
//! auditable record before it is an effect.

use serde::{Deserialize, Serialize};

/// An administrative action, journaled before execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAction {
    pub actor: String,
    pub action: String,
    pub target: String,
    pub unix_time: u64,
    /// Free-form justification, required for sensitive actions.
    pub justification: Option<String>,
}

/// Actions that are refused without a written justification.
pub const JUSTIFICATION_REQUIRED: &[&str] = &[
    "tenant.delete",
    "tenant.suspend",
    "quota.override",
    "policy.disable",
    "license.revoke",
];

/// Validate an administrative action before it takes effect (fail closed).
pub fn validate(a: &AdminAction) -> Result<(), String> {
    if a.actor.is_empty() || a.action.is_empty() || a.target.is_empty() {
        return Err("actor, action and target are required".into());
    }
    if JUSTIFICATION_REQUIRED.contains(&a.action.as_str()) && a.justification.is_none() {
        return Err(format!("'{}' requires a written justification", a.action));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_actions_need_justification() {
        let mut a = AdminAction {
            actor: "root".into(),
            action: "tenant.delete".into(),
            target: "acme".into(),
            unix_time: 0,
            justification: None,
        };
        assert!(validate(&a).is_err());
        a.justification = Some("contract terminated 2026-07-01".into());
        assert!(validate(&a).is_ok());
    }
}
