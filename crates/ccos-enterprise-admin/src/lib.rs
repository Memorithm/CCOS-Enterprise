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
    // A justification must be *written*: `Some("")` or whitespace is the same
    // audit hole as `None`.
    let justified = a
        .justification
        .as_deref()
        .is_some_and(|j| !j.trim().is_empty());
    if JUSTIFICATION_REQUIRED.contains(&a.action.as_str()) && !justified {
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

    #[test]
    fn blank_justification_is_no_justification() {
        let mut a = AdminAction {
            actor: "root".into(),
            action: "license.revoke".into(),
            target: "lic-0001".into(),
            unix_time: 0,
            justification: Some(String::new()),
        };
        assert!(validate(&a).is_err(), "empty string is not written");
        a.justification = Some("  \t ".into());
        assert!(validate(&a).is_err(), "whitespace is not written");
        // Non-sensitive actions still pass without one.
        a.action = "tenant.rename".into();
        a.justification = None;
        assert!(validate(&a).is_ok());
    }
}
