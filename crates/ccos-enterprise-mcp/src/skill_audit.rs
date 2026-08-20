//! Governed read-only exposure of the skill provenance audit.
//!
//! This is the operator-facing counterpart to `memory.skills`. The model-visible
//! projection deliberately withholds trial/evidence identifiers; the audit
//! exposes exactly those, under a distinct permission
//! (`audit.provenance`), never through DeepSeek Harness model context and
//! never as part of `memory.skills`.

use ccos_enterprise_rbac::Permission;
use ccos_enterprise_runtime::Deployment;
use ccos_enterprise_skills::{SkillRegistry, SkillTrialRegistry};
use ccos_enterprise_skills_audit::{audit_provenance, AuditLimits, AuditQuery, AuditSources};
use ccos_enterprise_tenancy::{TenantId, TenantScope};
use serde_json::{json, Value};

pub use ccos_enterprise_skills_audit::SKILL_AUDIT_PERMISSION;

pub const SKILL_AUDIT_TOOL: &str = "audit.provenance";
pub const DEFAULT_AUDIT_LIMIT: usize = 128;
pub const MAX_AUDIT_LIMIT: usize = 1024;

/// Declare the audit capability on a deployment: the tool and its permission.
pub fn govern_skill_audit(deployment: &mut Deployment) {
    deployment.govern_tool(SKILL_AUDIT_TOOL, SKILL_AUDIT_PERMISSION);
}

pub fn skill_audit_permission_for(tool: &str) -> Option<&'static str> {
    (tool == SKILL_AUDIT_TOOL).then_some(SKILL_AUDIT_PERMISSION)
}

pub fn skill_audit_tool_spec() -> Value {
    json!({
        "name": SKILL_AUDIT_TOOL,
        "description": "Operator-only provenance audit of validated skills and observational trials for the authenticated tenant: trial ids, evidence hashes and aggregate counters. Read-only; never returns raw prompts, sessions, tool input/output or model output; never available to model context.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_AUDIT_LIMIT,
                    "description": "Maximum skills to include in the report."
                }
            },
            "additionalProperties": false
        }
    })
}

/// Build the audit report for the tenant this server is bound to.
///
/// `actor` is the identity the server's token proved (the same one `admit`
/// keys authorization on). The permission gate is enforced by the
/// deployment's `admit` path before this runs (the tool is governed under
/// `audit.provenance`); the audit crate re-checks the same role book, so a
/// caller can never reach the report without holding the role.
pub fn skill_audit_result(
    deployment: &Deployment,
    actor: &str,
    tenant: &str,
    skills: &SkillRegistry,
    trials: &SkillTrialRegistry,
    arguments: &Value,
) -> Result<Value, String> {
    let limit = skill_audit_limit(arguments)?;
    let tenant_id = TenantId(tenant.to_string());
    let scope = TenantScope::new(tenant_id.clone(), ());
    // The tenant set is the deployment's own tenant map; an unknown tenant is
    // refused before any ledger material is touched.
    let known: std::collections::BTreeMap<TenantId, ()> =
        deployment.tenant_ids().map(|id| (id.clone(), ())).collect();
    let report = audit_provenance(
        AuditQuery {
            caller: actor,
            scope: &scope,
            limits: AuditLimits {
                max_trials_per_skill: limit,
                max_evidence_per_skill: limit,
                max_skills: limit,
            },
            sources: AuditSources {
                tenant: tenant_id,
                skills,
                trials,
            },
            roles: deployment.roles(),
        },
        &known,
    )
    .map_err(|error| format!("skill provenance audit refused: {error}"))?;

    let text = serde_json::to_string(&report)
        .map_err(|error| format!("cannot serialize skill provenance audit: {error}"))?;
    Ok(json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": report
    }))
}

fn skill_audit_limit(arguments: &Value) -> Result<usize, String> {
    let object = arguments
        .as_object()
        .ok_or_else(|| "audit.provenance arguments must be an object".to_string())?;
    if let Some(unexpected) = object.keys().find(|key| key.as_str() != "limit") {
        return Err(format!(
            "audit.provenance does not accept argument {unexpected:?}"
        ));
    }
    match object.get("limit") {
        None => Ok(DEFAULT_AUDIT_LIMIT),
        Some(value) => {
            let limit = value
                .as_u64()
                .ok_or_else(|| "audit.provenance limit must be an integer".to_string())?;
            if limit == 0 || limit > MAX_AUDIT_LIMIT as u64 {
                return Err(format!(
                    "audit.provenance limit must be within 1..={MAX_AUDIT_LIMIT}"
                ));
            }
            Ok(limit as usize)
        }
    }
}

/// The permission string the runtime's role book must contain for the audit.
///
/// The permission name is `audit.provenance`; its `Permission` form is
/// re-exported here so the server never has to spell the string twice.
pub fn skill_audit_permission() -> Permission {
    Permission(SKILL_AUDIT_PERMISSION.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ccos_enterprise_runtime::TenantState;

    #[test]
    fn input_is_bounded_and_closed() {
        assert_eq!(skill_audit_limit(&json!({})).unwrap(), DEFAULT_AUDIT_LIMIT);
        assert_eq!(skill_audit_limit(&json!({"limit": 1})).unwrap(), 1);
        assert_eq!(skill_audit_limit(&json!({"limit": 1024})).unwrap(), 1024);
        for invalid in [
            json!({"limit": 0}),
            json!({"limit": 1025}),
            json!({"limit": 1.5}),
            json!({"limit": "32"}),
            json!({"skill_id": "x"}),
        ] {
            assert!(skill_audit_limit(&invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn capability_is_read_only_and_distinct_from_skill_read() {
        assert_eq!(
            skill_audit_permission_for(SKILL_AUDIT_TOOL),
            Some(SKILL_AUDIT_PERMISSION)
        );
        assert_eq!(skill_audit_permission_for("memory.skills"), None);
        let spec = skill_audit_tool_spec();
        assert_eq!(spec["name"], SKILL_AUDIT_TOOL);
        assert_eq!(spec["inputSchema"]["additionalProperties"], false);
        // The audit permission is not the model-visible read permission.
        assert_ne!(SKILL_AUDIT_PERMISSION, "memory.read");
    }

    #[test]
    fn empty_tenant_is_an_explicit_empty_report() {
        let mut d = Deployment::new();
        d.add_role("reader", &["memory.read"]);
        let mut t = TenantState::new(100);
        t.allow_model("claude-opus");
        d.add_tenant("memorithm", "acme", t);
        d.assign("operator", "reader");
        let skills = SkillRegistry::new(ccos_enterprise_skills::SkillConfig::default()).unwrap();
        let trials =
            SkillTrialRegistry::new(ccos_enterprise_skills::SkillTrialConfig::default()).unwrap();
        // The deployment role book lacks audit.provenance, so this must be a
        // permission refusal before any ledger material is read.
        let err = skill_audit_result(&d, "operator", "acme", &skills, &trials, &json!({}))
            .expect_err("permission is deny by default");
        assert!(err.contains("refused"), "{err}");
        // Grant the audit permission and the same call reports the empty
        // tenant as a fact.
        d.add_role("auditor", &["audit.provenance"]);
        d.assign("operator", "auditor");
        let report = skill_audit_result(&d, "operator", "acme", &skills, &trials, &json!({}))
            .expect("granted audit reports");
        assert_eq!(report["structuredContent"]["empty"], true);
        assert_eq!(report["structuredContent"]["tenant"], "acme");
    }
}
