//! Physical purge requires an explicit permission independent of normal writes.
use ccos_enterprise_runtime::Deployment;
use serde_json::{json, Value};

pub const GOVERNED_PURGE_TOOL: &str = "memory.purge";
pub const GOVERNED_PURGE_PERMISSION: &str = "memory.purge";
pub const GOVERNED_KEY_ROTATE_TOOL: &str = "memory.keys.rotate";
pub const GOVERNED_KEY_ROTATE_PERMISSION: &str = "memory.keys.rotate";

pub fn govern_governed_purge(deployment: &mut Deployment) {
    deployment.govern_tool(GOVERNED_PURGE_TOOL, GOVERNED_PURGE_PERMISSION);
    deployment.govern_tool(GOVERNED_KEY_ROTATE_TOOL, GOVERNED_KEY_ROTATE_PERMISSION);
}

pub fn governed_key_rotate_tool_spec() -> Value {
    json!({"name":GOVERNED_KEY_ROTATE_TOOL,
        "description":"Rewrap this tenant's encrypted provider artifacts to the operator-configured active key. Requires an explicit key-rotation permission.",
        "inputSchema":{"type":"object","additionalProperties":false,"properties":{}}})
}

pub fn governed_purge_tool_spec() -> Value {
    json!({
        "name": GOVERNED_PURGE_TOOL,
        "description": "Permanently remove the selected tenant asset and its derived descendants from the governed provider generations. Retains invalidated IDs and lineage metadata. Requires explicit purge permission.",
        "inputSchema": {
            "type": "object", "additionalProperties": false, "required": ["asset_id"],
            "properties": { "asset_id": { "type": "string", "minLength": 1, "maxLength": 4096 } }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ccos_enterprise_auth::AuthStrength;
    use ccos_enterprise_runtime::{actor, request, Call, Outcome, TenantState};

    #[test]
    fn ordinary_writer_cannot_purge_but_explicit_permission_can() {
        for (permission, allowed) in [("memory.write", false), (GOVERNED_PURGE_PERMISSION, true)] {
            let mut deployment = Deployment::new();
            deployment.add_role("role", &[permission]);
            govern_governed_purge(&mut deployment);
            let mut tenant = TenantState::new(100);
            tenant.allow_model("model");
            deployment.add_tenant("org", "acme", tenant);
            deployment.assign("org", "alice", "role");
            let identity = actor("org", "alice", AuthStrength::Token);
            let request = request("acme", "alice", GOVERNED_PURGE_TOOL, "purge-1");
            let outcome = deployment.admit(Call {
                actor: &identity,
                request: &request,
                model: "model",
                cost_tokens: 1,
                variant: None,
                justification: None,
            });
            assert_eq!(matches!(outcome, Outcome::Forwarded), allowed);
        }
    }
}
