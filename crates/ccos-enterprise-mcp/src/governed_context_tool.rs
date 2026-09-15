//! Enterprise-local served governed-context capability.
//!
//! This tool is intentionally not a Core translation. `memory.recall` keeps its
//! historical Core contract; `memory.context` is the explicit Enterprise path
//! that uses reconstructed provider data plus Enterprise governance.

use ccos_enterprise_runtime::Deployment;
use serde_json::{json, Value};

pub const GOVERNED_CONTEXT_TOOL: &str = "memory.context";
pub const GOVERNED_CONTEXT_PERMISSION: &str = "memory.read";

pub fn govern_governed_context(deployment: &mut Deployment) {
    deployment.govern_tool(GOVERNED_CONTEXT_TOOL, GOVERNED_CONTEXT_PERMISSION);
}

/// MCP schema for the read-only governed context tool.
///
/// The caller supplies only an embedding and optional resource ceilings. Memory
/// spaces and trust policy are not client-controlled: the server derives the
/// bootstrap loadout from durable governance and requires verified assets.
pub fn governed_context_tool_spec() -> Value {
    json!({
        "name": GOVERNED_CONTEXT_TOOL,
        "description": "Retrieve verified, tenant-governed semantic memory as a bounded structured context. Spaces come from the durable bootstrap loadout; similarity never grants authority.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": false,
            "required": ["embedding"],
            "properties": {
                "embedding": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 8192,
                    "items": { "type": "number" }
                },
                "recall_max_items": { "type": "integer", "minimum": 1, "maximum": 1024 },
                "recall_max_shortlist": { "type": "integer", "minimum": 1, "maximum": 8192 },
                "recall_max_payload_bytes": { "type": "integer", "minimum": 1, "maximum": 16777216 },
                "context_max_items": { "type": "integer", "minimum": 1, "maximum": 256 },
                "context_max_payload_bytes": { "type": "integer", "minimum": 1, "maximum": 4194304 }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ccos_enterprise_auth::AuthStrength;
    use ccos_enterprise_gateway::{classify, Disposition, GatewayRequest};
    use ccos_enterprise_runtime::{actor, request, Call, Outcome, TenantState};

    #[test]
    fn capability_crosses_gateway_only_under_the_existing_memory_namespace() {
        let request = GatewayRequest {
            tenant: "acme".into(),
            actor: "alice".into(),
            tool: GOVERNED_CONTEXT_TOOL.into(),
            request_id: "context-1".into(),
        };
        assert_eq!(classify(&request), Disposition::Forward);
    }

    #[test]
    fn capability_uses_existing_memory_read_permission() {
        let mut deployment = Deployment::new();
        deployment.add_role("reader", &[GOVERNED_CONTEXT_PERMISSION]);
        govern_governed_context(&mut deployment);
        let mut tenant = TenantState::new(100);
        tenant.allow_model("model");
        deployment.add_tenant("memorithm", "acme", tenant);
        deployment.assign("memorithm", "alice", "reader");
        let identity = actor("memorithm", "alice", AuthStrength::Token);
        let request = request("acme", "alice", GOVERNED_CONTEXT_TOOL, "context-1");
        assert!(matches!(
            deployment.admit(Call {
                actor: &identity,
                request: &request,
                model: "model",
                cost_tokens: 1,
                variant: None,
                justification: None,
            }),
            Outcome::Forwarded
        ));
    }
}
