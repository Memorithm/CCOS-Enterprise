//! Enterprise-local direct-evidence write capability.
//!
//! This is not Core `memory.ingest` and never fabricates semantic vectors from
//! source text. The admitted caller supplies a stable asset id, one opaque
//! evidence reference, the already-produced embedding, and payload bytes. The
//! server fixes space=`Tenant`, stratum=`Evidence`, and trust=`Unverified`.

use ccos_enterprise_runtime::Deployment;
use serde_json::{json, Value};

pub const GOVERNED_EVIDENCE_WRITE_TOOL: &str = "memory.evidence.write";
pub const GOVERNED_EVIDENCE_WRITE_PERMISSION: &str = "memory.write";

pub fn govern_governed_evidence_write(deployment: &mut Deployment) {
    deployment.govern_tool(
        GOVERNED_EVIDENCE_WRITE_TOOL,
        GOVERNED_EVIDENCE_WRITE_PERMISSION,
    );
}

/// MCP schema for one direct governed evidence write.
///
/// Space, stratum, trust state, parents and loadout are intentionally absent.
/// `evidence_ref` is an opaque provenance pointer, not a verification claim.
pub fn governed_evidence_write_tool_spec() -> Value {
    json!({
        "name": GOVERNED_EVIDENCE_WRITE_TOOL,
        "description": "Append one tenant-scoped direct evidence asset to governed semantic memory. The server fixes the asset as unverified Evidence; this call does not promote trust.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": false,
            "required": ["asset_id", "evidence_ref", "embedding", "payload_bytes"],
            "properties": {
                "asset_id": { "type": "string", "minLength": 1, "maxLength": 4096 },
                "evidence_ref": { "type": "string", "minLength": 1, "maxLength": 4096 },
                "embedding": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 8192,
                    "items": { "type": "number" }
                },
                "payload_bytes": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 1048576,
                    "items": { "type": "integer", "minimum": 0, "maximum": 255 }
                }
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
    fn write_capability_stays_inside_the_governed_memory_namespace() {
        let request = GatewayRequest {
            tenant: "acme".into(),
            actor: "alice".into(),
            tool: GOVERNED_EVIDENCE_WRITE_TOOL.into(),
            request_id: "write-1".into(),
        };
        assert_eq!(classify(&request), Disposition::Forward);
    }

    #[test]
    fn write_capability_requires_existing_memory_write_permission() {
        let mut deployment = Deployment::new();
        deployment.add_role("writer", &[GOVERNED_EVIDENCE_WRITE_PERMISSION]);
        govern_governed_evidence_write(&mut deployment);
        let mut tenant = TenantState::new(100);
        tenant.allow_model("model");
        deployment.add_tenant("memorithm", "acme", tenant);
        deployment.assign("memorithm", "alice", "writer");
        let identity = actor("memorithm", "alice", AuthStrength::Token);
        let request = request("acme", "alice", GOVERNED_EVIDENCE_WRITE_TOOL, "write-1");
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

    #[test]
    fn schema_exposes_no_client_controlled_authority_fields() {
        let spec = governed_evidence_write_tool_spec();
        let properties = spec["inputSchema"]["properties"].as_object().unwrap();
        for forbidden in ["space", "stratum", "trust", "parents", "loadout"] {
            assert!(!properties.contains_key(forbidden));
        }
    }
}
