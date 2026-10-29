//! Enterprise-local governed **text** recall over [`GovernedDocumentMemory`].
//!
//! `memory.context` takes a client embedding and goes through
//! [`GovernedSemanticMemoryProvider`](ccos_enterprise_memory::GovernedSemanticMemoryProvider).
//! `GovernedDocumentMemory` ranks from query *text* (BM25 by default, dense/fused only when the
//! deployment injects an encoder), so it is deliberately **not** forced behind that
//! embedding-shaped trait. This module is the dedicated text adapter, with the same order of
//! security checks as [`crate::served_context`]:
//!
//! 1. `Deployment::admit` (RBAC, tenancy, quota) — only in [`serve_document_recall`];
//! 2. admitted tenant must equal the governance projection tenant, before any index access;
//! 3. spaces come from the projection's bootstrap loadout, never from the client;
//! 4. index output passes `admit_governed_recall` (unknown asset, relabelled space, lineage,
//!    trust policy) and is then item/byte bounded by the context budget.
//!
//! Scores are ordering data only. The index is in-memory and derived: the stdio server rebuilds
//! it (lexical-only) from the selected provider generation's governed assets at boot and after
//! each new generation (`RecoveredGovernedMemory::rebuild_document_index`).

use std::fmt;

use ccos_core::retrieval::Encoder;
use ccos_enterprise_docmemory::{
    DocumentMemoryError, DocumentRecallQuery, GovernedDocumentMemory, IngestScorer,
};
use ccos_enterprise_memory::{
    admit_governed_recall, assemble_governed_bootstrap_context, attest_governed_context,
    GovernedMemoryContextAssembly, GovernedMemoryProjection, GovernedRecallGate,
    GovernedRecallGateError, GovernedRecallTrustPolicy, MemoryContextBudget, MemoryContextError,
    MemoryLoadoutPlanError, MemorySpace,
};
use ccos_enterprise_runtime::{Call, Deployment, Outcome};
use ccos_enterprise_tenancy::{TenantId, TenantScope};
use serde_json::{json, Value};

pub const GOVERNED_DOCUMENT_RECALL_TOOL: &str = "memory.document_recall";
pub const GOVERNED_DOCUMENT_RECALL_PERMISSION: &str = "memory.read";

const MAX_QUERY_BYTES: usize = 8192;
const MAX_K: u64 = 256;

pub fn govern_governed_document_recall(deployment: &mut Deployment) {
    deployment.govern_tool(
        GOVERNED_DOCUMENT_RECALL_TOOL,
        GOVERNED_DOCUMENT_RECALL_PERMISSION,
    );
}

/// MCP schema. The client supplies only text and ceilings: no spaces, no tenant, no policy.
pub fn governed_document_recall_tool_spec() -> Value {
    json!({
        "name": GOVERNED_DOCUMENT_RECALL_TOOL,
        "description": "Text recall over tenant-governed DocumentMemory (lexical BM25 by default). Spaces come from the durable bootstrap loadout; results must pass governed recall admission (verified assets only); scores never grant authority.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": false,
            "required": ["query"],
            "properties": {
                "query": { "type": "string", "minLength": 1, "maxLength": MAX_QUERY_BYTES },
                "k": { "type": "integer", "minimum": 1, "maximum": MAX_K },
                "context_max_items": { "type": "integer", "minimum": 1, "maximum": 256 },
                "context_max_payload_bytes": { "type": "integer", "minimum": 1, "maximum": 4194304 }
            }
        }
    })
}

#[derive(Debug)]
pub enum DocumentRecallError {
    InvalidArguments(String),
    /// The front door refused the call; nothing was read.
    Refused(String),
    /// Same tenant/request_id already executed; the read is not repeated.
    Replayed,
    Loadout(MemoryLoadoutPlanError),
    NoBootstrapLoadout,
    Index(DocumentMemoryError),
    RecallAdmission(GovernedRecallGateError),
    Context(MemoryContextError),
}

impl fmt::Display for DocumentRecallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArguments(e) => {
                write!(f, "invalid {GOVERNED_DOCUMENT_RECALL_TOOL} arguments: {e}")
            }
            Self::Refused(e) => write!(f, "request refused: {e}"),
            Self::Replayed => f.write_str("request already executed (replay not repeated)"),
            Self::Loadout(e) => write!(f, "invalid governed memory loadout: {e}"),
            Self::NoBootstrapLoadout => {
                f.write_str("governed memory loadout has no bootstrap-enabled space")
            }
            Self::Index(e) => write!(f, "document recall failed: {e}"),
            Self::RecallAdmission(e) => write!(f, "governed recall admission failed: {e}"),
            Self::Context(e) => write!(f, "governed context assembly failed: {e}"),
        }
    }
}

impl std::error::Error for DocumentRecallError {}

/// Parsed, bounded tool arguments.
#[derive(Debug, Clone)]
pub struct DocumentRecallArguments {
    pub query: String,
    pub k: usize,
    pub context_budget: MemoryContextBudget,
}

pub fn parse_document_recall_arguments(
    arguments: &Value,
) -> Result<DocumentRecallArguments, DocumentRecallError> {
    let bad = |m: &str| DocumentRecallError::InvalidArguments(m.to_string());
    let object = arguments
        .as_object()
        .ok_or_else(|| bad("arguments must be an object"))?;
    const ALLOWED: &[&str] = &[
        "query",
        "k",
        "context_max_items",
        "context_max_payload_bytes",
    ];
    if object.keys().any(|k| !ALLOWED.contains(&k.as_str())) {
        return Err(bad("unknown argument"));
    }
    let query = object
        .get("query")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("query must be a string"))?;
    if query.trim().is_empty() || query.len() > MAX_QUERY_BYTES {
        return Err(bad("query must be non-blank and at most 8192 bytes"));
    }
    let get = |name: &str, default: u64, max: u64| -> Result<usize, DocumentRecallError> {
        match object.get(name) {
            None => Ok(default as usize),
            Some(v) => v
                .as_u64()
                .filter(|n| (1..=max).contains(n))
                .map(|n| n as usize)
                .ok_or_else(|| bad(&format!("{name} must be an integer in 1..={max}"))),
        }
    };
    let k = get("k", 8, MAX_K)?;
    let items = get("context_max_items", 8, 256)?;
    let bytes = get("context_max_payload_bytes", 64 * 1024, 4_194_304)?;
    Ok(DocumentRecallArguments {
        query: query.to_string(),
        k,
        context_budget: MemoryContextBudget::new(items, bytes)
            .map_err(|e| DocumentRecallError::InvalidArguments(e.to_string()))?,
    })
}

/// Recall + admission + bounded assembly, for an already admitted tenant.
///
/// Performs no RBAC itself: callers outside [`serve_document_recall`] must have crossed
/// `Deployment::admit` first.
pub fn recall_governed_documents<E: Encoder, F: Fn() -> E, S: IngestScorer>(
    memory: &mut GovernedDocumentMemory<E, F, S>,
    expected_tenant: &TenantId,
    projection: &GovernedMemoryProjection,
    policy: GovernedRecallTrustPolicy,
    query: &str,
    k: usize,
    context_budget: MemoryContextBudget,
) -> Result<GovernedMemoryContextAssembly, DocumentRecallError> {
    // Tenant check precedes any index access.
    if expected_tenant != &projection.tenant {
        return Err(DocumentRecallError::RecallAdmission(
            GovernedRecallGateError::TenantMismatch {
                expected: expected_tenant.as_str().to_string(),
                found: projection.tenant.as_str().to_string(),
            },
        ));
    }
    let loadout = projection
        .loadout
        .bootstrap_loadout()
        .map_err(DocumentRecallError::Loadout)?
        .ok_or(DocumentRecallError::NoBootstrapLoadout)?;
    let observations = memory
        .recall_documents(TenantScope::new(
            expected_tenant.clone(),
            DocumentRecallQuery {
                text: query,
                k,
                loadout: &loadout,
            },
        ))
        .map_err(DocumentRecallError::Index)?;
    let admitted = admit_governed_recall(
        GovernedRecallGate {
            expected_tenant,
            projection,
            policy,
        },
        observations,
    )
    .map_err(DocumentRecallError::RecallAdmission)?;
    assemble_governed_bootstrap_context(projection, admitted, context_budget)
        .map_err(DocumentRecallError::Context)
}

/// Full served path: front door, then verified-only governed text recall, then MCP result.
///
/// The trust policy is fixed to `VerifiedOnly` (same as `memory.context`), not client-controlled.
pub fn serve_document_recall<E: Encoder, F: Fn() -> E, S: IngestScorer>(
    deployment: &mut Deployment,
    call: Call<'_>,
    memory: &mut GovernedDocumentMemory<E, F, S>,
    projection: &GovernedMemoryProjection,
    arguments: &Value,
) -> Result<Value, DocumentRecallError> {
    if call.request.tool != GOVERNED_DOCUMENT_RECALL_TOOL {
        return Err(DocumentRecallError::InvalidArguments(
            "request tool is not memory.document_recall".into(),
        ));
    }
    let parsed = parse_document_recall_arguments(arguments)?;
    let request_tenant = call.request.tenant.clone();
    match deployment.admit(call) {
        Outcome::Forwarded => {}
        Outcome::Replayed => return Err(DocumentRecallError::Replayed),
        Outcome::Refused(r) => return Err(DocumentRecallError::Refused(format!("{r:?}"))),
    }
    let tenant = TenantId::validated(&request_tenant)
        .ok_or_else(|| DocumentRecallError::Refused("admitted tenant is not canonical".into()))?;
    let assembly = recall_governed_documents(
        memory,
        &tenant,
        projection,
        GovernedRecallTrustPolicy::VerifiedOnly,
        &parsed.query,
        parsed.k,
        parsed.context_budget,
    )?;
    Ok(document_recall_result(&assembly))
}

/// MCP `tools/call` result shape (content + structuredContent).
pub fn document_recall_result(assembly: &GovernedMemoryContextAssembly) -> Value {
    let attestations = attest_governed_context(assembly);
    let items: Vec<Value> = assembly
        .chunks()
        .iter()
        .zip(attestations.iter())
        .map(|(chunk, a)| {
            json!({
                "asset_id": chunk.asset_id.as_str(),
                "space": space_label(&chunk.space),
                "score": chunk.similarity,
                "text": String::from_utf8_lossy(&chunk.payload),
                "payload_sha256": a.payload_sha256,
                "projection_sha256": a.projection_sha256,
                "parents": a.parents.iter().map(|id| id.as_str()).collect::<Vec<_>>(),
                "evidence": a.evidence.iter().map(|e| e.as_str()).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({
        "content": [{
            "type": "text",
            "text": format!("CCOS Enterprise recalled {} governed document(s)", items.len())
        }],
        "structuredContent": {
            "tool": GOVERNED_DOCUMENT_RECALL_TOOL,
            "trust_policy": "verified_only",
            "tenant": assembly.tenant().as_str(),
            "projection_version": assembly.projection_version(),
            "projection_sha256": assembly.projection_sha256_hex(),
            "payload_bytes": assembly.payload_bytes(),
            "items": items
        }
    })
}

fn space_label(space: &MemorySpace) -> String {
    match space {
        MemorySpace::Tenant => "tenant".into(),
        MemorySpace::Project(id) => format!("project:{id}"),
        MemorySpace::Team(id) => format!("team:{id}"),
        MemorySpace::Agent(id) => format!("agent:{id}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ccos_enterprise_gateway::{classify, Disposition, GatewayRequest};

    #[test]
    fn tool_crosses_gateway_under_memory_namespace() {
        let request = GatewayRequest {
            tenant: "acme".into(),
            actor: "alice".into(),
            tool: GOVERNED_DOCUMENT_RECALL_TOOL.into(),
            request_id: "d-1".into(),
        };
        assert_eq!(classify(&request), Disposition::Forward);
    }

    #[test]
    fn arguments_are_closed_and_bounded() {
        assert!(parse_document_recall_arguments(&json!({"query":"x"})).is_ok());
        for bad in [
            json!({}),
            json!({"query":"  "}),
            json!({"query":"x","space":"project:p"}),
            json!({"query":"x","k":0}),
            json!({"query":"x","k":100000}),
            json!({"query":"x","tenant":"globex"}),
        ] {
            assert!(parse_document_recall_arguments(&bad).is_err(), "{bad}");
        }
    }
}
