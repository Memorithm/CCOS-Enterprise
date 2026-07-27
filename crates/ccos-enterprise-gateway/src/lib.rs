//! # CCOS Enterprise — Gateway
//!
//! The secure MCP front door: tenant resolution, authn/z enforcement and
//! request routing toward `ccos-core` (docs/HERMES_INTEGRATION.md,
//! docs/OPENCLAW_INTEGRATION.md). Foundation slice: the request context every
//! gateway decision is computed from.

use serde::{Deserialize, Serialize};

/// An inbound MCP request, fully qualified before any dispatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayRequest {
    pub tenant: String,
    pub actor: String,
    pub tool: String,
    /// Idempotency/correlation key for audit joins.
    pub request_id: String,
}

/// Gateway disposition for a fully qualified request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Disposition {
    Forward,
    Reject(String),
}

/// Namespace policy: Core tools (`ccos.*`) are forwardable; anything
/// experimental (`rsi.*`, `forge.*`, `slha.*`, `octa.*`) is rejected at the
/// Enterprise boundary — Research Lab namespaces never traverse Enterprise.
pub fn classify(req: &GatewayRequest) -> Disposition {
    let forbidden = ["rsi.", "forge.", "slha.", "octa."];
    if forbidden.iter().any(|p| req.tool.starts_with(p)) {
        return Disposition::Reject(format!(
            "tool namespace '{}' is outside the Enterprise boundary",
            req.tool
        ));
    }
    Disposition::Forward
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn research_namespaces_never_traverse() {
        let req = |tool: &str| GatewayRequest {
            tenant: "acme".into(),
            actor: "agent-1".into(),
            tool: tool.into(),
            request_id: "r-1".into(),
        };
        assert_eq!(classify(&req("ccos.recall")), Disposition::Forward);
        assert!(matches!(
            classify(&req("rsi.status")),
            Disposition::Reject(_)
        ));
        assert!(matches!(
            classify(&req("forge.run")),
            Disposition::Reject(_)
        ));
    }
}
