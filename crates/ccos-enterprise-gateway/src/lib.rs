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

/// Namespaces that never traverse Enterprise, whatever the caller's privilege.
///
/// Two families, both named by the product documentation:
/// - Research Lab (`rsi.`, `forge.`, `slha.`, `octa.`) — outside the product
///   boundary entirely (README "Product boundary");
/// - capabilities this profile refuses outright (charter §4.2,
///   `docs/HERMES_INTEGRATION.md`): autonomous patch promotion — forbidden
///   (`patch.`); process execution — forbidden (`shell.`); self-modification
///   — forbidden (`self.`).
pub const FORBIDDEN_PREFIXES: &[&str] = &[
    "rsi.", "forge.", "slha.", "octa.", "patch.", "shell.", "self.",
];

/// Individually named tools outside the boundary, matched exactly.
/// `docs/HERMES_INTEGRATION.md` names these two precisely rather than whole
/// namespaces, so read-only siblings (`code.read`, `repository.read`) are
/// unaffected — widening them to prefixes would be a product decision, not a
/// boundary repair.
pub const FORBIDDEN_TOOLS: &[&str] = &["code.execute", "repository.modify"];

/// Namespace policy: Core tools (`ccos.*`, `memory.*`, `context.*`, `policy.*`,
/// `audit.*`, `system.health`) are forwardable; everything in
/// [`FORBIDDEN_PREFIXES`] or [`FORBIDDEN_TOOLS`] is rejected at the Enterprise
/// boundary, no matter how privileged the caller.
///
/// The check is deliberately defensive: a tool name that is empty or carries
/// whitespace/control bytes is not a canonical name and is rejected outright
/// (fail closed — the boundary never forwards what it cannot classify), and
/// matching is case-insensitive so `RSI.x` cannot slip past a case-normalizing
/// router downstream.
///
/// Note this remains a **deny**-list: an unrecognised tool is forwarded. The
/// documented catalogue (`docs/HERMES_INTEGRATION.md`) describes an allowlist
/// — turning this into one requires fixing the tool-naming convention first
/// (the docs say `memory.*`, this crate's examples say `ccos.*`, Core's MCP
/// server exposes bare `recall`/`ingest`), which is a product decision.
pub fn classify(req: &GatewayRequest) -> Disposition {
    if req.tool.is_empty()
        || req
            .tool
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return Disposition::Reject("tool name is empty or not canonical".into());
    }
    let lowered = req.tool.to_ascii_lowercase();
    let forbidden = FORBIDDEN_PREFIXES.iter().any(|p| lowered.starts_with(p))
        || FORBIDDEN_TOOLS.contains(&lowered.as_str());
    if forbidden {
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

    #[test]
    fn boundary_rejects_non_canonical_spellings() {
        let req = |tool: &str| GatewayRequest {
            tenant: "acme".into(),
            actor: "agent-1".into(),
            tool: tool.into(),
            request_id: "r-2".into(),
        };
        // Case variants of a forbidden namespace never traverse.
        for t in ["RSI.status", "Rsi.status", "FORGE.run", "Slha.q", "OCTA.x"] {
            assert!(matches!(classify(&req(t)), Disposition::Reject(_)), "{t}");
        }
        // Empty, padded and control-byte names are not classifiable → reject.
        for t in ["", " rsi.status", "rsi .status", "ccos.\trecall", "a\nb"] {
            assert!(matches!(classify(&req(t)), Disposition::Reject(_)), "{t:?}");
        }
        // Legitimate names are untouched — including ones that merely share
        // letters with a forbidden namespace without the dot boundary.
        for t in ["ccos.recall", "ccos.qpage.read", "forget.nothing", "octant"] {
            assert_eq!(classify(&req(t)), Disposition::Forward, "{t}");
        }
    }
}
