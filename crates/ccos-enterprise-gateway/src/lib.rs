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
/// namespaces, so a sibling like `code.read` is not a boundary *violation* —
/// it is simply not in the exposed catalogue, and [`classify`] says so with a
/// different refusal. Widening these to whole namespaces would be a product
/// decision, not a boundary repair.
pub const FORBIDDEN_TOOLS: &[&str] = &["code.execute", "repository.modify"];

/// The **exposed catalogue**: the tool classes Enterprise offers toward Core
/// (`docs/HERMES_INTEGRATION.md`). Anything not named here does not traverse.
///
/// Names are **capability classes**, not provenance: the prefix says what a
/// tool touches, which is what the authorization layer keys permissions on
/// (`memory.recall` needs `memory.read`). Core itself exposes bare
/// `recall`/`ingest` over MCP, so the gateway is deliberately a translation
/// boundary — that is what lets Enterprise pin its surface, so a Core upgrade
/// cannot widen it silently.
///
/// `ccos.` is kept as an accepted alias for the catalogue this crate shipped
/// with, so nothing that already speaks it breaks; class names are canonical
/// for anything new.
pub const ALLOWED_PREFIXES: &[&str] = &["memory.", "context.", "policy.", "audit.", "ccos."];

/// Individually exposed tools, matched exactly — `system.health` is one tool,
/// not an open `system.` namespace.
pub const ALLOWED_TOOLS: &[&str] = &["system.health"];

/// Classify a fully qualified request against the Enterprise boundary.
///
/// **Deny by default**, matching the posture of every other gate in the
/// product (unknown roles grant nothing; unlisted models are denied): a tool
/// traverses only if it is in [`ALLOWED_PREFIXES`] or [`ALLOWED_TOOLS`].
/// The refusals are distinguishable on purpose —
///
/// - *outside the Enterprise boundary* — [`FORBIDDEN_PREFIXES`] /
///   [`FORBIDDEN_TOOLS`]: a capability the product must never carry, checked
///   first so it is reported as a boundary violation even if some future
///   catalogue edit were to also match it;
/// - *not in the Enterprise catalogue* — merely unlisted: unknown, perhaps a
///   Core tool nobody has exposed yet. Refused just as firmly, but it is an
///   omission, not a violation, and an operator reading the audit trail
///   should be able to tell the two apart.
///
/// The check is deliberately defensive: a tool name that is empty or carries
/// whitespace/control bytes is not a canonical name and is rejected outright
/// (fail closed — the boundary never forwards what it cannot classify), and
/// matching is case-insensitive so `RSI.x` cannot slip past a case-normalizing
/// router downstream.
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
    let exposed = ALLOWED_PREFIXES.iter().any(|p| lowered.starts_with(p))
        || ALLOWED_TOOLS.contains(&lowered.as_str());
    if !exposed {
        return Disposition::Reject(format!(
            "tool '{}' is not in the Enterprise catalogue",
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
        // Catalogue names are untouched, including the `ccos.` alias.
        for t in [
            "ccos.recall",
            "ccos.qpage.read",
            "memory.recall",
            "system.health",
        ] {
            assert_eq!(classify(&req(t)), Disposition::Forward, "{t}");
        }
    }

    #[test]
    fn unlisted_tools_are_refused_but_not_as_boundary_violations() {
        let req = |tool: &str| GatewayRequest {
            tenant: "acme".into(),
            actor: "agent-1".into(),
            tool: tool.into(),
            request_id: "r-3".into(),
        };
        // Deny by default: merely sharing letters with a namespace, forbidden
        // or exposed, does not put a tool in the catalogue.
        for t in ["forget.nothing", "octant", "memoryleak", "systemhealth"] {
            let Disposition::Reject(why) = classify(&req(t)) else {
                panic!("{t} is not in the catalogue and must not traverse");
            };
            assert!(
                why.contains("not in the Enterprise catalogue"),
                "{t}: {why}"
            );
        }
        // …and an omission still reads differently from a violation.
        let Disposition::Reject(why) = classify(&req("shell.exec")) else {
            panic!("forbidden tools never traverse");
        };
        assert!(why.contains("outside the Enterprise boundary"), "{why}");
    }
}
