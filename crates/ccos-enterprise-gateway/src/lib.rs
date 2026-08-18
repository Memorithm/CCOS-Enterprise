//! # CCOS Enterprise — Gateway
//!
//! The secure MCP front door: tenant resolution, authn/z enforcement and
//! request routing toward governed Enterprise capabilities. Foundation slice:
//! the request context every gateway decision is computed from.

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
pub const FORBIDDEN_PREFIXES: &[&str] = &[
    "rsi.", "forge.", "slha.", "octa.", "patch.", "shell.", "self.",
];

/// Individually named tools outside the boundary, matched exactly.
pub const FORBIDDEN_TOOLS: &[&str] = &["code.execute", "repository.modify"];

/// Prefix-scoped capability classes. New sensitive families should not be added
/// here merely for convenience: a prefix implicitly exposes future siblings.
pub const ALLOWED_PREFIXES: &[&str] = &["memory.", "context.", "policy.", "audit.", "ccos."];

/// Individually exposed tools, matched exactly.
pub const ALLOWED_TOOLS: &[&str] = &["system.health"];

/// Decision Intelligence is intentionally **not** an open `decision.` namespace.
/// Every tool is named independently so adding a future mutation cannot widen the
/// gateway by accident.
pub const DECISION_TOOLS: &[&str] = &[
    "decision.ancestry",
    "decision.dependents",
    "decision.get",
    "decision.impact",
    "decision.regulatory_trail",
    "decision.similar",
    "decision.record",
    "decision.record_outcome",
];

/// Classify a fully qualified request against the Enterprise boundary.
///
/// Deny by default. Forbidden capabilities are checked first and at every segment
/// boundary; exposed capabilities then pass only by an allowed prefix or exact tool.
pub fn classify(req: &GatewayRequest) -> Disposition {
    if !is_canonical_tool_name(&req.tool) {
        return Disposition::Reject("tool name is empty or not canonical".into());
    }
    let lowered = req.tool.to_ascii_lowercase();
    let forbidden = segment_suffixes(&lowered).any(|suffix| {
        FORBIDDEN_PREFIXES.iter().any(|p| suffix.starts_with(p))
            || FORBIDDEN_TOOLS.contains(&suffix)
    });
    if forbidden {
        return Disposition::Reject(format!(
            "tool namespace '{}' is outside the Enterprise boundary",
            sanitize(&req.tool)
        ));
    }
    let exposed = ALLOWED_PREFIXES.iter().any(|p| lowered.starts_with(p))
        || ALLOWED_TOOLS.contains(&lowered.as_str())
        || DECISION_TOOLS.contains(&lowered.as_str());
    if !exposed {
        return Disposition::Reject(format!(
            "tool '{}' is not in the Enterprise catalogue",
            sanitize(&req.tool)
        ));
    }
    Disposition::Forward
}

/// A canonical tool name: one or more dot-separated segments of `[a-z0-9_]`,
/// ASCII only, no empty segment, no leading or trailing dot.
fn is_canonical_tool_name(tool: &str) -> bool {
    !tool.is_empty()
        && tool.len() <= MAX_TOOL_NAME_BYTES
        && tool.split('.').all(|segment| {
            !segment.is_empty()
                && segment.bytes().all(|b| {
                    b.is_ascii_lowercase()
                        || b.is_ascii_uppercase()
                        || b.is_ascii_digit()
                        || b == b'_'
                })
        })
}

/// Every suffix of `name` that begins at a segment boundary, longest first.
fn segment_suffixes(name: &str) -> impl Iterator<Item = &str> {
    std::iter::once(name).chain(name.match_indices('.').map(|(i, _)| &name[i + 1..]))
}

const MAX_TOOL_NAME_BYTES: usize = 256;

fn sanitize(tool: &str) -> String {
    const MAX: usize = 64;
    let mut out: String = tool
        .chars()
        .take(MAX)
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '\u{fffd}'
            }
        })
        .collect();
    if tool.chars().nth(MAX).is_some() {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(tool: &str) -> GatewayRequest {
        GatewayRequest {
            tenant: "acme".into(),
            actor: "agent-1".into(),
            tool: tool.into(),
            request_id: "r-1".into(),
        }
    }

    #[test]
    fn research_namespaces_never_traverse() {
        assert_eq!(classify(&req("ccos.recall")), Disposition::Forward);
        for tool in ["rsi.status", "forge.run", "slha.q", "octa.x"] {
            assert!(
                matches!(classify(&req(tool)), Disposition::Reject(_)),
                "{tool}"
            );
        }
    }

    #[test]
    fn boundary_rejects_non_canonical_spellings() {
        for tool in ["RSI.status", "Rsi.status", "FORGE.run", "Slha.q", "OCTA.x"] {
            assert!(
                matches!(classify(&req(tool)), Disposition::Reject(_)),
                "{tool}"
            );
        }
        for tool in ["", " rsi.status", "rsi .status", "ccos.\trecall", "a\nb"] {
            assert!(
                matches!(classify(&req(tool)), Disposition::Reject(_)),
                "{tool:?}"
            );
        }
        for tool in [
            "ccos.recall",
            "ccos.qpage.read",
            "memory.recall",
            "system.health",
            "decision.get",
            "decision.record",
        ] {
            assert_eq!(classify(&req(tool)), Disposition::Forward, "{tool}");
        }
    }

    #[test]
    fn decision_surface_is_exact_not_prefix_open() {
        for tool in DECISION_TOOLS {
            assert_eq!(classify(&req(tool)), Disposition::Forward, "{tool}");
        }
        for tool in [
            "decision.future",
            "decision.delete",
            "decision.execute",
            "decision.record.extra",
        ] {
            let Disposition::Reject(why) = classify(&req(tool)) else {
                panic!("unlisted decision capability {tool} traversed");
            };
            assert!(
                why.contains("not in the Enterprise catalogue"),
                "{tool}: {why}"
            );
        }
    }

    #[test]
    fn unlisted_tools_are_refused_but_not_as_boundary_violations() {
        for tool in ["forget.nothing", "octant", "memoryleak", "systemhealth"] {
            let Disposition::Reject(why) = classify(&req(tool)) else {
                panic!("{tool} is not in the catalogue and must not traverse");
            };
            assert!(
                why.contains("not in the Enterprise catalogue"),
                "{tool}: {why}"
            );
        }
        let Disposition::Reject(why) = classify(&req("shell.exec")) else {
            panic!("forbidden tools never traverse");
        };
        assert!(why.contains("outside the Enterprise boundary"), "{why}");
    }
}
