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

/// Decision Intelligence is deliberately an exact allowlist, not an open
/// `decision.` namespace. A future sibling must be reviewed and added here
/// explicitly before the gateway can forward it.
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
/// **Deny by default**, matching the posture of every other gate in the
/// product (unknown roles grant nothing; unlisted models are denied): a tool
/// traverses only if it is in [`ALLOWED_PREFIXES`], [`ALLOWED_TOOLS`] or the
/// exact [`DECISION_TOOLS`] list. The refusals are distinguishable on purpose —
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
    if !is_canonical_tool_name(&req.tool) {
        return Disposition::Reject("tool name is empty or not canonical".into());
    }
    let lowered = req.tool.to_ascii_lowercase();
    // Match the forbidden lists at EVERY segment boundary, not only at byte 0.
    //
    // Anchoring both checks at the start of the name let an exposed prefix
    // launder every forbidden capability: `ccos.shell.exec` does not begin
    // with `shell.`, so it escaped the boundary, and it does begin with
    // `ccos.`, so the catalogue admitted it. 121 spellings forwarded, and on
    // the composed path a read-only actor reached `shell.exec` for real
    // budget with no boundary counter moving. A forbidden capability must be
    // refused wherever it appears in the name, not only when it is the head.
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

/// A canonical tool name: one or more dot-separated segments of
/// `[a-z0-9_]`, ASCII only, no empty segment, no leading or trailing dot.
///
/// Deliberately narrow, and that narrowness is the point. Path separators,
/// command separators, zero-width joiners, RTL overrides, homoglyphs and
/// trailing dots are all ways of writing a forbidden capability that some
/// downstream router might normalize back — `memory.recall/../shell.exec`
/// and `policy.set;shell.exec` were both forwarded before this existed. A
/// name the boundary cannot read unambiguously is not classified: it is
/// refused.
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

/// Every suffix of `name` that begins at a segment boundary, longest first:
/// `a.b.c` yields `a.b.c`, `b.c`, `c`.
fn segment_suffixes(name: &str) -> impl Iterator<Item = &str> {
    std::iter::once(name).chain(name.match_indices('.').map(|(i, _)| &name[i + 1..]))
}

/// Longest tool name the boundary will even look at. A canonical name is a
/// few dozen bytes; anything larger is a probe, and refusing it early keeps
/// megabyte-scale names out of refusal messages and audit records.
const MAX_TOOL_NAME_BYTES: usize = 256;

/// Render a rejected name safe to put in a message that will be logged.
///
/// The refusal embedded the caller's string verbatim, so a name containing
/// newlines or ANSI escapes could forge log lines. Canonical names never
/// reach this (they are ASCII by construction), but non-canonical ones are
/// exactly the hostile case.
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

    fn req(tool: &str, request_id: &str) -> GatewayRequest {
        GatewayRequest {
            tenant: "acme".into(),
            actor: "agent-1".into(),
            tool: tool.into(),
            request_id: request_id.into(),
        }
    }

    #[test]
    fn research_namespaces_never_traverse() {
        assert_eq!(classify(&req("ccos.recall", "r-1")), Disposition::Forward);
        assert!(matches!(
            classify(&req("rsi.status", "r-1")),
            Disposition::Reject(_)
        ));
        assert!(matches!(
            classify(&req("forge.run", "r-1")),
            Disposition::Reject(_)
        ));
    }

    #[test]
    fn boundary_rejects_non_canonical_spellings() {
        // Case variants of a forbidden namespace never traverse.
        for t in ["RSI.status", "Rsi.status", "FORGE.run", "Slha.q", "OCTA.x"] {
            assert!(
                matches!(classify(&req(t, "r-2")), Disposition::Reject(_)),
                "{t}"
            );
        }
        // Empty, padded and control-byte names are not classifiable → reject.
        for t in ["", " rsi.status", "rsi .status", "ccos.\trecall", "a\nb"] {
            assert!(
                matches!(classify(&req(t, "r-2")), Disposition::Reject(_)),
                "{t:?}"
            );
        }
        // Catalogue names are untouched, including the `ccos.` alias and exact decision tools.
        for t in [
            "ccos.recall",
            "ccos.qpage.read",
            "memory.recall",
            "system.health",
            "decision.get",
            "decision.record",
        ] {
            assert_eq!(classify(&req(t, "r-2")), Disposition::Forward, "{t}");
        }
    }

    #[test]
    fn decision_surface_is_exact_not_prefix_open() {
        for tool in DECISION_TOOLS {
            assert_eq!(
                classify(&req(tool, "r-decision")),
                Disposition::Forward,
                "{tool}"
            );
        }
        for tool in [
            "decision.future",
            "decision.delete",
            "decision.execute",
            "decision.record.extra",
        ] {
            let Disposition::Reject(why) = classify(&req(tool, "r-decision")) else {
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
        // Deny by default: merely sharing letters with a namespace, forbidden
        // or exposed, does not put a tool in the catalogue.
        for t in ["forget.nothing", "octant", "memoryleak", "systemhealth"] {
            let Disposition::Reject(why) = classify(&req(t, "r-3")) else {
                panic!("{t} is not in the catalogue and must not traverse");
            };
            assert!(
                why.contains("not in the Enterprise catalogue"),
                "{t}: {why}"
            );
        }
        // …and an omission still reads differently from a violation.
        let Disposition::Reject(why) = classify(&req("shell.exec", "r-3")) else {
            panic!("forbidden tools never traverse");
        };
        assert!(why.contains("outside the Enterprise boundary"), "{why}");
    }
}
