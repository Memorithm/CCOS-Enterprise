//! # CCOS Enterprise — the governed MCP front door
//!
//! Core advertises **bare tool names** over MCP (`recall`, `ingest`,
//! `page_fault`, …) — 16 in a default build, plus `octa_feedback` when Core is
//! compiled with its `octasoma` feature. Enterprise governs **dotted capability
//! classes**
//! (`memory.recall`, `ccos.causal_flash`, …), because the gateway's boundary,
//! the RBAC permissions and the audit trail are all keyed on a namespace.
//! Until this crate, nothing connected the two: Core's catalogue was reachable
//! only by talking to Core directly — that is, by going *around* every gate
//! Enterprise exists to impose.
//!
//! Core's translation table remains a closed contract. Enterprise-local
//! capabilities such as Decision Intelligence live in a separate catalogue
//! (`decision`) and never masquerade as Core tools. Both paths still share the
//! one composed admission policy:
//! [`ccos_enterprise_runtime::Deployment::admit`].
//!
//! ## The table is the contract
//!
//! [`CATALOGUE`] maps each Core tool to exactly one Enterprise name, or marks
//! it deliberately outside the product boundary. Two properties make it worth
//! having, and both are tested:
//!
//! * it is **total** — `catalogue_covers_every_core_tool` asks a live
//!   `ccos_core` session for its `tools/list` and fails if Core has grown a
//!   tool this table does not mention. A capability that appears in Core and
//!   is silently unreachable through Enterprise is the failure mode this
//!   product cannot afford: the customer bought the governed edition of a
//!   thing, not a subset of it that drifts;
//! * it is **injective** — no two Core tools share an Enterprise name, so an
//!   audit record names exactly one capability.
//!
//! ## `octa_feedback`, and a trap worth naming
//!
//! One tool is mapped [`Disposition::OutsideBoundary`]:
//! [`OCTA_FEEDBACK`] is a stateful relevance-feedback channel whose labels
//! calibrate the conformal anchor gate that *future* recalls run through. In a
//! single-user Core session that is a feature. In a governed multi-tenant
//! deployment it is a per-call mutation of retrieval behaviour with no tenant
//! scoping, no permission and no audit shape — so it is excluded here until it
//! has all three, rather than exposed and hoped about.
//!
//! The trap: the gateway forbids the `octa.` **prefix**, and
//! `octa_feedback` does not have it — the underscore means
//! `FORBIDDEN_PREFIXES` never matches, so naming it `octa_feedback` or
//! `ccos.octa_feedback` would sail straight through the boundary check. The
//! exclusion here is therefore explicit data, not a side effect of the
//! namespace rules, and `the_excluded_tool_is_not_saved_by_the_prefix_rule`
//! pins exactly that.

pub mod decision;
pub mod server;
pub use decision::{
    decision_governance_map, decision_governed_names, govern_decision_catalogue, DecisionBackend,
    NoDecisionBackend,
};
pub use server::{govern_catalogue, AdvertisedTool, Backend, GovernedMcp, McpOutcome};

use std::collections::BTreeMap;

use ccos_enterprise_gateway::{classify, Disposition as GatewayDisposition};

/// The Core tool this crate deliberately does not expose. See the module docs.
pub const OCTA_FEEDBACK: &str = "octa_feedback";

/// How a Core tool is treated by the Enterprise front door.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Reachable, under this Enterprise capability name and permission.
    Governed {
        enterprise: &'static str,
        permission: &'static str,
    },
    /// Deliberately not exposed, for the stated reason.
    OutsideBoundary { why: &'static str },
}

/// One row of the translation table.
#[derive(Debug, Clone, Copy)]
pub struct CoreTool {
    /// The bare name Core advertises over MCP.
    pub core: &'static str,
    pub disposition: Disposition,
}

const fn governed(
    core: &'static str,
    enterprise: &'static str,
    permission: &'static str,
) -> CoreTool {
    CoreTool {
        core,
        disposition: Disposition::Governed {
            enterprise,
            permission,
        },
    }
}

/// Core's catalogue, translated.
///
/// The namespace choice is deliberate. `memory.*` for the primitives that read
/// or write the memory graph, `context.*` for the working-set assembly Hermes
/// consumes, and `ccos.*` for the causal and belief-revision family — which is
/// the product's distinguishing capability and reads better grouped than
/// scattered across `memory.*`. Every name here is in the gateway's allowlist
/// and canonical under its grammar; `every_governed_name_clears_the_boundary`
/// proves it rather than assuming it.
pub const CATALOGUE: &[CoreTool] = &[
    // ── Memory primitives ────────────────────────────────────────────────
    governed("recall", "memory.recall", "memory.read"),
    governed("recall_what_if", "memory.recall_what_if", "memory.read"),
    governed("get", "memory.get", "memory.read"),
    governed("stats", "memory.stats", "memory.read"),
    governed("timeline", "memory.timeline", "memory.read"),
    governed("verify", "memory.verify", "memory.read"),
    governed("ingest", "memory.ingest", "memory.write"),
    governed("page_fault", "memory.page_fault", "memory.write"),
    governed("sync", "memory.sync", "memory.write"),
    // ── Working-set assembly ─────────────────────────────────────────────
    governed("ccos_retrieve", "context.retrieve", "memory.read"),
    // ── Causal and belief revision ───────────────────────────────────────
    governed("causal_blame", "ccos.causal_blame", "memory.read"),
    governed("causal_flash", "ccos.causal_flash", "memory.read"),
    governed("drift_cause", "ccos.drift_cause", "memory.read"),
    governed("retrodict_belief", "ccos.retrodict_belief", "memory.read"),
    // `causal_intervene` and `signal_failure` change what later recalls
    // return, so they are writes however read-only their names sound.
    governed("causal_intervene", "ccos.causal_intervene", "memory.write"),
    governed("signal_failure", "ccos.signal_failure", "memory.write"),
    // ── Deliberately outside the boundary ────────────────────────────────
    CoreTool {
        core: OCTA_FEEDBACK,
        disposition: Disposition::OutsideBoundary {
            why: "stateful relevance feedback: it calibrates the gate future \
                  recalls run through, with no tenant scoping, no permission \
                  and no audit shape",
        },
    },
];

/// The Enterprise capability name for a Core tool, if it has one.
pub fn to_enterprise(core: &str) -> Option<&'static str> {
    match CATALOGUE.iter().find(|t| t.core == core)?.disposition {
        Disposition::Governed { enterprise, .. } => Some(enterprise),
        Disposition::OutsideBoundary { .. } => None,
    }
}

/// The Core tool an Enterprise capability name resolves to.
pub fn to_core(enterprise: &str) -> Option<&'static str> {
    CATALOGUE
        .iter()
        .find(|t| match t.disposition {
            Disposition::Governed { enterprise: e, .. } => e == enterprise,
            Disposition::OutsideBoundary { .. } => false,
        })
        .map(|t| t.core)
}

/// The permission a Core tool requires once governed.
pub fn permission_for(core: &str) -> Option<&'static str> {
    match CATALOGUE.iter().find(|t| t.core == core)?.disposition {
        Disposition::Governed { permission, .. } => Some(permission),
        Disposition::OutsideBoundary { .. } => None,
    }
}

/// Why a Core tool is not exposed, if it is not.
pub fn excluded_because(core: &str) -> Option<&'static str> {
    match CATALOGUE.iter().find(|t| t.core == core)?.disposition {
        Disposition::OutsideBoundary { why } => Some(why),
        Disposition::Governed { .. } => None,
    }
}

/// Every Enterprise capability this front door serves, in wire order.
pub fn governed_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = CATALOGUE
        .iter()
        .filter_map(|t| match t.disposition {
            Disposition::Governed { enterprise, .. } => Some(enterprise),
            Disposition::OutsideBoundary { .. } => None,
        })
        .collect();
    names.sort_unstable();
    names
}

/// The `tool -> permission` map a [`ccos_enterprise_runtime::Deployment`] needs
/// in order to govern this catalogue.
///
/// A deployment built from this is exhaustive by construction: every capability
/// the front door advertises has a declared permission, so none of them can
/// fall through to `ToolNotGoverned` by omission.
pub fn governance_map() -> BTreeMap<&'static str, &'static str> {
    CATALOGUE
        .iter()
        .filter_map(|t| match t.disposition {
            Disposition::Governed {
                enterprise,
                permission,
            } => Some((enterprise, permission)),
            Disposition::OutsideBoundary { .. } => None,
        })
        .collect()
}

/// Whether the gateway would admit this Enterprise name at all.
///
/// The front door never advertises a name the boundary would refuse: a
/// catalogue entry that cannot be called is worse than an absent one, because
/// it reads to a client as a permissions problem.
pub fn clears_the_boundary(enterprise: &str) -> bool {
    let request = ccos_enterprise_gateway::GatewayRequest {
        tenant: "t".into(),
        actor: "a".into(),
        tool: enterprise.into(),
        request_id: "r".into(),
    };
    matches!(classify(&request), GatewayDisposition::Forward)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn the_table_is_injective_and_every_core_name_appears_once() {
        let cores: BTreeSet<&str> = CATALOGUE.iter().map(|t| t.core).collect();
        assert_eq!(cores.len(), CATALOGUE.len(), "a Core tool is listed twice");
        let names = governed_names();
        let unique: BTreeSet<&str> = names.iter().copied().collect();
        assert_eq!(
            unique.len(),
            names.len(),
            "two Core tools share one Enterprise name, so an audit record \
             would not say which capability ran"
        );
    }

    #[test]
    fn translation_round_trips_both_ways() {
        for t in CATALOGUE {
            match t.disposition {
                Disposition::Governed { enterprise, .. } => {
                    assert_eq!(to_enterprise(t.core), Some(enterprise));
                    assert_eq!(to_core(enterprise), Some(t.core));
                }
                Disposition::OutsideBoundary { why } => {
                    assert_eq!(to_enterprise(t.core), None);
                    assert!(!why.is_empty(), "an exclusion must give its reason");
                }
            }
        }
        assert_eq!(to_enterprise("no_such_tool"), None);
        assert_eq!(to_core("memory.no_such_tool"), None);
    }

    #[test]
    fn every_governed_name_clears_the_boundary() {
        for name in governed_names() {
            assert!(
                clears_the_boundary(name),
                "the front door would advertise {name:?}, which the gateway refuses"
            );
        }
    }

    /// The trap named in the module docs, pinned. `octa_feedback` is excluded
    /// by **data**, not by the namespace rules: the gateway forbids the
    /// `octa.` prefix, and an underscore is not a dot, so every plausible
    /// spelling of this tool sails through `classify`. If the exclusion is
    /// ever removed from `CATALOGUE`, nothing else stops it.
    #[test]
    fn the_excluded_tool_is_not_saved_by_the_prefix_rule() {
        assert!(
            excluded_because(OCTA_FEEDBACK).is_some(),
            "the exclusion must be explicit data"
        );
        assert_eq!(to_enterprise(OCTA_FEEDBACK), None);

        // …and the boundary would NOT have caught it on its own.
        for spelling in ["ccos.octa_feedback", "memory.octa_feedback"] {
            assert!(
                clears_the_boundary(spelling),
                "if the gateway now refuses {spelling:?} this test can be \
                 tightened — but do not delete the catalogue exclusion, which \
                 is still the only thing that refuses the bare name"
            );
        }
    }

    #[test]
    fn the_governance_map_covers_every_advertised_capability() {
        let map = governance_map();
        assert_eq!(map.len(), governed_names().len());
        for name in governed_names() {
            assert!(
                map.contains_key(name),
                "{name} is advertised with no permission, so it would be \
                 refused as ungoverned"
            );
        }
        // Permissions are drawn from a small closed set on purpose: a
        // permission per tool is a permission nobody administers.
        let perms: BTreeSet<&str> = map.values().copied().collect();
        assert_eq!(
            perms,
            BTreeSet::from(["memory.read", "memory.write"]),
            "the permission vocabulary drifted"
        );
    }

    #[test]
    fn writes_are_classified_as_writes() {
        // The three that read as queries but change what later recalls return.
        for tool in ["causal_intervene", "signal_failure", "page_fault"] {
            assert_eq!(
                permission_for(tool),
                Some("memory.write"),
                "{tool} mutates retrieval state and must need a write grant"
            );
        }
        for tool in ["recall", "get", "stats", "causal_blame"] {
            assert_eq!(permission_for(tool), Some("memory.read"));
        }
    }
}
