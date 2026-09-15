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
pub mod governed_context_tool;
pub mod governed_evidence_tool;
pub mod served_context;
pub mod server;
pub mod skill_audit;
pub mod skills;
pub use decision::{
    decision_governance_map, decision_governed_names, govern_decision_catalogue, DecisionBackend,
    NoDecisionBackend,
};
pub use governed_context_tool::{
    govern_governed_context, governed_context_tool_spec, GOVERNED_CONTEXT_PERMISSION,
    GOVERNED_CONTEXT_TOOL,
};
pub use governed_evidence_tool::{
    govern_governed_evidence_write, governed_evidence_write_tool_spec,
    GOVERNED_EVIDENCE_WRITE_PERMISSION, GOVERNED_EVIDENCE_WRITE_TOOL,
};
pub use served_context::{
    assemble_attested_served_context, assemble_served_governed_context,
    assemble_stored_governed_context, ServedContextError,
};
pub use server::{govern_catalogue, AdvertisedTool, Backend, GovernedMcp, McpOutcome};
pub use skill_audit::{
    govern_skill_audit, skill_audit_permission, skill_audit_permission_for, skill_audit_result,
    skill_audit_tool_spec, DEFAULT_AUDIT_LIMIT, MAX_AUDIT_LIMIT, SKILL_AUDIT_PERMISSION,
    SKILL_AUDIT_TOOL,
};
pub use skills::{
    active_skill_tool_result, active_skill_tool_result_with_observational, govern_skill_catalogue,
    skill_permission_for, skill_tool_spec, DEFAULT_SKILL_READ_LIMIT, MAX_SKILL_READ_LIMIT,
    SKILL_READ_PERMISSION, SKILL_READ_TOOL,
};

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

const fn outside(core: &'static str, why: &'static str) -> CoreTool {
    CoreTool {
        core,
        disposition: Disposition::OutsideBoundary { why },
    }
}

/// Canonical Core → Enterprise mapping. Additions to Core must be classified here.
pub const CATALOGUE: &[CoreTool] = &[
    governed("recall", "memory.recall", "memory.read"),
    governed("ingest", "memory.ingest", "memory.write"),
    governed("page_fault", "memory.page_fault", "memory.read"),
    governed("context_status", "memory.context_status", "memory.read"),
    governed("context_page", "memory.context_page", "memory.read"),
    governed("context_release", "memory.context_release", "memory.write"),
    governed("context_prefetch", "memory.context_prefetch", "memory.read"),
    governed("memory_write", "memory.write", "memory.write"),
    governed("memory_read", "memory.read", "memory.read"),
    governed("memory_forget", "memory.forget", "memory.write"),
    governed("decision_trace", "ccos.decision_trace", "memory.read"),
    governed("causal_flash", "ccos.causal_flash", "memory.read"),
    governed("postmortem", "ccos.postmortem", "memory.read"),
    governed("checkpoint", "ccos.checkpoint", "memory.write"),
    governed("restore", "ccos.restore", "memory.write"),
    governed("session_status", "ccos.session_status", "memory.read"),
    outside(
        OCTA_FEEDBACK,
        "stateful relevance feedback lacks Enterprise tenant/permission/audit semantics",
    ),
];

pub fn to_enterprise(core: &str) -> Option<&'static str> {
    CATALOGUE.iter().find_map(|row| {
        (row.core == core)
            .then_some(row.disposition)
            .and_then(|disposition| match disposition {
                Disposition::Governed { enterprise, .. } => Some(enterprise),
                Disposition::OutsideBoundary { .. } => None,
            })
    })
}

pub fn to_core(enterprise: &str) -> Option<&'static str> {
    CATALOGUE.iter().find_map(|row| match row.disposition {
        Disposition::Governed {
            enterprise: governed_name,
            ..
        } if governed_name == enterprise => Some(row.core),
        _ => None,
    })
}

pub fn permission_for(enterprise: &str) -> Option<&'static str> {
    CATALOGUE.iter().find_map(|row| match row.disposition {
        Disposition::Governed {
            enterprise: governed_name,
            permission,
        } if governed_name == enterprise => Some(permission),
        _ => None,
    })
}

pub fn core_catalogue() -> BTreeMap<&'static str, Disposition> {
    CATALOGUE
        .iter()
        .map(|row| (row.core, row.disposition))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ccos_core::agent_session::AgentSession;
    use serde_json::json;

    #[test]
    fn catalogue_is_injective_for_governed_names() {
        let mut seen = std::collections::BTreeSet::new();
        for row in CATALOGUE {
            if let Disposition::Governed { enterprise, .. } = row.disposition {
                assert!(seen.insert(enterprise), "duplicate Enterprise name {enterprise}");
            }
        }
    }

    #[test]
    fn catalogue_covers_every_core_tool() {
        let mut session = AgentSession::new();
        let response = ccos_core::mcp::handle(
            &mut session,
            &json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": null }),
        )
        .unwrap();
        let tools = response["result"]["tools"].as_array().unwrap();
        for tool in tools {
            let name = tool["name"].as_str().unwrap();
            assert!(
                CATALOGUE.iter().any(|row| row.core == name),
                "Core tool {name:?} is unclassified by Enterprise"
            );
        }
    }

    #[test]
    fn excluded_feedback_is_not_saved_by_gateway_prefix_rule() {
        let request = ccos_enterprise_gateway::GatewayRequest {
            tenant: "acme".into(),
            actor: "alice".into(),
            tool: OCTA_FEEDBACK.into(),
            request_id: "feedback-1".into(),
        };
        assert_eq!(classify(&request), GatewayDisposition::Forward);
        assert_eq!(to_enterprise(OCTA_FEEDBACK), None);
    }
}
