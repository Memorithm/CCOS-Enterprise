//! # The contract with Core's catalogue
//!
//! `docs/` promises that Enterprise is the *governed edition* of CCOS, not a
//! subset of it. The way that promise rots is silent: Core grows a tool, the
//! translation table does not, and the capability becomes reachable only by
//! bypassing every gate Enterprise exists to impose. Nobody notices, because
//! nothing fails.
//!
//! This file is what fails. It asks a **live** `ccos_core` session for its
//! `tools/list` — not a copy of the list, not a constant checked in here — and
//! compares it with [`ccos_enterprise_mcp::CATALOGUE`]. A tool in Core that
//! this table does not mention is a hard error naming the tool, and so is a
//! table entry for a tool Core no longer has.
//!
//! When this test fails after a Core upgrade, the fix is never to edit the
//! expected list: it is to decide, explicitly, whether the new capability is
//! governed (give it an Enterprise name and a permission) or outside the
//! boundary (give it a reason). That decision is the point.
//!
//! ## Core's catalogue is feature-conditional, and so is the governed surface
//!
//! Core advertises **16** tools by default and a 17th, `octa_feedback`, only
//! when built with its `octasoma` (Pro) feature. This workspace depends on
//! Core with `default-features = false`, so the live list here is 16.
//!
//! That asymmetry is a real property of the product and is asserted below
//! rather than smoothed over: the set of capabilities Enterprise can govern
//! depends on how Core was compiled, so a deployment's governed surface is a
//! function of its Core build and not of Enterprise alone. The table
//! deliberately carries the `octa_feedback` exclusion **even though this build
//! of Core does not advertise it**, so that a Pro build does not silently gain
//! an ungoverned capability the moment the feature is switched on. A standing
//! exclusion for an absent tool is correct; a *governed* entry for an absent
//! tool is not, and the two are checked separately.

use std::collections::BTreeSet;

use ccos_core::agent_session::AgentSession;
use ccos_enterprise_mcp::{governed_names, Disposition, CATALOGUE, OCTA_FEEDBACK};
use serde_json::{json, Value};

/// Ask Core what it advertises, through the same entry point a client uses.
fn core_tool_names() -> BTreeSet<String> {
    let mut session = AgentSession::new();
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": null
    });
    let response = ccos_core::mcp::handle(&mut session, &request).expect("Core answers tools/list");
    let tools = response
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(Value::as_array)
        .expect("tools/list returns a tools array");
    tools
        .iter()
        .filter_map(|t| t.get("name").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

#[test]
fn catalogue_covers_every_core_tool() {
    let core = core_tool_names();
    assert!(
        !core.is_empty(),
        "Core advertised no tools at all — the contract cannot be checked"
    );

    let table: BTreeSet<String> = CATALOGUE.iter().map(|t| t.core.to_string()).collect();

    let missing: Vec<&String> = core.difference(&table).collect();
    assert!(
        missing.is_empty(),
        "Core advertises {missing:?}, which the Enterprise translation table \
         does not mention. Do NOT add them to an expected list — decide, in \
         ccos-enterprise-mcp::CATALOGUE, whether each is governed (Enterprise \
         name + permission) or outside the boundary (with a reason). A Core \
         capability unreachable through Enterprise is the drift this test exists \
         to stop."
    );

    // A *governed* entry for a tool Core does not advertise is a defect: the
    // front door would offer a capability that is not there. A standing
    // *exclusion* for an absent tool is not — it is a decision held in advance,
    // and it is what stops a feature flag from quietly widening the surface.
    let governed_but_absent: Vec<&str> = CATALOGUE
        .iter()
        .filter(|t| matches!(t.disposition, Disposition::Governed { .. }))
        .map(|t| t.core)
        .filter(|c| !core.contains(*c))
        .collect();
    assert!(
        governed_but_absent.is_empty(),
        "the table governs {governed_but_absent:?}, which Core does not advertise \
         — the front door would offer a capability that does not exist"
    );

    let excluded_and_absent: Vec<&str> = CATALOGUE
        .iter()
        .filter(|t| matches!(t.disposition, Disposition::OutsideBoundary { .. }))
        .map(|t| t.core)
        .filter(|c| !core.contains(*c))
        .collect();
    assert_eq!(
        excluded_and_absent,
        vec![OCTA_FEEDBACK],
        "the only exclusion held in advance of Core advertising it is \
         `octa_feedback`, behind Core's `octasoma` feature"
    );
}

/// The catalogue's *size* is asserted separately and deliberately: a table that
/// grew and a Core that grew by the same tool would keep the test above green
/// while this one records that the surface changed at all.
#[test]
fn the_governed_surface_is_the_size_it_is_documented_to_be() {
    let core = core_tool_names();
    // 16 by default; `octa_feedback` is Core's 17th and needs `octasoma`.
    assert_eq!(core.len(), 16, "Core's catalogue changed size: {core:?}");
    assert!(
        !core.contains(OCTA_FEEDBACK),
        "this build of Core advertises {OCTA_FEEDBACK} — the `octasoma` feature \
         is on, and the exclusion in CATALOGUE is now load-bearing rather than \
         precautionary. Tighten this assertion; do not remove the exclusion."
    );
    assert_eq!(CATALOGUE.len(), 17, "16 governed + 1 excluded in advance");
    assert_eq!(
        governed_names().len(),
        16,
        "16 governed, 1 deliberately outside the boundary"
    );
    let outside: Vec<&str> = CATALOGUE
        .iter()
        .filter(|t| matches!(t.disposition, Disposition::OutsideBoundary { .. }))
        .map(|t| t.core)
        .collect();
    assert_eq!(outside, vec![OCTA_FEEDBACK]);
}

/// Every Core tool this table claims to govern must actually be *callable* on
/// Core — a table entry that translates to a `tools/call` Core rejects as
/// unknown would turn a governed capability into a 500 at the far end.
#[test]
fn every_governed_tool_is_one_core_will_answer() {
    let core = core_tool_names();
    for tool in CATALOGUE {
        if let Disposition::Governed { .. } = tool.disposition {
            assert!(
                core.contains(tool.core),
                "the table governs {:?}, which Core does not advertise",
                tool.core
            );
        }
    }
}
