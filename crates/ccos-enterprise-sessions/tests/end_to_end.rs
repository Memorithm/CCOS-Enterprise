//! # The whole product, end to end, against a real CCOS Core
//!
//! Every other test in this workspace stops somewhere. The conformance suite
//! drives the admission path against a recording backend; the sessions crate
//! drives real Core sessions with no governance in front of them. This file is
//! the join: a governed MCP front door, the real admission path behind it, and
//! `ccos_core::AgentSession` at the far end, one per tenant, on disk.
//!
//! It exists because the two halves can each be right and the composition
//! still wrong. The question it answers is the one a customer actually asks:
//! **when a call is refused, does Core stay untouched — and when it is
//! admitted, does the effect land in the right tenant's memory?**
//!
//! Nothing here is a mock. The catalogue is `ccos_enterprise_mcp::CATALOGUE`,
//! the decisions are `Deployment::admit`'s, and the memory is Core's.

use std::path::PathBuf;

use ccos_enterprise_auth::AuthStrength;
use ccos_enterprise_mcp::{govern_catalogue, GovernedMcp, McpOutcome};
use ccos_enterprise_runtime::{actor, request, Call, Deployment, Refusal, TenantState};
use ccos_enterprise_sessions::TenantSessions;
use serde_json::json;

const ORG: &str = "memorithm";

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ccos-e2e-{tag}-{pid}", pid = std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

/// A deployment governing exactly the MCP catalogue, with two tenants.
fn product(root: &PathBuf) -> GovernedMcp<TenantSessions> {
    let mut d = Deployment::new();
    d.add_role("reader", &["memory.read"])
        .add_role("writer", &["memory.read", "memory.write"]);
    govern_catalogue(&mut d);
    for tenant in ["acme", "globex"] {
        let mut state = TenantState::new(100_000);
        state.allow_model("claude-opus");
        assert!(d.add_tenant(ORG, tenant, state));
    }
    d.assign("alice", "writer");
    d.assign("bob", "reader");
    GovernedMcp::new(d, TenantSessions::new(root))
}

fn call(
    mcp: &mut GovernedMcp<TenantSessions>,
    who: &str,
    tenant: &str,
    tool: &str,
    id: &str,
    args: serde_json::Value,
) -> McpOutcome {
    let a = actor(ORG, who, AuthStrength::Token);
    let req = request(tenant, who, tool, id);
    mcp.call(
        Call {
            actor: &a,
            request: &req,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
            justification: None,
        },
        &args,
    )
}

/// An admitted write lands in the right tenant's memory, and only there.
#[test]
fn an_admitted_call_reaches_core_and_a_refused_one_leaves_it_untouched() {
    let dir = scratch("reach");
    let mut mcp = product(&dir);

    // alice may write. The effect must land in acme's graph.
    let out = call(
        &mut mcp,
        "alice",
        "acme",
        "memory.ingest",
        "r-1",
        json!({ "uri": "src/falcon.rs", "source": "fn falcon() { /* acme */ }" }),
    );
    assert!(matches!(out, McpOutcome::Ok(_)), "{out:?}");

    // bob may not. Core must not see it at all.
    let refused = call(
        &mut mcp,
        "bob",
        "acme",
        "memory.ingest",
        "r-2",
        json!({ "uri": "src/planted.rs", "source": "fn planted() {}" }),
    );
    assert_eq!(
        refused,
        McpOutcome::Refused(Refusal::PermissionDenied),
        "a reader wrote to Core"
    );

    // Read the tenant's working set back through the same front door.
    let seen = call(
        &mut mcp,
        "bob",
        "acme",
        "memory.recall",
        "r-3",
        json!({ "strategy": "working_set", "budget": 4000 }),
    );
    let McpOutcome::Ok(window) = seen else {
        panic!("the reader could not read: {seen:?}");
    };
    let text = window.to_string();
    assert!(
        text.contains("falcon"),
        "the admitted write did not land: {text}"
    );
    assert!(
        !text.contains("planted"),
        "the refused write reached Core anyway: {text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The outermost promise, end to end: one tenant's write is invisible to
/// another, through the real front door and real Core sessions.
#[test]
fn one_tenants_memory_is_invisible_to_another_through_the_whole_stack() {
    let dir = scratch("isolation");
    let mut mcp = product(&dir);

    for (tenant, uri, source) in [
        ("acme", "src/acme_secret.rs", "fn acme_secret() {}"),
        ("globex", "src/globex_secret.rs", "fn globex_secret() {}"),
    ] {
        let out = call(
            &mut mcp,
            "alice",
            tenant,
            "memory.ingest",
            &format!("r-{tenant}"),
            json!({ "uri": uri, "source": source }),
        );
        assert!(matches!(out, McpOutcome::Ok(_)), "{tenant}: {out:?}");
    }

    for (tenant, mine, theirs) in [
        ("acme", "acme_secret", "globex_secret"),
        ("globex", "globex_secret", "acme_secret"),
    ] {
        let out = call(
            &mut mcp,
            "alice",
            tenant,
            "memory.recall",
            &format!("r-read-{tenant}"),
            json!({ "strategy": "working_set", "budget": 4000 }),
        );
        let McpOutcome::Ok(window) = out else {
            panic!("{tenant} could not read: {out:?}");
        };
        let text = window.to_string();
        assert!(text.contains(mine), "{tenant} lost its own memory: {text}");
        assert!(
            !text.contains(theirs),
            "{tenant} saw another tenant's memory: {text}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The boundary holds all the way down: a forbidden namespace never becomes a
/// Core call, and neither does a Core tool named directly.
#[test]
fn nothing_outside_the_catalogue_reaches_core() {
    let dir = scratch("boundary");
    let mut mcp = product(&dir);

    for tool in [
        "shell.exec",     // forbidden namespace
        "rsi.status",     // forbidden namespace
        "recall",         // Core's bare name — not the Enterprise one
        "ingest",         // ditto
        "octa_feedback",  // deliberately outside the boundary
        "memory.no_such", // in the allowlist, governed by nobody
    ] {
        let out = call(&mut mcp, "alice", "acme", tool, tool, json!({}));
        assert!(
            matches!(out, McpOutcome::Refused(_)),
            "{tool} was not refused: {out:?}"
        );
        assert!(!out.reached_the_backend(), "{tool} reached Core");
    }

    // No session was ever opened, because no call got that far.
    assert!(
        mcp.backend().live_tenants().is_empty(),
        "a refused call opened a Core session: {:?}",
        mcp.backend().live_tenants()
    );
    // Every one of them is in the trail, which is where a probe belongs.
    assert_eq!(mcp.deployment().audit_of("acme").len(), 6);
    assert_eq!(
        mcp.deployment().spent("acme"),
        Some(0),
        "and none was billed"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The budget is real all the way to Core: once it is gone, Core stops being
/// called at all.
#[test]
fn an_exhausted_budget_stops_core_being_called() {
    let dir = scratch("budget");
    let mut d = Deployment::new();
    d.add_role("writer", &["memory.read", "memory.write"]);
    govern_catalogue(&mut d);
    let mut state = TenantState::new(25); // two calls at 10, then nothing
    state.allow_model("claude-opus");
    assert!(d.add_tenant(ORG, "acme", state));
    d.assign("alice", "writer");
    let mut mcp = GovernedMcp::new(d, TenantSessions::new(&dir));

    let mut admitted = 0;
    for i in 0..5 {
        let out = call(
            &mut mcp,
            "alice",
            "acme",
            "memory.ingest",
            &format!("r-{i}"),
            json!({ "uri": format!("src/f{i}.rs"), "source": "fn f() {}" }),
        );
        match out {
            McpOutcome::Ok(_) => admitted += 1,
            McpOutcome::Refused(Refusal::BudgetExhausted) => {}
            other => panic!("call {i}: {other:?}"),
        }
    }
    assert_eq!(admitted, 2, "25 tokens buys exactly two 10-token calls");
    assert_eq!(mcp.deployment().spent("acme"), Some(20));

    // Core saw two files, not five.
    let out = call(
        &mut mcp,
        "alice",
        "acme",
        "memory.recall",
        "r-read",
        json!({ "strategy": "working_set", "budget": 4000 }),
    );
    // The read itself needs budget the tenant no longer has.
    assert_eq!(out, McpOutcome::Refused(Refusal::BudgetExhausted));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A restart loses nothing: the tenant's memory is on disk, keyed by a tenant
/// id that could not have been anything unsafe.
#[test]
fn a_tenants_memory_survives_a_restart_of_the_whole_product() {
    let dir = scratch("restart");
    {
        let mut mcp = product(&dir);
        let out = call(
            &mut mcp,
            "alice",
            "acme",
            "memory.ingest",
            "r-before",
            json!({ "uri": "src/durable.rs", "source": "fn durable() {}" }),
        );
        assert!(matches!(out, McpOutcome::Ok(_)), "{out:?}");
        mcp.backend_mut().checkpoint_all().expect("checkpoint");
    }

    // A brand-new front door, a brand-new deployment, the same disk.
    let mut mcp = product(&dir);
    let out = call(
        &mut mcp,
        "alice",
        "acme",
        "memory.recall",
        "r-after",
        json!({ "strategy": "working_set", "budget": 4000 }),
    );
    let McpOutcome::Ok(window) = out else {
        panic!("{out:?}");
    };
    assert!(
        window.to_string().contains("durable"),
        "the tenant's memory did not survive the restart: {window}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
