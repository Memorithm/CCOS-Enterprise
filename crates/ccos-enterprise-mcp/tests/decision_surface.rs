use ccos_enterprise_auth::AuthStrength;
use ccos_enterprise_decision_service::{DECISION_READ, DECISION_TOOLS, DECISION_WRITE};
use ccos_enterprise_mcp::{
    govern_catalogue, Backend, DecisionBackend, GovernedMcp, McpOutcome,
};
use ccos_enterprise_runtime::{actor, request, Call, Deployment, TenantState};
use serde_json::{json, Value};

#[derive(Default)]
struct CoreRecorder {
    calls: usize,
}

impl Backend for CoreRecorder {
    fn dispatch(
        &mut self,
        _tenant: &str,
        _core_tool: &str,
        _arguments: &Value,
    ) -> Result<Value, String> {
        self.calls += 1;
        Ok(json!({"core": true}))
    }
}

#[derive(Default)]
struct DecisionRecorder {
    calls: Vec<(String, String, String)>,
}

impl DecisionBackend for DecisionRecorder {
    fn dispatch_decision(
        &mut self,
        tenant: &str,
        actor: &ccos_enterprise_auth::AuthenticatedActor,
        enterprise_tool: &str,
        _arguments: &Value,
    ) -> Result<Value, String> {
        self.calls.push((
            tenant.to_string(),
            actor.actor().0.clone(),
            enterprise_tool.to_string(),
        ));
        Ok(json!({"decision": true, "tool": enterprise_tool}))
    }
}

fn deployment() -> Deployment {
    let mut deployment = Deployment::new();
    deployment
        .add_role("memory-writer", &["memory.read", "memory.write"])
        .add_role("decision-reader", &[DECISION_READ])
        .add_role("decision-writer", &[DECISION_READ, DECISION_WRITE]);
    govern_catalogue(&mut deployment);
    let mut tenant = TenantState::new(10_000);
    tenant.allow_model("claude-opus");
    deployment.add_tenant("memorithm", "acme", tenant);
    deployment.assign("alice", "memory-writer");
    deployment.assign("alice", "decision-writer");
    deployment.assign("bob", "decision-reader");
    deployment
}

fn front_door() -> GovernedMcp<CoreRecorder, DecisionRecorder> {
    GovernedMcp::with_decisions(
        deployment(),
        CoreRecorder::default(),
        DecisionRecorder::default(),
    )
}

#[test]
fn decision_tools_are_advertised_individually_with_closed_permissions() {
    let mcp = front_door();
    let listed = mcp.list_tools();
    for spec in DECISION_TOOLS {
        let tool = listed
            .iter()
            .find(|tool| tool.name == spec.name)
            .unwrap_or_else(|| panic!("{} was not advertised", spec.name));
        assert_eq!(tool.permission, spec.permission);
    }
    assert!(listed.iter().all(|tool| tool.name != "decision.*"));
}

#[test]
fn read_permission_cannot_execute_a_decision_mutation() {
    let mut mcp = front_door();
    let bob = actor("memorithm", "bob", AuthStrength::Token);
    let req = request("acme", "bob", "decision.record", "r-denied");
    let outcome = mcp.call(
        Call {
            actor: &bob,
            request: &req,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
            justification: None,
        },
        &json!({}),
    );
    assert!(matches!(outcome, McpOutcome::Refused(_)));
    assert!(mcp.decision_backend().calls.is_empty());
    assert_eq!(mcp.deployment().spent("acme"), Some(0));
}

#[test]
fn replayed_decision_mutation_never_executes_twice() {
    let mut mcp = front_door();
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let req = request("acme", "alice", "decision.record", "r-idempotent");

    let first = mcp.call(
        Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
            justification: None,
        },
        &json!({"id":"decision:1"}),
    );
    assert!(matches!(first, McpOutcome::Ok(_)));

    let replay = mcp.call(
        Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
            justification: None,
        },
        &json!({"id":"decision:1"}),
    );
    assert_eq!(replay, McpOutcome::Replayed);
    assert_eq!(mcp.decision_backend().calls.len(), 1);
    assert_eq!(mcp.deployment().spent("acme"), Some(10));
}

#[test]
fn local_backend_receives_verified_identity_and_tenant() {
    let mut mcp = front_door();
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let req = request("acme", "alice", "decision.get", "r-get");
    let outcome = mcp.call(
        Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
            justification: None,
        },
        &json!({"decision":"decision:1"}),
    );
    assert!(matches!(outcome, McpOutcome::Ok(_)));
    assert_eq!(
        mcp.decision_backend().calls,
        vec![(
            "acme".to_string(),
            "alice".to_string(),
            "decision.get".to_string()
        )]
    );
}

#[test]
fn unlisted_decision_sibling_never_reaches_any_backend() {
    let mut mcp = front_door();
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let req = request("acme", "alice", "decision.delete", "r-delete");
    let outcome = mcp.call(
        Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
            justification: None,
        },
        &json!({}),
    );
    assert!(matches!(outcome, McpOutcome::Refused(_)));
    assert!(mcp.decision_backend().calls.is_empty());
    assert_eq!(mcp.backend().calls, 0);
}
