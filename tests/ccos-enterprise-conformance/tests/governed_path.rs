//! The governed request path, end to end: what a Hermes session actually
//! does against a running deployment, and what every refusal costs.

use ccos_enterprise_auth::AuthStrength;
use ccos_enterprise_conformance::{
    actor, request, two_tenant_deployment, Call, Deployment, Outcome, Refusal, TenantState,
};
use ccos_enterprise_qpages::AdvancedQPageVariant;

#[test]
fn a_governed_call_reaches_core_and_is_billed_once() {
    let mut d = two_tenant_deployment();
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let req = request("acme", "alice", "memory.recall", "r-1");

    let outcome = d.admit(Call {
        actor: &alice,
        request: &req,
        model: "claude-opus",
        cost_tokens: 120,
        variant: None,
    });

    assert_eq!(outcome, Outcome::Forwarded);
    assert_eq!(
        d.spent("acme"),
        120,
        "an admitted call is billed exactly once"
    );
    assert_eq!(d.spent("globex"), 0, "and billed to nobody else");

    // The decision is journaled, correlated by request id.
    let trail = d.audit_of("acme");
    assert_eq!(trail.len(), 1);
    assert_eq!(trail[0].request_id, "r-1");
    assert_eq!(trail[0].actor, "alice");
    assert_eq!(trail[0].tool, "memory.recall");
    assert!(trail[0].outcome.is_forwarded());
}

/// The load-bearing accounting rule: the budget is charged last, so a call
/// refused by ANY other gate costs the tenant nothing. A product that bills
/// refused calls lets a badly-configured client drain a tenant's quota
/// without ever reaching Core.
#[test]
fn no_refusal_is_ever_billed() {
    let anonymous = actor("memorithm", "mallory", AuthStrength::Anonymous);
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let bob = actor("memorithm", "bob", AuthStrength::Token);

    // (label, actor, request, model, variant, expected refusal)
    let cases: Vec<(&str, _, _, &str, Option<AdvancedQPageVariant>, Refusal)> = vec![
        (
            "unauthenticated",
            &anonymous,
            request("acme", "mallory", "memory.recall", "r-a"),
            "claude-opus",
            None,
            Refusal::Unauthenticated,
        ),
        (
            "unknown tenant",
            &alice,
            request("nowhere", "alice", "memory.recall", "r-b"),
            "claude-opus",
            None,
            Refusal::UnknownTenant,
        ),
        (
            "outside the boundary",
            &alice,
            request("acme", "alice", "rsi.status", "r-c"),
            "claude-opus",
            None,
            Refusal::OutsideBoundary(String::new()),
        ),
        (
            "ungoverned tool",
            &alice,
            request("acme", "alice", "memory.forget", "r-d"),
            "claude-opus",
            None,
            Refusal::ToolNotGoverned,
        ),
        (
            "permission denied",
            &bob,
            request("acme", "bob", "memory.ingest", "r-e"),
            "claude-opus",
            None,
            Refusal::PermissionDenied,
        ),
        (
            "model not allowed",
            &alice,
            request("acme", "alice", "memory.recall", "r-f"),
            "gpt-5",
            None,
            Refusal::ModelNotAllowed,
        ),
        (
            "variant not activated",
            &alice,
            request("acme", "alice", "memory.recall", "r-g"),
            "claude-opus",
            Some(AdvancedQPageVariant::Probabilistic),
            Refusal::VariantNotActivated,
        ),
        (
            "budget exhausted",
            &alice,
            request("acme", "alice", "memory.recall", "r-h"),
            "claude-opus",
            None,
            Refusal::BudgetExhausted,
        ),
    ];

    for (label, who, req, model, variant, expected) in cases {
        let mut d = two_tenant_deployment();
        // The budget case needs a cost the tenant cannot cover; every other
        // case uses a cost it easily can, so a refusal is the gate's doing.
        let cost = if matches!(expected, Refusal::BudgetExhausted) {
            10_000
        } else {
            50
        };
        let outcome = d.admit(Call {
            actor: who,
            request: &req,
            model,
            cost_tokens: cost,
            variant,
        });

        match (&expected, outcome.refusal()) {
            // The boundary refusal carries the gateway's own message; compare
            // the variant, not the text.
            (Refusal::OutsideBoundary(_), Some(Refusal::OutsideBoundary(why))) => {
                assert!(why.contains("outside the Enterprise boundary"), "{label}");
            }
            (expected, Some(got)) => assert_eq!(got, expected, "{label}"),
            (_, None) => panic!("{label}: expected a refusal, the call was forwarded"),
        }
        assert_eq!(
            d.spent("acme"),
            0,
            "{label}: a refused call must cost nothing"
        );
    }
}

/// Evaluation order is a security property, not a detail. Identity is
/// resolved before anything tenant-specific; the boundary before anything a
/// tenant can configure.
#[test]
fn gates_are_evaluated_in_the_documented_order() {
    let mut d = two_tenant_deployment();

    // Unauthenticated AND outside the boundary → identity answers first, so
    // the refusal never reveals which namespaces exist.
    let anon = actor("memorithm", "mallory", AuthStrength::Anonymous);
    let req = request("acme", "mallory", "rsi.status", "r-1");
    let outcome = d.admit(Call {
        actor: &anon,
        request: &req,
        model: "claude-opus",
        cost_tokens: 1,
        variant: None,
    });
    assert_eq!(outcome.refusal(), Some(&Refusal::Unauthenticated));

    // Authenticated, but the tool is BOTH outside the boundary and
    // ungoverned → the boundary answers, ahead of authorization.
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let req = request("acme", "alice", "forge.run", "r-2");
    let outcome = d.admit(Call {
        actor: &alice,
        request: &req,
        model: "claude-opus",
        cost_tokens: 1,
        variant: None,
    });
    assert!(matches!(
        outcome.refusal(),
        Some(Refusal::OutsideBoundary(_))
    ));

    // Unknown tenant beats a boundary-legal but ungoverned tool.
    let req = request("nowhere", "alice", "memory.forget", "r-3");
    let outcome = d.admit(Call {
        actor: &alice,
        request: &req,
        model: "claude-opus",
        cost_tokens: 1,
        variant: None,
    });
    assert_eq!(outcome.refusal(), Some(&Refusal::UnknownTenant));
}

/// A deployment may demand strong proof; a token-strength actor is then
/// refused even though it is genuinely authenticated.
#[test]
fn required_authentication_strength_is_enforced() {
    let mut d = two_tenant_deployment();
    d.require_strength(AuthStrength::Strong);

    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let req = request("acme", "alice", "memory.recall", "r-1");
    let outcome = d.admit(Call {
        actor: &alice,
        request: &req,
        model: "claude-opus",
        cost_tokens: 10,
        variant: None,
    });
    assert_eq!(outcome.refusal(), Some(&Refusal::Unauthenticated));

    let strong = actor("memorithm", "alice", AuthStrength::Strong);
    let req = request("acme", "alice", "memory.recall", "r-2");
    assert_eq!(
        d.admit(Call {
            actor: &strong,
            request: &req,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
        }),
        Outcome::Forwarded
    );
}

/// An activated Q-Page variant is what makes an advanced call possible, and
/// activation is per tenant — Core's standard primitives never need one.
#[test]
fn advanced_variants_are_policy_activated_per_tenant() {
    let mut d = two_tenant_deployment();
    let alice = actor("memorithm", "alice", AuthStrength::Token);

    // acme activated Hierarchical in the fixture.
    let req = request("acme", "alice", "memory.recall", "r-1");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 10,
            variant: Some(AdvancedQPageVariant::Hierarchical),
        }),
        Outcome::Forwarded
    );

    // globex did not — the same call, same actor, same variant, refused.
    d.assign("alice", "writer");
    d.tenant_mut("globex").unwrap().allow_model("claude-opus");
    let req = request("globex", "alice", "memory.recall", "r-2");
    let outcome = d.admit(Call {
        actor: &alice,
        request: &req,
        model: "claude-opus",
        cost_tokens: 10,
        variant: Some(AdvancedQPageVariant::Hierarchical),
    });
    assert_eq!(outcome.refusal(), Some(&Refusal::VariantNotActivated));
}

/// Replay: the same sequence of calls against a fresh deployment must
/// produce byte-identical audit trails and metric exports. Determinism is
/// the invariant Enterprise inherits from Core and must not weaken.
#[test]
fn the_path_is_deterministic_under_replay() {
    fn run() -> (Vec<String>, Vec<(String, u64)>) {
        let mut d = two_tenant_deployment();
        let alice = actor("memorithm", "alice", AuthStrength::Token);
        let bob = actor("memorithm", "bob", AuthStrength::Token);
        let script = [
            (&alice, "acme", "memory.recall", "claude-opus", 100u64),
            (&bob, "acme", "memory.ingest", "claude-opus", 100),
            (&alice, "acme", "rsi.status", "claude-opus", 100),
            (&alice, "acme", "memory.ingest", "claude-opus", 900),
            (&alice, "globex", "memory.recall", "gpt-5", 10),
        ];
        for (i, (who, tenant, tool, model, cost)) in script.iter().enumerate() {
            let req = request(tenant, &who.actor.0, tool, &format!("r-{i}"));
            d.admit(Call {
                actor: who,
                request: &req,
                model,
                cost_tokens: *cost,
                variant: None,
            });
        }
        let trail = d
            .audit()
            .iter()
            .map(|r| format!("{}|{}|{}|{:?}", r.request_id, r.tenant, r.tool, r.outcome))
            .collect();
        (trail, d.metrics())
    }

    let (trail_a, metrics_a) = run();
    let (trail_b, metrics_b) = run();
    assert_eq!(trail_a, trail_b, "audit trail is reproducible");
    assert_eq!(metrics_a, metrics_b, "metric export is reproducible");
    assert!(!trail_a.is_empty());

    // And the export is ordered, so diffs between two runs are readable.
    let names: Vec<&String> = metrics_a.iter().map(|(k, _)| k).collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted, "metric export is in deterministic key order");
}

/// Every decision — allowed or refused — is journaled. An audit trail with
/// holes is not an audit trail.
#[test]
fn every_decision_is_journaled_with_its_outcome() {
    let mut d = Deployment::new();
    d.add_role("reader", &["memory.read"])
        .govern_tool("memory.recall", "memory.read");
    let mut t = TenantState::new(100);
    t.allow_model("claude-opus");
    d.add_tenant("acme", t);
    d.assign("bob", "reader");

    let bob = actor("memorithm", "bob", AuthStrength::Token);
    for (i, (tool, cost)) in [
        ("memory.recall", 10u64),
        ("shell.exec", 10),
        ("memory.recall", 10_000),
    ]
    .iter()
    .enumerate()
    {
        let req = request("acme", "bob", tool, &format!("r-{i}"));
        d.admit(Call {
            actor: &bob,
            request: &req,
            model: "claude-opus",
            cost_tokens: *cost,
            variant: None,
        });
    }

    let trail = d.audit();
    assert_eq!(trail.len(), 3, "three calls, three records");
    assert!(trail[0].outcome.is_forwarded());
    assert!(matches!(
        trail[1].outcome.refusal(),
        Some(Refusal::OutsideBoundary(_))
    ));
    assert_eq!(trail[2].outcome.refusal(), Some(&Refusal::BudgetExhausted));

    // Counters agree with the journal.
    let metrics = d.metrics();
    let get = |k: &str| {
        metrics
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    };
    assert_eq!(get("gateway.requests"), 3);
    assert_eq!(get("gateway.forwarded"), 1);
    assert_eq!(get("gateway.refused"), 2);
    assert_eq!(get("gateway.refused.outside_boundary"), 1);
    assert_eq!(get("gateway.refused.budget_exhausted"), 1);
}
