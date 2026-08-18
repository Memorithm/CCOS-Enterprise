//! The governed request path, end to end: what a Hermes session actually
//! does against a running deployment, and what every refusal costs.
//!
//! The path exercised here used to live in this test harness. It now ships in
//! `ccos-enterprise-runtime` and the harness only re-exports it, so every
//! assertion below is made against shipped product code rather than a copy of
//! it kept alive for the tests.
//!
//! ## What was repaired — the tests below are now regression guards
//!
//! - **The credential did not bind the request.** The deployment
//!   authenticated one identity and then authorized a *different*,
//!   caller-supplied one: it read only the `AuthenticatedActor`'s strength,
//!   keyed RBAC on `request.actor` (a plain client string) and resolved the
//!   tenant from `request.tenant`. Any token-strength principal could present
//!   another actor's name and another tenant's id and act with their
//!   permissions against their budget. Two gates now stand ahead of tenant
//!   resolution — [`Refusal::ActorMismatch`] and
//!   [`Refusal::TenantNotOwnedByOrg`] — and both the ordering test and the
//!   no-refusal-is-billed table pin them.
//! - **Identifiers arrived from the wire unbounded.** The gateway bounded
//!   tool names; nothing bounded the tenant, actor or request id, so an
//!   unauthenticated caller could make every audit record a megabyte wide.
//!   An empty or oversized identifier is now
//!   [`Refusal::MalformedRequest`], refused ahead of everything else the
//!   request could be compared against.
//! - **The journal could not be reconciled against the meter.** A record
//!   carried no cost and no ordering, so no amount of auditing could show
//!   which decisions produced a tenant's `spent`. Records now carry
//!   `sequence` and `cost`, and `cost` is `0` for every refusal.
//!
//! ## What was already right, and must stay right
//!
//! The budget is charged **last**, so a call refused by any other gate costs
//! the tenant nothing; and the namespace boundary is evaluated before every
//! tenant-configurable gate, so no tenant's roles, allowlist or budget can
//! widen it. Both are load-bearing and both are pinned below.

use ccos_enterprise_auth::{AuthStrength, AuthenticatedActor};
use ccos_enterprise_conformance::{
    actor, request, two_tenant_deployment, Call, Deployment, Outcome, Refusal, TenantState,
    MAX_IDENTIFIER_BYTES,
};
use ccos_enterprise_gateway::GatewayRequest;
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
        justification: None,
    });

    assert_eq!(outcome, Outcome::Forwarded);
    assert_eq!(
        d.spent("acme"),
        Some(120),
        "an admitted call is billed exactly once"
    );
    assert_eq!(d.spent("globex"), Some(0), "and billed to nobody else");
    assert_eq!(
        d.spent("nowhere"),
        None,
        "a tenant that does not exist is not a tenant that spent nothing"
    );

    // The decision is journaled, correlated by request id, and carries what
    // it charged — the journal must reconcile against the meter on its own.
    let trail = d.audit_of("acme");
    assert_eq!(trail.len(), 1);
    assert_eq!(trail[0].request_id, "r-1");
    assert_eq!(trail[0].actor, "alice");
    assert_eq!(trail[0].tool, "memory.recall");
    assert_eq!(trail[0].sequence, 0);
    assert_eq!(trail[0].cost, 120);
    assert!(trail[0].outcome.is_forwarded());
}

#[test]
fn replay_is_an_explicit_zero_cost_non_execution_outcome() {
    let mut d = two_tenant_deployment();
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let req = request("acme", "alice", "memory.recall", "r-replay");

    let call = || Call {
        actor: &alice,
        request: &req,
        model: "claude-opus",
        cost_tokens: 120,
        variant: None,
        justification: None,
    };
    assert_eq!(d.admit(call()), Outcome::Forwarded);
    assert_eq!(d.admit(call()), Outcome::Replayed);
    assert_eq!(d.spent("acme"), Some(120));

    let trail = d.audit_of("acme");
    assert_eq!(trail.len(), 2);
    assert_eq!(trail[0].outcome, Outcome::Forwarded);
    assert_eq!(trail[1].outcome, Outcome::Replayed);
    assert_eq!(trail[1].cost, 0);
}

/// The load-bearing accounting rule: the budget is charged last, so a call
/// refused by ANY other gate costs the tenant nothing. A product that bills
/// refused calls lets a badly-configured client drain a tenant's quota
/// without ever reaching Core.
///
/// The table gained a row per refusal that did not exist before the
/// credential was bound to the request. Those three are the ones that used to
/// cost the *wrong tenant* real budget rather than nothing: an impersonated
/// call was billed to the impersonated tenant's ledger, a foreign
/// organization's call was billed to a tenant it did not own, and an
/// unbounded identifier was journaled verbatim before anything looked at it.
/// This test now guards that each of them is refused free of charge — in the
/// ledger *and* in the journal.
#[test]
fn no_refusal_is_ever_billed() {
    let anonymous = actor("memorithm", "mallory", AuthStrength::Anonymous);
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let bob = actor("memorithm", "bob", AuthStrength::Token);
    // Genuinely authenticated, in an organization that owns neither tenant.
    let trudy = actor("initech", "trudy", AuthStrength::Token);
    let oversized = "a".repeat(MAX_IDENTIFIER_BYTES + 1);

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
        // bob authenticates and then claims to be alice, who may write. This
        // used to be forwarded and charged to acme.
        (
            "impersonation: the request names another actor",
            &bob,
            request("acme", "alice", "memory.ingest", "r-i"),
            "claude-opus",
            None,
            Refusal::ActorMismatch,
        ),
        // A real credential from another organization, aimed at a tenant that
        // organization does not own. This used to be forwarded and charged to
        // acme as well.
        (
            "tenant not owned by the credential's org",
            &trudy,
            request("acme", "trudy", "memory.recall", "r-j"),
            "claude-opus",
            None,
            Refusal::TenantNotOwnedByOrg,
        ),
        (
            "malformed: empty tenant",
            &alice,
            request("", "alice", "memory.recall", "r-k"),
            "claude-opus",
            None,
            Refusal::MalformedRequest("tenant".to_string()),
        ),
        (
            "malformed: oversized actor",
            &alice,
            request("acme", &oversized, "memory.recall", "r-l"),
            "claude-opus",
            None,
            Refusal::MalformedRequest("actor".to_string()),
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
            justification: None,
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
            Some(0),
            "{label}: a refused call must cost nothing"
        );
        assert_eq!(
            d.spent("globex"),
            Some(0),
            "{label}: and must not be billed sideways to another tenant"
        );
        // The ledger and the journal have to agree about that: a record whose
        // cost is non-zero for a refusal would mean the meter and the audit
        // trail disagree, which is the state no operator can reconcile.
        assert_eq!(d.audit().count(), 1, "{label}: one call, one record");
        assert!(
            d.audit().all(|r| r.cost == 0),
            "{label}: the journal must show a refusal charged nothing"
        );
    }
}

/// Evaluation order is a security property, not a detail. Identity is
/// resolved first; identifiers are validated before anything is compared
/// against them; the credential is bound to the request before any tenant
/// state is touched; and the boundary is settled before anything a tenant can
/// configure.
///
/// The middle two positions are the repair. The path used to authenticate one
/// identity and authorize a different, caller-supplied one, so a request that
/// disagreed with its credential simply *won*: it reached RBAC under the name
/// it chose and the budget of the tenant it named. It now cannot get past
/// [`Refusal::ActorMismatch`] or [`Refusal::TenantNotOwnedByOrg`], and this
/// test pins those two ahead of tenant resolution — where they have to be, so
/// that no refusal downstream of them can be used as an oracle.
#[test]
fn gates_are_evaluated_in_the_documented_order() {
    /// One admission against a pristine deployment. Every case differs only
    /// in the credential and the request, so the gate that answers is the
    /// only variable — and each case is deliberately guilty of *several*
    /// things at once, so the answer names the gate that runs first.
    fn refusal(who: &AuthenticatedActor, req: &GatewayRequest) -> Option<Refusal> {
        let mut d = two_tenant_deployment();
        d.admit(Call {
            actor: who,
            request: req,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
            justification: None,
        })
        .refusal()
        .cloned()
    }

    let anon = actor("memorithm", "mallory", AuthStrength::Anonymous);
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    // A real credential whose organization owns neither fixture tenant.
    let trudy = actor("initech", "trudy", AuthStrength::Token);
    // Authenticated as bob, in the wrong organization, about to claim to be
    // alice: guilty at three gates at once.
    let bob_elsewhere = actor("initech", "bob", AuthStrength::Token);
    let oversized = "a".repeat(MAX_IDENTIFIER_BYTES + 1);

    // 1. Unauthenticated AND outside the boundary → identity answers first,
    //    so the refusal never reveals which namespaces exist.
    assert_eq!(
        refusal(&anon, &request("acme", "mallory", "rsi.status", "r-1")),
        Some(Refusal::Unauthenticated),
        "identity is decided before the boundary"
    );

    // 2. Unauthenticated AND malformed → still identity: proof strength is
    //    cheaper to check than anything the request carries.
    assert_eq!(
        refusal(&anon, &request("", "mallory", "memory.recall", "r-2")),
        Some(Refusal::Unauthenticated),
        "identity is decided before the identifiers are inspected"
    );

    // 3. Identifier validation comes before the credential binding: an
    //    oversized actor is refused for its shape, not for disagreeing with
    //    the credential — an unbounded string must never be compared, echoed
    //    or journaled in full.
    assert_eq!(
        refusal(&alice, &request("acme", &oversized, "memory.recall", "r-3")),
        Some(Refusal::MalformedRequest("actor".to_string())),
        "an oversized identifier is refused before it is compared to anything"
    );

    // 4. …and before every tenant-shaped gate: this request is also naming an
    //    actor its credential does not prove, and an ungoverned tool.
    assert_eq!(
        refusal(&alice, &request("", "bob", "memory.forget", "r-4")),
        Some(Refusal::MalformedRequest("tenant".to_string())),
        "an empty tenant is refused before tenancy, RBAC or the boundary"
    );
    assert_eq!(
        refusal(&alice, &request("acme", "alice", "memory.recall", "")),
        Some(Refusal::MalformedRequest("request_id".to_string())),
        "the correlation key is validated too — it is journaled"
    );

    // 5. The credential binding: naming another actor is settled BEFORE the
    //    tenant's ownership, so the two new gates have a defined order
    //    between them rather than racing.
    assert_eq!(
        refusal(
            &bob_elsewhere,
            &request("acme", "alice", "memory.ingest", "r-5")
        ),
        Some(Refusal::ActorMismatch),
        "who the caller claims to be is settled before whose tenant it is"
    );

    // 6. And BEFORE tenant resolution, so an impersonation attempt cannot be
    //    used to enumerate tenants: the refusal is the same whether or not
    //    the named tenant exists.
    assert_eq!(
        refusal(&alice, &request("nowhere", "bob", "memory.recall", "r-6")),
        Some(Refusal::ActorMismatch),
        "the credential binding is checked before the tenant is resolved"
    );

    // 7. Ownership beats the boundary and everything downstream of it: a
    //    foreign organization learns nothing about the tenant it aimed at,
    //    not its catalogue, not its roles, not its budget.
    assert_eq!(
        refusal(&trudy, &request("acme", "trudy", "rsi.status", "r-7")),
        Some(Refusal::TenantNotOwnedByOrg),
        "tenant ownership is settled before the boundary"
    );

    // 8. Authenticated, bound, and the tool is BOTH outside the boundary and
    //    ungoverned → the boundary answers, ahead of authorization.
    assert!(
        matches!(
            refusal(&alice, &request("acme", "alice", "forge.run", "r-8")),
            Some(Refusal::OutsideBoundary(_))
        ),
        "the boundary is settled before authorization"
    );

    // 9. Unknown tenant beats a boundary-legal but ungoverned tool…
    assert_eq!(
        refusal(&alice, &request("nowhere", "alice", "memory.forget", "r-9")),
        Some(Refusal::UnknownTenant),
        "an unknown tenant reaches no gate"
    );
    // …and beats the boundary itself.
    assert_eq!(
        refusal(&alice, &request("nowhere", "alice", "rsi.status", "r-10")),
        Some(Refusal::UnknownTenant),
        "an unknown tenant reaches no gate, boundary included"
    );

    // 10. STILL OPEN (pinned, not asserted as desirable): the ownership gate
    //     answers `TenantNotOwnedByOrg` for a tenant that exists and
    //     `UnknownTenant` for one that does not, so any authenticated
    //     principal — in ANY organization — can enumerate the tenant ids of
    //     the whole deployment by the refusal it gets back. Case 7 above is
    //     the same credential against a tenant that exists. This assertion
    //     records today's behaviour; it is not an endorsement of it.
    assert_eq!(
        refusal(
            &trudy,
            &request("nowhere", "trudy", "memory.recall", "r-11")
        ),
        Some(Refusal::UnknownTenant),
        "existence is still distinguishable from non-ownership"
    );

    // 11. Replay suppression sits ahead of the budget: a request id already
    //     decided returns its prior outcome and is NOT charged again, even
    //     when the retry's cost could no longer be afforded.
    let mut d = two_tenant_deployment();
    let req = request("acme", "alice", "memory.ingest", "r-replay");
    let call = |cost| Call {
        actor: &alice,
        request: &req,
        model: "claude-opus",
        cost_tokens: cost,
        variant: None,
        justification: None,
    };
    assert_eq!(d.admit(call(600)), Outcome::Forwarded);
    assert_eq!(d.spent("acme"), Some(600));
    assert_eq!(
        d.admit(call(600)),
        Outcome::Forwarded,
        "a decided request id replays its outcome"
    );
    assert_eq!(
        d.spent("acme"),
        Some(600),
        "replay is settled before the budget: the retry is not billed"
    );
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
        justification: None,
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
            justification: None,
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
            justification: None,
        }),
        Outcome::Forwarded
    );

    // globex did not — the same call, same actor, same variant, refused.
    // Both tenants belong to alice's organization, so nothing but the
    // activation differs between the two calls.
    d.assign("alice", "writer");
    d.tenant_mut("globex").unwrap().allow_model("claude-opus");
    let req = request("globex", "alice", "memory.recall", "r-2");
    let outcome = d.admit(Call {
        actor: &alice,
        request: &req,
        model: "claude-opus",
        cost_tokens: 10,
        variant: Some(AdvancedQPageVariant::Hierarchical),
        justification: None,
    });
    assert_eq!(outcome.refusal(), Some(&Refusal::VariantNotActivated));
    assert_eq!(d.spent("globex"), Some(0), "and the refusal cost nothing");
}

/// Replay: the same sequence of calls against a fresh deployment must
/// produce byte-identical audit trails and metric exports. Determinism is
/// the invariant Enterprise inherits from Core and must not weaken.
///
/// The trail now includes each record's sequence and cost. Those were the
/// two fields whose absence made a journal impossible to reconcile against
/// the meter, so replay determinism has to cover them as well.
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
            // The request names the actor its credential proves: anything
            // else is refused before it reaches a gate this test is about.
            let req = request(tenant, &who.actor().0, tool, &format!("r-{i}"));
            d.admit(Call {
                actor: who,
                request: &req,
                model,
                cost_tokens: *cost,
                variant: None,
                justification: None,
            });
        }
        let trail = d
            .audit()
            .map(|r| {
                format!(
                    "{}|{}|{}|{}|{}|{:?}",
                    r.sequence, r.request_id, r.tenant, r.tool, r.cost, r.outcome
                )
            })
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
///
/// It used to be a trail without costs or ordering, which is a subtler hole:
/// the records were all there, but nothing in them said which decisions had
/// produced the tenant's `spent`, so a journal and a meter that disagreed
/// could not be told apart from a journal and a meter that agreed. This test
/// now also guards that the trail sums back to the ledger, and that a
/// refusal contributes zero to that sum.
#[test]
fn every_decision_is_journaled_with_its_outcome() {
    let mut d = Deployment::new();
    d.add_role("reader", &["memory.read"])
        .govern_tool("memory.recall", "memory.read");
    let mut t = TenantState::new(100);
    t.allow_model("claude-opus");
    assert!(
        d.add_tenant("memorithm", "acme", t),
        "a fresh tenant is provisioned"
    );
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
            justification: None,
        });
    }

    let trail: Vec<_> = d.audit().collect();
    assert_eq!(trail.len(), 3, "three calls, three records");
    assert!(trail[0].outcome.is_forwarded());
    assert!(matches!(
        trail[1].outcome.refusal(),
        Some(Refusal::OutsideBoundary(_))
    ));
    assert_eq!(trail[2].outcome.refusal(), Some(&Refusal::BudgetExhausted));

    // Nothing was dropped, the order is the decision order, and the costs
    // reconcile against the meter with every refusal contributing nothing.
    assert_eq!(d.audit_dropped(), 0, "no record was dropped");
    let seqs: Vec<u64> = trail.iter().map(|r| r.sequence).collect();
    assert_eq!(
        seqs,
        vec![0, 1, 2],
        "sequence is monotonic in decision order"
    );
    assert_eq!(trail[0].cost, 10, "the forwarded call carries its cost");
    assert_eq!(trail[1].cost, 0, "a boundary refusal is not billed");
    assert_eq!(trail[2].cost, 0, "a budget refusal is not billed either");
    let billed: u64 = trail.iter().map(|r| r.cost).sum();
    assert_eq!(
        d.spent("acme"),
        Some(billed),
        "the journal sums back to the ledger"
    );

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
