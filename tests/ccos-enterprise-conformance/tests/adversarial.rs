//! Adversarial scenarios: privilege escalation, quota abuse, restore of
//! foreign or forged backups, and administrative acts without a paper trail.
//!
//! # What was repaired
//!
//! These scenarios used to run against a composed path that lived in a
//! `publish = false` harness — it authenticated one identity and authorized a
//! different, caller-supplied one. That path now ships in
//! `ccos-enterprise-runtime`, and the defects below were closed in the move.
//! Each one is pinned here with the same hostile inputs and the opposite
//! expectation, so a regression fails in this file rather than in a tenant:
//!
//! * **Impersonation.** RBAC was keyed on `request.actor` — a plain client
//!   string — while the credential contributed only its *strength*. Any
//!   token-strength principal could write a privileged actor's name on the
//!   request and act with their permissions, against their tenant's budget.
//!   Now [`Refusal::ActorMismatch`], guarded by `privilege_cannot_be_invented`
//!   and `permissions_do_not_widen_by_adjacency`.
//! * **Cross-organization reach.** The tenant was resolved from
//!   `request.tenant` and nothing checked who owned it, so a genuine principal
//!   of one org spent another org's quota. Now
//!   [`Refusal::TenantNotOwnedByOrg`], guarded by
//!   `a_foreign_org_cannot_spend_another_orgs_quota`.
//! * **Re-provisioning as a quota reset.** `add_tenant` was a bare `insert`,
//!   so re-adding a live tenant silently zeroed its ledger, allowlist and
//!   activations while the journal still showed its forwarded calls — an
//!   exhausted tenant could buy itself a fresh budget. Now refused, guarded by
//!   `an_exhausted_tenant_cannot_re_provision_a_fresh_quota`.
//! * **Unbounded identifiers.** Nothing bounded the tenant, actor or
//!   request_id arriving from the wire, so every audit record could be made a
//!   megabyte wide. Now [`Refusal::MalformedRequest`], guarded by
//!   `oversized_or_empty_identifiers_are_refused_before_any_gate`.
//! * **An unbounded audit journal.** The journal was an unbounded `Vec`: an
//!   unauthenticated caller retained 1.15 GiB across five million *refused*
//!   calls. It is now a bounded buffer that says what it dropped, guarded by
//!   `a_refusal_flood_cannot_grow_the_journal_without_bound`.
//! * **A meter that could not say "no such tenant".** `spent()` answered a
//!   bare `0` for a tenant that does not exist, indistinguishable from one
//!   that has spent nothing, so a departed tenant read as a healthy idle one.
//!   Now `Option<u64>`, guarded by `a_call_naming_a_departed_tenant_is_refused`.
//!
//! # Still open
//!
//! Nothing this file pins is still failing. One product-level gap remains, and
//! it is not a defect of the code under test: the bounded journal is a *memory*
//! bound, not an audit story. `audit_dropped()` going non-zero means the trail
//! is incomplete and must be read from durable storage — which this deployment
//! does not have yet (see `ccos_enterprise_runtime`'s module docs). The flood
//! test below asserts the bound and the drop count, which is the honest
//! guarantee; it does not assert that nothing was lost, because things were.

use std::collections::BTreeMap;

use ccos_enterprise_admin::{validate, AdminAction};
use ccos_enterprise_auth::AuthStrength;
use ccos_enterprise_backup::BackupManifest;
use ccos_enterprise_conformance::{
    actor, request, two_tenant_deployment, Call, Deployment, Outcome, Refusal, TenantState,
    MAX_IDENTIFIER_BYTES,
};
use ccos_enterprise_observability::CounterRegistry;

/// An actor cannot grant itself a role that does not exist, an unassigned
/// actor holds nothing — and, the repair this test now guards, it cannot
/// borrow somebody else's roles by writing their name on the request.
///
/// The composed path used to authorize `request.actor`, a string the client
/// chose, having authenticated somebody else entirely. `mallory` therefore
/// only had to *spell* `alice` to write to acme's memory, or `root` to reach
/// `policy.set`: the entire RBAC layer was one field away from being bypassed,
/// and the impersonated tenant paid for the call. The credential now binds the
/// request ([`Refusal::ActorMismatch`]), the refusal is announced under its
/// own metric tag, and the attempt costs the impersonated tenant nothing.
#[test]
fn privilege_cannot_be_invented() {
    let mut d = two_tenant_deployment();

    assert!(
        !d.assign("mallory", "superuser"),
        "unknown role grants nothing"
    );
    assert!(!d.assign("mallory", "root"), "nor does a role-shaped guess");

    let mallory = actor("memorithm", "mallory", AuthStrength::Strong);
    let req = request("acme", "mallory", "memory.recall", "r-1");
    assert_eq!(
        d.admit(Call {
            actor: &mallory,
            request: &req,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::PermissionDenied),
        "strong identity is not authorization"
    );
    assert_eq!(d.spent("acme"), Some(0));

    // The flipped scenario: the same principal, now presenting a privileged
    // actor's name. Every one of these was forwarded before the repair.
    for (borrowed, tool, id) in [
        ("alice", "memory.ingest", "r-2"),
        ("root", "policy.set", "r-3"),
    ] {
        let req = request("acme", borrowed, tool, id);
        assert_eq!(
            d.admit(Call {
                actor: &mallory,
                request: &req,
                model: "claude-opus",
                cost_tokens: 10,
                variant: None,
            })
            .refusal(),
            Some(&Refusal::ActorMismatch),
            "mallory must not act as {borrowed} to reach {tool}"
        );
    }
    assert_eq!(
        d.spent("acme"),
        Some(0),
        "no impersonation ever reached the meter"
    );

    // The attempt is visible to an operator: the journal keeps the name that
    // was *presented*, marked refused and billed nothing.
    let trail = d.audit_of("acme");
    assert_eq!(trail.len(), 3);
    assert!(
        trail.iter().all(|r| r.cost == 0),
        "not one refusal was billed"
    );
    let impersonated: Vec<&str> = trail
        .iter()
        .filter(|r| r.outcome.refusal() == Some(&Refusal::ActorMismatch))
        .map(|r| r.actor.as_str())
        .collect();
    assert_eq!(impersonated, vec!["alice", "root"]);

    let metrics: BTreeMap<String, u64> = d.metrics().into_iter().collect();
    assert_eq!(
        metrics.get("gateway.refused.actor_mismatch").copied(),
        Some(2),
        "impersonation is counted under its own low-cardinality tag"
    );
    assert_eq!(metrics.get("gateway.forwarded").copied(), None);

    // What the impersonation was reaching for, and the measure of what the
    // hole was worth: the byte-identical request, presented by the actor it
    // names, is forwarded and billed. The credential binding is the only
    // thing that stood between mallory and alice's write.
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let req = request("acme", "alice", "memory.ingest", "r-2");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
        }),
        Outcome::Forwarded
    );
    assert_eq!(d.spent("acme"), Some(10), "billed to the actor who is real");
}

/// A reader stays a reader: holding one permission never implies the next one
/// along, however adjacent the names — and no longer, as this test now also
/// guards, however privileged the name the reader writes on the request.
///
/// Refusing `bob` the write permission was worth nothing while `bob` could
/// simply claim to be `alice`: the deployment authenticated bob's credential
/// and then looked up alice's roles, so the forged request was forwarded and
/// billed to acme. Same inputs here, opposite expectation.
#[test]
fn permissions_do_not_widen_by_adjacency() {
    let mut d = two_tenant_deployment();
    let bob = actor("memorithm", "bob", AuthStrength::Token); // "reader"

    // Reading is granted…
    let req = request("acme", "bob", "memory.recall", "r-1");
    assert_eq!(
        d.admit(Call {
            actor: &bob,
            request: &req,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
        }),
        Outcome::Forwarded
    );
    // …writing and administering are not.
    for (tool, id) in [("memory.ingest", "r-2"), ("policy.set", "r-3")] {
        let req = request("acme", "bob", tool, id);
        assert_eq!(
            d.admit(Call {
                actor: &bob,
                request: &req,
                model: "claude-opus",
                cost_tokens: 10,
                variant: None,
            })
            .refusal(),
            Some(&Refusal::PermissionDenied),
            "a reader must not reach {tool}"
        );
    }
    // …and neither is reachable by borrowing the name of somebody who holds
    // them. The refusal lands before RBAC is ever consulted, so bob's own
    // permissions are not what is being tested here — the binding is.
    for (borrowed, tool, id) in [
        ("alice", "memory.ingest", "r-4"),
        ("root", "policy.set", "r-5"),
        ("alice", "memory.recall", "r-6"),
    ] {
        let req = request("acme", borrowed, tool, id);
        assert_eq!(
            d.admit(Call {
                actor: &bob,
                request: &req,
                model: "claude-opus",
                cost_tokens: 10,
                variant: None,
            })
            .refusal(),
            Some(&Refusal::ActorMismatch),
            "a reader claiming to be {borrowed} must not reach {tool}"
        );
    }
    assert_eq!(
        d.spent("acme"),
        Some(10),
        "only the one genuinely authorized call was billed"
    );
}

/// A tool nobody governed is refused rather than forwarded. Exposure must be
/// a decision; forgetting to declare a permission must not be a grant.
#[test]
fn an_ungoverned_tool_is_refused_not_forwarded() {
    let mut d = two_tenant_deployment();
    let root = actor("memorithm", "root", AuthStrength::Strong);
    let req = request("acme", "root", "memory.purge", "r-1");
    assert_eq!(
        d.admit(Call {
            actor: &root,
            request: &req,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::ToolNotGoverned),
        "an operator with every role still cannot reach an undeclared tool"
    );
    assert_eq!(d.spent("acme"), Some(0), "and it costs the tenant nothing");
}

/// Quota abuse: a client hammering a refused call must not drain the tenant,
/// and the ledger must stay exact rather than drifting under repetition.
///
/// The journal now carries the cost of each decision, so the claim is checked
/// against the record rather than only against the meter: 500 refusals, 500
/// journaled zeroes, and a complete trail (nothing dropped) to prove it.
#[test]
fn a_refused_call_repeated_forever_costs_nothing() {
    let mut d = two_tenant_deployment();
    let bob = actor("memorithm", "bob", AuthStrength::Token);
    for i in 0..500 {
        let req = request("acme", "bob", "memory.ingest", &format!("r-{i}"));
        d.admit(Call {
            actor: &bob,
            request: &req,
            model: "claude-opus",
            cost_tokens: 999_999,
            variant: None,
        });
    }
    assert_eq!(d.spent("acme"), Some(0), "500 refusals drained nothing");
    assert_eq!(d.audit_dropped(), 0, "the trail of the abuse is complete");
    let refusals = d.audit_of("acme");
    assert_eq!(refusals.len(), 500);
    assert!(
        refusals
            .iter()
            .all(|r| r.cost == 0 && r.outcome.refusal() == Some(&Refusal::PermissionDenied)),
        "every journaled refusal is billed zero"
    );

    // And the tenant's full budget is still there for a legitimate call.
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let req = request("acme", "alice", "memory.ingest", "r-ok");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1_000,
            variant: None,
        }),
        Outcome::Forwarded,
        "the whole budget survived the abuse"
    );
    assert_eq!(d.spent("acme"), Some(1_000));
}

/// The budget boundary is exact: the last affordable token is spent, the next
/// one is refused, and the refusal does not nudge the ledger.
///
/// The journal now reconciles the meter — every decision carries the tokens it
/// actually charged and a monotonic sequence, so an operator can replay the
/// trail and arrive at `spent()`. Neither field existed before, and without
/// them no amount of auditing could reconcile a ledger.
#[test]
fn the_budget_boundary_is_exact() {
    let mut d = Deployment::new();
    d.add_role("writer", &["memory.write"])
        .govern_tool("memory.ingest", "memory.write");
    let mut t = TenantState::new(100);
    t.allow_model("m");
    assert!(
        d.add_tenant("o", "acme", t),
        "a fresh tenant is provisioned"
    );
    d.assign("a", "writer");
    let who = actor("o", "a", AuthStrength::Token);

    let call = |d: &mut Deployment, cost: u64, id: &str| {
        let req = request("acme", "a", "memory.ingest", id);
        d.admit(Call {
            actor: &who,
            request: &req,
            model: "m",
            cost_tokens: cost,
            variant: None,
        })
    };

    assert_eq!(call(&mut d, 99, "r-1"), Outcome::Forwarded);
    assert_eq!(
        call(&mut d, 2, "r-2").refusal(),
        Some(&Refusal::BudgetExhausted)
    );
    assert_eq!(
        d.spent("acme"),
        Some(99),
        "the refused charge is not accounted"
    );
    assert_eq!(call(&mut d, 1, "r-3"), Outcome::Forwarded, "the last token");
    assert_eq!(d.spent("acme"), Some(100));
    assert_eq!(
        call(&mut d, 1, "r-4").refusal(),
        Some(&Refusal::BudgetExhausted)
    );
    assert_eq!(d.spent("acme"), Some(100), "exhausted stays exhausted");

    let trail: Vec<_> = d.audit().collect();
    let sequences: Vec<u64> = trail.iter().map(|r| r.sequence).collect();
    assert_eq!(sequences, vec![0, 1, 2, 3], "decision order is recoverable");
    let billed: u64 = trail.iter().map(|r| r.cost).sum();
    assert_eq!(
        Some(billed),
        d.spent("acme"),
        "the journal reconciles the meter exactly"
    );
    assert_eq!(
        trail
            .iter()
            .filter(|r| r.outcome.is_forwarded())
            .map(|r| r.cost)
            .collect::<Vec<_>>(),
        vec![99, 1]
    );
}

/// An exhausted tenant cannot buy itself a fresh quota by being provisioned
/// again — the regression guard for a defect that made every budget optional.
///
/// Provisioning was a bare `insert`, so re-adding a live tenant replaced its
/// ledger, model allowlist and Q-Page activations with a blank state and said
/// nothing. Anyone who could reach the provisioning path could therefore zero
/// a running tenant's meter — with the journal still showing the calls that
/// had been billed to it, which is how a ledger stops reconciling. Re-adding
/// a live tenant is now refused and changes nothing.
#[test]
fn an_exhausted_tenant_cannot_re_provision_a_fresh_quota() {
    let mut d = two_tenant_deployment();
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let req = request("acme", "alice", "memory.ingest", "r-1");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1_000,
            variant: None,
        }),
        Outcome::Forwarded
    );
    assert_eq!(d.spent("acme"), Some(1_000), "the budget is now spent");

    assert!(
        !d.add_tenant("memorithm", "acme", TenantState::new(9_999)),
        "a live tenant is not silently replaced"
    );
    // Nor can another organization claim an existing tenant's name.
    assert!(
        !d.add_tenant("initech", "acme", TenantState::new(9_999)),
        "and re-provisioning cannot hand it to a different org"
    );
    assert_eq!(d.spent("acme"), Some(1_000), "the ledger survived");

    let req = request("acme", "alice", "memory.ingest", "r-2");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::BudgetExhausted),
        "the tenant is still exhausted after the attempted reset"
    );
}

/// A genuine principal of one organization cannot spend another
/// organization's quota — the regression guard for the second half of the
/// credential hole.
///
/// The tenant was resolved from `request.tenant` alone. The organization was
/// carried on every credential and read by nothing, so `mallory@initech`,
/// authenticated and legitimately privileged inside her own org, could name
/// `acme` and bill her calls to a customer she has no relationship with —
/// cross-tenant billing and cross-tenant reach in one field. The credential's
/// org must now own the tenant ([`Refusal::TenantNotOwnedByOrg`]).
#[test]
fn a_foreign_org_cannot_spend_another_orgs_quota() {
    let mut d = two_tenant_deployment();
    let mut hooli = TenantState::new(100);
    hooli.allow_model("claude-opus");
    assert!(d.add_tenant("initech", "hooli", hooli));
    assert!(d.assign("mallory", "writer"), "a real role in her own org");

    let mallory = actor("initech", "mallory", AuthStrength::Token);

    // She is genuinely entitled inside initech…
    let req = request("hooli", "mallory", "memory.ingest", "r-1");
    assert_eq!(
        d.admit(Call {
            actor: &mallory,
            request: &req,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
        }),
        Outcome::Forwarded
    );
    assert_eq!(d.spent("hooli"), Some(10));

    // …and that entitlement stops at her organization's edge.
    for tenant in ["acme", "globex"] {
        let req = request(tenant, "mallory", "memory.ingest", "r-2");
        assert_eq!(
            d.admit(Call {
                actor: &mallory,
                request: &req,
                model: "claude-opus",
                cost_tokens: 10,
                variant: None,
            })
            .refusal(),
            Some(&Refusal::TenantNotOwnedByOrg),
            "initech must not reach memorithm's {tenant}"
        );
        assert_eq!(d.spent(tenant), Some(0), "{tenant} was not billed");
    }
    assert_eq!(d.spent("hooli"), Some(10), "nor was her own tenant");

    // The victim's trail shows the attempt, refused and unbilled.
    let trail = d.audit_of("acme");
    assert_eq!(trail.len(), 1);
    assert_eq!(
        trail[0].outcome.refusal(),
        Some(&Refusal::TenantNotOwnedByOrg)
    );
    assert_eq!(trail[0].cost, 0);
}

/// Identifiers arriving from the wire are bounded before they are compared,
/// resolved or journaled — the regression guard for a free memory-amplifier.
///
/// The gateway bounded tool names; nothing bounded the tenant, actor or
/// request_id. A caller who could not authenticate at all could still make
/// every audit record a megabyte wide, and the record was written *after* the
/// refusal, so the cheapest possible refusal was also the most expensive one
/// to journal. Malformed identifiers are now refused first, naming the field
/// ([`Refusal::MalformedRequest`]), and anything that does reach a record is
/// clamped.
#[test]
fn oversized_or_empty_identifiers_are_refused_before_any_gate() {
    let mut d = two_tenant_deployment();
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let huge = "t".repeat(4_096);

    let cases = [
        ("tenant", request(&huge, "alice", "memory.recall", "r-1")),
        ("actor", request("acme", &huge, "memory.recall", "r-2")),
        (
            "request_id",
            request("acme", "alice", "memory.recall", &huge),
        ),
        ("tenant", request("", "alice", "memory.recall", "r-4")),
        ("actor", request("acme", "", "memory.recall", "r-5")),
        ("request_id", request("acme", "alice", "memory.recall", "")),
    ];
    for (field, req) in &cases {
        assert_eq!(
            d.admit(Call {
                actor: &alice,
                request: req,
                model: "claude-opus",
                cost_tokens: 10,
                variant: None,
            })
            .refusal(),
            Some(&Refusal::MalformedRequest((*field).to_string())),
            "a malformed {field} is refused, and says which field"
        );
    }
    assert_eq!(d.spent("acme"), Some(0), "no malformed call was billed");

    // The bound is exact rather than a blanket refusal of long names: a name
    // at the limit is well formed, it simply names no tenant here.
    let at_limit = "t".repeat(MAX_IDENTIFIER_BYTES);
    let req = request(&at_limit, "alice", "memory.recall", "r-limit");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::UnknownTenant),
        "{MAX_IDENTIFIER_BYTES} bytes is well formed, just unknown"
    );
    let over = "t".repeat(MAX_IDENTIFIER_BYTES + 1);
    let req = request(&over, "alice", "memory.recall", "r-over");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::MalformedRequest("tenant".to_string())),
        "one byte over is not"
    );

    // Nothing hostile survives into the journal at its original size.
    assert!(
        d.audit().all(|r| r.tenant.len() <= MAX_IDENTIFIER_BYTES
            && r.actor.len() <= MAX_IDENTIFIER_BYTES
            && r.request_id.len() <= MAX_IDENTIFIER_BYTES),
        "every journaled identifier is clamped"
    );
}

/// A flood of refused calls cannot grow the audit journal without bound — the
/// regression guard for the cheapest denial of service in the product.
///
/// The journal was an unbounded `Vec` appended to *after* every decision,
/// including refusals, so a caller who never authenticated once still made the
/// deployment retain a record per attempt: 1.15 GiB across five million
/// refused calls, from a principal the product had already rejected. The
/// buffer is now bounded, drops oldest-first, counts exactly what it dropped,
/// and keeps the newest window intact and in order.
#[test]
fn a_refusal_flood_cannot_grow_the_journal_without_bound() {
    const CAPACITY: usize = 64;
    const CALLS: u64 = 5_000;

    let mut d = two_tenant_deployment().with_audit_capacity(CAPACITY);
    d.require_strength(AuthStrength::Strong);
    // A principal that cannot meet the deployment's proof requirement at all.
    let nobody = actor("memorithm", "nobody", AuthStrength::Token);

    for i in 0..CALLS {
        let req = request("acme", "nobody", "memory.recall", &format!("r-{i}"));
        assert_eq!(
            d.admit(Call {
                actor: &nobody,
                request: &req,
                model: "claude-opus",
                cost_tokens: 10,
                variant: None,
            })
            .refusal(),
            Some(&Refusal::Unauthenticated)
        );
    }

    assert_eq!(
        d.audit().count(),
        CAPACITY,
        "the journal never grows past its cap"
    );
    assert_eq!(
        d.audit_dropped(),
        CALLS - CAPACITY as u64,
        "and it says exactly how much of the trail it lost"
    );
    let sequences: Vec<u64> = d.audit().map(|r| r.sequence).collect();
    assert_eq!(
        sequences,
        (CALLS - CAPACITY as u64..CALLS).collect::<Vec<_>>(),
        "the retained window is the newest, still in decision order"
    );
    assert!(
        d.audit().all(|r| r.cost == 0),
        "and not one of them was billed"
    );
    assert_eq!(d.spent("acme"), Some(0));

    let metrics: BTreeMap<String, u64> = d.metrics().into_iter().collect();
    assert_eq!(
        metrics.get("audit.dropped").copied(),
        Some(CALLS - CAPACITY as u64),
        "the loss is announced on a counter, not only on a getter"
    );
    assert_eq!(
        metrics.get("gateway.refused.unauthenticated").copied(),
        Some(CALLS)
    );
}

/// Restore gates: a manifest from the future, a forged digest, or an empty
/// backup are all refused. A backup that cannot verify itself is not a
/// backup (`docs/BACKUP_AND_RESTORE.md`).
#[test]
fn restore_refuses_forged_future_and_empty_manifests() {
    const BUILD_SCHEMA: u32 = 3;
    let good = BackupManifest {
        tenant: "acme".into(),
        created_unix: 1_700_000_000,
        digest: "ab".repeat(32),
        segments: 12,
        schema_version: 3,
    };
    assert!(good.restorable_by(BUILD_SCHEMA).is_ok());

    // Newer schema than this build understands → refuse rather than guess.
    let mut future = good.clone();
    future.schema_version = BUILD_SCHEMA + 1;
    assert!(future.restorable_by(BUILD_SCHEMA).is_err());

    // Digest shapes an attacker might try.
    for forged in [
        "".to_string(),
        "z".repeat(64),
        "AB".repeat(32),
        "ab".repeat(31),
        format!("{} ", "ab".repeat(32).trim()),
    ] {
        let mut bad = good.clone();
        bad.digest = forged.clone();
        assert!(
            bad.restorable_by(BUILD_SCHEMA).is_err(),
            "digest {forged:?} must be refused"
        );
    }

    // An empty backup restores nothing and must say so.
    let mut empty = good;
    empty.segments = 0;
    assert!(empty.restorable_by(BUILD_SCHEMA).is_err());
}

/// Administrative acts are journaled before they are effects, and the
/// sensitive ones do not proceed on a blank justification
/// (`docs/HUMAN_APPROVAL_POLICIES.md`: "Unrecorded approval = denial").
#[test]
fn sensitive_admin_acts_need_a_real_justification() {
    let act = |action: &str, justification: Option<&str>| AdminAction {
        actor: "ZEKRITI Tarek".into(),
        action: action.into(),
        target: "acme".into(),
        unix_time: 1_700_000_000,
        justification: justification.map(str::to_string),
    };

    for action in [
        "tenant.delete",
        "tenant.suspend",
        "quota.override",
        "policy.disable",
        "license.revoke",
    ] {
        assert!(
            validate(&act(action, None)).is_err(),
            "{action} without one"
        );
        assert!(validate(&act(action, Some(""))).is_err(), "{action} blank");
        assert!(
            validate(&act(action, Some("   \t"))).is_err(),
            "{action} spaces"
        );
        assert!(
            validate(&act(action, Some("contract terminated 2026-07-01"))).is_ok(),
            "{action} with a written reason"
        );
    }

    // An act missing its subject is refused whatever the justification.
    let mut headless = act("tenant.delete", Some("because"));
    headless.target = String::new();
    assert!(validate(&headless).is_err());
    let mut anonymous = act("tenant.delete", Some("because"));
    anonymous.actor = String::new();
    assert!(validate(&anonymous).is_err());
}

/// A hostile client cannot blow up the metrics registry: unbounded label
/// cardinality folds into `overflow` rather than exhausting memory, and the
/// export stays ordered and readable.
#[test]
fn metric_label_explosion_stays_bounded_and_ordered() {
    let mut r = CounterRegistry::default();
    for i in 0..CounterRegistry::MAX_SERIES + 5_000 {
        r.inc(&format!("attacker.series.{i}"), 1);
    }
    assert!(
        r.series() <= CounterRegistry::MAX_SERIES + 1,
        "series count stays bounded"
    );
    assert!(
        r.get("overflow") >= 5_000,
        "the excess is accounted, not lost"
    );

    let export = r.export();
    let names: Vec<&str> = export.iter().map(|(n, _)| *n).collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted, "export order is deterministic");
    assert_eq!(export.len(), r.series());
}

/// A tenant deleted from the deployment stops being reachable immediately —
/// no cached state keeps answering for it, and the meter now says so.
///
/// `spent()` used to answer a bare `0` for a tenant this deployment does not
/// have, which is exactly what a healthy idle tenant answers: a departed or
/// misspelled tenant read as a live one on every dashboard built on it. It
/// returns `None` now, so "gone" and "quiet" are different facts.
#[test]
fn a_call_naming_a_departed_tenant_is_refused() {
    let mut d = two_tenant_deployment();
    let alice = actor("memorithm", "alice", AuthStrength::Token);

    let req = request("acme", "alice", "memory.recall", "r-1");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
        }),
        Outcome::Forwarded
    );
    assert_eq!(d.spent("acme"), Some(10));

    // A tenant that was never provisioned is refused the same way a deleted
    // one would be: the deployment is the only source of truth.
    let req = request("acme-old", "alice", "memory.recall", "r-2");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::UnknownTenant)
    );
    assert_eq!(
        d.spent("acme-old"),
        None,
        "a tenant that is not here is not a tenant that spent nothing"
    );
    assert_eq!(d.spent("globex"), Some(0), "which is what this one is");
}
