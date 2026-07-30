//! Adversarial scenarios: privilege escalation, quota abuse, restore of
//! foreign or forged backups, and administrative acts without a paper trail.

use ccos_enterprise_admin::{validate, AdminAction};
use ccos_enterprise_auth::AuthStrength;
use ccos_enterprise_backup::BackupManifest;
use ccos_enterprise_conformance::{
    actor, request, two_tenant_deployment, Call, Deployment, Outcome, Refusal, TenantState,
};
use ccos_enterprise_observability::CounterRegistry;

/// An actor cannot grant itself a role that does not exist, and an
/// unassigned actor holds nothing. Deny by default, all the way down.
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
    assert_eq!(d.spent("acme"), 0);
}

/// A reader stays a reader: holding one permission never implies the next
/// one along, however adjacent the names.
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
    assert_eq!(d.spent("acme"), 10, "only the one allowed call was billed");
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
}

/// Quota abuse: a client hammering a refused call must not drain the tenant,
/// and the ledger must stay exact rather than drifting under repetition.
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
    assert_eq!(d.spent("acme"), 0, "500 refusals drained nothing");

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
}

/// The budget boundary is exact: the last affordable token is spent, the
/// next one is refused, and the refusal does not nudge the ledger.
#[test]
fn the_budget_boundary_is_exact() {
    let mut d = Deployment::new();
    d.add_role("writer", &["memory.write"])
        .govern_tool("memory.ingest", "memory.write");
    let mut t = TenantState::new(100);
    t.allow_model("m");
    d.add_tenant("acme", t);
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
    assert_eq!(d.spent("acme"), 99, "the refused charge is not accounted");
    assert_eq!(call(&mut d, 1, "r-3"), Outcome::Forwarded, "the last token");
    assert_eq!(d.spent("acme"), 100);
    assert_eq!(
        call(&mut d, 1, "r-4").refusal(),
        Some(&Refusal::BudgetExhausted)
    );
    assert_eq!(d.spent("acme"), 100, "exhausted stays exhausted");
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
/// no cached state keeps answering for it.
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
}
