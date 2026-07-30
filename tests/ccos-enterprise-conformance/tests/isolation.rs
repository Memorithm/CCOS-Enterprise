//! Tenant isolation: the promise `docs/TENANT_MEMORY_ISOLATION.md` makes —
//! "a recall under tenant A must return zero tenant-B nodes" — exercised on
//! the composed path rather than asserted about types.

use std::sync::{Arc, Mutex};

use ccos_enterprise_auth::AuthStrength;
use ccos_enterprise_conformance::{
    actor, request, two_tenant_deployment, Call, Deployment, Outcome, Refusal, TenantState,
};
use ccos_enterprise_tenancy::{TenantId, TenantScope};

fn scope(tenant: &str, key: &str) -> TenantScope<String> {
    TenantScope::new(TenantId(tenant.to_string()), key.to_string())
}

/// The same inner key under two tenants names two different cells. This is
/// the "no shared caches keyed without tenant" rule, tested rather than
/// trusted.
#[test]
fn identical_keys_under_two_tenants_never_collide() {
    let mut d = two_tenant_deployment();
    d.put(&scope("acme", "memory-root"), "acme's private note");
    d.put(&scope("globex", "memory-root"), "globex's private note");

    assert_eq!(
        d.get(&scope("acme", "memory-root")),
        Some("acme's private note")
    );
    assert_eq!(
        d.get(&scope("globex", "memory-root")),
        Some("globex's private note")
    );

    // Everything visible to each tenant, and nothing more.
    assert_eq!(
        d.cells_of("acme"),
        vec![("memory-root", "acme's private note")]
    );
    assert_eq!(
        d.cells_of("globex"),
        vec![("memory-root", "globex's private note")]
    );
}

/// A tenant that never wrote a key cannot read it, however well it guesses
/// the name — the miss is a miss, not a fallback to some global pool.
#[test]
fn a_tenant_cannot_read_what_another_wrote() {
    let mut d = two_tenant_deployment();
    d.put(&scope("acme", "secret"), "the acme secret");
    d.put(&scope("acme", "invoice-2026"), "€120,000");

    for guess in ["secret", "invoice-2026", "memory-root", ""] {
        assert_eq!(
            d.get(&scope("globex", guess)),
            None,
            "globex must not reach acme's '{guess}'"
        );
    }
    assert!(
        d.cells_of("globex").is_empty(),
        "globex sees nothing of acme's"
    );
}

/// Crossing tenants requires building a new scope — it cannot happen by
/// forgetting one. `rescope` is the deliberate, auditable act.
#[test]
fn crossing_tenants_is_explicit_and_visible() {
    let mut d = two_tenant_deployment();
    let acme_root = scope("acme", "memory-root");
    d.put(&acme_root, "acme data");

    let crossed = acme_root.clone().rescope(TenantId("globex".into()));
    assert_eq!(crossed.tenant, TenantId("globex".into()));
    assert_eq!(crossed.inner, acme_root.inner, "same cell name…");
    assert_eq!(d.get(&crossed), None, "…but a different, empty cell");
}

/// Budgets do not leak either: exhausting one tenant leaves the other whole.
#[test]
fn exhausting_one_tenants_budget_leaves_the_other_untouched() {
    let mut d = two_tenant_deployment();
    d.tenant_mut("globex").unwrap().allow_model("claude-opus");
    let alice = actor("memorithm", "alice", AuthStrength::Token);

    // Drain acme (limit 1_000 in the fixture).
    let req = request("acme", "alice", "memory.recall", "r-drain");
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
    let req = request("acme", "alice", "memory.recall", "r-over");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::BudgetExhausted)
    );

    // globex is unaffected.
    let req = request("globex", "alice", "memory.recall", "r-other");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 400,
            variant: None,
        }),
        Outcome::Forwarded
    );
    assert_eq!(d.spent("acme"), 1_000);
    assert_eq!(d.spent("globex"), 400);
}

/// Model governance is per tenant: the model acme allows is not the model
/// globex allows, and neither inherits the other's.
#[test]
fn model_allowlists_do_not_leak_between_tenants() {
    let mut d = two_tenant_deployment();
    let alice = actor("memorithm", "alice", AuthStrength::Token);

    // acme allows claude-opus only; globex allows gpt-5 only.
    let req = request("acme", "alice", "memory.recall", "r-1");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "gpt-5",
            cost_tokens: 10,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::ModelNotAllowed)
    );
    let req = request("globex", "alice", "memory.recall", "r-2");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::ModelNotAllowed)
    );
}

/// Concurrency: many tenants driven from many threads must not contaminate
/// one another's accounting or audit trail. Isolation that only holds
/// single-threaded is not isolation.
#[test]
fn concurrent_tenants_do_not_contaminate_each_other() {
    const TENANTS: usize = 8;
    const CALLS: u64 = 25;
    const COST: u64 = 10;

    let mut d = Deployment::new();
    d.add_role("writer", &["memory.write"])
        .govern_tool("memory.ingest", "memory.write");
    for i in 0..TENANTS {
        let mut t = TenantState::new(CALLS * COST);
        t.allow_model("claude-opus");
        d.add_tenant(&format!("tenant-{i}"), t);
        d.assign(&format!("agent-{i}"), "writer");
    }
    let deployment = Arc::new(Mutex::new(d));

    let handles: Vec<_> = (0..TENANTS)
        .map(|i| {
            let deployment = Arc::clone(&deployment);
            std::thread::spawn(move || {
                let who = actor("memorithm", &format!("agent-{i}"), AuthStrength::Token);
                for c in 0..CALLS {
                    let req = request(
                        &format!("tenant-{i}"),
                        &format!("agent-{i}"),
                        "memory.ingest",
                        &format!("r-{i}-{c}"),
                    );
                    let outcome = deployment.lock().unwrap().admit(Call {
                        actor: &who,
                        request: &req,
                        model: "claude-opus",
                        cost_tokens: COST,
                        variant: None,
                    });
                    assert_eq!(outcome, Outcome::Forwarded, "tenant-{i} call {c}");
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("no thread panicked");
    }

    let d = deployment.lock().unwrap();
    for i in 0..TENANTS {
        let tenant = format!("tenant-{i}");
        assert_eq!(
            d.spent(&tenant),
            CALLS * COST,
            "{tenant} was billed exactly its own calls"
        );
        let trail = d.audit_of(&tenant);
        assert_eq!(
            trail.len() as u64,
            CALLS,
            "{tenant} journaled its own calls"
        );
        assert!(
            trail.iter().all(|r| r.actor == format!("agent-{i}")),
            "{tenant}'s trail contains only its own actor"
        );
    }
    assert_eq!(
        d.audit().len() as u64,
        TENANTS as u64 * CALLS,
        "no record lost"
    );
}
