//! Micro-benchmarks for the governed admission path.
//!
//! Every Enterprise call pays `Deployment::admit`: nine gates, a replay
//! lookup, a budget charge and an audit append. These benches pin that cost
//! down so a regression cannot hide:
//!
//! * `forwarded_full_nine_gates` — the full happy path against one tenant.
//! * `replay_hit_saturated_memory` — the replay-suppression lookup while the
//!   memory sits at its bound: the worst-case membership probe.
//! * `refused_unknown_tenant` — the cheapest refusal; bounds how much of the
//!   path a prober can force the deployment to run.
//!
//! Run with `cargo bench -p ccos-enterprise-runtime`.

use std::hint::black_box;
use std::time::{SystemTime, UNIX_EPOCH};

use criterion::{criterion_group, criterion_main, Criterion};

use ccos_enterprise_auth::{
    issue_identity_token, AuthStrength, Authenticator, IdentityClaims, TokenAuthenticator,
    IDENTITY_TOKEN_VERSION,
};
use ccos_enterprise_runtime::{request, Call, Deployment, Outcome, Refusal, TenantState};

/// One verified identity, minted through the production path: a signed token
/// checked by the shipped verifier. The benches therefore never touch a
/// constructor production builds cannot compile.
fn verified_actor() -> ccos_enterprise_auth::AuthenticatedActor {
    const SEED: [u8; 32] = [9u8; 32];
    let signing = ed25519_dalek::SigningKey::from_bytes(&SEED);
    let mut verifier = TokenAuthenticator::new("bench-aud", AuthStrength::Token);
    assert!(verifier.add_issuer("bench-key", signing.verifying_key()));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is sane")
        .as_secs();
    let claims = IdentityClaims {
        version: IDENTITY_TOKEN_VERSION,
        jti: "bench-actor".into(),
        org: "memorithm".into(),
        actor: "alice".into(),
        audience: "bench-aud".into(),
        issued_at: now,
        expires_at: now + 3600,
        not_before: None,
    };
    let token = issue_identity_token(&SEED, "bench-key", &claims).expect("token issues");
    verifier
        .authenticate(&token, now)
        .expect("bench identity verifies")
}

/// One writer identity, one tenant, one allowed model: the smallest
/// deployment whose happy path exercises every gate.
fn single_tenant_deployment() -> Deployment {
    let mut d = Deployment::new();
    d.add_role("writer", &["memory.read", "memory.write"])
        .govern_tool("memory.ingest", "memory.write")
        .govern_tool("memory.recall", "memory.read");
    let mut tenant = TenantState::new(u64::MAX);
    tenant.allow_model("claude-opus");
    assert!(d.add_tenant("memorithm", "acme", tenant));
    assert!(d.assign("alice", "writer"));
    d
}

fn admit_forwarded(c: &mut Criterion) {
    let mut group = c.benchmark_group("admission");
    let mut d = single_tenant_deployment();
    let alice = verified_actor();
    // A budget ceiling means the charge gate stays on the path without ever
    // tripping, exactly as in production traffic.
    let mut i = 0u64;
    group.bench_function("forwarded_full_nine_gates", |b| {
        b.iter(|| {
            i += 1;
            let req = request(
                black_box("acme"),
                black_box("alice"),
                black_box("memory.ingest"),
                black_box(&format!("bench-{i}")),
            );
            let outcome = d.admit(Call {
                actor: &alice,
                request: &req,
                model: "claude-opus",
                cost_tokens: 1,
                variant: None,
                justification: None,
            });
            assert!(outcome.is_forwarded());
        })
    });
    group.finish();
}

fn admit_refusal_and_replay(c: &mut Criterion) {
    let mut group = c.benchmark_group("admission");
    // No audit buffer: this bench isolates the decision path from buffer
    // bookkeeping, and replay memory is small enough to fill quickly but
    // large enough that structure costs are real.
    let mut d = single_tenant_deployment()
        .with_audit_capacity(0)
        .with_replay_memory(4096);
    let alice = verified_actor();
    for i in 0..4096 {
        let req = request("acme", "alice", "memory.ingest", &format!("fill-{i}"));
        assert_eq!(
            d.admit(Call {
                actor: &alice,
                request: &req,
                model: "claude-opus",
                cost_tokens: 0,
                variant: None,
                justification: None,
            }),
            Outcome::Forwarded
        );
    }
    let replayed_request = request("acme", "alice", "memory.ingest", "fill-0");
    group.bench_function("replay_hit_saturated_memory", |b| {
        b.iter(|| {
            let outcome = d.admit(Call {
                actor: &alice,
                request: black_box(&replayed_request),
                model: "claude-opus",
                cost_tokens: 1,
                variant: None,
                justification: None,
            });
            assert!(outcome.is_replayed(), "the probe must be a replay hit");
        })
    });

    let probed_request = request("nowhere", "alice", "memory.ingest", "probe");
    group.bench_function("refused_unknown_tenant", |b| {
        b.iter(|| {
            let outcome = d.admit(Call {
                actor: &alice,
                request: black_box(&probed_request),
                model: "claude-opus",
                cost_tokens: 1,
                variant: None,
                justification: None,
            });
            assert_eq!(
                outcome.refusal(),
                Some(&Refusal::UnknownTenant),
                "the probe must be refused at gate 3"
            );
        })
    });
    group.finish();
}

criterion_group!(benches, admit_forwarded, admit_refusal_and_replay);
criterion_main!(benches);
