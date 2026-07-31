//! # Hostile concurrency chaos over the composed governed path
//!
//! Every other file in this suite drives `Deployment` from one thread. That is
//! not how a multi-tenant gateway is used, and it is not where a governance
//! layer fails. This file asks the questions that only exist once 32 threads
//! share one deployment:
//!
//! * does the **ledger** still equal what the product itself said it forwarded,
//!   when the calls that drained it were interleaved by the scheduler?
//! * is every admission journaled **exactly once** — no lost record, no double
//!   record — under contention?
//! * can a tenant's actor, cells or budget reach another tenant's when the
//!   writes overlap?
//! * do the **standalone types** (`CounterRegistry`, `RoleBook`, `TokenBudget`)
//!   still produce the single-threaded answer when 32 threads run the same
//!   script on private instances?
//! * and does anything **deadlock**? (Nothing here can hang: every concurrent
//!   test is armed with a watchdog that `abort()`s the binary, which libtest
//!   reports as a failure. Verified against a real self-deadlock.)
//!
//! The op sequences are fixed before a single thread starts — one seeded
//! SplitMix64 stream per thread, shuffled deterministically, request ids
//! assigned by position. **Only the interleaving is nondeterministic**, which
//! is exactly the variable under test. Ten pinned probes per thread are
//! constructed so that their outcome is a function of one gate and of nothing
//! any other thread can do (`ghost` is never a tenant, `context.read` is never
//! governed, `<t>/nobody` is never assigned, `never-allowed` is never
//! allowlisted, `ExperimentalBridge` is never activated, `t-zero`'s limit is 0)
//! — so all eight refusal kinds *and* forwarding are guaranteed on every run,
//! whatever the scheduler does.
//!
//! Measured on the default run: **135 680 operations across 32 threads**,
//! 84 662 admissions (13 695 forwarded, 70 967 refused across all eight
//! kinds), 51 018 state-changing operations, 7 tenants — 1.7 s in debug,
//! 0.5 s in release. The `#[ignore]`d soak repeats it at 10x
//! (**1 356 800 operations**, 846 086 admissions, 19 s).
//!
//! ## What held
//!
//! * **The ledger is exact under contention.** `spent(t)` equalled the sum of
//!   the costs of the calls the product itself journaled as `Forwarded`, for
//!   every tenant, on every run. Three pinned races prove the edges:
//!   an **exact-fit** budget (768 one-token calls from 32 threads against a
//!   768-token limit) was consumed to the last token with all 768 forwarded —
//!   no lost update; a **contended** budget (768 racers, 384 tokens) admitted
//!   exactly 384 and refused exactly 384 with `BudgetExhausted` — no
//!   overdraft, not by one token, ever; a **zero** budget refused all 768.
//!   Two organically drained tenants landed on 8 000/8 000 exactly.
//! * **The journal is exactly one row per admission, no duplicates, no
//!   losses.** 84 662 admissions produced 84 662 rows carrying 84 662
//!   *distinct* request ids.
//! * **The counters agree with the journal to the unit** — `requests ==
//!   forwarded + refused`, both equal to the journal's own tallies, the eight
//!   `gateway.refused.*` series summing to `refused` — and the series set
//!   stays at exactly 11 names however hostile the input.
//! * **Isolation holds for data.** No tenant's audit trail ever named another
//!   tenant's actor; no tenant's cells ever held another tenant's value; the
//!   unknown tenant was never billed. `t-race`'s tokens were won by all 32
//!   threads (pigeonhole floor 16): a plain `Mutex` did not starve anyone.
//! * **Concurrency does not change outcomes.** 32 threads replaying the same
//!   5 322-op script on private `CounterRegistry` / `RoleBook` /
//!   `TokenBudget` instances produced results byte-identical to a
//!   single-threaded replay — every intermediate observation, not just the
//!   final state — including the `MAX_SERIES = 4096` fold, the counter pinned
//!   at `u64::MAX`, `assign`'s fail-closed refusals, `add_role`'s silent
//!   replacement, and `TokenBudget`'s saturating ledger at `limit == u64::MAX`.
//!   Every container in the product is a `BTree*`; there is no hash seed, no
//!   clock and no interior nondeterminism to shake loose.
//! * **No deadlock, no livelock, no panic.** 12 consecutive runs, debug and
//!   release, all green; the watchdog never fired outside its own self-check.
//!
//! ## What BROKE
//!
//! 1. **Replay determinism does not survive concurrency, and the journal
//!    cannot recover it.** `docs/ENTERPRISE_SECURITY_MODEL.md` ends with
//!    "Enterprise ADDS gates; it never WEAKENS a Core guarantee (determinism,
//!    replay, …)". Feed the composed path the *identical* call set from two
//!    threads and the journal depends entirely on which reached the lock
//!    first — different order, different outcomes, different billing — while
//!    `AuditRecord` (`src/lib.rs:96-102`) carries **no sequence number, no
//!    timestamp, no thread or connection id**. The `Vec`'s position is the
//!    only ordering information that exists, and `audit_of`
//!    (`src/lib.rs:343-345`) discards even that. Neither journal can be
//!    replayed to reproduce the other.
//!    → [`one_call_set_produces_two_different_journals_under_two_interleavings`]
//!
//! 2. **The journal is self-colliding under concurrency.** 32 threads issuing
//!    the byte-identical call produce 32 records that compare `==` in every
//!    field. All 32 were separately billed (`request_id` is documented as an
//!    "Idempotency/correlation key",
//!    `crates/ccos-enterprise-gateway/src/lib.rs:16`, and nothing reads it —
//!    the replay half of this is pinned by `stress_endurance` and
//!    `stress_budget_property`; what is new here is that concurrency makes the
//!    rows *indistinguishable*, so an operator cannot even count callers).
//!    → [`identical_concurrent_calls_produce_indistinguishable_audit_records`]
//!
//! 3. **Governance changes race the admissions they govern, and nothing
//!    records them.** 51 018 of the storm's 135 680 operations —
//!    `put`, `assign`, `allow_model`, `activate` — produced **zero** audit
//!    records and **zero** counters. The staged test shows the consequence:
//!    two admissions identical but for their request id, the first
//!    `ModelNotAllowed` and the second `Forwarded`, with a journal of exactly
//!    two rows and nothing at all explaining the flip.
//!    `tenant_mut(..).allow_model(..)` (`src/lib.rs:195`, `src/lib.rs:121`)
//!    returns `&mut Self`, needs no identity, no permission and no
//!    `ccos_enterprise_admin::AdminAction` justification.
//!    → [`a_concurrent_governance_change_flips_an_outcome_and_the_journal_cannot_explain_it`]
//!
//! 4. **There is no atomic snapshot of the product's own accounting.**
//!    `spent` (`src/lib.rs:331`), `audit`/`audit_of` (`src/lib.rs:338`,
//!    `:343`) and `metrics` (`src/lib.rs:348`) are three separate calls on
//!    three separate borrows. An operator reconciling them the obvious way —
//!    one `lock()` per read — reports a tenant as under-billed by a whole
//!    call, deterministically, although the deployment was never once
//!    internally inconsistent. The product ships the hazard and no API that
//!    avoids it.
//!    → [`ledger_and_journal_tear_when_read_in_separate_lock_acquisitions`]
//!
//! 5. **Zero per-tenant concurrency, and a deployment-wide blast radius.**
//!    Every mutator — `admit`, `put`, `assign`, `tenant_mut`, `add_tenant`,
//!    `add_role`, `govern_tool` — takes `&mut self`, and `Deployment` has no
//!    interior mutability and hands out no per-tenant handle. The only sound
//!    topology is one exclusive lock over the whole deployment, so tenant A's
//!    admission blocks tenant B's, and a single panic under that lock denies
//!    service to **every** tenant at once. There is no recovery path in the
//!    product: no `Clone`, no serialization, no snapshot/restore, and nothing
//!    that records that it happened — after `PoisonError::into_inner()` the
//!    deployment carries on with an unchanged journal and unchanged counters.
//!    The unbounded audit `Vec` that every refused call grows (1.1 GiB after
//!    5M calls, measured by `stress_endurance`) is a real allocation-failure
//!    site under exactly that lock.
//!    → [`one_panic_under_the_global_lock_denies_service_to_every_tenant`],
//!    [`composed_path_types_are_send_and_sync_but_every_mutator_is_exclusive`]
//!
//! 6. **Cross-tenant work amplification, paid under the shared lock.**
//!    `audit_of` filters the entire journal, so a tenant that has never made a
//!    call still pays a full scan of every other tenant's traffic — while
//!    holding the one lock every other tenant's admissions need. Tenant A's
//!    volume is tenant B's latency: the isolation the product proves for data
//!    does not exist in the time domain. (`cells_of`'s scan cost is pinned by
//!    `stress_tenancy_fuzz`; that it is paid under the global lock is the part
//!    that only concurrency exposes.)
//!    → [`audit_of_a_silent_tenant_walks_the_whole_global_trail`]
//!
//! 7. **The journal cannot reconcile the ledger on its own.** `AuditRecord`
//!    records the tool but not the cost, so "what was tenant X billed for?"
//!    is unanswerable from the trail. Invariant 2 below is only checkable
//!    because *this test* keeps a side table of `request_id → cost` that the
//!    product does not.
//!
//! ## Not re-litigated here (siblings own them)
//!
//! Authorization keys on the request-supplied actor string rather than the
//! authenticated identity, and `RoleBook` grants are deployment-global rather
//! than tenant-scoped (`stress_rbac_scale`); `put`/`get`/`cells_of` are
//! reachable with no identity and no audit record (`stress_tenancy_fuzz`);
//! `request_id` replays are billed (`stress_endurance`,
//! `stress_budget_property`); the audit `Vec` is unbounded in length and in
//! per-record size (`stress_endurance`). The storm's invariants hold here
//! *because its threads are well behaved* — each is bound to one tenant and
//! uses tenant-qualified actor names — not because the product would stop a
//! thread that was not.
//!
//! Run: `cargo test -p ccos-enterprise-conformance --test stress_concurrency_chaos`
//! (add `-- --nocapture` for the measured tables, `-- --ignored` for the soak).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use ccos_enterprise_auth::AuthStrength;
use ccos_enterprise_conformance::{
    actor, request, two_tenant_deployment, Call, Deployment, Outcome, Refusal, TenantState,
};
use ccos_enterprise_observability::CounterRegistry;
use ccos_enterprise_policy::{PolicyDecision, TokenBudget};
use ccos_enterprise_qpages::{AdvancedQPageVariant, QPageRegistry};
use ccos_enterprise_rbac::{Permission, Role, RoleBook};
use ccos_enterprise_tenancy::{TenantId, TenantScope};

// ─────────────────────────────────────────────────────────────────────────────
// Determinism kit: a seeded PRNG, so every thread's *op sequence* is fixed
// before a single thread starts. Only the interleaving is nondeterministic.
// ─────────────────────────────────────────────────────────────────────────────

/// SplitMix64. Fixed seed in, fixed stream out, in debug and release alike.
struct Rng(u64);

impl Rng {
    fn seeded(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        debug_assert!(n > 0);
        self.next_u64() % n
    }

    fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[self.below(xs.len() as u64) as usize]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Watchdog: the test binary must not be able to hang. A blocked storm is a
// *failure*, not a timeout, so the watchdog aborts the process — libtest then
// reports the run as failed instead of waiting forever on a poisoned join.
// ─────────────────────────────────────────────────────────────────────────────

struct Watchdog {
    done: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Watchdog {
    fn arm(label: &'static str, seconds: u64) -> Self {
        let done = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&done);
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(seconds);
            while Instant::now() < deadline {
                if flag.load(Ordering::SeqCst) {
                    return;
                }
                thread::sleep(Duration::from_millis(20));
            }
            if !flag.load(Ordering::SeqCst) {
                eprintln!(
                    "WATCHDOG: `{label}` made no progress for {seconds}s — deadlock or livelock \
                     in the governed path. Aborting the test binary."
                );
                std::process::abort();
            }
        });
        Self {
            done,
            handle: Some(handle),
        }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.done.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The storm's fixture
// ─────────────────────────────────────────────────────────────────────────────

const THREADS: usize = 32;
const PINNED_KINDS: usize = 10;

/// The storm's dimensions. Everything derived from it is fixed before a single
/// thread starts; only the interleaving is left to the scheduler.
struct StormConfig {
    threads: usize,
    /// Pinned probes per kind, per thread.
    probe_repeats: usize,
    chaos_ops: usize,
}

impl StormConfig {
    fn ops_per_thread(&self) -> usize {
        self.probe_repeats * PINNED_KINDS + self.chaos_ops
    }

    /// `t-ok`'s budget: exactly one token per forward probe, so the whole
    /// deployment's worth of racers must fit to the token.
    fn exact_fit(&self) -> u64 {
        (self.threads * self.probe_repeats) as u64
    }

    /// `t-race`'s budget: half the racers can win, the rest must be refused.
    fn race_limit(&self) -> u64 {
        self.exact_fit() / 2
    }

    /// Every tenant this deployment knows about, and the budget it starts with.
    /// Two chaos budget regimes on purpose: `t-a`/`t-c` are drained to the
    /// token well before the storm ends, `t-b`/`t-d` never run out — so both
    /// the exhausted and the solvent paths are hammered for the whole run.
    fn tenants(&self) -> Vec<(&'static str, u64)> {
        let tight = self.chaos_ops as u64 * 2;
        let ample = self.chaos_ops as u64 * 60;
        vec![
            ("t-ok", self.exact_fit()),
            ("t-race", self.race_limit()),
            ("t-zero", 0),
            ("t-a", tight),
            ("t-b", ample),
            ("t-c", tight),
            ("t-d", ample),
        ]
    }
}

/// Tenants the chaos ops mutate and bill. Each thread is bound to exactly one
/// of them, so an actor/cell that shows up under another tenant is a leak and
/// not a badly written test.
const CHAOS_TENANTS: &[&str] = &["t-a", "t-b", "t-c", "t-d"];
/// Drained by design (`t-a`, `t-c`) vs. never exhausted (`t-b`, `t-d`).
const TIGHT_TENANTS: &[&str] = &["t-a", "t-c"];
const AMPLE_TENANTS: &[&str] = &["t-b", "t-d"];

const BASE_MODEL: &str = "base-model";
/// Never added to any allowlist, by any op, ever.
const NEVER_ALLOWED_MODEL: &str = "never-allowed";
/// Never activated by any op, ever.
const NEVER_ACTIVE: AdvancedQPageVariant = AdvancedQPageVariant::ExperimentalBridge;
/// Never added by `add_role`, so `assign` must always fail closed on it.
const GHOST_ROLE: &str = "ghost-role";

/// The nine variants chaos may activate — `ExperimentalBridge` is reserved so
/// the `VariantNotActivated` probe stays pinned whatever the interleaving.
const CHAOS_VARIANTS: &[AdvancedQPageVariant] = &[
    AdvancedQPageVariant::Hierarchical,
    AdvancedQPageVariant::CausalChain,
    AdvancedQPageVariant::Probabilistic,
    AdvancedQPageVariant::MultiTenantFederated,
    AdvancedQPageVariant::TemporalWindowed,
    AdvancedQPageVariant::AuthorityWeighted,
    AdvancedQPageVariant::ConsensusMediated,
    AdvancedQPageVariant::CostBounded,
    AdvancedQPageVariant::ComplianceTagged,
];

const CHAOS_TOOLS: &[&str] = &[
    "memory.recall",
    "memory.ingest",
    "policy.set",
    "audit.query",
    "context.read",  // in the catalogue, deliberately never governed
    "memory.purge",  // ditto
    "shell.exec",    // outside the boundary
    "code.execute",  // outside the boundary, matched exactly
    "rsi.status",    // Research Lab namespace
    "system.health", // exposed as a single tool, never governed
];

const CHAOS_ROLES: &[&str] = &["reader", "writer", "operator", GHOST_ROLE];

fn storm_deployment(cfg: &StormConfig) -> Deployment {
    let mut d = Deployment::new();
    d.add_role("reader", &["memory.read"])
        .add_role("writer", &["memory.read", "memory.write"])
        .add_role("operator", &["memory.read", "memory.write", "policy.admin"])
        .govern_tool("memory.recall", "memory.read")
        .govern_tool("memory.ingest", "memory.write")
        .govern_tool("policy.set", "policy.admin")
        .govern_tool("audit.query", "memory.read");

    for (name, limit) in cfg.tenants() {
        let mut st = TenantState::new(limit);
        st.allow_model(BASE_MODEL)
            .activate(AdvancedQPageVariant::Hierarchical);
        d.add_tenant(name, st);
        // Actors are tenant-qualified: `t-a/alice` belongs to `t-a` and to
        // nothing else. Cross-tenant contamination is then a string prefix
        // away from being visible.
        assert!(d.assign(&format!("{name}/alice"), "writer"));
    }
    d
}

// ─────────────────────────────────────────────────────────────────────────────
// The op script
// ─────────────────────────────────────────────────────────────────────────────

/// The refusal a *pinned* probe must produce under every interleaving. Chaos
/// ops carry `None`: their outcome is a genuine function of the interleaving,
/// and only the global invariants constrain them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Forwarded,
    Unauthenticated,
    UnknownTenant,
    OutsideBoundary,
    ToolNotGoverned,
    PermissionDenied,
    ModelNotAllowed,
    VariantNotActivated,
    BudgetExhausted,
}

fn kind_of(o: &Outcome) -> Kind {
    match o {
        Outcome::Forwarded => Kind::Forwarded,
        Outcome::Refused(Refusal::Unauthenticated) => Kind::Unauthenticated,
        Outcome::Refused(Refusal::UnknownTenant) => Kind::UnknownTenant,
        Outcome::Refused(Refusal::OutsideBoundary(_)) => Kind::OutsideBoundary,
        Outcome::Refused(Refusal::ToolNotGoverned) => Kind::ToolNotGoverned,
        Outcome::Refused(Refusal::PermissionDenied) => Kind::PermissionDenied,
        Outcome::Refused(Refusal::ModelNotAllowed) => Kind::ModelNotAllowed,
        Outcome::Refused(Refusal::VariantNotActivated) => Kind::VariantNotActivated,
        Outcome::Refused(Refusal::BudgetExhausted) => Kind::BudgetExhausted,
    }
}

#[derive(Debug, Clone)]
struct AdmitOp {
    tenant: String,
    actor: String,
    tool: String,
    model: String,
    cost: u64,
    variant: Option<AdvancedQPageVariant>,
    strength: AuthStrength,
    request_id: String,
    pinned: Option<Kind>,
}

#[derive(Debug, Clone)]
enum Op {
    Admit(AdmitOp),
    Put {
        tenant: String,
        key: String,
        value: String,
    },
    Get {
        tenant: String,
        key: String,
    },
    Assign {
        actor: String,
        role: &'static str,
    },
    AllowModel {
        tenant: String,
        model: String,
    },
    Activate {
        tenant: String,
        variant: AdvancedQPageVariant,
    },
}

/// The ten pinned probes. Each one is refused (or forwarded) by exactly one
/// gate, and nothing any other thread can do reaches that gate's input:
/// `ghost` is never added as a tenant, `context.read` is never governed,
/// `<t>/nobody` is never assigned a role, `never-allowed` is never allowlisted,
/// `ExperimentalBridge` is never activated, `t-zero`'s limit is 0.
fn pinned_probe(home: &str, which: usize) -> AdmitOp {
    let base = |tenant: &str, who: &str| AdmitOp {
        tenant: tenant.to_string(),
        actor: format!("{tenant}/{who}"),
        tool: "memory.recall".to_string(),
        model: BASE_MODEL.to_string(),
        cost: 1,
        variant: None,
        strength: AuthStrength::Token,
        request_id: String::new(), // filled in after the shuffle
        pinned: None,
    };
    match which {
        // Exact-fit budget: `threads * probe_repeats` calls of 1 token against
        // a limit of exactly that. Every single one must forward.
        0 => AdmitOp {
            pinned: Some(Kind::Forwarded),
            ..base("t-ok", "alice")
        },
        // Contended budget: twice as many racers as tokens. Per-call outcome
        // is a race; the aggregate is pinned (see the storm's assertions).
        1 => base("t-race", "alice"),
        2 => AdmitOp {
            pinned: Some(Kind::BudgetExhausted),
            ..base("t-zero", "alice")
        },
        3 => AdmitOp {
            strength: AuthStrength::Anonymous,
            pinned: Some(Kind::Unauthenticated),
            ..base(home, "alice")
        },
        4 => AdmitOp {
            pinned: Some(Kind::UnknownTenant),
            ..base("ghost", "alice")
        },
        5 => AdmitOp {
            tool: "shell.exec".to_string(),
            pinned: Some(Kind::OutsideBoundary),
            ..base(home, "alice")
        },
        6 => AdmitOp {
            tool: "context.read".to_string(),
            pinned: Some(Kind::ToolNotGoverned),
            ..base(home, "alice")
        },
        7 => AdmitOp {
            pinned: Some(Kind::PermissionDenied),
            ..base(home, "nobody")
        },
        8 => AdmitOp {
            model: NEVER_ALLOWED_MODEL.to_string(),
            pinned: Some(Kind::ModelNotAllowed),
            ..base(home, "alice")
        },
        _ => AdmitOp {
            variant: Some(NEVER_ACTIVE),
            pinned: Some(Kind::VariantNotActivated),
            ..base(home, "alice")
        },
    }
}

fn chaos_op(rng: &mut Rng, tid: usize, home: &str, k: usize) -> Op {
    let worker = format!("{home}/w{tid}-{}", k % 6);
    match rng.below(10) {
        0..=5 => Op::Admit(AdmitOp {
            tenant: home.to_string(),
            actor: worker,
            tool: rng.pick(CHAOS_TOOLS).to_string(),
            model: match rng.below(6) {
                0 => NEVER_ALLOWED_MODEL.to_string(),
                n => format!("chaos-model-{}", n - 1),
            },
            cost: 1 + rng.below(17),
            variant: if rng.below(3) == 0 {
                Some(rng.pick(CHAOS_VARIANTS))
            } else {
                None
            },
            strength: if rng.below(8) == 0 {
                AuthStrength::Anonymous
            } else {
                AuthStrength::Strong
            },
            request_id: String::new(),
            pinned: None,
        }),
        6 => Op::Put {
            tenant: home.to_string(),
            key: format!("cell-{}", rng.below(8)),
            value: format!("{home}#{tid}#{k}"),
        },
        7 => Op::Get {
            tenant: home.to_string(),
            key: format!("cell-{}", rng.below(8)),
        },
        8 => Op::Assign {
            actor: worker,
            role: rng.pick(CHAOS_ROLES),
        },
        _ => match rng.below(2) {
            0 => Op::AllowModel {
                tenant: home.to_string(),
                model: format!("chaos-model-{}", rng.below(5)),
            },
            _ => Op::Activate {
                tenant: home.to_string(),
                variant: rng.pick(CHAOS_VARIANTS),
            },
        },
    }
}

/// One thread's whole future, decided from its fixed seed before any thread
/// starts. The sequence is a function of `(cfg, tid)` and nothing else — no
/// clock, no address, no thread id from the OS.
fn script_for_thread(cfg: &StormConfig, tid: usize) -> Vec<Op> {
    let home = CHAOS_TENANTS[tid % CHAOS_TENANTS.len()];
    let mut rng = Rng::seeded(0x5EED_0000_0000_0001 ^ ((tid as u64 + 1).wrapping_mul(0x9E37_79B9)));

    let mut ops = Vec::with_capacity(cfg.ops_per_thread());
    for _ in 0..cfg.probe_repeats {
        for which in 0..PINNED_KINDS {
            ops.push(Op::Admit(pinned_probe(home, which)));
        }
    }
    for k in 0..cfg.chaos_ops {
        ops.push(chaos_op(&mut rng, tid, home, k));
    }
    // Deterministic Fisher-Yates: the probes are scattered through the chaos,
    // not bunched at the front, so every gate is hit at every phase of the run.
    for i in (1..ops.len()).rev() {
        let j = rng.below((i + 1) as u64) as usize;
        ops.swap(i, j);
    }
    // Request ids are assigned by final position, so they are globally unique
    // and each names exactly one (tenant, cost) pair.
    for (pos, op) in ops.iter_mut().enumerate() {
        if let Op::Admit(a) = op {
            a.request_id = format!("t{tid:02}-{pos:06}");
        }
    }
    assert_eq!(ops.len(), cfg.ops_per_thread());
    ops
}

fn guard(m: &Mutex<Deployment>) -> MutexGuard<'_, Deployment> {
    // Never `unwrap`: one poisoned lock must not turn one thread's failure
    // into 31 more, which would bury the real diagnosis.
    m.lock().unwrap_or_else(|poison| poison.into_inner())
}

fn scope(tenant: &str, key: &str) -> TenantScope<String> {
    TenantScope::new(TenantId(tenant.to_string()), key.to_string())
}

/// What one thread observed. Collected instead of asserted, so a thread never
/// panics and never poisons the deployment other threads are still driving.
#[derive(Default)]
struct ThreadReport {
    admits: usize,
    problems: Vec<String>,
}

fn run_thread(deployment: &Mutex<Deployment>, ops: &[Op], start: &Barrier) -> ThreadReport {
    let mut report = ThreadReport::default();
    // Every thread waits here, so the storm actually overlaps instead of
    // degenerating into 32 sequential runs.
    start.wait();

    for op in ops {
        match op {
            Op::Admit(a) => {
                report.admits += 1;
                let who = actor("memorithm", &a.actor, a.strength);
                let req = request(&a.tenant, &a.actor, &a.tool, &a.request_id);
                let outcome = guard(deployment).admit(Call {
                    actor: &who,
                    request: &req,
                    model: &a.model,
                    cost_tokens: a.cost,
                    variant: a.variant,
                });
                if let Some(expected) = a.pinned {
                    let got = kind_of(&outcome);
                    if got != expected {
                        report.problems.push(format!(
                            "{}: pinned probe expected {expected:?}, got {got:?}",
                            a.request_id
                        ));
                    }
                }
            }
            Op::Put { tenant, key, value } => guard(deployment).put(&scope(tenant, key), value),
            Op::Get { tenant, key } => {
                let d = guard(deployment);
                if let Some(v) = d.get(&scope(tenant, key)) {
                    if !v.starts_with(&format!("{tenant}#")) {
                        report
                            .problems
                            .push(format!("{tenant}/{key} read foreign value {v:?}"));
                    }
                }
            }
            Op::Assign { actor, role } => {
                let ok = guard(deployment).assign(actor, role);
                if *role == GHOST_ROLE && ok {
                    report.problems.push(format!(
                        "{actor} was granted the never-declared {GHOST_ROLE}"
                    ));
                }
                if *role != GHOST_ROLE && !ok {
                    report
                        .problems
                        .push(format!("{actor} was refused the declared role {role}"));
                }
            }
            Op::AllowModel { tenant, model } => {
                let mut d = guard(deployment);
                match d.tenant_mut(tenant) {
                    Some(st) => {
                        st.allow_model(model);
                    }
                    None => report.problems.push(format!("tenant {tenant} vanished")),
                }
            }
            Op::Activate { tenant, variant } => {
                let mut d = guard(deployment);
                match d.tenant_mut(tenant) {
                    Some(st) => {
                        st.activate(*variant);
                    }
                    None => report.problems.push(format!("tenant {tenant} vanished")),
                }
            }
        }
    }
    report
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. The storm
// ═════════════════════════════════════════════════════════════════════════════

/// 32 threads, a fixed op script each, one `Arc<Mutex<Deployment>>`, an
/// interleaving nobody controls — then every global invariant the product
/// claims, checked against the journal the product itself wrote.
fn run_storm(cfg: &StormConfig, label: &'static str, watchdog_secs: u64) {
    let _wd = Watchdog::arm(label, watchdog_secs);

    // ── Everything decided up front, so the run is reproducible ──────────
    let scripts: Vec<Vec<Op>> = (0..cfg.threads)
        .map(|tid| script_for_thread(cfg, tid))
        .collect();

    // The journal does not record what a call cost (`AuditRecord` has no cost
    // field — see the module docs), so reconciling the ledger against the
    // journal is only possible with this side table, which the *test* keeps.
    let mut cost_of: HashMap<String, u64> = HashMap::new();
    let mut tenant_of: HashMap<String, String> = HashMap::new();
    let mut expected_admits = 0usize;
    for script in &scripts {
        for op in script {
            if let Op::Admit(a) = op {
                assert!(
                    cost_of.insert(a.request_id.clone(), a.cost).is_none(),
                    "request ids must be globally unique for this reconciliation"
                );
                tenant_of.insert(a.request_id.clone(), a.tenant.clone());
                expected_admits += 1;
            }
        }
    }
    let total_ops = cfg.threads * cfg.ops_per_thread();

    // ── The storm ────────────────────────────────────────────────────────
    let deployment = Arc::new(Mutex::new(storm_deployment(cfg)));
    let start = Arc::new(Barrier::new(cfg.threads));
    let reports: Vec<ThreadReport> = thread::scope(|s| {
        let handles: Vec<_> = scripts
            .iter()
            .map(|ops| {
                let deployment = Arc::clone(&deployment);
                let start = Arc::clone(&start);
                s.spawn(move || run_thread(&deployment, ops, &start))
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("no thread may panic"))
            .collect()
    });

    let problems: Vec<&String> = reports.iter().flat_map(|r| &r.problems).collect();
    assert!(
        problems.is_empty(),
        "{} in-flight invariant violations, first 8: {:?}",
        problems.len(),
        &problems[..problems.len().min(8)]
    );
    let admits: usize = reports.iter().map(|r| r.admits).sum();
    assert_eq!(admits, expected_admits, "the scripts were executed in full");

    let d = Arc::try_unwrap(deployment)
        .unwrap_or_else(|_| unreachable!("scoped threads are joined"))
        .into_inner()
        .unwrap_or_else(|poison| poison.into_inner());

    // ── Invariant 1: one journal record per admission, and only per
    //    admission. The five *state-changing* op kinds journal nothing. ────
    assert_eq!(
        d.audit().len(),
        admits,
        "every admission is journaled exactly once, whatever the interleaving"
    );
    // DEFECT (documented, not weakened): `put`, `assign`, `allow_model` and
    // `activate` all change what a later admission decides, and none of them
    // leaves a record. The journal cannot explain its own contents.
    assert!(
        admits < total_ops,
        "the storm really did run non-admission operations"
    );
    let unjournaled = total_ops - admits;
    assert_eq!(
        d.audit().len(),
        total_ops - unjournaled,
        "DEFECT: {unjournaled} of {total_ops} governed operations \
         (put/assign/allow_model/activate) left no audit record at all"
    );

    // ── Invariant 2: per-tenant ledger == sum of that tenant's forwarded
    //    costs, reconstructed from the product's own journal. ─────────────
    let mut forwarded_cost: BTreeMap<String, u64> = BTreeMap::new();
    let mut forwarded_count: BTreeMap<String, u64> = BTreeMap::new();
    let mut seen_kinds: BTreeSet<Kind> = BTreeSet::new();
    let mut kind_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut journal_forwarded = 0u64;
    let mut journal_refused = 0u64;
    let mut journaled_ids: BTreeSet<&str> = BTreeSet::new();
    let mut race_winners: BTreeSet<&str> = BTreeSet::new();
    for rec in d.audit() {
        let kind = kind_of(&rec.outcome);
        seen_kinds.insert(kind);
        *kind_counts.entry(format!("{kind:?}")).or_default() += 1;
        journaled_ids.insert(rec.request_id.as_str());
        if rec.tenant == "t-race" && rec.outcome.is_forwarded() {
            // "t07-001234" → "t07": which thread won this token.
            race_winners.insert(&rec.request_id[..3]);
        }
        let cost = *cost_of
            .get(&rec.request_id)
            .expect("every journaled request id came from a script");
        assert_eq!(
            tenant_of.get(&rec.request_id).map(String::as_str),
            Some(rec.tenant.as_str()),
            "a record was journaled under a tenant its request never named"
        );
        if rec.outcome.is_forwarded() {
            journal_forwarded += 1;
            *forwarded_cost.entry(rec.tenant.clone()).or_default() += cost;
            *forwarded_count.entry(rec.tenant.clone()).or_default() += 1;
        } else {
            journal_refused += 1;
        }
    }
    for (tenant, _) in cfg.tenants() {
        assert_eq!(
            d.spent(tenant),
            forwarded_cost.get(tenant).copied().unwrap_or(0),
            "{tenant}: the ledger must equal the journal's forwarded costs"
        );
    }
    // The tenant that does not exist was never billed and cannot be.
    assert_eq!(d.spent("ghost"), 0);
    assert!(!forwarded_cost.contains_key("ghost"));
    // No record lost, none duplicated: `admits` distinct request ids, exactly
    // one journal row each, under an interleaving nobody controlled.
    assert_eq!(
        journaled_ids.len(),
        admits,
        "every admission is journaled once and only once"
    );

    // ── Invariant 3: no tenant's trail contains another tenant's actor ───
    let tenants_in_journal: BTreeSet<&str> = d.audit().iter().map(|r| r.tenant.as_str()).collect();
    for tenant in &tenants_in_journal {
        let prefix = format!("{tenant}/");
        for rec in d.audit_of(tenant) {
            assert!(
                rec.actor.starts_with(&prefix),
                "{tenant}'s trail names {}, which belongs to another tenant",
                rec.actor
            );
            assert_eq!(&rec.tenant, *tenant, "audit_of returned a foreign record");
        }
    }
    assert!(
        tenants_in_journal.contains("ghost"),
        "the unknown-tenant probe is journaled under the tenant it named"
    );

    // ── Invariant 4: no tenant's cells contain another tenant's data ─────
    for (tenant, _) in cfg.tenants() {
        let prefix = format!("{tenant}#");
        for (key, value) in d.cells_of(tenant) {
            assert!(
                value.starts_with(&prefix),
                "{tenant}/{key} holds {value:?}, written by another tenant"
            );
        }
    }
    // Chaos never wrote outside its own tenant, so the tenants that only ever
    // appeared in admissions hold nothing at all.
    for quiet in ["t-ok", "t-race", "t-zero", "ghost"] {
        assert!(d.cells_of(quiet).is_empty(), "{quiet} wrote no cells");
    }

    // ── Invariant 5: metrics == journal, in aggregate and per tag ────────
    let metrics: BTreeMap<String, u64> = d.metrics().into_iter().collect();
    let m = |k: &str| metrics.get(k).copied().unwrap_or(0);
    assert_eq!(m("gateway.requests"), admits as u64, "one count per call");
    assert_eq!(
        m("gateway.requests"),
        m("gateway.forwarded") + m("gateway.refused"),
        "requests == forwarded + refused"
    );
    assert_eq!(m("gateway.forwarded"), journal_forwarded);
    assert_eq!(m("gateway.refused"), journal_refused);
    let tag_total: u64 = metrics
        .iter()
        .filter(|(k, _)| k.starts_with("gateway.refused."))
        .map(|(_, v)| *v)
        .sum();
    assert_eq!(tag_total, m("gateway.refused"), "the tags sum to the total");
    assert_eq!(
        metrics.len(),
        3 + 8,
        "requests/forwarded/refused plus one series per refusal kind, and \
         nothing attacker-shaped: {:?}",
        metrics.keys().collect::<Vec<_>>()
    );

    // ── The mix really covered every gate ───────────────────────────────
    for kind in [
        Kind::Forwarded,
        Kind::Unauthenticated,
        Kind::UnknownTenant,
        Kind::OutsideBoundary,
        Kind::ToolNotGoverned,
        Kind::PermissionDenied,
        Kind::ModelNotAllowed,
        Kind::VariantNotActivated,
        Kind::BudgetExhausted,
    ] {
        assert!(
            seen_kinds.contains(&kind),
            "the storm never produced {kind:?}"
        );
    }

    // ── The measured shape of the storm (`-- --nocapture`) ───────────────
    println!(
        "── {label}: {} threads ─────────────────────────────",
        cfg.threads
    );
    println!("  operations attempted   {total_ops}");
    println!("  admissions             {admits}");
    println!("  journaled records      {}", d.audit().len());
    println!("  unjournaled operations {unjournaled}");
    for (kind, n) in &kind_counts {
        println!("    {kind:<20} {n:>8}");
    }
    for (tenant, limit) in cfg.tenants() {
        println!(
            "  {tenant:<8} spent {:>8} / {limit:<8} forwarded {:>8} records {:>8}",
            d.spent(tenant),
            forwarded_count.get(tenant).copied().unwrap_or(0),
            d.audit_of(tenant).len()
        );
    }

    // ── The pinned budget races, checked in aggregate ────────────────────
    // Exact fit: `threads * probe_repeats` one-token calls against a limit of
    // exactly that, from 32 threads. Every one forwards and the ledger lands
    // exactly on the limit — no lost update, no double spend.
    assert_eq!(d.spent("t-ok"), cfg.exact_fit());
    assert_eq!(forwarded_count.get("t-ok").copied(), Some(cfg.exact_fit()));
    assert!(d.audit_of("t-ok").iter().all(|r| r.outcome.is_forwarded()));
    // Contended: twice as many racers as tokens. Which racers win is a race;
    // *how many* is not, and the tenant is never overdrawn by a single token.
    assert_eq!(
        d.spent("t-race"),
        cfg.race_limit(),
        "no overdraft, no underspend"
    );
    assert_eq!(
        forwarded_count.get("t-race").copied(),
        Some(cfg.race_limit())
    );
    // No thread can monopolise the contended budget beyond the calls its own
    // script contains — the pigeonhole bound below is the strongest fairness
    // statement a plain `Mutex` supports, and it is the one the product gets.
    println!(
        "  t-race won by {} of {} threads (pigeonhole floor {})",
        race_winners.len(),
        cfg.threads,
        cfg.race_limit() as usize / cfg.probe_repeats
    );
    assert!(
        race_winners.len() >= cfg.race_limit() as usize / cfg.probe_repeats,
        "one thread held more slots than it had calls: {} winners",
        race_winners.len()
    );
    assert!(d
        .audit_of("t-race")
        .iter()
        .filter(|r| !r.outcome.is_forwarded())
        .all(|r| r.outcome.refusal() == Some(&Refusal::BudgetExhausted)));
    // Zero budget: every call refused, nothing spent, forever.
    assert_eq!(d.spent("t-zero"), 0);
    assert!(d
        .audit_of("t-zero")
        .iter()
        .all(|r| r.outcome.refusal() == Some(&Refusal::BudgetExhausted)));
    // And no tenant ever exceeded the limit it was created with.
    for (tenant, limit) in cfg.tenants() {
        assert!(
            d.spent(tenant) <= limit,
            "{tenant} spent {} against a limit of {limit}",
            d.spent(tenant)
        );
    }
    // Both chaos budget regimes were really exercised: the tight tenants were
    // driven to the token, the ample ones never ran out — so the storm hammers
    // the exhausted path and the solvent path at once.
    let limits: BTreeMap<&str, u64> = cfg.tenants().into_iter().collect();
    for t in TIGHT_TENANTS {
        assert_eq!(d.spent(t), limits[t], "{t} was meant to be drained dry");
    }
    for t in AMPLE_TENANTS {
        assert!(
            d.spent(t) > 0 && d.spent(t) < limits[t],
            "{t} was meant to stay solvent: spent {} of {}",
            d.spent(t),
            limits[t]
        );
    }
}

/// The headline storm: 32 threads x 4 240 fixed operations = 135 680
/// interleaved operations against one `Arc<Mutex<Deployment>>`.
#[test]
fn chaos_storm_thirty_two_threads_holds_every_global_invariant() {
    run_storm(
        &StormConfig {
            threads: THREADS,
            probe_repeats: 24,
            chaos_ops: 4_000,
        },
        "chaos storm",
        45,
    );
}

/// The same storm at 10x, ~1.3M interleaved operations. Too slow for the
/// default run; behaviour must be identical, not merely similar.
///
/// `cargo test -p ccos-enterprise-conformance --test stress_concurrency_chaos \
///  -- --ignored --nocapture`
#[test]
#[ignore = "~30s soak; run with --ignored (see the doc comment for the command)"]
fn chaos_storm_soak_ten_times_the_traffic() {
    run_storm(
        &StormConfig {
            threads: THREADS,
            probe_repeats: 240,
            chaos_ops: 40_000,
        },
        "chaos storm soak",
        600,
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. Concurrency must not change outcomes: the standalone types
// ═════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
enum StdOp {
    Inc { name: String, by: u64 },
    Peek { name: String },
    Series,
    AddRole { name: String, perms: Vec<String> },
    Assign { actor: String, role: String },
    Allows { actor: String, perm: String },
    Charge { tokens: u64 },
}

#[derive(Debug, PartialEq, Eq)]
struct StdDigest {
    trace: Vec<u64>,
    counters: Vec<(String, u64)>,
    series: usize,
    finite_spent: u64,
    unlimited_spent: u64,
}

fn decision_code(d: PolicyDecision) -> u64 {
    match d {
        PolicyDecision::Allow => 1,
        PolicyDecision::Deny => 2,
        PolicyDecision::RequireApproval => 3,
    }
}

/// Replay a script on freshly built standalone types and return everything
/// observable about the result.
fn run_std_script(ops: &[StdOp]) -> StdDigest {
    let mut counters = CounterRegistry::default();
    let mut roles = RoleBook::default();
    let mut finite = TokenBudget::new(1_000_000);
    // `limit == u64::MAX` reaches `TokenBudget`'s saturating accounting branch,
    // which is the one place its ledger can stop matching what it allowed.
    let mut unlimited = TokenBudget::new(u64::MAX);
    let mut trace = Vec::with_capacity(ops.len());

    for op in ops {
        let observed = match op {
            StdOp::Inc { name, by } => {
                counters.inc(name, *by);
                0
            }
            StdOp::Peek { name } => counters.get(name),
            StdOp::Series => counters.series() as u64,
            StdOp::AddRole { name, perms } => {
                let mut role = Role {
                    name: name.clone(),
                    ..Default::default()
                };
                for p in perms {
                    role.permissions.insert(Permission(p.clone()));
                }
                roles.add_role(role);
                0
            }
            StdOp::Assign { actor, role } => u64::from(roles.assign(actor, role)),
            StdOp::Allows { actor, perm } => {
                u64::from(roles.allows(actor, &Permission(perm.clone())))
            }
            StdOp::Charge { tokens } => {
                let a = decision_code(finite.charge(*tokens));
                let b = decision_code(unlimited.charge(*tokens));
                (a << 8) | b
            }
        };
        trace.push(observed);
    }

    StdDigest {
        trace,
        counters: counters
            .export()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        series: counters.series(),
        finite_spent: finite.spent,
        unlimited_spent: unlimited.spent,
    }
}

/// A script that walks every branch worth walking: the registry's
/// `MAX_SERIES` fold, its saturating add, the role book's fail-closed
/// assignment, and the budget's saturating ledger.
fn std_script() -> Vec<StdOp> {
    let mut rng = Rng::seeded(0x0BAD_C0DE_0BAD_C0DE);
    let mut ops = Vec::new();

    // Past MAX_SERIES, so the "fold into `overflow`" branch is exercised.
    for i in 0..CounterRegistry::MAX_SERIES + 128 {
        ops.push(StdOp::Inc {
            name: format!("series.{i:05}"),
            by: 1 + rng.below(3),
        });
        if i % 512 == 0 {
            ops.push(StdOp::Series);
            ops.push(StdOp::Peek {
                name: "overflow".to_string(),
            });
        }
    }
    // A counter pinned at u64::MAX must stay pinned, identically, everywhere.
    ops.push(StdOp::Inc {
        name: "hot".to_string(),
        by: u64::MAX - 3,
    });
    for _ in 0..4 {
        ops.push(StdOp::Inc {
            name: "hot".to_string(),
            by: 2,
        });
        ops.push(StdOp::Peek {
            name: "hot".to_string(),
        });
    }

    // Roles: some declared, some never declared; assignment must fail closed
    // on the latter in every thread, identically.
    for r in 0..64 {
        ops.push(StdOp::AddRole {
            name: format!("role-{r}"),
            perms: (0..1 + rng.below(4))
                .map(|p| format!("perm-{}", (r as u64 + p) % 32))
                .collect(),
        });
    }
    for i in 0..600 {
        let actor = format!("actor-{}", rng.below(48));
        match rng.below(3) {
            0 => ops.push(StdOp::Assign {
                actor,
                role: format!("role-{}", rng.below(96)), // half of them undeclared
            }),
            _ => ops.push(StdOp::Allows {
                actor,
                perm: format!("perm-{}", rng.below(40)),
            }),
        }
        if i % 97 == 0 {
            ops.push(StdOp::AddRole {
                name: format!("role-{}", rng.below(64)), // silent replacement
                perms: vec!["perm-0".to_string()],
            });
        }
    }

    // Budget: normal charges, exact-boundary charges, and charges that only
    // the saturating path survives.
    for _ in 0..400 {
        ops.push(StdOp::Charge {
            tokens: match rng.below(8) {
                0 => u64::MAX,
                1 => u64::MAX - 1,
                2 => 0,
                _ => rng.below(9_000),
            },
        });
    }
    ops
}

/// The same fixed op sequence, run on 32 threads' worth of private
/// `CounterRegistry` / `RoleBook` / `TokenBudget`, must produce results
/// **identical** to a single-threaded replay — every intermediate observation,
/// not just the final state.
#[test]
fn standalone_types_replay_identically_under_thirty_two_way_concurrency() {
    let _wd = Watchdog::arm("standalone_types_replay_identically", 45);

    let ops = Arc::new(std_script());
    // The single-threaded truth, computed before anything is spawned.
    let reference = run_std_script(&ops);
    assert!(
        reference.series <= CounterRegistry::MAX_SERIES + 1,
        "the script must reach the MAX_SERIES fold: {} series",
        reference.series
    );
    assert!(
        reference.trace.contains(&0),
        "the script observes something"
    );
    assert_eq!(
        reference.unlimited_spent,
        u64::MAX,
        "the u64::MAX budget saturates, which is the branch under test"
    );
    println!(
        "── standalone replay: {} ops x {THREADS} threads, {} series, \
         finite ledger {}, saturating ledger {}",
        ops.len(),
        reference.series,
        reference.finite_spent,
        reference.unlimited_spent
    );

    let start = Arc::new(Barrier::new(THREADS));
    let digests: Vec<StdDigest> = thread::scope(|s| {
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let ops = Arc::clone(&ops);
                let start = Arc::clone(&start);
                s.spawn(move || {
                    start.wait();
                    run_std_script(&ops)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("no thread may panic"))
            .collect()
    });

    for (i, d) in digests.iter().enumerate() {
        assert_eq!(
            d.trace, reference.trace,
            "thread {i} observed a different op trace than the single-threaded replay"
        );
        assert_eq!(d.counters, reference.counters, "thread {i} counters differ");
        assert_eq!(
            d.series, reference.series,
            "thread {i} series count differs"
        );
        assert_eq!(d.finite_spent, reference.finite_spent, "thread {i} ledger");
        assert_eq!(d.unlimited_spent, reference.unlimited_spent, "thread {i}");
    }
    // …and the single-threaded replay is still the same after the storm: the
    // types carry no hidden global state.
    assert_eq!(run_std_script(&ops), reference);
}

/// The composed path is `Send + Sync` — but every mutator takes `&mut self`,
/// so the *only* sound sharing topology is one exclusive lock over the whole
/// deployment. `Sync` buys nothing: no two tenants can be admitted at once.
#[test]
fn composed_path_types_are_send_and_sync_but_every_mutator_is_exclusive() {
    fn send<T: Send>() {}
    fn sync<T: Sync>() {}

    send::<Deployment>();
    sync::<Deployment>();
    send::<TenantState>();
    send::<CounterRegistry>();
    sync::<CounterRegistry>();
    send::<RoleBook>();
    sync::<RoleBook>();
    send::<TokenBudget>();
    sync::<TokenBudget>();
    send::<QPageRegistry>();
    sync::<QPageRegistry>();
    send::<TenantScope<String>>();

    // The exclusivity, stated as code: an `&Deployment` can be shared by any
    // number of readers, and none of them can admit anything.
    let d = storm_deployment(&StormConfig {
        threads: THREADS,
        probe_repeats: 1,
        chaos_ops: 1,
    });
    let shared: &Deployment = &d;
    assert_eq!(shared.spent("t-ok"), 0);
    assert!(shared.audit().is_empty());
    // `admit`, `put`, `assign`, `tenant_mut`, `govern_tool`, `add_role` and
    // `add_tenant` all require `&mut Deployment`; there is no interior
    // mutability anywhere in the type, and no per-tenant handle to hand out.
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. Targeted concurrency defects
// ═════════════════════════════════════════════════════════════════════════════

fn one_tenant(limit: u64) -> Deployment {
    let mut d = Deployment::new();
    d.add_role("writer", &["memory.read", "memory.write"])
        .govern_tool("memory.recall", "memory.read");
    let mut st = TenantState::new(limit);
    st.allow_model(BASE_MODEL);
    d.add_tenant("acme", st);
    d.assign("alice", "writer");
    d
}

/// 32 threads race for a budget that fits half of them. **HELD:** exactly
/// `limit` calls are admitted, the ledger lands exactly on the limit, and the
/// losers are refused for the right reason — no lost update, no double spend,
/// no overdraft. Which threads win is a race; the totals are not.
#[test]
fn budget_race_admits_exactly_the_limit_and_never_overdrafts() {
    let _wd = Watchdog::arm("budget_race", 30);
    const ATTEMPTS_PER_THREAD: usize = 8;
    const LIMIT: u64 = (THREADS * ATTEMPTS_PER_THREAD) as u64 / 2;

    let d = Arc::new(Mutex::new(one_tenant(LIMIT)));
    let start = Arc::new(Barrier::new(THREADS));
    thread::scope(|s| {
        for tid in 0..THREADS {
            let d = Arc::clone(&d);
            let start = Arc::clone(&start);
            s.spawn(move || {
                let who = actor("memorithm", "alice", AuthStrength::Token);
                start.wait();
                for i in 0..ATTEMPTS_PER_THREAD {
                    let req = request("acme", "alice", "memory.recall", &format!("r-{tid}-{i}"));
                    guard(&d).admit(Call {
                        actor: &who,
                        request: &req,
                        model: BASE_MODEL,
                        cost_tokens: 1,
                        variant: None,
                    });
                }
            });
        }
    });

    let d = guard(&d);
    let forwarded = d
        .audit()
        .iter()
        .filter(|r| r.outcome.is_forwarded())
        .count() as u64;
    assert_eq!(forwarded, LIMIT, "exactly `limit` one-token calls won");
    assert_eq!(
        d.spent("acme"),
        LIMIT,
        "the ledger is exact under contention"
    );
    assert_eq!(d.audit().len(), THREADS * ATTEMPTS_PER_THREAD);
    assert!(
        d.audit()
            .iter()
            .filter(|r| !r.outcome.is_forwarded())
            .all(|r| r.outcome.refusal() == Some(&Refusal::BudgetExhausted)),
        "the losers lost for the right reason"
    );
}

/// **DEFECT (replay determinism does not survive concurrency).**
/// `docs/ENTERPRISE_SECURITY_MODEL.md` closes with "Enterprise ADDS gates; it
/// never WEAKENS a Core guarantee (determinism, replay, …)". Feed the composed
/// path the *identical* set of calls — same actors, same tools, same models,
/// same costs, same request ids — from two threads, and the journal it
/// produces depends entirely on which thread reached the lock first: different
/// order, different outcomes, different billing. That is defensible for a
/// contended resource; what is not is that **no field of `AuditRecord` records
/// the ordering**, so neither journal can be replayed to reproduce the other,
/// and an auditor cannot tell a legitimate loss of the race from a call that
/// was never made.
///
/// The two interleavings below are forced by a barrier, so this test is fully
/// deterministic: it does not *hope* for a race, it stages both sides of one.
#[test]
fn one_call_set_produces_two_different_journals_under_two_interleavings() {
    let _wd = Watchdog::arm("two_interleavings", 30);

    /// Runs `call-a` and `call-b` (one token each, one token of budget) with
    /// the order pinned, and returns the journal as (request id, forwarded).
    fn staged(a_goes_first: bool) -> Vec<(String, bool)> {
        let d = Arc::new(Mutex::new(one_tenant(1)));
        let gate = Arc::new(Barrier::new(2));
        thread::scope(|s| {
            for (id, goes_first) in [("call-a", a_goes_first), ("call-b", !a_goes_first)] {
                let d = Arc::clone(&d);
                let gate = Arc::clone(&gate);
                s.spawn(move || {
                    let who = actor("memorithm", "alice", AuthStrength::Token);
                    let req = request("acme", "alice", "memory.recall", id);
                    let call = || Call {
                        actor: &who,
                        request: &req,
                        model: BASE_MODEL,
                        cost_tokens: 1,
                        variant: None,
                    };
                    if goes_first {
                        guard(&d).admit(call());
                        gate.wait();
                    } else {
                        gate.wait();
                        guard(&d).admit(call());
                    }
                });
            }
        });
        let d = guard(&d);
        d.audit()
            .iter()
            .map(|r| (r.request_id.clone(), r.outcome.is_forwarded()))
            .collect()
    }

    let a_first = staged(true);
    let b_first = staged(false);
    assert_eq!(
        a_first,
        vec![("call-a".to_string(), true), ("call-b".to_string(), false)]
    );
    assert_eq!(
        b_first,
        vec![("call-b".to_string(), true), ("call-a".to_string(), false)]
    );
    assert_ne!(
        a_first, b_first,
        "DEFECT: one call set, two journals — and nothing in an AuditRecord \
         says which interleaving produced it, so neither is replayable"
    );
}

/// **DEFECT (audit integrity).** An `AuditRecord` carries no sequence number,
/// no timestamp, no thread or connection id — the `Vec`'s position is the only
/// ordering information in the journal, and `audit_of` discards it (it returns
/// `Vec<&AuditRecord>` with no indices). Under concurrency that makes the
/// journal *self-colliding*: 32 threads issuing the byte-identical call
/// produce 32 records that compare `==` to one another. Every one of them was
/// separately billed, and no operator reading the trail can tell them apart,
/// order them, or attribute one to a caller.
#[test]
fn identical_concurrent_calls_produce_indistinguishable_audit_records() {
    let _wd = Watchdog::arm("identical_concurrent_calls", 30);
    let d = Arc::new(Mutex::new(one_tenant(1_000)));
    let start = Arc::new(Barrier::new(THREADS));
    thread::scope(|s| {
        for _ in 0..THREADS {
            let d = Arc::clone(&d);
            let start = Arc::clone(&start);
            s.spawn(move || {
                let who = actor("memorithm", "alice", AuthStrength::Token);
                // Byte-identical, including the "idempotency/correlation key".
                let req = request("acme", "alice", "memory.recall", "r-same");
                start.wait();
                guard(&d).admit(Call {
                    actor: &who,
                    request: &req,
                    model: BASE_MODEL,
                    cost_tokens: 1,
                    variant: None,
                });
            });
        }
    });

    let d = guard(&d);
    assert_eq!(d.audit().len(), THREADS);
    let first = &d.audit()[0];
    assert!(
        d.audit().iter().all(|r| r == first),
        "DEFECT: {THREADS} concurrent admissions produced {THREADS} records that \
         are equal in every field — the journal has no ordering or identity key"
    );
    assert_eq!(
        d.spent("acme"),
        THREADS as u64,
        "DEFECT: one request id, {THREADS} concurrent replays, {THREADS} charges"
    );
    // And the per-tenant view offers no way back to the global order.
    assert_eq!(d.audit_of("acme").len(), THREADS);
}

/// **DEFECT (audit completeness).** A governance change races with the
/// admissions it governs, and *nothing* records it. The two admissions below
/// are identical apart from their request id; the first is refused, the second
/// forwarded, and the journal contains exactly two records and no third one
/// explaining why the answer changed. `tenant_mut(..).allow_model(..)` returns
/// `&mut Self`, journals nothing, increments no counter and requires no
/// identity, no permission and no `AdminAction` justification.
#[test]
fn a_concurrent_governance_change_flips_an_outcome_and_the_journal_cannot_explain_it() {
    let _wd = Watchdog::arm("governance_change_flips_outcome", 30);
    let d = Arc::new(Mutex::new(one_tenant(1_000)));
    let gate = Arc::new(Barrier::new(2));

    let admin_d = Arc::clone(&d);
    let admin_gate = Arc::clone(&gate);
    thread::scope(|s| {
        s.spawn(move || {
            admin_gate.wait(); // …after the first call
            guard(&admin_d)
                .tenant_mut("acme")
                .expect("tenant exists")
                .allow_model("smuggled-model");
            admin_gate.wait(); // …before the second
        });

        let who = actor("memorithm", "alice", AuthStrength::Token);
        let before = {
            let req = request("acme", "alice", "memory.recall", "r-before");
            guard(&d).admit(Call {
                actor: &who,
                request: &req,
                model: "smuggled-model",
                cost_tokens: 10,
                variant: None,
            })
        };
        gate.wait();
        gate.wait();
        let after = {
            let req = request("acme", "alice", "memory.recall", "r-after");
            guard(&d).admit(Call {
                actor: &who,
                request: &req,
                model: "smuggled-model",
                cost_tokens: 10,
                variant: None,
            })
        };
        assert_eq!(before.refusal(), Some(&Refusal::ModelNotAllowed));
        assert_eq!(after, Outcome::Forwarded);
    });

    let d = guard(&d);
    assert_eq!(
        d.audit().len(),
        2,
        "DEFECT: the allowlist widened between the two calls and the journal \
         holds only the two admissions — no record of the change, its actor, \
         or its justification"
    );
    let metrics = d.metrics();
    let names: Vec<&String> = metrics.iter().map(|(k, _)| k).collect();
    assert!(
        metrics.iter().all(|(k, _)| k.starts_with("gateway.")),
        "no counter tracks policy mutation either: {names:?}"
    );
}

/// **DEFECT (no atomic snapshot).** `spent`, `audit`/`audit_of` and `metrics`
/// are three separate calls on three separate borrows. The product offers no
/// snapshot accessor, so an operator reconciling the ledger against the
/// journal under load must invent their own lock discipline; done the obvious
/// way — one `lock()` per read — the reconciliation reports a tenant as
/// under-billed by a whole call, although the deployment was never once
/// internally inconsistent. The barriers below pin the interleaving, so this
/// is a *deterministic* demonstration of a real operator-facing hazard.
#[test]
fn ledger_and_journal_tear_when_read_in_separate_lock_acquisitions() {
    let _wd = Watchdog::arm("ledger_journal_tear", 30);
    let d = Arc::new(Mutex::new(one_tenant(1_000)));
    let gate = Arc::new(Barrier::new(2));

    let traffic_d = Arc::clone(&d);
    let traffic_gate = Arc::clone(&gate);
    thread::scope(|s| {
        s.spawn(move || {
            let who = actor("memorithm", "alice", AuthStrength::Token);
            traffic_gate.wait(); // the operator has read `spent`, lock released
            let req = request("acme", "alice", "memory.recall", "r-inflight");
            let out = guard(&traffic_d).admit(Call {
                actor: &who,
                request: &req,
                model: BASE_MODEL,
                cost_tokens: 100,
                variant: None,
            });
            assert_eq!(out, Outcome::Forwarded);
            traffic_gate.wait(); // …now let the operator read the journal
        });

        // The operator's naive reconciliation: two reads, two lock acquisitions.
        let spent_snapshot = guard(&d).spent("acme");
        gate.wait();
        gate.wait();
        let journal_snapshot: u64 = guard(&d)
            .audit_of("acme")
            .iter()
            .filter(|r| r.outcome.is_forwarded())
            .count() as u64
            * 100;

        assert_eq!(spent_snapshot, 0);
        assert_eq!(journal_snapshot, 100);
        assert_ne!(
            spent_snapshot, journal_snapshot,
            "DEFECT: with no atomic snapshot accessor, the two halves of the \
             product's own accounting disagree by a full call"
        );
    });

    // Held under one guard, the two agree — the hazard is the missing API,
    // not an internal inconsistency.
    let d = guard(&d);
    assert_eq!(d.spent("acme"), 100);
    assert_eq!(d.audit_of("acme").len(), 1);
}

/// **DEFECT (blast radius).** Because the only sound topology is one lock over
/// the whole `Deployment`, a panic *anywhere* under that lock denies service
/// to **every** tenant at once, and the product has no recovery story: no
/// `Clone`, no serialization, no snapshot/restore, and nothing that records
/// that it happened. The unbounded audit `Vec` that every refused call grows
/// (measured at 1.1 GiB after 5M calls by `stress_endurance`) is a real
/// allocation-failure site under that lock.
///
/// The panic below is injected by the test; the point being pinned is what the
/// *product* offers afterwards, which is nothing.
#[test]
fn one_panic_under_the_global_lock_denies_service_to_every_tenant() {
    let d = Arc::new(Mutex::new(two_tenant_deployment()));
    {
        let mut g = guard(&d);
        let who = actor("memorithm", "alice", AuthStrength::Token);
        let req = request("acme", "alice", "memory.recall", "r-1");
        assert_eq!(
            g.admit(Call {
                actor: &who,
                request: &req,
                model: "claude-opus",
                cost_tokens: 10,
                variant: None,
            }),
            Outcome::Forwarded
        );
    }

    let victim = Arc::clone(&d);
    // (an "attempt to ..." panic message on stderr is expected here)
    let h = thread::spawn(move || {
        let _held = victim.lock().expect("not poisoned yet");
        panic!("any panic while the deployment's single lock is held");
    });
    assert!(h.join().is_err());

    // Every tenant, not just the one whose call panicked.
    assert!(
        d.lock().is_err(),
        "DEFECT: one panic poisons the single lock the whole deployment sits behind"
    );
    for tenant in ["acme", "globex"] {
        assert!(
            d.lock().is_err(),
            "{tenant} is denied service by an unrelated tenant's panic"
        );
    }

    // Recovery exists only by deliberately ignoring the poison, and the
    // deployment then carries on with no idea it was ever suspect.
    let g = d.lock().unwrap_or_else(|p| p.into_inner());
    assert_eq!(g.spent("acme"), 10, "the state itself survived intact");
    assert_eq!(g.audit().len(), 1);
    assert!(
        g.metrics().iter().all(|(k, _)| k.starts_with("gateway.")),
        "DEFECT: nothing in the journal or the metrics records the incident"
    );
}

/// **DEFECT (cross-tenant work amplification, under the global lock).**
/// `audit_of` filters the whole journal, so a tenant that has never made a
/// single call still pays a full scan of every other tenant's traffic — while
/// holding the one lock every other tenant's admissions need. Tenant A's
/// volume is therefore tenant B's latency: isolation that holds for data does
/// not hold in the time domain.
#[test]
fn audit_of_a_silent_tenant_walks_the_whole_global_trail() {
    const NOISE: usize = 20_000;
    let mut d = two_tenant_deployment();
    // globex never speaks.
    let who = actor("memorithm", "bob", AuthStrength::Token);
    for i in 0..NOISE {
        let req = request("acme", "bob", "memory.ingest", &format!("r-{i}"));
        // Refused (a reader cannot ingest) — free for acme, and still a record.
        d.admit(Call {
            actor: &who,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
        });
    }
    assert_eq!(d.audit().len(), NOISE, "acme's refusals cost acme nothing…");
    assert_eq!(d.spent("acme"), 0);
    assert!(
        d.audit_of("globex").is_empty(),
        "…and globex has no records of its own — yet answering that question \
         required scanning all {NOISE} of acme's, under the shared lock"
    );
    assert!(d.cells_of("globex").is_empty());
}
