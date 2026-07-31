//! # Hostile endurance stress of the composed governed path
//!
//! Everything else in this suite asks "is one decision right?". This file
//! asks the only question a governance layer is actually judged on in
//! production: **does it still tell the truth after two hundred thousand
//! decisions, and does it survive the two hundred thousand and first?**
//!
//! Three properties are hammered, continuously, at every 10 000-call
//! checkpoint of a 50-tenant, 200 000-call run:
//!
//! 1. **the ledger** — `Deployment::spent(t)` equals, exactly, the sum of the
//!    costs of the calls the deployment itself reported as `Forwarded` for
//!    `t` (the expectation is built from the product's own return values, so
//!    a drift between *deciding* and *accounting* cannot hide behind a
//!    re-implementation of the decision);
//! 2. **the journal** — `audit().len()` equals the number of calls, always,
//!    and every earlier record is byte-identical to what it was hundreds of
//!    thousands of calls ago (append-only, no rewrite);
//! 3. **the counters** — `gateway.requests == gateway.forwarded +
//!    gateway.refused`, each equals the journal's own tally, and the eight
//!    `gateway.refused.*` series sum to `gateway.refused`.
//!
//! plus **determinism**: two `Deployment`s built independently and fed the
//! byte-identical sequence produce identical audit digests and identical
//! metric exports at every checkpoint.
//!
//! Run the non-ignored file (well under a minute in debug):
//! `cargo test -p ccos-enterprise-conformance --test stress_endurance`
//! (add `-- --nocapture` for the measured memory tables).
//!
//! ## What held
//!
//! * **The ledger never drifts.** Across 200 000 admissions over 50 tenants
//!   (62 122 forwarded, 137 878 refused, 15 tenants driven to a fully drained
//!   budget mid-run), `spent(t)` matched the sum of admitted costs to the
//!   token at all 20 checkpoints, and never once exceeded the tenant's limit.
//!   Refusals are free: a drained tenant refused for the rest of the run
//!   spends nothing more.
//!   → [`endurance_two_hundred_thousand_admissions_across_fifty_tenants`]
//! * **The journal is exactly one record per call, append-only.** Never a
//!   record more, never one fewer, over 200 000 calls; record 0 and record
//!   9 999 are byte-identical at checkpoint 20 to what they were at
//!   checkpoint 1. (Which is also precisely the defect — see below.)
//! * **The counters agree with the journal to the unit**, in aggregate and
//!   per refusal tag, and the series set stays at exactly 11 names however
//!   hostile the input: `admit` folds every refusal through a `&'static str`,
//!   so the one bounded pool in the product stays bounded.
//! * **Determinism is total.** Two independently built deployments fed the
//!   same 200 000 steps agreed on every single outcome, produced the same
//!   SHA-256 audit digest at all 20 checkpoints, and exported byte-identical
//!   metrics. Every container in the composed path is a `BTree*`; there is no
//!   hash seed, no clock and no interior nondeterminism to shake loose. Debug
//!   and release agree to the byte, on outcomes and on measured memory alike.
//! * **Nothing rots at 25x the scale.** The `#[ignore]`d 5 000 000-call run
//!   holds every one of the above at all 20 of its checkpoints — ledger,
//!   journal length, counters, prefix stability — in 9.7 s (1.95 us per
//!   admission, flat throughout: no gate degrades as the trail grows).
//!   → [`endurance_five_million_admissions`]
//!
//! ## What was repaired
//!
//! * **A boundary refusal no longer doubles the attacker's bytes.** It used
//!   to: `classify` formatted the *whole* tool name into
//!   `Refusal::OutsideBoundary`, `admit` cloned that message into the record
//!   and returned it, and a merely token-authenticated caller sending a 1 MiB
//!   tool name therefore retained **2.00 bytes per attacker byte** — twice
//!   what an anonymous one cost, putting 4 GiB of operator memory 2 GiB of
//!   request body away. The gateway now refuses any name over
//!   `MAX_TOOL_NAME_BYTES` (256) as non-canonical *before* it matches
//!   anything, so a megabyte-scale name is refused unread with a 35-byte
//!   constant, and it passes what it does echo through a sanitizer capped at
//!   64 characters. Re-measured on the identical workload: **1.00 bytes per
//!   attacker byte**, the same single copy the anonymous path costs, with no
//!   second one. The cap holds where it bites, too — at the largest name the
//!   boundary will still classify (256 bytes, canonical, forbidden) the name
//!   *is* echoed, truncated at 64 characters with an ellipsis, for a 119-byte
//!   message. The message is now bounded by the template, not by the caller.
//!   → [`audit_record_size_is_attacker_controlled_but_boundary_refusals_no_longer_double_it`]
//!
//! ## What BROKE
//!
//! 1. **The audit trail is an unbounded `Vec` with no cap, no rotation and no
//!    persistence, and an *unauthenticated* caller drives it.**
//!    `Deployment::admit` pushes an `AuditRecord` *after* `decide`, on every
//!    path (`tests/ccos-enterprise-conformance/src/lib.rs:271`), so a refusal
//!    costs the operator memory exactly like an admission does. 1 000 000
//!    calls from an `AuthStrength::Anonymous` principal — refused at the very
//!    first gate, zero tokens spent, zero tenants touched — leave 1 000 000
//!    records and a **measured 150.5 MiB** of retained heap in the governance
//!    layer (158 B per refusal, on 8-byte request ids), growing dead linearly
//!    with no plateau anywhere: 37.6 MiB at 250 000 refusals, 75.3 at
//!    500 000, 150.5 at 1 000 000; the long run reaches **1 150.9 MiB at
//!    5 000 000** and is still climbing. The registry two
//!    fields over folds at 4096 series precisely so "a label explosion can
//!    never exhaust memory"; the `Vec` beside it has no such bound, and it is
//!    the one an anonymous client can drive. Dropping the whole `Deployment`
//!    is the only thing that frees a byte of it.
//!    → [`unauthenticated_flood_grows_the_audit_trail_without_bound`],
//!    [`endurance_five_million_admissions`]
//!
//! 2. **Per-record size is *still* attacker-controlled, so the vector is
//!    unbounded in two dimensions at once.** Only the second dimension's
//!    doubling was closed (above); the copy underneath it was not. `admit`
//!    clones `request.{tenant,actor,tool}` into the record verbatim,
//!    unvalidated and untruncated, *before and regardless of* which gate
//!    refused the call — so the gateway's 256-byte canonical-name limit
//!    bounds what the boundary will classify and echo, and bounds nothing
//!    about what is journaled. An anonymous caller who never passes the
//!    identity gate still gets a 1 MiB tool name copied into the trail —
//!    re-measured at **1.00 bytes retained per attacker byte**, and the
//!    token-authenticated boundary case now costs the same 1.00 rather than
//!    2.00. 4 GiB of memory is still 4 GiB of request body away; it merely
//!    takes twice the request body it used to.
//!    → [`audit_record_size_is_attacker_controlled_but_boundary_refusals_no_longer_double_it`]
//!
//! 3. **There is no way to shed the trail short of destroying the
//!    deployment.** The only accessors are `audit()` (a shared slice),
//!    `audit_of()` and `metrics()`. No `truncate`, no `drain`, no export, no
//!    persistence, no size accessor — and the record carries **no timestamp
//!    and no cost**, so age-based rotation and spend reconstruction are not
//!    merely unimplemented, they are unimplementable from what is stored.
//!    → [`audit_records_carry_neither_time_nor_cost_so_rotation_is_impossible`]
//!
//! 4. **The one per-tenant audit accessor is O(total trail) and allocates
//!    8 bytes per match, so flooding the trail also poisons every query
//!    against it.** `audit_of` filters the whole `Vec`
//!    (`src/lib.rs:344`): after an attacker parks 200 000 refused calls under
//!    a tenant, one `audit_of` call allocates 2.1 MB, and the *innocent*
//!    neighbour's 8-record query still walks all 200 008 (7.4 ms measured in
//!    debug) because there is no index. The exhaustion vector amplifies
//!    itself.
//!    → [`audit_of_scans_the_whole_trail_and_allocates_per_match`]
//!
//! 5. **`request_id` is documented as an "Idempotency/correlation key"
//!    (`crates/ccos-enterprise-gateway/src/lib.rs:16`) and `admit` never reads
//!    the field.** Replaying one captured request 20 000 times charges the
//!    budget every time — enough to drain a tenant outright — and writes
//!    20 000 audit rows under a single id, so the key an operator would join
//!    on has cardinality 1 for the whole incident.
//!    → [`replayed_request_id_is_charged_every_time`]
//!
//! 6. **`spent()` cannot distinguish "unknown tenant" from "spent nothing".**
//!    It returns `0` for a tenant that does not exist (`src/lib.rs:331`), so
//!    a typo in a billing or quota-monitor query reads as a healthy,
//!    idle tenant forever. → [`spent_of_an_unknown_tenant_is_indistinguishable_from_zero`]
//!
//! 7. **The metrics have no tenant dimension.** All 11 series are
//!    deployment-global, so in a 50-tenant install the counters can say *that*
//!    4 000 calls were refused but never *whose* — the only attribution path
//!    is the O(n) scan from finding 4. → asserted in
//!    [`endurance_two_hundred_thousand_admissions_across_fifty_tenants`].
//!
//! 8. **An "unlimited" tenant's ledger stops being a sum.** `TokenBudget`
//!    saturates on the accounting side, so with `limit == u64::MAX` the
//!    deployment forwards work it then declines to bill: the invariant this
//!    whole file rests on — `spent == Σ admitted` — is false past `u64::MAX`,
//!    silently and permanently.
//!    → [`unlimited_budget_stops_summing_admitted_costs`]
//!
//! Not re-litigated here because siblings own it: the authenticated identity
//! is never bound to `request.actor`, so authorization keys on a caller-
//! supplied string (see `stress_rbac_scale.rs`, `stress_budget_property.rs`).
//! This file therefore drives an honest workload — every principal sends its
//! own name — because the endurance invariants must hold even when nobody is
//! cheating.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

use ccos_enterprise_auth::{AuthStrength, AuthenticatedActor};
use ccos_enterprise_conformance::{
    actor, request, AuditRecord, Call, Deployment, Outcome, Refusal, TenantState,
};
use ccos_enterprise_gateway::GatewayRequest;
use ccos_enterprise_qpages::AdvancedQPageVariant;

// ─────────────────────────────────────────────────────────────────────────
// Measurement harness
//
// A counting allocator is the only honest answer to "does the audit trail
// actually grow without bound". It counts `Layout::size()`, so the numbers
// are allocator-independent and identical in debug and release but for
// harness noise. Every test takes `serialized()` so a sibling allocating on
// another libtest thread cannot pollute a measurement; that makes runtime
// additive, which is why the scale constants below are tuned to keep the
// whole non-ignored file well under a minute in debug.
// ─────────────────────────────────────────────────────────────────────────

struct CountingAlloc;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            LIVE_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
        System.dealloc(ptr, layout);
    }
}

#[global_allocator]
static ALLOCATOR: CountingAlloc = CountingAlloc;

fn live_bytes() -> usize {
    LIVE_BYTES.load(Ordering::Relaxed)
}

static TEST_LOCK: Mutex<()> = Mutex::new(());

/// Serialize the tests in this binary. Poisoning is ignored on purpose: one
/// failing assertion must not turn every sibling into an unrelated panic.
fn serialized() -> MutexGuard<'static, ()> {
    TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ─────────────────────────────────────────────────────────────────────────
// Deterministic workload
// ─────────────────────────────────────────────────────────────────────────

/// SplitMix64. Fixed seed, no clock, no thread-local state: the byte-for-byte
/// same sequence in debug, in release, and on every run.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
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
        self.next_u64() % n
    }
}

const TENANTS: usize = 50;
const MAIN_CALLS: usize = 200_000;
const CHECKPOINT: usize = 10_000;
/// The unauthenticated flood: one million refusals, one million records.
const FLOOD_CALLS: usize = 1_000_000;
/// The `#[ignore]`d long run.
const LONG_CALLS: usize = 5_000_000;

/// Principals. `ghost` never clears the identity gate; `mallory` clears it and
/// holds no role. Each principal sends its own name (see the module docs).
const PRINCIPALS: [(&str, AuthStrength); 5] = [
    ("alice", AuthStrength::Token),
    ("bob", AuthStrength::Token),
    ("root", AuthStrength::Strong),
    ("mallory", AuthStrength::Token),
    ("ghost", AuthStrength::Anonymous),
];

/// Governed, catalogued-but-ungoverned, forbidden and simply-unlisted tools,
/// so all three boundary/authorization refusals are exercised continuously.
const TOOLS: [&str; 8] = [
    "memory.recall",    // governed: memory.read
    "memory.ingest",    // governed: memory.write
    "policy.set",       // governed: policy.admin
    "audit.query",      // governed: memory.read
    "context.window",   // in the catalogue, nobody governed it
    "shell.exec",       // forbidden namespace
    "rsi.status",       // forbidden namespace
    "quantum.entangle", // not in the catalogue at all
];

const MODELS: [&str; 3] = ["claude-opus", "gpt-5", "mystery-model"];

/// Spread limits so some tenants exhaust early and stay exhausted for
/// hundreds of thousands of calls while others never come close.
fn limit_of(i: usize) -> u64 {
    250 + (i as u64) * 400
}

fn tenant_names() -> Vec<String> {
    (0..TENANTS).map(|i| format!("t-{i:02}")).collect()
}

/// A 50-tenant deployment. Built from scratch each time it is called — the
/// determinism claim is about two *independently constructed* deployments,
/// not two clones of one.
fn fleet_deployment(names: &[String]) -> Deployment {
    let mut d = Deployment::new();
    d.add_role("reader", &["memory.read"])
        .add_role("writer", &["memory.read", "memory.write"])
        .add_role("operator", &["memory.read", "memory.write", "policy.admin"])
        .govern_tool("memory.recall", "memory.read")
        .govern_tool("memory.ingest", "memory.write")
        .govern_tool("policy.set", "policy.admin")
        .govern_tool("audit.query", "memory.read");
    for (i, name) in names.iter().enumerate() {
        let mut st = TenantState::new(limit_of(i));
        st.allow_model("claude-opus");
        if i % 2 == 0 {
            // Even tenants are the "advanced" ones: second model, activated
            // variant. Odd tenants refuse both, forever.
            st.allow_model("gpt-5")
                .activate(AdvancedQPageVariant::Hierarchical);
        }
        d.add_tenant(name, st);
    }
    assert!(d.assign("alice", "writer"));
    assert!(d.assign("bob", "reader"));
    assert!(d.assign("root", "operator"));
    // `mallory` and `ghost` are deliberately left role-less.
    d
}

/// One planned call. Kept as indices so the plan itself allocates nothing and
/// both deployments provably receive the same bytes.
#[derive(Clone, Copy)]
struct Step {
    tenant: usize,
    principal: usize,
    tool: usize,
    model: usize,
    variant: bool,
    cost: u64,
}

/// Weighted so that all eight refusal kinds occur continuously, not once at
/// the start: an endurance test that stops producing a refusal kind stops
/// testing it.
fn next_step(rng: &mut Rng) -> Step {
    let tenant = rng.below(TENANTS as u64) as usize;
    let cost = 1 + rng.below(7);
    let roll = rng.below(100);
    let (principal, tool, model, variant, tenant) = match roll {
        0..=44 => (
            rng.below(3) as usize,
            rng.below(4) as usize,
            0,
            false,
            tenant,
        ),
        45..=54 => (4, 0, 0, false, tenant),  // Unauthenticated
        55..=61 => (0, 0, 0, false, TENANTS), // UnknownTenant
        62..=69 => (0, 5 + rng.below(2) as usize, 0, false, tenant), // OutsideBoundary (violation)
        70..=75 => (0, 7, 0, false, tenant),  // OutsideBoundary (omission)
        76..=82 => (0, 4, 0, false, tenant),  // ToolNotGoverned
        83..=89 => (3, rng.below(4) as usize, 0, false, tenant), // PermissionDenied
        90..=94 => (0, 0, 2, false, tenant),  // ModelNotAllowed
        _ => (0, 0, 0, true, tenant),         // VariantNotActivated on odd tenants
    };
    Step {
        tenant,
        principal,
        tool,
        model,
        variant,
        cost,
    }
}

/// Overwrite in place: the request is re-used across steps so the workload's
/// own allocation noise does not swamp the trail measurement.
fn set_str(dst: &mut String, src: &str) {
    dst.clear();
    dst.push_str(src);
}

fn fill_request(req: &mut GatewayRequest, step: &Step, names: &[String], seq: usize) {
    let tenant: &str = if step.tenant == TENANTS {
        "ghost-tenant"
    } else {
        &names[step.tenant]
    };
    set_str(&mut req.tenant, tenant);
    set_str(&mut req.actor, PRINCIPALS[step.principal].0);
    set_str(&mut req.tool, TOOLS[step.tool]);
    req.request_id.clear();
    write!(req.request_id, "r-{seq:08}").expect("String write is infallible");
}

// ─────────────────────────────────────────────────────────────────────────
// Audit digest
//
// Rolling, so the cost of digesting is O(records) over the *whole run*
// rather than O(records × checkpoints): each checkpoint absorbs only the
// suffix appended since the last one. That is only sound if the trail is
// append-only, which is exactly why prefix stability is asserted separately
// (`stable_prefix`) rather than assumed.
// ─────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct RollingDigest {
    state: u64,
    absorbed: usize,
}

impl RollingDigest {
    fn absorb(&mut self, records: &[AuditRecord]) {
        assert!(
            records.len() >= self.absorbed,
            "the audit trail shrank: {} records now, {} already digested",
            records.len(),
            self.absorbed
        );
        for r in &records[self.absorbed..] {
            fnv_field(&mut self.state, r.request_id.as_bytes());
            fnv_field(&mut self.state, r.tenant.as_bytes());
            fnv_field(&mut self.state, r.actor.as_bytes());
            fnv_field(&mut self.state, r.tool.as_bytes());
            absorb_outcome(&mut self.state, &r.outcome);
        }
        self.absorbed = records.len();
    }

    /// A real SHA-256, through the product's own primitive, over the rolling
    /// state and the record count — so "identical digests" means identical
    /// trails, not merely identical lengths.
    fn hex(&self) -> String {
        let mut blob = [0u8; 16];
        blob[..8].copy_from_slice(&self.state.to_le_bytes());
        blob[8..].copy_from_slice(&(self.absorbed as u64).to_le_bytes());
        ccos_enterprise_governance::vendor::token_sha256(&blob)
    }
}

fn fnv_bytes(state: &mut u64, bytes: &[u8]) {
    for b in bytes {
        *state ^= u64::from(*b);
        *state = state.wrapping_mul(0x0000_0100_0000_01B3);
    }
}

/// Length-prefixed, so `("ab","c")` and `("a","bc")` cannot collide — a digest
/// that can be fooled by moving a byte between fields proves nothing.
fn fnv_field(state: &mut u64, bytes: &[u8]) {
    fnv_bytes(state, &(bytes.len() as u64).to_le_bytes());
    fnv_bytes(state, bytes);
}

fn absorb_outcome(state: &mut u64, o: &Outcome) {
    match o {
        Outcome::Forwarded => fnv_field(state, b"forwarded"),
        Outcome::Refused(r) => {
            fnv_field(state, b"refused");
            fnv_field(state, tag_of(r).as_bytes());
            // The boundary refusal carries a message; digest it too, so a
            // change in what an operator is told changes the digest.
            if let Refusal::OutsideBoundary(why) = r {
                fnv_field(state, why.as_bytes());
            }
        }
    }
}

/// Mirror of the deployment's private `tag` fn: the metric-name mapping has to
/// be restated here to check the counters against the journal at all.
fn tag_of(r: &Refusal) -> &'static str {
    match r {
        Refusal::Unauthenticated => "unauthenticated",
        Refusal::UnknownTenant => "unknown_tenant",
        Refusal::OutsideBoundary(_) => "outside_boundary",
        Refusal::ToolNotGoverned => "tool_not_governed",
        Refusal::PermissionDenied => "permission_denied",
        Refusal::ModelNotAllowed => "model_not_allowed",
        Refusal::VariantNotActivated => "variant_not_activated",
        Refusal::BudgetExhausted => "budget_exhausted",
    }
}

// ─────────────────────────────────────────────────────────────────────────
// The expectation, built from the product's own answers
// ─────────────────────────────────────────────────────────────────────────

/// Everything the deployment is supposed to be able to tell us, accumulated
/// independently of how it stores it. `spent` is `u128` on purpose: if the
/// product's `u64` ledger ever saturates, the expectation must not saturate
/// with it, or the bug would cancel itself out.
struct Ledger {
    spent: Vec<u128>,
    calls: u64,
    forwarded: u64,
    refused: u64,
    tags: BTreeMap<&'static str, u64>,
}

impl Ledger {
    fn new() -> Self {
        Self {
            spent: vec![0; TENANTS],
            calls: 0,
            forwarded: 0,
            refused: 0,
            tags: BTreeMap::new(),
        }
    }

    fn record(&mut self, step: &Step, outcome: &Outcome) {
        self.calls += 1;
        match outcome {
            Outcome::Forwarded => {
                self.forwarded += 1;
                assert!(step.tenant < TENANTS, "an unknown tenant cannot be charged");
                self.spent[step.tenant] += u128::from(step.cost);
            }
            Outcome::Refused(r) => {
                self.refused += 1;
                *self.tags.entry(tag_of(r)).or_insert(0) += 1;
            }
        }
    }
}

fn metric(export: &[(String, u64)], name: &str) -> u64 {
    export
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| *v)
        .unwrap_or(0)
}

/// Every invariant this file exists to defend, checked against one deployment.
fn check_invariants(d: &Deployment, l: &Ledger, names: &[String], at: usize) {
    // 1. The ledger: `spent` is exactly the sum of admitted costs, per tenant.
    for (i, name) in names.iter().enumerate() {
        assert_eq!(
            u128::from(d.spent(name)),
            l.spent[i],
            "call {at}: tenant {name} spend drifted from the sum of its admitted costs"
        );
        assert!(
            d.spent(name) <= limit_of(i),
            "call {at}: tenant {name} spent {} over a limit of {}",
            d.spent(name),
            limit_of(i)
        );
    }

    // 2. The journal: one record per call, no more, no fewer, ever.
    assert_eq!(
        d.audit().len() as u64,
        l.calls,
        "call {at}: audit trail length diverged from the call count"
    );

    // 3. The counters, against the journal.
    let m = d.metrics();
    let requests = metric(&m, "gateway.requests");
    let forwarded = metric(&m, "gateway.forwarded");
    let refused = metric(&m, "gateway.refused");
    assert_eq!(
        requests,
        forwarded + refused,
        "call {at}: requests != forwarded + refused"
    );
    assert_eq!(requests, l.calls, "call {at}: requests != calls made");
    assert_eq!(
        forwarded, l.forwarded,
        "call {at}: forwarded counter != journal's forwarded count"
    );
    assert_eq!(
        refused, l.refused,
        "call {at}: refused counter != journal's refused count"
    );
    let mut tag_total = 0u64;
    for (tag, count) in &l.tags {
        let series = format!("gateway.refused.{tag}");
        assert_eq!(
            metric(&m, &series),
            *count,
            "call {at}: {series} != journal's count for that refusal"
        );
        tag_total += *count;
    }
    assert_eq!(
        tag_total, refused,
        "call {at}: per-tag counters do not sum to gateway.refused"
    );

    // DEFECT (finding 7): every series is deployment-global. With 50 tenants
    // in this deployment, not one counter name mentions a tenant — the
    // metrics can say 4 000 calls were refused, never whose. Asserting the
    // real shape so that adding a tenant dimension trips here loudly.
    assert!(
        m.len() <= 11,
        "call {at}: expected at most 11 global series, got {}",
        m.len()
    );
    for (name, _) in &m {
        for tenant in names {
            assert!(
                !name.contains(tenant.as_str()),
                "call {at}: series {name} unexpectedly carries a tenant dimension"
            );
        }
    }
}

/// A record cloned early and re-checked later: proof the trail is appended to
/// and never rewritten, compacted or rotated.
fn stable_prefix(d: &Deployment, sample: &[(usize, AuditRecord)], at: usize) {
    for (idx, expected) in sample {
        assert_eq!(
            &d.audit()[*idx],
            expected,
            "call {at}: audit record {idx} was rewritten under us"
        );
    }
}

fn mib(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

// ─────────────────────────────────────────────────────────────────────────
// 1. The main endurance run
// ─────────────────────────────────────────────────────────────────────────

/// 200 000 admissions across 50 tenants, on two independently built
/// deployments fed the identical sequence, with every invariant re-checked at
/// each of the 20 checkpoints.
#[test]
fn endurance_two_hundred_thousand_admissions_across_fifty_tenants() {
    let _guard = serialized();
    let names = tenant_names();
    let principals: Vec<AuthenticatedActor> = PRINCIPALS
        .iter()
        .map(|(name, strength)| actor("memorithm", name, *strength))
        .collect();

    let mut a = fleet_deployment(&names);
    let mut b = fleet_deployment(&names);
    let mut ledger = Ledger::new();
    let mut roll_a = RollingDigest::default();
    let mut roll_b = RollingDigest::default();
    let mut rng = Rng::new(0x5EED_0001_C0DE_F00D);
    let mut req = request("", "", "", "");
    let mut sample: Vec<(usize, AuditRecord)> = Vec::new();
    let mut exhausted_tenants = 0usize;

    let started = Instant::now();
    let base_bytes = live_bytes();
    for seq in 0..MAIN_CALLS {
        let step = next_step(&mut rng);
        fill_request(&mut req, &step, &names, seq);
        let variant = step.variant.then_some(AdvancedQPageVariant::Hierarchical);
        let out_a = a.admit(Call {
            actor: &principals[step.principal],
            request: &req,
            model: MODELS[step.model],
            cost_tokens: step.cost,
            variant,
        });
        let out_b = b.admit(Call {
            actor: &principals[step.principal],
            request: &req,
            model: MODELS[step.model],
            cost_tokens: step.cost,
            variant,
        });
        assert_eq!(
            out_a, out_b,
            "call {seq}: two identical deployments disagreed on the same request"
        );
        ledger.record(&step, &out_a);

        if (seq + 1) % CHECKPOINT == 0 {
            check_invariants(&a, &ledger, &names, seq + 1);
            check_invariants(&b, &ledger, &names, seq + 1);

            // Determinism: identical audit digests, identical metric exports.
            roll_a.absorb(a.audit());
            roll_b.absorb(b.audit());
            assert_eq!(
                roll_a.hex(),
                roll_b.hex(),
                "call {}: audit digests diverged between two identical deployments",
                seq + 1
            );
            assert_eq!(
                a.metrics(),
                b.metrics(),
                "call {}: metric exports diverged between two identical deployments",
                seq + 1
            );

            if sample.is_empty() {
                sample.push((0, a.audit()[0].clone()));
                sample.push((CHECKPOINT - 1, a.audit()[CHECKPOINT - 1].clone()));
            }
            stable_prefix(&a, &sample, seq + 1);
        }
    }
    let elapsed = started.elapsed();
    let grown = live_bytes().saturating_sub(base_bytes);

    // The workload must actually have been a workload: all eight refusal
    // kinds present, real traffic forwarded, and budgets genuinely drained.
    assert_eq!(ledger.tags.len(), 8, "not every refusal kind was exercised");
    for tag in [
        "unauthenticated",
        "unknown_tenant",
        "outside_boundary",
        "tool_not_governed",
        "permission_denied",
        "model_not_allowed",
        "variant_not_activated",
        "budget_exhausted",
    ] {
        assert!(
            ledger.tags.get(tag).copied().unwrap_or(0) > 100,
            "refusal kind {tag} barely occurred: the endurance run is not exercising it"
        );
    }
    assert!(
        ledger.forwarded > 10_000,
        "only {} calls were forwarded; the run is all refusals",
        ledger.forwarded
    );
    for (i, name) in names.iter().enumerate() {
        if a.spent(name) + 1 > limit_of(i) {
            exhausted_tenants += 1;
        }
    }
    assert!(
        exhausted_tenants >= 10,
        "only {exhausted_tenants} tenants exhausted their budget; \
         the run never tested life after exhaustion"
    );

    // The bounded pool stayed bounded, exactly: three aggregate series plus
    // one per refusal kind, and not a name more after 200 000 hostile calls.
    let final_series: Vec<String> = a.metrics().into_iter().map(|(n, _)| n).collect();
    assert_eq!(
        final_series,
        vec![
            "gateway.forwarded",
            "gateway.refused",
            "gateway.refused.budget_exhausted",
            "gateway.refused.model_not_allowed",
            "gateway.refused.outside_boundary",
            "gateway.refused.permission_denied",
            "gateway.refused.tool_not_governed",
            "gateway.refused.unauthenticated",
            "gateway.refused.unknown_tenant",
            "gateway.refused.variant_not_activated",
            "gateway.requests",
        ],
        "the metric series set drifted from the 11 low-cardinality names"
    );

    // A final full-journal audit: the incremental expectation above is only
    // as good as its agreement with what is actually stored.
    let mut journal_forwarded = 0u64;
    let mut journal_tags: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut journal_ids = 0u64;
    for r in a.audit() {
        match &r.outcome {
            Outcome::Forwarded => journal_forwarded += 1,
            Outcome::Refused(x) => *journal_tags.entry(tag_of(x)).or_insert(0) += 1,
        }
        journal_ids += u64::from(r.request_id.starts_with("r-"));
    }
    assert_eq!(journal_forwarded, ledger.forwarded);
    assert_eq!(journal_tags, ledger.tags);
    assert_eq!(journal_ids, MAIN_CALLS as u64, "every call is correlated");

    // DEFECT (finding 1, second edge): the trail keeps rows attributed to a
    // tenant that was never provisioned, and `audit_of` hands them back under
    // that name. The tenant label in the journal is attacker-chosen, so the
    // unbounded `Vec` also holds an unbounded set of distinct tenant strings.
    let phantom = a.audit_of("ghost-tenant");
    assert_eq!(
        phantom.len() as u64,
        ledger.tags.get("unknown_tenant").copied().unwrap_or(0),
        "the journal stores rows for a tenant that does not exist"
    );
    assert!(!phantom.is_empty());
    assert_eq!(a.spent("ghost-tenant"), 0, "and it can never be billed");

    // DEFECT (finding 1), quantified on the honest workload: 200 000 calls,
    // of which only ~31% were forwarded, still cost one record each.
    let refused_share = ledger.refused as f64 / ledger.calls as f64;
    println!(
        "endurance: {MAIN_CALLS} calls x2 deployments in {:?} \
         ({:.2} us/admit) | forwarded {} refused {} ({:.0}% refused) | \
         exhausted tenants {exhausted_tenants} | retained {:.1} MiB \
         ({:.0} B per record, both trails)",
        elapsed,
        elapsed.as_secs_f64() * 1e6 / (2.0 * MAIN_CALLS as f64),
        ledger.forwarded,
        ledger.refused,
        refused_share * 100.0,
        mib(grown),
        grown as f64 / (2.0 * MAIN_CALLS as f64),
    );
    assert!(
        grown >= 2 * MAIN_CALLS * 64,
        "expected the two unbounded trails to retain >= 64 B per record, \
         measured {grown} B total"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 2. THE EXHAUSTION VECTOR
// ─────────────────────────────────────────────────────────────────────────

/// **Finding 1 — exhaustion vector, high.** One million calls from an
/// `AuthStrength::Anonymous` principal. Every one is refused at the *first*
/// gate: no tenant is resolved, no role consulted, no token spent. And every
/// one allocates an audit record that lives until the `Deployment` is
/// dropped.
///
/// The comparison that makes it a defect rather than a design choice is in
/// the same struct: `CounterRegistry` folds at `MAX_SERIES` "so a label
/// explosion can never exhaust memory", and here it does exactly that — three
/// series, flat, for a million hostile calls. The `Vec` beside it has no cap,
/// no rotation and no persistence, and it is the one an unauthenticated
/// client controls.
#[test]
fn unauthenticated_flood_grows_the_audit_trail_without_bound() {
    let _guard = serialized();
    let names = tenant_names();
    let mut d = fleet_deployment(&names);
    let attacker = actor("nowhere", "ghost", AuthStrength::Anonymous);
    let mut req = request(&names[0], "ghost", "memory.recall", "");

    let base = live_bytes();
    let started = Instant::now();
    let mut samples = Vec::new();
    for i in 0..FLOOD_CALLS {
        req.request_id.clear();
        write!(req.request_id, "r-{i:08}").expect("String write is infallible");
        let out = d.admit(Call {
            actor: &attacker,
            request: &req,
            model: "claude-opus",
            cost_tokens: 0,
            variant: None,
        });
        assert!(
            matches!(out, Outcome::Refused(Refusal::Unauthenticated)),
            "call {i}: the identity gate stopped refusing"
        );
        if (i + 1) % (FLOOD_CALLS / 4) == 0 {
            samples.push((i + 1, live_bytes().saturating_sub(base)));
        }
    }
    let elapsed = started.elapsed();

    // Nothing was earned by the attacker …
    for name in &names {
        assert_eq!(d.spent(name), 0, "a refused call charged tenant {name}");
    }
    // … and nothing was bounded either.
    assert_eq!(
        d.audit().len(),
        FLOOD_CALLS,
        "one refused call, one audit record — no cap, no rotation"
    );

    // The bounded pool right next door stayed bounded: 3 series, flat.
    let m = d.metrics();
    assert_eq!(
        m.len(),
        3,
        "expected exactly requests/refused/refused.unauthenticated, got {m:?}"
    );
    assert_eq!(metric(&m, "gateway.requests"), FLOOD_CALLS as u64);
    assert_eq!(metric(&m, "gateway.refused"), FLOOD_CALLS as u64);
    assert_eq!(
        metric(&m, "gateway.refused.unauthenticated"),
        FLOOD_CALLS as u64
    );

    println!("unauthenticated flood ({FLOOD_CALLS} refusals, {elapsed:?}):");
    for (calls, bytes) in &samples {
        println!(
            "  after {calls:>9} refusals: {:>8.1} MiB retained ({:>5.0} B/record)",
            mib(*bytes),
            *bytes as f64 / *calls as f64
        );
    }

    let (_, quarter) = samples[0];
    let (_, full) = samples[3];
    assert!(
        full >= 64 * FLOOD_CALLS,
        "expected >= 64 B retained per refused call, measured {full} B for \
         {FLOOD_CALLS} records"
    );
    // Linear, not logarithmic, not plateauing: four times the refusals retain
    // at least three times the memory. A bounded structure would flatten.
    assert!(
        full >= 3 * quarter,
        "growth is not linear: {quarter} B at 25% vs {full} B at 100% — \
         if this now plateaus, the trail grew a cap and this finding is fixed"
    );

    // The only way to get the memory back is to destroy the governance layer:
    // `audit()` hands out a shared slice, and no `truncate`/`drain`/`rotate`/
    // `persist` exists on `Deployment` at all. Dropping is the whole API.
    drop(d);
    let after_drop = live_bytes().saturating_sub(base);
    assert!(
        after_drop < full / 8,
        "dropping the deployment should be the one thing that frees the \
         trail: {full} B before, {after_drop} B after"
    );
}

/// **Finding 2 — the same vector, per byte; half repaired, half still open.**
///
/// What the defect was: the record clones `request.{tenant,actor,tool}` with
/// no length check anywhere in the path, so the attacker chose the *size* of
/// each record as well as the count — and it was worse for a token-strength
/// caller, because `Refusal::OutsideBoundary` formatted the **whole** tool
/// name into its message, which `admit` then cloned into the record *and*
/// returned. Two copies of every attacker byte: a measured 2.00 retained
/// bytes per attacker byte against an anonymous caller's 1.00, so 4 GiB of
/// operator memory was 2 GiB of request body away.
///
/// What it cost and what was repaired: `classify` now refuses any name over
/// `MAX_TOOL_NAME_BYTES` (256) as non-canonical *before* it matches anything,
/// and passes everything it does echo through a sanitizer capped at 64
/// characters, so a refusal message is a bounded constant however large the
/// name. The doubling is gone; this test now guards that bound, at a 1 MiB
/// name (refused unread) and at the largest name the boundary will still
/// classify (256 bytes, canonical, forbidden — the one that does reach the
/// message).
///
/// **Still open, deliberately pinned below:** the *first* copy. `admit`
/// journals `request.tool` verbatim before and regardless of which gate
/// refused the call, so an anonymous caller who never passes the identity
/// gate still gets a 1 MiB tool name copied into the trail at 1.00 retained
/// bytes per attacker byte. Bounding the boundary's message did not bound the
/// record.
#[test]
fn audit_record_size_is_attacker_controlled_but_boundary_refusals_no_longer_double_it() {
    let _guard = serialized();
    const BIG: usize = 1024 * 1024;
    const CALLS: usize = 32;
    /// Hard ceiling on a refusal message: the longest template
    /// (`"tool namespace '…' is outside the Enterprise boundary"`, 52 bytes)
    /// around a sanitized name of at most 64 characters — 3 bytes each in the
    /// worst case, every one replaced by U+FFFD — plus the ellipsis.
    const REFUSAL_MESSAGE_CAP: usize = 52 + 64 * 3 + 3;
    let names = tenant_names();
    let huge_tool = "x".repeat(BIG);

    // (a) STILL OPEN. Unauthenticated: refused at gate 1, still copied
    //     verbatim into the record. Unchanged by the repair, and asserted
    //     here at its real value so that bounding the record would trip it.
    let mut d = fleet_deployment(&names);
    let ghost = actor("nowhere", "ghost", AuthStrength::Anonymous);
    let mut req = request(&names[0], "ghost", &huge_tool, "r-0");
    let base = live_bytes();
    for i in 0..CALLS {
        req.request_id.clear();
        write!(req.request_id, "r-{i}").expect("String write is infallible");
        let out = d.admit(Call {
            actor: &ghost,
            request: &req,
            model: "claude-opus",
            cost_tokens: 0,
            variant: None,
        });
        assert!(matches!(out, Outcome::Refused(Refusal::Unauthenticated)));
    }
    let anon_bytes = live_bytes().saturating_sub(base);
    let anon_ratio = anon_bytes as f64 / (CALLS * BIG) as f64;
    assert_eq!(d.audit().len(), CALLS);
    assert_eq!(
        d.audit()[0].tool.len(),
        BIG,
        "the trail stored the attacker's 1 MiB tool name in full"
    );
    assert!(
        anon_ratio >= 0.99,
        "expected ~1 retained byte per attacker byte, measured {anon_ratio:.2}"
    );
    drop(d);

    // (b) REPAIRED. Token strength, no role, known tenant — the case that used
    //     to cost double, because the boundary refusal repeated the whole tool
    //     name inside its message and the trail then kept it twice. Identical
    //     input, opposite expectation: a 1 MiB name is now over the 256-byte
    //     canonical limit, so it is refused unread and the message it produces
    //     is a constant that mentions none of it.
    let mut d = fleet_deployment(&names);
    let mallory = actor("memorithm", "mallory", AuthStrength::Token);
    let forbidden = format!("shell.{}", "y".repeat(BIG));
    let mut req = request(&names[0], "mallory", &forbidden, "r-0");
    let base = live_bytes();
    let mut longest_message = 0usize;
    for i in 0..CALLS {
        req.request_id.clear();
        write!(req.request_id, "r-{i}").expect("String write is infallible");
        let out = d.admit(Call {
            actor: &mallory,
            request: &req,
            model: "claude-opus",
            cost_tokens: 0,
            variant: None,
        });
        let Some(Refusal::OutsideBoundary(why)) = out.refusal() else {
            panic!("call {i}: expected a boundary refusal");
        };
        longest_message = longest_message.max(why.len());
        assert!(
            why.len() <= REFUSAL_MESSAGE_CAP,
            "call {i}: the refusal message is {} B for a {BIG} B name — it \
             must not grow with the caller's input",
            why.len()
        );
        assert!(
            !why.contains(&"y".repeat(65)),
            "call {i}: the refusal message still echoes an unbounded run of \
             the attacker's bytes: {why}"
        );
    }
    let boundary_bytes = live_bytes().saturating_sub(base);
    let boundary_ratio = boundary_bytes as f64 / (CALLS * BIG) as f64;

    println!(
        "attacker-sized records ({CALLS} x {} MiB tool name): \
         anonymous {:.1} MiB retained ({anon_ratio:.2} B/attacker byte), \
         boundary refusal {:.1} MiB retained ({boundary_ratio:.2} B/attacker \
         byte), longest refusal message {longest_message} B",
        BIG / (1024 * 1024),
        mib(anon_bytes),
        mib(boundary_bytes),
    );
    // THE REPAIR, measured: the second copy is gone. A boundary refusal now
    // costs the same one copy an anonymous refusal does, not two. If the
    // message ever embeds the name again this crosses 1.5 and fails.
    assert!(
        boundary_ratio < 1.5,
        "a boundary refusal must no longer retain a second copy of every \
         attacker byte, measured {boundary_ratio:.2}"
    );
    // STILL OPEN: the first copy. The record itself is unbounded, and the
    // gate that refused the call never had a say in that.
    assert!(
        boundary_ratio >= 0.99,
        "the record still stores the name verbatim (finding 2 is only half \
         repaired); measured {boundary_ratio:.2} — if this dropped, the \
         record grew a length cap and the rest of the finding is fixed too"
    );
    assert_eq!(
        d.audit()[0].tool.len(),
        forbidden.len(),
        "the trail still stores the attacker's whole name, refused or not"
    );
    drop(d);

    // (c) The bound where it actually bites: the largest name the boundary
    //     will still classify — 256 bytes, canonical, and forbidden on its
    //     `shell.` head. This one *does* reach the message, so it is the case
    //     that proves the sanitizer caps the echo rather than the length check
    //     merely hiding it.
    let mut d = fleet_deployment(&names);
    let at_limit = format!("shell.{}", "y".repeat(250));
    assert_eq!(at_limit.len(), 256, "the largest name still classified");
    let req = request(&names[0], "mallory", &at_limit, "r-max");
    let out = d.admit(Call {
        actor: &mallory,
        request: &req,
        model: "claude-opus",
        cost_tokens: 0,
        variant: None,
    });
    let Some(Refusal::OutsideBoundary(why)) = out.refusal() else {
        panic!("a 256-byte `shell.` name must still be a boundary refusal");
    };
    assert!(
        why.len() <= REFUSAL_MESSAGE_CAP,
        "the echoed name must be truncated, message was {} B: {why}",
        why.len()
    );
    assert!(
        why.len() < at_limit.len(),
        "the message ({} B) must be shorter than the name it reports \
         ({} B)",
        why.len(),
        at_limit.len()
    );
    assert!(
        !why.contains(&"y".repeat(65)),
        "the sanitizer must cap the echoed name at 64 characters: {why}"
    );
    assert!(why.contains('…'), "a truncated name must say so: {why}");
    println!(
        "  at the 256-byte classification limit the refusal reads ({} B): {why}",
        why.len()
    );
    // …and, still open, the record beside it keeps all 256 bytes.
    assert_eq!(d.audit()[0].tool.len(), at_limit.len());
}

/// **Finding 3.** Rotation is not merely absent, it is unimplementable from
/// what an `AuditRecord` stores: five fields, none of them a timestamp, a
/// cost, a model or a variant. An operator holding a 5 000 000-record trail
/// cannot answer "drop everything older than 30 days" (no time), nor "prove
/// how `spent` reached 1 000" (no cost) — the two questions retention policy
/// and budget policy are made of.
#[test]
fn audit_records_carry_neither_time_nor_cost_so_rotation_is_impossible() {
    let _guard = serialized();
    let names = tenant_names();
    let mut d = fleet_deployment(&names);
    let alice = actor("memorithm", "alice", AuthStrength::Token);

    for i in 0..64u64 {
        let req = request(&names[0], "alice", "memory.ingest", &format!("r-{i}"));
        let out = d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 3,
            variant: None,
        });
        assert!(out.is_forwarded(), "call {i} should be admitted");
    }
    assert_eq!(d.spent(&names[0]), 64 * 3);

    // The record is exhaustively {request_id, tenant, actor, tool, outcome}.
    // Serializing it is the honest way to show what is *not* there, and it
    // fails to mention the 192 tokens it just authorized.
    let r = &d.audit()[0];
    let rendered = format!(
        "{{\"request_id\":\"{}\",\"tenant\":\"{}\",\"actor\":\"{}\",\"tool\":\"{}\",\"outcome\":\"{:?}\"}}",
        r.request_id, r.tenant, r.actor, r.tool, r.outcome
    );
    for absent in ["cost", "token", "time", "unix", "model", "variant"] {
        assert!(
            !rendered.to_ascii_lowercase().contains(absent),
            "an AuditRecord unexpectedly carries {absent}: {rendered}"
        );
    }
    // Spend is a single u64 with no derivation anywhere in the journal: the
    // 64 admitted records are indistinguishable from each other cost-wise.
    let admitted: Vec<&AuditRecord> = d
        .audit()
        .iter()
        .filter(|r| r.outcome.is_forwarded())
        .collect();
    assert_eq!(admitted.len(), 64);
    assert!(
        admitted.windows(2).all(|w| w[0].outcome == w[1].outcome),
        "every admitted record is byte-identical bar the id: the trail \
         cannot explain a single token of the 192 that were charged"
    );
}

/// **Finding 4.** `audit_of` is the only per-tenant view and it filters the
/// entire `Vec`, allocating one pointer per match. So the exhaustion vector
/// amplifies itself: an attacker who parks 200 000 refused records under a
/// tenant makes every legitimate audit query scan them and allocate 1.6 MB.
#[test]
fn audit_of_scans_the_whole_trail_and_allocates_per_match() {
    let _guard = serialized();
    const FLOOD: usize = 200_000;
    let names = tenant_names();
    let mut d = fleet_deployment(&names);
    let ghost = actor("nowhere", "ghost", AuthStrength::Anonymous);
    let alice = actor("memorithm", "alice", AuthStrength::Token);

    // One honest tenant with 8 records …
    for i in 0..8u64 {
        let req = request(&names[1], "alice", "memory.recall", &format!("h-{i}"));
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
        });
    }
    // … and one tenant an anonymous client has buried.
    let mut req = request(&names[0], "ghost", "memory.recall", "");
    for i in 0..FLOOD {
        req.request_id.clear();
        write!(req.request_id, "r-{i:08}").expect("String write is infallible");
        d.admit(Call {
            actor: &ghost,
            request: &req,
            model: "claude-opus",
            cost_tokens: 0,
            variant: None,
        });
    }
    assert_eq!(d.audit().len(), FLOOD + 8);

    // The buried tenant's own query allocates 8 bytes per match.
    let before = live_bytes();
    let buried = d.audit_of(&names[0]);
    let buried_alloc = live_bytes().saturating_sub(before);
    assert_eq!(buried.len(), FLOOD);
    assert!(
        buried_alloc >= 8 * FLOOD,
        "expected >= {} B for {FLOOD} borrowed records, measured {buried_alloc} B",
        8 * FLOOD
    );
    drop(buried);

    // And the *innocent* tenant pays too: its 8-record query still walks all
    // 200 008. Timed rather than asserted (wall clock is not an invariant),
    // but the scan is unconditional in `src/lib.rs:344` — there is no index.
    let started = Instant::now();
    let innocent = d.audit_of(&names[1]);
    let innocent_scan = started.elapsed();
    assert_eq!(innocent.len(), 8);
    println!(
        "audit_of on a flooded deployment: buried tenant {} records / {} B allocated; \
         innocent tenant 8 records but {innocent_scan:?} of scan over {} total",
        FLOOD,
        buried_alloc,
        d.audit().len()
    );
}

/// **Finding 5 — spec violation.** `GatewayRequest::request_id` is documented
/// as an "Idempotency/correlation key for audit joins"
/// (`crates/ccos-enterprise-gateway/src/lib.rs:16`) and the composed path's
/// own docs promise every call is "audit-correlated by request id". `admit`
/// never reads the field: one byte-identical request replayed 20 000 times is
/// charged 20 000 times and journaled 20 000 times under the same id, so the
/// key an operator would join on has cardinality 1 for 20 000 rows — and a
/// replay of a *single* captured request is enough to drain a tenant's whole
/// budget and then keep growing the trail for free.
#[test]
fn replayed_request_id_is_charged_every_time() {
    let _guard = serialized();
    const REPLAYS: u64 = 10_000;
    const ID: &str = "the-one-and-only-id";
    let names = tenant_names();
    let mut d = fleet_deployment(&names);
    let alice = actor("memorithm", "alice", AuthStrength::Token);

    // (a) The fattest budget in the fleet (t-49: 250 + 49*400 = 20 050) against
    //     10 000 replays at 1 token: every single replay is admitted and billed.
    let fat = &names[TENANTS - 1];
    let req = request(fat, "alice", "memory.ingest", ID);
    let mut admitted = 0u64;
    for _ in 0..REPLAYS {
        let out = d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
        });
        admitted += u64::from(out.is_forwarded());
    }
    assert_eq!(
        admitted, REPLAYS,
        "DEFECT: the 'idempotency key' deduplicated nothing — \
         {REPLAYS} replays of one request, {REPLAYS} admissions"
    );
    assert_eq!(
        d.spent(fat),
        REPLAYS,
        "DEFECT: one captured request, replayed, bills the tenant every time"
    );

    // (b) The same replay against the thinnest budget (t-00: 250) at 5 tokens
    //     drains it in 50 calls — and the remaining 9 950 replays are refused
    //     yet still journaled, so the attacker keeps paying nothing and the
    //     operator keeps paying memory.
    let thin = &names[0];
    let req = request(thin, "alice", "memory.ingest", ID);
    let mut admitted_thin = 0u64;
    for _ in 0..REPLAYS {
        let out = d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 5,
            variant: None,
        });
        admitted_thin += u64::from(out.is_forwarded());
    }
    assert_eq!(admitted_thin, limit_of(0) / 5, "250 tokens / 5 per replay");
    assert_eq!(d.spent(thin), limit_of(0));

    assert_eq!(d.audit().len() as u64, 2 * REPLAYS);
    let same_id = d.audit().iter().filter(|r| r.request_id == ID).count();
    assert_eq!(
        same_id,
        2 * REPLAYS as usize,
        "DEFECT: {} audit rows share one 'idempotency/correlation key'",
        2 * REPLAYS
    );
}

/// **Finding 6.** `spent` folds "no such tenant" into "spent nothing"
/// (`src/lib.rs:331`). A quota monitor pointed at a mistyped tenant reports a
/// perfectly healthy, perfectly idle tenant, forever.
#[test]
fn spent_of_an_unknown_tenant_is_indistinguishable_from_zero() {
    let _guard = serialized();
    let names = tenant_names();
    let d = fleet_deployment(&names);
    assert_eq!(d.spent(&names[0]), 0, "a fresh tenant has spent nothing");
    assert_eq!(
        d.spent("t-00 "),
        0,
        "DEFECT: a trailing space reads as an idle tenant, not as an error"
    );
    assert_eq!(d.spent("no-such-tenant"), 0);
    assert_eq!(d.spent(""), 0);
    // …and the audit view answers the same way: silence, not an error.
    assert!(d.audit_of("no-such-tenant").is_empty());
}

/// **Finding 8.** The invariant this whole file rests on — `spent(t)` equals
/// the sum of admitted costs — is false for an "unlimited" tenant. The budget
/// saturates on the accounting side (`crates/ccos-enterprise-policy/src/lib.rs:39`),
/// which is the right call against a wrapping ledger, but it means the
/// deployment can forward work it then declines to bill, permanently and
/// without a signal anywhere.
#[test]
fn unlimited_budget_stops_summing_admitted_costs() {
    let _guard = serialized();
    let mut d = Deployment::new();
    d.add_role("writer", &["memory.read", "memory.write"])
        .govern_tool("memory.ingest", "memory.write");
    let mut unlimited = TenantState::new(u64::MAX);
    unlimited.allow_model("claude-opus");
    d.add_tenant("infinite", unlimited);
    assert!(d.assign("alice", "writer"));
    let alice = actor("memorithm", "alice", AuthStrength::Token);

    let mut admitted_sum = 0u128;
    for (i, cost) in [u64::MAX - 1, 1_000, 7].into_iter().enumerate() {
        let req = request("infinite", "alice", "memory.ingest", &format!("r-{i}"));
        let out = d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: cost,
            variant: None,
        });
        assert!(out.is_forwarded(), "an unlimited budget admits everything");
        admitted_sum += u128::from(cost);
    }

    assert_eq!(d.audit().len(), 3, "all three calls were journaled");
    assert_eq!(u128::from(d.spent("infinite")), u128::from(u64::MAX));
    assert!(
        admitted_sum > u128::from(d.spent("infinite")),
        "the ledger should have fallen behind the admitted sum"
    );
    assert_eq!(
        admitted_sum - u128::from(d.spent("infinite")),
        1_006,
        "DEFECT: 1 006 tokens were admitted and never billed, and nothing in \
         the audit trail records the difference"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 3. The long run
// ─────────────────────────────────────────────────────────────────────────

/// The `#[ignore]`d endurance run: **5 000 000 admissions**, the same
/// invariants, checked every 250 000 calls, with a memory-growth table.
///
/// Exact command:
///
/// ```text
/// cargo test -p ccos-enterprise-conformance --test stress_endurance --release \
///     -- --ignored --nocapture endurance_five_million_admissions
/// ```
///
/// Release is recommended (measured 9.7 s / 1.95 us per admission, against
/// 29.1 s in debug) but not required: the memory table is byte-identical in
/// both profiles, because the counting allocator measures requested layouts.
///
/// **Measured result: 1 150.9 MiB retained for 5 000 000 calls** — 241 B per
/// record, still climbing, no plateau. That is the finding, not an accident,
/// which is also why the determinism cross-check runs its *second* deployment
/// over the first 500 000 steps only and then drops it: holding two
/// 5 000 000-record trails at once would cost 2.3 GiB, and this test should
/// document the exhaustion rather than perform it. (The first two rows of the
/// growth table therefore include the mirror; from 750 000 on it is one
/// trail.) The stepped rows are `Vec` capacity doublings — at 4 250 000
/// records the trail reallocates and briefly holds ~1.6 GiB.
#[test]
#[ignore = "5M admissions; run explicitly, see the doc comment for the command"]
fn endurance_five_million_admissions() {
    let _guard = serialized();
    const CHECK_EVERY: usize = 250_000;
    const MIRROR_UNTIL: usize = 500_000;

    let names = tenant_names();
    let principals: Vec<AuthenticatedActor> = PRINCIPALS
        .iter()
        .map(|(name, strength)| actor("memorithm", name, *strength))
        .collect();

    let mut a = fleet_deployment(&names);
    let mut mirror = Some(fleet_deployment(&names));
    let mut ledger = Ledger::new();
    let mut roll_a = RollingDigest::default();
    let mut roll_b = RollingDigest::default();
    let mut rng = Rng::new(0x5EED_0001_C0DE_F00D);
    let mut req = request("", "", "", "");
    let mut sample: Vec<(usize, AuditRecord)> = Vec::new();
    let mut growth: Vec<(usize, usize)> = Vec::new();

    let base = live_bytes();
    let started = Instant::now();
    for seq in 0..LONG_CALLS {
        let step = next_step(&mut rng);
        fill_request(&mut req, &step, &names, seq);
        let variant = step.variant.then_some(AdvancedQPageVariant::Hierarchical);
        let out = a.admit(Call {
            actor: &principals[step.principal],
            request: &req,
            model: MODELS[step.model],
            cost_tokens: step.cost,
            variant,
        });
        if let Some(b) = mirror.as_mut() {
            let out_b = b.admit(Call {
                actor: &principals[step.principal],
                request: &req,
                model: MODELS[step.model],
                cost_tokens: step.cost,
                variant,
            });
            assert_eq!(out, out_b, "call {seq}: the mirror deployment diverged");
        }
        ledger.record(&step, &out);

        if seq + 1 == MIRROR_UNTIL {
            let b = mirror.take().expect("mirror still running");
            roll_a.absorb(a.audit());
            roll_b.absorb(b.audit());
            assert_eq!(
                roll_a.hex(),
                roll_b.hex(),
                "audit digests diverged over the mirrored prefix"
            );
            assert_eq!(a.metrics(), b.metrics(), "metric exports diverged");
            // The mirror is dropped here, on purpose: see the doc comment.
            drop(b);
        }

        if (seq + 1) % CHECK_EVERY == 0 {
            check_invariants(&a, &ledger, &names, seq + 1);
            roll_a.absorb(a.audit());
            if sample.is_empty() {
                sample.push((0, a.audit()[0].clone()));
                sample.push((CHECK_EVERY - 1, a.audit()[CHECK_EVERY - 1].clone()));
            }
            stable_prefix(&a, &sample, seq + 1);
            growth.push((seq + 1, live_bytes().saturating_sub(base)));
        }
    }
    let elapsed = started.elapsed();

    assert_eq!(
        a.audit().len(),
        LONG_CALLS,
        "no cap engaged at five million"
    );
    assert_eq!(ledger.tags.len(), 8);

    println!(
        "five-million-call endurance run in {elapsed:?} ({:.2} us/admit); \
         final digest {}",
        elapsed.as_secs_f64() * 1e6 / LONG_CALLS as f64,
        roll_a.hex()
    );
    println!("  calls        retained MiB   B/record   MiB per additional 250k");
    let mut previous = 0usize;
    for (calls, bytes) in &growth {
        println!(
            "  {calls:>9}    {:>10.1}   {:>8.0}   {:>10.1}",
            mib(*bytes),
            *bytes as f64 / *calls as f64,
            mib(bytes.saturating_sub(previous)),
        );
        previous = *bytes;
    }

    // Growth is linear all the way out: the last quarter of the run costs at
    // least as much as the first did. Nothing rotates, nothing plateaus.
    let (_, first_quarter) = growth[LONG_CALLS / CHECK_EVERY / 4 - 1];
    let (_, all) = growth[growth.len() - 1];
    assert!(
        all >= 3 * first_quarter,
        "expected linear growth to five million: {first_quarter} B at 25%, {all} B at 100%"
    );
    assert!(
        all >= 64 * LONG_CALLS,
        "expected >= 64 B retained per record, measured {all} B"
    );
}
