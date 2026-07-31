//! # Hostile endurance stress of the composed governed path
//!
//! Everything else in this suite asks "is one decision right?". This file
//! asks the only question a governance layer is actually judged on in
//! production: **does it still tell the truth after two hundred thousand
//! decisions, and does it survive the two hundred thousand and first?**
//!
//! Four properties are hammered, continuously, at every 10 000-call
//! checkpoint of a 50-tenant, 200 000-call run:
//!
//! 1. **the ledger** — `Deployment::spent(t)` equals, exactly, the sum of the
//!    costs of the calls the deployment itself reported as `Forwarded` for
//!    `t` (the expectation is built from the product's own return values, so
//!    a drift between *deciding* and *accounting* cannot hide behind a
//!    re-implementation of the decision);
//! 2. **the journal** — bounded now, and honest about it:
//!    `audit().count() + audit_dropped()` equals the number of calls, always;
//!    what is retained is exactly the newest `DEFAULT_AUDIT_CAPACITY`
//!    decisions, contiguous in `sequence` and ending at the call just made;
//!    and a record still inside that window is byte-identical to what it was
//!    a hundred thousand calls ago, while a record that left it left through
//!    the front door — counted, never rewritten;
//! 3. **the counters** — `gateway.requests == gateway.forwarded +
//!    gateway.refused`, each equals the journal's own tally, the
//!    `gateway.refused.*` series sum to `gateway.refused`, and
//!    `audit.dropped` agrees with `audit_dropped()`;
//! 4. **the journal reconciles the meter** — every record carries the cost it
//!    was charged (`0` for every refusal), and the retained window matches,
//!    decision for decision, an independently maintained mirror of the last
//!    100 000 outcomes the deployment returned.
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
//! * **The counters agree with the journal to the unit**, in aggregate and
//!   per refusal tag, and the series set stays at exactly 12 names however
//!   hostile the input: `admit` folds every refusal through a `&'static str`,
//!   so the one bounded pool in the product stays bounded.
//! * **Determinism is total.** Two independently built deployments fed the
//!   same 200 000 steps agreed on every single outcome, produced the same
//!   SHA-256 audit digest at all 20 checkpoints, and exported byte-identical
//!   metrics. Every container in the composed path is a `BTree*` or a
//!   `VecDeque`; there is no hash seed, no clock and no interior
//!   nondeterminism to shake loose. Debug and release agree to the byte, on
//!   outcomes and on measured memory alike.
//! * **Nothing rots at 25x the scale.** The `#[ignore]`d 5 000 000-call run
//!   holds every one of the above at all 20 of its checkpoints — ledger,
//!   journal bound, counters, window stability — in 40.2 s of debug (8.03 us
//!   per admission) and, from the moment the determinism mirror is dropped at
//!   call 500 000, **31.6 MiB retained and +0.0 MiB per additional 250 000
//!   calls, eighteen checkpoints running**. No gate degrades as the run goes
//!   on, because nothing in the composed path grows with it any more.
//!   → [`endurance_five_million_admissions`]
//!
//! ## What was repaired
//!
//! * **The audit trail is bounded, and says what it dropped.** It used to be
//!   an unbounded `Vec` with no cap, no rotation and no persistence, and an
//!   *unauthenticated* caller drove it: `admit` journalled after `decide`, on
//!   every path, so a refusal cost the operator memory exactly like an
//!   admission did. 1 000 000 calls from an `AuthStrength::Anonymous`
//!   principal — refused at the very first gate, zero tokens spent, zero
//!   tenants touched — left 1 000 000 records and a **measured 150.5 MiB** of
//!   retained heap, growing dead linearly with no plateau anywhere (37.6 MiB
//!   at 250 000 refusals, 75.3 at 500 000, 150.5 at 1 000 000), and the long
//!   run reached **1 150.9 MiB at 5 000 000** and was still climbing. Dropping
//!   the whole `Deployment` was the only thing that freed a byte of it.
//!   The journal is now a `VecDeque` capped at `DEFAULT_AUDIT_CAPACITY`
//!   (100 000): the oldest record is evicted, `audit_dropped()` counts every
//!   eviction, and an `audit.dropped` counter moves with it. Re-measured on
//!   the identical million-refusal workload: **21.1 MiB retained and flat** —
//!   21.1 at 250 000 refusals, 21.1 at 500 000, 21.1 at 1 000 000, a steady
//!   221 B per *retained* record and 22.1 B per call at a million and still
//!   falling. The main run measures the same shape from the other side: 57.3
//!   MiB at call 100 000, where the cap engages, and 63.9 MiB at call 200 000
//!   — the second hundred thousand calls add only replay memory, where they
//!   used to add a second hundred thousand records. The plateau, not the
//!   slope, is now the finding.
//!   → [`unauthenticated_flood_is_bounded_by_the_audit_capacity`],
//!   [`endurance_five_million_admissions`]
//! * **Per-record size is no longer attacker-controlled either.** The record
//!   cloned `request.{tenant,actor,tool}` verbatim, unvalidated and
//!   untruncated, *before and regardless of* which gate refused the call, so
//!   the vector was unbounded in two dimensions at once: an anonymous caller
//!   who never passed the identity gate still got a 1 MiB tool name copied
//!   into the trail at a measured **1.00 retained bytes per attacker byte**,
//!   and a token-strength caller cost **2.00**, because
//!   `Refusal::OutsideBoundary` formatted the whole name into its message and
//!   `admit` kept that too. 4 GiB of operator memory was 2 GiB of request body
//!   away. Both copies are gone: `classify` refuses any name over
//!   `MAX_TOOL_NAME_BYTES` (256) as non-canonical *before* it matches
//!   anything and caps what it does echo at 64 characters (119 B at the
//!   largest name it will still classify, 35 B for a megabyte one), and
//!   `journal` clamps every identifier it stores to `MAX_IDENTIFIER_BYTES`
//!   (128) on a character boundary. Re-measured on the identical workload:
//!   **0.0003 retained bytes per attacker byte** — 32 MiB of tool names now
//!   retain 10 KiB in total rather than 32 MiB (anonymous) or 64 MiB
//!   (boundary refusal) — and a record is the same ~300 B whatever the caller
//!   sends.
//!   → [`attacker_sized_names_no_longer_size_the_audit_record`]
//! * **A replayed `request_id` is charged exactly once.** The field is
//!   documented as an "Idempotency/correlation key"
//!   (`crates/ccos-enterprise-gateway/src/lib.rs:16`) and `admit` never read
//!   it: one captured request replayed 10 000 times was billed 10 000 times,
//!   enough to drain a tenant outright from a single captured frame. A
//!   `(tenant, request_id)` already decided now returns `Forwarded` without
//!   charging again and moves `gateway.replayed`. 10 000 replays, 1 token
//!   billed; the 250-token tenant that used to be drained to its last token
//!   now spends 5.
//!   → [`a_replayed_request_id_is_charged_exactly_once`]
//! * **`spent()` distinguishes "unknown tenant" from "spent nothing".** It
//!   returned a bare `0` for a tenant that does not exist, so a typo in a
//!   billing or quota-monitor query read as a healthy, idle tenant forever.
//!   It returns `Option<u64>` now, and a mistyped tenant is `None`.
//!   → [`spent_distinguishes_an_unknown_tenant_from_an_idle_one`]
//! * **The record can explain the meter.** An `AuditRecord` was five fields,
//!   none of them a cost, so "prove how `spent` reached 1 000" was not merely
//!   unimplemented but unimplementable from what was stored. It carries
//!   `cost` (always `0` for a refusal) and a monotonic `sequence` now, and
//!   this file reconstructs `spent` from the journal alone.
//!   → [`audit_records_carry_cost_and_sequence_but_still_no_timestamp`]
//! * **The credential binds the request.** The predecessor authenticated one
//!   identity and authorized a different, caller-supplied one, and carried an
//!   `OrgId` on every credential that nothing ever read — so any
//!   token-strength principal could present another actor's name and another
//!   tenant's id and act with their permissions against their budget. This
//!   file's attacker is issued for the org `"nowhere"`, which owns no tenant
//!   in the fleet: the same principal at token strength is now refused
//!   `TenantNotOwnedByOrg` even holding a full `writer` role, and a caller who
//!   borrows another principal's name is refused `ActorMismatch` — both
//!   before a byte of tenant state is touched, both for zero tokens.
//!   → asserted in [`unauthenticated_flood_is_bounded_by_the_audit_capacity`]
//!
//! ## What is still open
//!
//! 1. **There is still no way to shed or export the trail on purpose.** The
//!    accessors are `audit()`, `audit_of()`, `audit_dropped()` and
//!    `metrics()` — no `drain`, no export, no persistence — and the record
//!    still carries **no timestamp**, so age-based retention remains
//!    unimplementable from what is stored. The cap bounds memory; it is not an
//!    audit story on its own, because the only thing that ever leaves the
//!    buffer is the *oldest* evidence and it leaves unread.
//!    → [`audit_records_carry_cost_and_sequence_but_still_no_timestamp`]
//!
//! 2. **The bound handed the flood a new prize: eviction.** `audit_of` is
//!    still the only per-tenant view, still O(total trail), still allocating
//!    8 bytes per match — and now an attacker who parks 200 000 refused calls
//!    under their own tenant does not merely make the innocent neighbour's
//!    8-record query walk 100 000 records, it **deletes the neighbour's eight
//!    records outright** while the meter goes on billing the tokens they were
//!    the evidence for. The loss is counted, which is precisely why this
//!    buffer must be flushed somewhere durable. Nothing in the product
//!    flushes it.
//!    → [`audit_of_scans_the_whole_trail_and_allocates_per_match`]
//!
//! 3. **The metrics have no tenant dimension.** All 12 series are
//!    deployment-global, so in a 50-tenant install the counters can say *that*
//!    4 000 calls were refused but never *whose* — and the only attribution
//!    path is the O(n) scan from finding 2, over a window that no longer holds
//!    the whole run. → asserted in
//!    [`endurance_two_hundred_thousand_admissions_across_fifty_tenants`].
//!
//! 4. **An "unlimited" tenant's ledger stops being a sum.** `TokenBudget`
//!    saturates on the accounting side, so with `limit == u64::MAX` the
//!    deployment forwards work it then declines to bill: the invariant this
//!    whole file rests on — `spent == Σ admitted` — is false past `u64::MAX`,
//!    silently and permanently. The journal's new `cost` field now *shows* the
//!    1 006 tokens that were never billed, so the drift is at last provable
//!    from the trail; it is still a drift, and nothing raises it.
//!    → [`unlimited_budget_stops_summing_admitted_costs`]

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

use ccos_enterprise_auth::{AuthStrength, AuthenticatedActor};
use ccos_enterprise_conformance::{
    actor, request, AuditRecord, Call, Deployment, Outcome, Refusal, TenantState,
    DEFAULT_AUDIT_CAPACITY, DEFAULT_REPLAY_MEMORY, MAX_IDENTIFIER_BYTES,
};
use ccos_enterprise_gateway::GatewayRequest;
use ccos_enterprise_qpages::AdvancedQPageVariant;

// ─────────────────────────────────────────────────────────────────────────
// Measurement harness
//
// A counting allocator is the only honest answer to "is the audit trail
// actually bounded". It counts `Layout::size()`, so the numbers are
// allocator-independent and identical in debug and release but for harness
// noise. Every test takes `serialized()` so a sibling allocating on another
// libtest thread cannot pollute a measurement; that makes runtime additive,
// which is why the scale constants below are tuned to keep the whole
// non-ignored file well under a minute in debug.
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

/// The organization that owns every fleet tenant. The credential binds the
/// request now, so a principal must be issued for *this* org to reach any of
/// them — which is why `ghost`, deliberately issued for `"nowhere"`, is a
/// refusal on two independent grounds rather than one.
const FLEET_ORG: &str = "memorithm";

const TENANTS: usize = 50;
const MAIN_CALLS: usize = 200_000;
const CHECKPOINT: usize = 10_000;
/// The unauthenticated flood: one million refusals against a bounded journal.
const FLOOD_CALLS: usize = 1_000_000;
/// The `#[ignore]`d long run.
const LONG_CALLS: usize = 5_000_000;

/// Principals. `ghost` never clears the identity gate; `mallory` clears it and
/// holds no role. Each principal sends its own name and every credential is
/// issued for the org that owns the tenants it addresses — the endurance
/// invariants must hold even when nobody is cheating, and the cheating cases
/// are pinned deliberately, on their own, below.
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

/// A 50-tenant deployment, every tenant owned by [`FLEET_ORG`]. Built from
/// scratch each time it is called — the determinism claim is about two
/// *independently constructed* deployments, not two clones of one.
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
        assert!(
            d.add_tenant(FLEET_ORG, name, st),
            "tenant {name} was provisioned twice"
        );
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

/// The tenant name a step addresses. Index [`TENANTS`] is the tenant that was
/// never provisioned.
fn tenant_label(index: usize, names: &[String]) -> &str {
    if index == TENANTS {
        "ghost-tenant"
    } else {
        &names[index]
    }
}

/// Overwrite in place: the request is re-used across steps so the workload's
/// own allocation noise does not swamp the trail measurement.
fn set_str(dst: &mut String, src: &str) {
    dst.clear();
    dst.push_str(src);
}

/// Fill one request, giving every call its own `request_id`. That is not
/// cosmetic any more: a repeated `(tenant, request_id)` is suppressed as a
/// replay and **not billed**, so a workload that reused one id would quietly
/// stop testing the meter it exists to test.
fn fill_request(req: &mut GatewayRequest, step: &Step, names: &[String], seq: usize) {
    set_str(&mut req.tenant, tenant_label(step.tenant, names));
    set_str(&mut req.actor, PRINCIPALS[step.principal].0);
    set_str(&mut req.tool, TOOLS[step.tool]);
    req.request_id.clear();
    write!(req.request_id, "r-{seq:08}").expect("String write is infallible");
}

// ─────────────────────────────────────────────────────────────────────────
// Audit digest
//
// Rolling, so the cost of digesting is O(records) over the *whole run* rather
// than O(records × checkpoints): each checkpoint absorbs only the records
// appended since the last one — keyed on `sequence` rather than on a position,
// because positions move now that the buffer evicts from the front. That is
// only sound while checkpoints are closer together than the buffer is deep,
// which `absorb` asserts rather than assumes, and while records inside the
// window are never rewritten, which `stable_or_dropped` pins separately.
// ─────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct RollingDigest {
    state: u64,
    /// The next `sequence` this digest has not yet absorbed.
    next: u64,
    absorbed: u64,
}

impl RollingDigest {
    fn absorb<'a>(&mut self, journal: impl Iterator<Item = &'a AuditRecord>) {
        let resume = self.next;
        let mut oldest: Option<u64> = None;
        for r in journal {
            oldest.get_or_insert(r.sequence);
            if r.sequence < resume {
                continue;
            }
            assert_eq!(
                r.sequence, self.next,
                "the journal skipped a sequence: expected {}, found {}",
                self.next, r.sequence
            );
            absorb_record(&mut self.state, r);
            self.next += 1;
            self.absorbed += 1;
        }
        if let Some(oldest) = oldest {
            assert!(
                oldest <= resume,
                "records were evicted between checkpoints and never digested: \
                 oldest retained sequence {oldest}, digest resumed at {resume}"
            );
        }
    }

    /// A real SHA-256, through the product's own primitive, over the rolling
    /// state and the record count — so "identical digests" means identical
    /// trails, not merely identical lengths.
    fn hex(&self) -> String {
        digest_hex(self.state, self.absorbed)
    }
}

/// The digest of everything a deployment *still holds*. Used where the rolling
/// form cannot be: when checkpoints are further apart than the buffer is deep,
/// the only history two deployments provably share is the window they both
/// still retain.
fn window_digest(d: &Deployment) -> String {
    let mut state = 0u64;
    let mut records = 0u64;
    for r in d.audit() {
        absorb_record(&mut state, r);
        records += 1;
    }
    digest_hex(state, records)
}

fn digest_hex(state: u64, records: u64) -> String {
    let mut blob = [0u8; 16];
    blob[..8].copy_from_slice(&state.to_le_bytes());
    blob[8..].copy_from_slice(&records.to_le_bytes());
    ccos_enterprise_governance::vendor::token_sha256(&blob)
}

/// Every field of a record, `sequence` and `cost` included: the two the
/// predecessor did not have, and the two an operator reconciles a meter
/// against a journal with. A digest that ignored them would not notice a
/// deployment that mis-billed a call it correctly forwarded.
fn absorb_record(state: &mut u64, r: &AuditRecord) {
    fnv_field(state, &r.sequence.to_le_bytes());
    fnv_field(state, r.request_id.as_bytes());
    fnv_field(state, r.tenant.as_bytes());
    fnv_field(state, r.actor.as_bytes());
    fnv_field(state, r.tool.as_bytes());
    fnv_field(state, &r.cost.to_le_bytes());
    absorb_outcome(state, &r.outcome);
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
            // Two refusals carry a message; digest it too, so a change in what
            // an operator is told changes the digest.
            match r {
                Refusal::OutsideBoundary(why) | Refusal::MalformedRequest(why) => {
                    fnv_field(state, why.as_bytes())
                }
                _ => {}
            }
        }
    }
}

/// Mirror of the deployment's private `tag` fn: the metric-name mapping has to
/// be restated here to check the counters against the journal at all. The
/// three names at the top are new — the credential binding and the identifier
/// validation did not exist when this file was written.
fn tag_of(r: &Refusal) -> &'static str {
    match r {
        Refusal::ActorMismatch => "actor_mismatch",
        Refusal::TenantNotOwnedByOrg => "tenant_not_owned",
        Refusal::MalformedRequest(_) => "malformed_request",
        Refusal::Unauthenticated => "unauthenticated",
        Refusal::UnknownTenant => "unknown_tenant",
        Refusal::OutsideBoundary(_) => "outside_boundary",
        Refusal::ToolNotGoverned => "tool_not_governed",
        Refusal::PermissionDenied => "permission_denied",
        Refusal::ModelNotAllowed => "model_not_allowed",
        Refusal::VariantNotActivated => "variant_not_activated",
        Refusal::BudgetExhausted => "budget_exhausted",
        Refusal::JustificationRequired => "justification_required",
    }
}

/// The journal's own word for an outcome, forwarded included.
fn outcome_tag(o: &Outcome) -> &'static str {
    match o {
        Outcome::Forwarded => "forwarded",
        Outcome::Refused(r) => tag_of(r),
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

/// One decision as the *test* saw it, to be matched against the record the
/// deployment kept. Plain `Copy` data on purpose: the mirror is preallocated
/// before any memory measurement starts, so maintaining it allocates nothing
/// and cannot be mistaken for the trail it is measuring.
#[derive(Clone, Copy)]
struct Decision {
    sequence: u64,
    tenant: usize,
    cost: u64,
    tag: &'static str,
}

/// The last [`DEFAULT_AUDIT_CAPACITY`] decisions: what a correctly bounded
/// journal must still be holding, maintained independently of it.
struct Window {
    decisions: VecDeque<Decision>,
}

impl Window {
    fn new() -> Self {
        Self {
            decisions: VecDeque::with_capacity(DEFAULT_AUDIT_CAPACITY + 1),
        }
    }

    fn push(&mut self, d: Decision) {
        while self.decisions.len() >= DEFAULT_AUDIT_CAPACITY {
            self.decisions.pop_front();
        }
        self.decisions.push_back(d);
    }
}

/// The ledger of a tenant the fleet provisioned. `spent` returns `None` for a
/// tenant that does not exist, a distinction this harness never wants to paper
/// over — so it is an assertion, not an `unwrap_or(0)`.
fn spent_of(d: &Deployment, name: &str) -> u64 {
    d.spent(name)
        .unwrap_or_else(|| panic!("fleet tenant {name} vanished from the deployment"))
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
            u128::from(spent_of(d, name)),
            l.spent[i],
            "call {at}: tenant {name} spend drifted from the sum of its admitted costs"
        );
        assert!(
            spent_of(d, name) <= limit_of(i),
            "call {at}: tenant {name} spent {} over a limit of {}",
            spent_of(d, name),
            limit_of(i)
        );
    }

    // 2. The journal: bounded, contiguous, and accounting for every call as
    //    either retained or announced-dropped. What used to be "one record per
    //    call, forever" is now "the newest `DEFAULT_AUDIT_CAPACITY` decisions,
    //    and a counter for everything the cap shed".
    let retained = d.audit().count() as u64;
    let dropped = d.audit_dropped();
    let cap = DEFAULT_AUDIT_CAPACITY as u64;
    assert_eq!(
        retained + dropped,
        l.calls,
        "call {at}: {retained} retained + {dropped} dropped != {} calls",
        l.calls
    );
    assert_eq!(
        retained,
        l.calls.min(cap),
        "call {at}: the buffer is not holding the newest {cap} decisions"
    );
    assert_eq!(
        dropped,
        l.calls.saturating_sub(cap),
        "call {at}: the drop counter does not match what the cap must have shed"
    );
    let mut expected_sequence = l.calls - retained;
    for r in d.audit() {
        assert_eq!(
            r.sequence, expected_sequence,
            "call {at}: the retained window is not contiguous in sequence"
        );
        expected_sequence += 1;
    }
    assert_eq!(
        expected_sequence, l.calls,
        "call {at}: the newest retained record is not the call just decided"
    );

    // 3. The counters, against the journal. Counters are cumulative: unlike
    //    the journal they must still describe the calls the buffer dropped.
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
    assert_eq!(
        metric(&m, "audit.dropped"),
        dropped,
        "call {at}: the audit.dropped counter disagrees with audit_dropped()"
    );
    assert_eq!(
        metric(&m, "gateway.replayed"),
        0,
        "call {at}: a replay was suppressed, but every request id in this \
         workload is distinct — an unbilled forward would silently hollow out \
         every billing assertion in this file"
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

    // STILL OPEN (finding 3): every series is deployment-global. With 50
    // tenants in this deployment, not one counter name mentions a tenant — the
    // metrics can say 4 000 calls were refused, never whose. Asserting the
    // real shape so that adding a tenant dimension trips here loudly.
    assert!(
        m.len() <= 12,
        "call {at}: expected at most 12 global series, got {}",
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

/// Records cloned early and re-checked much later: proof that the trail is
/// appended to and never rewritten, compacted or reordered. A record that has
/// left the bounded window is allowed to be gone — but only if the deployment
/// counted its departure, and only if everything older than the window went
/// with it.
fn stable_or_dropped(d: &Deployment, sample: &[AuditRecord], at: usize) {
    let oldest = d.audit().next().map(|r| r.sequence);
    for expected in sample {
        match d.audit().find(|r| r.sequence == expected.sequence) {
            Some(found) => assert_eq!(
                found, expected,
                "call {at}: audit record {} was rewritten under us",
                expected.sequence
            ),
            None => {
                let oldest = oldest.expect("a non-empty journal");
                assert!(
                    expected.sequence < oldest,
                    "call {at}: record {} vanished from inside the retained \
                     window (oldest retained is {oldest})",
                    expected.sequence
                );
                assert!(
                    d.audit_dropped() > expected.sequence,
                    "call {at}: record {} left the buffer without being counted \
                     ({} dropped)",
                    expected.sequence,
                    d.audit_dropped()
                );
            }
        }
    }
}

fn mib(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

/// A retained-heap ceiling that is a function of the product's caps and of
/// nothing else — in particular, not of how many calls were made. Deliberately
/// generous per unit (a record measures ~300 B, a remembered request id
/// ~130 B): what is asserted is the *shape* of the bound, and the printed
/// tables carry the sharp numbers.
fn bounded_heap_ceiling(deployments: usize) -> usize {
    deployments * (DEFAULT_AUDIT_CAPACITY * 512 + DEFAULT_REPLAY_MEMORY * 256)
}

// ─────────────────────────────────────────────────────────────────────────
// 1. The main endurance run
// ─────────────────────────────────────────────────────────────────────────

/// 200 000 admissions across 50 tenants, on two independently built
/// deployments fed the identical sequence, with every invariant re-checked at
/// each of the 20 checkpoints.
///
/// The journal is bounded at [`DEFAULT_AUDIT_CAPACITY`] now, so this run
/// crosses the cap at call 100 000 and spends its whole second half evicting.
/// The strongest thing it can say about the trail is therefore no longer "one
/// record per call, forever" but "the newest 100 000 decisions, contiguous,
/// byte-exact, every departure counted, and every retained record carrying the
/// cost the meter actually charged" — and the memory table printed here is the
/// measurement that makes the bound a fact rather than a claim.
#[test]
fn endurance_two_hundred_thousand_admissions_across_fifty_tenants() {
    let _guard = serialized();
    let names = tenant_names();
    let principals: Vec<AuthenticatedActor> = PRINCIPALS
        .iter()
        .map(|(name, strength)| actor(FLEET_ORG, name, *strength))
        .collect();

    let mut a = fleet_deployment(&names);
    let mut b = fleet_deployment(&names);
    let mut ledger = Ledger::new();
    let mut window = Window::new();
    let mut roll_a = RollingDigest::default();
    let mut roll_b = RollingDigest::default();
    let mut rng = Rng::new(0x5EED_0001_C0DE_F00D);
    let mut req = request("", "", "", "");
    let mut sample: Vec<AuditRecord> = Vec::new();
    let mut growth: Vec<(usize, usize)> = Vec::with_capacity(MAIN_CALLS / CHECKPOINT);
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
            justification: None,
        });
        let out_b = b.admit(Call {
            actor: &principals[step.principal],
            request: &req,
            model: MODELS[step.model],
            cost_tokens: step.cost,
            variant,
            justification: None,
        });
        assert_eq!(
            out_a, out_b,
            "call {seq}: two identical deployments disagreed on the same request"
        );
        ledger.record(&step, &out_a);
        window.push(Decision {
            sequence: seq as u64,
            tenant: step.tenant,
            // Every request id in this run is distinct, so a forwarded call is
            // a charged call: nothing here is a suppressed replay, which
            // `check_invariants` re-asserts against `gateway.replayed`.
            cost: if out_a.is_forwarded() { step.cost } else { 0 },
            tag: outcome_tag(&out_a),
        });

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
                let first = a.audit().next().expect("a non-empty journal").clone();
                let last = a.audit().last().expect("a non-empty journal").clone();
                sample.push(first);
                sample.push(last);
            }
            stable_or_dropped(&a, &sample, seq + 1);
            growth.push((seq + 1, live_bytes().saturating_sub(base_bytes)));
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
        if spent_of(&a, name) + 1 > limit_of(i) {
            exhausted_tenants += 1;
        }
    }
    assert!(
        exhausted_tenants >= 10,
        "only {exhausted_tenants} tenants exhausted their budget; \
         the run never tested life after exhaustion"
    );

    // The bounded pool stayed bounded, exactly: three aggregate series, one
    // per refusal kind, and the drop counter — not a name more after 200 000
    // hostile calls. `gateway.replayed` is absent because every request id in
    // this run is distinct, which is what keeps the billing assertions honest.
    let final_series: Vec<String> = a.metrics().into_iter().map(|(n, _)| n).collect();
    assert_eq!(
        final_series,
        vec![
            "audit.dropped",
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
        "the metric series set drifted from the 12 low-cardinality names"
    );

    // A final full-journal audit: the incremental expectation above is only as
    // good as its agreement with what is actually stored. The window the
    // deployment kept must be, decision for decision, the last 100 000 answers
    // it gave — same order, same sequences, same tenants, same costs.
    let retained = a.audit().count();
    assert_eq!(retained, DEFAULT_AUDIT_CAPACITY);
    assert_eq!(retained, window.decisions.len());
    assert_eq!(
        a.audit_dropped() as usize,
        MAIN_CALLS - DEFAULT_AUDIT_CAPACITY,
        "the cap shed exactly the overflow, and counted every record of it"
    );
    let mut journal_forwarded = 0u64;
    let mut journal_tags: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut journal_cost = 0u128;
    let mut phantom_rows = 0u64;
    for (r, expected) in a.audit().zip(window.decisions.iter()) {
        assert_eq!(r.sequence, expected.sequence, "the retained window slipped");
        assert_eq!(
            outcome_tag(&r.outcome),
            expected.tag,
            "record {} disagrees with the outcome the deployment returned",
            r.sequence
        );
        assert_eq!(
            r.cost, expected.cost,
            "record {} was journalled at a cost the deployment never charged",
            r.sequence
        );
        assert_eq!(r.tenant, tenant_label(expected.tenant, &names));
        assert!(
            r.request_id.starts_with("r-"),
            "record {} lost its correlation id",
            r.sequence
        );
        match &r.outcome {
            Outcome::Forwarded => journal_forwarded += 1,
            Outcome::Refused(x) => *journal_tags.entry(tag_of(x)).or_insert(0) += 1,
        }
        journal_cost += u128::from(r.cost);
        phantom_rows += u64::from(expected.tenant == TENANTS);
    }
    assert_eq!(
        journal_forwarded + journal_tags.values().sum::<u64>(),
        DEFAULT_AUDIT_CAPACITY as u64
    );
    let fleet_spend: u128 = ledger.spent.iter().sum();
    assert!(
        journal_cost > 0 && journal_cost <= fleet_spend,
        "the retained window bills {journal_cost}, the fleet spent {fleet_spend}"
    );

    // STILL OPEN (finding 2, second edge): the trail keeps rows attributed to
    // a tenant that was never provisioned, and `audit_of` hands them back
    // under that name. The tenant label in the journal is attacker-chosen —
    // bounded in *length* now (128 bytes) and in *count* (the cap), but the
    // buffer still holds an arbitrary set of attacker-chosen strings.
    let phantom = a.audit_of("ghost-tenant");
    assert_eq!(
        phantom.len() as u64,
        phantom_rows,
        "the journal stores rows for a tenant that does not exist"
    );
    assert!(!phantom.is_empty());
    assert!(
        phantom.iter().all(|r| r.cost == 0),
        "a phantom tenant's rows must at least all be free"
    );
    assert_eq!(
        a.spent("ghost-tenant"),
        None,
        "the tenant does not exist, so it has no ledger at all — not a zero one"
    );

    // THE REPAIR, measured. 200 000 calls, of which only ~31% were forwarded,
    // used to cost one retained record each and grew dead linearly to the end
    // of the run. The journal now stops growing when the cap engages at call
    // 100 000: the second half of the run adds only what replay memory costs,
    // and the retained heap is a function of the product's caps rather than of
    // the number of calls made.
    let refused_share = ledger.refused as f64 / ledger.calls as f64;
    println!(
        "endurance: {MAIN_CALLS} calls x2 deployments in {:?} \
         ({:.2} us/admit) | forwarded {} refused {} ({:.0}% refused) | \
         exhausted tenants {exhausted_tenants} | retained {:.1} MiB for \
         {} retained records ({:.0} B/record, both trails) | dropped {} each",
        elapsed,
        elapsed.as_secs_f64() * 1e6 / (2.0 * MAIN_CALLS as f64),
        ledger.forwarded,
        ledger.refused,
        refused_share * 100.0,
        mib(grown),
        2 * retained,
        grown as f64 / (2.0 * retained as f64),
        a.audit_dropped(),
    );
    println!("  calls        retained MiB   B per call so far");
    for (calls, bytes) in &growth {
        println!(
            "  {calls:>9}    {:>10.1}   {:>16.0}",
            mib(*bytes),
            *bytes as f64 / (2.0 * *calls as f64),
        );
    }
    let (_, first_half) = growth[growth.len() / 2 - 1];
    let (_, all) = growth[growth.len() - 1];
    let second_half = all.saturating_sub(first_half);
    assert!(
        2 * second_half <= first_half,
        "the journal is still growing with the call count: the first 100 000 \
         calls retained {first_half} B, the second {second_half} B — once the \
         cap engages a bounded buffer must add nothing but replay memory"
    );
    assert!(
        grown <= bounded_heap_ceiling(2),
        "retained heap must be a function of the caps, not of the call count: \
         measured {grown} B against a ceiling of {} B",
        bounded_heap_ceiling(2)
    );
    // …and the buffer really is holding its cap, rather than being cheaply
    // bounded by being empty.
    assert!(
        grown >= 2 * DEFAULT_AUDIT_CAPACITY * 64,
        "expected the two capped trails to retain >= 64 B per retained record, \
         measured {grown} B in total"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 2. THE EXHAUSTION VECTOR, CLOSED
// ─────────────────────────────────────────────────────────────────────────

/// **Finding 1 — exhaustion vector, high — REPAIRED; this is its regression
/// guard.**
///
/// What the defect was: one million calls from an `AuthStrength::Anonymous`
/// principal, every one refused at the *first* gate — no tenant resolved, no
/// role consulted, no token spent — and every one allocating an audit record
/// that lived until the `Deployment` was dropped. The trail was a `Vec` with
/// no cap, no rotation and no persistence, so this exact workload retained a
/// measured **150.5 MiB**, dead linear (37.6 MiB at 250 000 refusals, 75.3 at
/// 500 000, 150.5 at 1 000 000) with no plateau anywhere, and the long run
/// reached 1 150.9 MiB at five million. What it cost: an unauthenticated
/// client could exhaust an operator's memory for free, and destroying the
/// governance layer was the only way to get a byte of it back.
///
/// The comparison that made it a defect rather than a design choice was in the
/// same struct: `CounterRegistry` folds at `MAX_SERIES` "so a label explosion
/// can never exhaust memory". The journal now bounds itself the same way — a
/// `VecDeque` capped at [`DEFAULT_AUDIT_CAPACITY`], oldest evicted, every
/// eviction counted by `audit_dropped()` and by the `audit.dropped` series.
/// Identical input, opposite expectation: this test proves the plateau, and
/// keeps measuring it, because a cap that is never measured is a comment.
///
/// It also closes the other repair this scenario was always half of: the
/// attacker here is issued for the org `"nowhere"`. That org was carried on
/// every credential and read by nothing, so a token-strength `ghost` used to
/// be admitted against a tenant it had no relationship with. Both halves of
/// the credential binding are asserted at the end.
#[test]
fn unauthenticated_flood_is_bounded_by_the_audit_capacity() {
    let _guard = serialized();
    let names = tenant_names();
    let mut d = fleet_deployment(&names);
    let attacker = actor("nowhere", "ghost", AuthStrength::Anonymous);
    let mut req = request(&names[0], "ghost", "memory.recall", "");

    let base = live_bytes();
    let started = Instant::now();
    let mut samples = Vec::with_capacity(4);
    for i in 0..FLOOD_CALLS {
        req.request_id.clear();
        write!(req.request_id, "r-{i:08}").expect("String write is infallible");
        let out = d.admit(Call {
            actor: &attacker,
            request: &req,
            model: "claude-opus",
            cost_tokens: 0,
            variant: None,
            justification: None,
        });
        // Identity is still evaluated first, before the credential binding:
        // this caller is *also* in an org that owns no tenant here, and never
        // learns which of the two refused it.
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
        assert_eq!(
            d.spent(name),
            Some(0),
            "a refused call charged tenant {name}"
        );
    }
    // … and nothing was retained past the cap either.
    assert_eq!(
        d.audit().count(),
        DEFAULT_AUDIT_CAPACITY,
        "one refused call, one audit record — up to the cap, and then no more"
    );
    assert_eq!(
        d.audit_dropped() as usize,
        FLOOD_CALLS - DEFAULT_AUDIT_CAPACITY,
        "every dropped record must be counted: an announced loss, not a silent one"
    );
    // What survives is the *newest* window, in order: the evidence closest to
    // the incident rather than the oldest.
    let first = d.audit().next().expect("a non-empty journal");
    let last = d.audit().last().expect("a non-empty journal");
    assert_eq!(
        first.sequence as usize,
        FLOOD_CALLS - DEFAULT_AUDIT_CAPACITY
    );
    assert_eq!(last.sequence as usize, FLOOD_CALLS - 1);
    assert_eq!(last.request_id, format!("r-{:08}", FLOOD_CALLS - 1));

    // The bounded pool right next door stayed bounded, and the trail has
    // joined it: four series, flat, one of them counting what the trail shed.
    let m = d.metrics();
    assert_eq!(
        m.len(),
        4,
        "expected requests/refused/refused.unauthenticated/audit.dropped, got {m:?}"
    );
    assert_eq!(metric(&m, "gateway.requests"), FLOOD_CALLS as u64);
    assert_eq!(metric(&m, "gateway.refused"), FLOOD_CALLS as u64);
    assert_eq!(
        metric(&m, "gateway.refused.unauthenticated"),
        FLOOD_CALLS as u64
    );
    assert_eq!(
        metric(&m, "audit.dropped") as usize,
        FLOOD_CALLS - DEFAULT_AUDIT_CAPACITY
    );

    println!("unauthenticated flood ({FLOOD_CALLS} refusals, {elapsed:?}):");
    for (calls, bytes) in &samples {
        println!(
            "  after {calls:>9} refusals: {:>8.1} MiB retained \
             ({:>5.0} B/retained record, {:>4.1} B/call)",
            mib(*bytes),
            *bytes as f64 / DEFAULT_AUDIT_CAPACITY as f64,
            *bytes as f64 / *calls as f64,
        );
    }

    let (_, quarter) = samples[0];
    let (_, full) = samples[3];
    // THE REPAIR, measured. This is the assertion that used to demand
    // `full >= 64 * FLOOD_CALLS` — one retained record per call, forever. Same
    // constant, opposite direction: a million refusals must now cost less than
    // 64 B per *call*, because 900 000 of those calls cost nothing at all.
    assert!(
        full < 64 * FLOOD_CALLS,
        "expected the cap to hold a million refusals under {} B, measured {full} B",
        64 * FLOOD_CALLS
    );
    // Flat, not linear: four times the refusals retain the same memory. An
    // unbounded structure would have quadrupled here.
    assert!(
        full <= quarter + quarter / 8,
        "growth has not plateaued: {quarter} B at 25% vs {full} B at 100% — \
         the audit buffer is tracking the call count again"
    );
    // …and it is bounded by holding its cap, not by holding nothing.
    assert!(
        full >= 64 * DEFAULT_AUDIT_CAPACITY,
        "expected >= 64 B retained per retained record, measured {full} B for \
         {DEFAULT_AUDIT_CAPACITY} records"
    );

    // Dropping the deployment still frees the buffer — the cap bounds it, it
    // does not persist it. `audit()` hands out a borrowed iterator and there is
    // still no `drain`/`export`/`persist` anywhere (see "still open", 1).
    drop(d);
    let after_drop = live_bytes().saturating_sub(base);
    assert!(
        after_drop < full / 8,
        "dropping the deployment must still free the trail: {full} B before, \
         {after_drop} B after"
    );

    // THE OTHER REPAIR, same scenario, opposite expectation. `ghost` is issued
    // for the org "nowhere", which owns nothing in this fleet. The predecessor
    // read only the credential's *strength* and then keyed authorization on
    // the request's own copy of the actor and resolved the tenant from the
    // request's own copy of the tenant id — so this call, and any call naming
    // any actor and any tenant, was decided against somebody else's roles and
    // charged to somebody else's budget. Both bindings are now checked before
    // a byte of tenant state is touched, and both refusals are free.
    let mut d = fleet_deployment(&names);
    let foreign = actor("nowhere", "ghost", AuthStrength::Token);
    assert!(
        d.assign("ghost", "writer"),
        "give the foreigner a full role: the org gate must still refuse"
    );
    let req = request(&names[0], "ghost", "memory.ingest", "r-foreign");
    assert_eq!(
        d.admit(Call {
            actor: &foreign,
            request: &req,
            model: "claude-opus",
            cost_tokens: 25,
            variant: None,
            justification: None,
        })
        .refusal(),
        Some(&Refusal::TenantNotOwnedByOrg),
        "an org that owns no tenant here must not reach one"
    );
    let alice = actor(FLEET_ORG, "alice", AuthStrength::Token);
    let req = request(&names[0], "root", "policy.set", "r-borrowed");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 25,
            variant: None,
            justification: None,
        })
        .refusal(),
        Some(&Refusal::ActorMismatch),
        "alice must not become root by saying she is"
    );
    assert_eq!(
        d.spent(&names[0]),
        Some(0),
        "neither impersonation cost the tenant a token"
    );
    // Both are journalled, at zero cost, under the name the caller claimed.
    let trail: Vec<&AuditRecord> = d.audit().collect();
    assert_eq!(trail.len(), 2);
    assert!(trail.iter().all(|r| r.cost == 0));
    assert_eq!(
        trail[1].actor, "root",
        "the journal records what was claimed"
    );
}

/// **Finding 2 — the same vector, per byte — REPAIRED in both dimensions;
/// this is its regression guard.**
///
/// What the defect was: the record cloned `request.{tenant,actor,tool}` with
/// no length check anywhere in the path, so the attacker chose the *size* of
/// each record as well as the count — and it was worse for a token-strength
/// caller, because `Refusal::OutsideBoundary` formatted the **whole** tool
/// name into its message, which `admit` then cloned into the record *and*
/// returned. Two copies of every attacker byte: a measured 2.00 retained bytes
/// per attacker byte against an anonymous caller's 1.00. What it cost: 4 GiB
/// of operator memory was 2 GiB of request body away, and no gate had a say in
/// it, because the record was written after `decide` on every path.
///
/// What was repaired, in two places. `classify` refuses any name over
/// `MAX_TOOL_NAME_BYTES` (256) as non-canonical *before* it matches anything,
/// and passes everything it does echo through a sanitizer capped at 64
/// characters, so a refusal message is a bounded constant however large the
/// name. And `journal` clamps every identifier it stores to
/// `MAX_IDENTIFIER_BYTES` (128) on a character boundary — which is the half
/// that matters for the anonymous caller, because no gate that could have
/// refused on length is ever reached. Identical input, opposite expectation:
/// a 1 MiB tool name costs a measured 0.0003 retained bytes per attacker byte
/// instead of 1.00 (or 2.00), and the record is 128 bytes wide instead of a
/// megabyte.
#[test]
fn attacker_sized_names_no_longer_size_the_audit_record() {
    let _guard = serialized();
    const BIG: usize = 1024 * 1024;
    const CALLS: usize = 32;
    /// Hard ceiling on a refusal message: the longest template
    /// (`"tool namespace '…' is outside the Enterprise boundary"`, 52 bytes)
    /// around a sanitized name of at most 64 characters — 3 bytes each in the
    /// worst case, every one replaced by U+FFFD — plus the ellipsis.
    const REFUSAL_MESSAGE_CAP: usize = 52 + 64 * 3 + 3;
    /// What one record may retain now that identifiers are clamped: four
    /// clamped identifiers, the record itself, and the deque slot it sits in.
    const RECORD_CAP: usize = 4 * MAX_IDENTIFIER_BYTES + 512;
    let names = tenant_names();
    let huge_tool = "x".repeat(BIG);

    // (a) REPAIRED. Unauthenticated: refused at gate 1, and *because* the
    //     record is written after `decide` on every path, this is the case no
    //     gate could ever have bounded. The clamp is in `journal`, so it does.
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
            justification: None,
        });
        assert!(matches!(out, Outcome::Refused(Refusal::Unauthenticated)));
    }
    let anon_bytes = live_bytes().saturating_sub(base);
    let anon_ratio = anon_bytes as f64 / (CALLS * BIG) as f64;
    assert_eq!(d.audit().count(), CALLS);
    assert_eq!(
        d.audit().next().expect("a non-empty journal").tool.len(),
        MAX_IDENTIFIER_BYTES,
        "the trail must clamp the attacker's 1 MiB tool name, not store it"
    );
    assert!(
        anon_ratio < 0.01,
        "expected the record to stop tracking the attacker's size, measured \
         {anon_ratio:.4} retained bytes per attacker byte"
    );
    assert!(
        anon_bytes <= CALLS * RECORD_CAP,
        "expected <= {} B for {CALLS} clamped records, measured {anon_bytes} B",
        CALLS * RECORD_CAP
    );
    drop(d);

    // (b) REPAIRED. Token strength, no role, known tenant — the case that used
    //     to cost double, because the boundary refusal repeated the whole tool
    //     name inside its message and the trail then kept it twice. Identical
    //     input, opposite expectation: a 1 MiB name is over the 256-byte
    //     canonical limit, so it is refused unread and the message it produces
    //     is a constant that mentions none of it.
    let mut d = fleet_deployment(&names);
    let mallory = actor(FLEET_ORG, "mallory", AuthStrength::Token);
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
            justification: None,
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
         anonymous {:.3} MiB retained ({anon_ratio:.4} B/attacker byte), \
         boundary refusal {:.3} MiB retained ({boundary_ratio:.4} B/attacker \
         byte), longest refusal message {longest_message} B, record tool field \
         clamped to {MAX_IDENTIFIER_BYTES} B",
        BIG / (1024 * 1024),
        mib(anon_bytes),
        mib(boundary_bytes),
    );
    // THE REPAIR, measured, in both dimensions at once: neither the message
    // nor the record tracks the caller's size any more. If either copy comes
    // back, this crosses 0.01 and fails.
    assert!(
        boundary_ratio < 0.01,
        "a boundary refusal must retain neither copy of the attacker's bytes, \
         measured {boundary_ratio:.4}"
    );
    assert!(
        boundary_bytes <= CALLS * RECORD_CAP,
        "expected <= {} B for {CALLS} clamped records, measured {boundary_bytes} B",
        CALLS * RECORD_CAP
    );
    assert_eq!(
        d.audit().next().expect("a non-empty journal").tool.len(),
        MAX_IDENTIFIER_BYTES,
        "the trail clamps the attacker's name, refused or not"
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
        justification: None,
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
    // …and the record beside it keeps 128 of those 256 bytes, not all of them,
    // truncated rather than rewritten.
    let stored = d.audit().next().expect("a non-empty journal").tool.clone();
    assert_eq!(stored.len(), MAX_IDENTIFIER_BYTES);
    assert!(
        at_limit.starts_with(stored.as_str()),
        "the clamp must truncate the name, not transform it"
    );
}

/// **Finding 3 — half repaired.**
///
/// What the defect was: rotation was not merely absent, it was unimplementable
/// from what an `AuditRecord` stored — five fields, none of them a timestamp,
/// a cost, a model or a variant. An operator holding a 5 000 000-record trail
/// could answer neither "drop everything older than 30 days" (no time) nor
/// "prove how `spent` reached 1 000" (no cost), the two questions retention
/// policy and budget policy are made of. What it cost: the meter and the
/// journal could not be reconciled at all, so a billing dispute had no
/// evidence on either side of it.
///
/// What was repaired: the record carries `cost` — the tokens actually charged,
/// `0` for every refusal — and a monotonic `sequence`. This test guards that
/// repair by reconstructing `spent` from the journal alone, to the token.
///
/// **Still open, deliberately pinned below:** there is still no timestamp, and
/// still no way to shed, export or persist the trail on purpose. Age-based
/// retention remains unimplementable from what is stored; the capacity bound
/// sheds the *oldest* evidence rather than the least interesting, and nothing
/// reads it on the way out.
#[test]
fn audit_records_carry_cost_and_sequence_but_still_no_timestamp() {
    let _guard = serialized();
    let names = tenant_names();
    let mut d = fleet_deployment(&names);
    let alice = actor(FLEET_ORG, "alice", AuthStrength::Token);

    for i in 0..64u64 {
        let req = request(&names[0], "alice", "memory.ingest", &format!("r-{i}"));
        let out = d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 3,
            variant: None,
            justification: None,
        });
        assert!(out.is_forwarded(), "call {i} should be admitted");
    }
    assert_eq!(d.spent(&names[0]), Some(64 * 3));

    // The record is exhaustively {sequence, request_id, tenant, actor, tool,
    // cost, outcome}. Serializing it is the honest way to show both what is
    // now there and what is still not.
    let r = d.audit().next().expect("a non-empty journal");
    let rendered = format!(
        "{{\"sequence\":{},\"request_id\":\"{}\",\"tenant\":\"{}\",\"actor\":\"{}\",\
         \"tool\":\"{}\",\"cost\":{},\"outcome\":\"{:?}\"}}",
        r.sequence, r.request_id, r.tenant, r.actor, r.tool, r.cost, r.outcome
    );
    for present in ["cost", "sequence"] {
        assert!(
            rendered.contains(present),
            "an AuditRecord no longer carries {present}: {rendered}"
        );
    }
    // STILL OPEN: no clock anywhere in the record, so no age-based retention.
    for absent in ["time", "unix", "stamp", "model", "variant"] {
        assert!(
            !rendered.to_ascii_lowercase().contains(absent),
            "an AuditRecord unexpectedly carries {absent}: {rendered}"
        );
    }

    // THE REPAIR: spend is derivable from the journal alone now — every
    // admitted record says what it cost, and the sum is the meter.
    let admitted: Vec<&AuditRecord> = d.audit().filter(|r| r.outcome.is_forwarded()).collect();
    assert_eq!(admitted.len(), 64);
    assert!(
        admitted.iter().all(|r| r.cost == 3),
        "every admitted record must carry the cost it was charged"
    );
    let reconstructed: u64 = d.audit().map(|r| r.cost).sum();
    assert_eq!(
        Some(reconstructed),
        d.spent(&names[0]),
        "the journal must reconcile the meter to the token"
    );
    // And `sequence` orders them, so two interleaved journals can be merged
    // into the order the deployment actually decided in.
    assert!(
        admitted.windows(2).all(|w| w[0].sequence < w[1].sequence),
        "sequences must be strictly increasing in decision order"
    );
    assert_eq!(admitted[0].sequence, 0);
    assert_eq!(admitted[63].sequence, 63);

    // STILL OPEN: the accessors are read-only aggregates. There is no `drain`,
    // no `export`, no `persist` — the only way a record leaves is the capacity
    // bound, oldest first, unread by anything.
    assert_eq!(d.audit_dropped(), 0, "nothing has been shed at this scale");
}

/// **Finding 4 — still open, and the capacity bound gave it a new edge.**
///
/// `audit_of` is still the only per-tenant view, it still filters the entire
/// buffer, and it still allocates one pointer per match (a measured 1.0 MiB to
/// answer one query over the 100 000-record window). The exhaustion vector
/// therefore still amplifies itself — an attacker who parks 200 000 refused
/// calls under their own tenant makes every legitimate audit query scan the
/// whole retained window, 5.3 ms of it in debug for eight matching rows — and
/// now it does something the unbounded version
/// could not: it **evicts the innocent neighbour's records entirely**, while
/// the meter goes on billing the tokens those records were the evidence for.
/// The loss is announced (`audit_dropped` counts it), which is exactly why the
/// runtime's own docs say this buffer is not an audit story until it is
/// flushed somewhere durable. Nothing in the product flushes it.
#[test]
fn audit_of_scans_the_whole_trail_and_allocates_per_match() {
    let _guard = serialized();
    const FLOOD: usize = 200_000;
    let names = tenant_names();
    let mut d = fleet_deployment(&names);
    let ghost = actor("nowhere", "ghost", AuthStrength::Anonymous);
    let alice = actor(FLEET_ORG, "alice", AuthStrength::Token);

    // One honest tenant with 8 records …
    for i in 0..8u64 {
        let req = request(&names[1], "alice", "memory.recall", &format!("h-{i}"));
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
            justification: None,
        });
    }
    assert_eq!(d.audit_of(&names[1]).len(), 8);

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
            justification: None,
        });
    }
    assert_eq!(d.audit().count(), DEFAULT_AUDIT_CAPACITY);
    assert_eq!(
        d.audit_dropped() as usize,
        FLOOD + 8 - DEFAULT_AUDIT_CAPACITY
    );

    // STILL OPEN, and sharper than it was: the flood no longer merely buries
    // the innocent tenant's records, it evicts them. Eight forwarded, billed
    // calls, and the journal can no longer show one of them — announced by
    // `audit_dropped`, unrecoverable without durable storage the product does
    // not have.
    assert!(
        d.audit_of(&names[1]).is_empty(),
        "the flood evicted the innocent tenant's whole trail"
    );
    assert_eq!(
        d.spent(&names[1]),
        Some(8),
        "…while the meter still bills 8 tokens the journal can no longer explain"
    );

    // The buried tenant's own query allocates 8 bytes per match, over the
    // whole retained window.
    let before = live_bytes();
    let buried = d.audit_of(&names[0]);
    let buried_alloc = live_bytes().saturating_sub(before);
    assert_eq!(buried.len(), DEFAULT_AUDIT_CAPACITY);
    assert!(
        buried_alloc >= 8 * DEFAULT_AUDIT_CAPACITY,
        "expected >= {} B for {DEFAULT_AUDIT_CAPACITY} borrowed records, \
         measured {buried_alloc} B",
        8 * DEFAULT_AUDIT_CAPACITY
    );
    drop(buried);

    // And the *innocent* tenant pays too: eight fresh records, and its query
    // still walks all 100 000. Timed rather than asserted (wall clock is not
    // an invariant), but the scan is unconditional — there is no index.
    for i in 0..8u64 {
        let req = request(&names[1], "alice", "memory.recall", &format!("h2-{i}"));
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
            justification: None,
        });
    }
    let started = Instant::now();
    let innocent = d.audit_of(&names[1]);
    let innocent_scan = started.elapsed();
    assert_eq!(innocent.len(), 8);
    println!(
        "audit_of on a flooded deployment: buried tenant {} records / {} B allocated; \
         innocent tenant 8 records but {innocent_scan:?} of scan over {} retained \
         ({} dropped, 8 of them the innocent tenant's)",
        DEFAULT_AUDIT_CAPACITY,
        buried_alloc,
        d.audit().count(),
        d.audit_dropped(),
    );
}

/// **Finding 5 — spec violation — REPAIRED; this is its regression guard.**
///
/// What the defect was: `GatewayRequest::request_id` is documented as an
/// "Idempotency/correlation key for audit joins"
/// (`crates/ccos-enterprise-gateway/src/lib.rs:16`) and the composed path's
/// own docs promised every call was "audit-correlated by request id" — but
/// `admit` never read the field. One byte-identical request replayed 10 000
/// times was charged 10 000 times. What it cost: a single captured frame,
/// replayed, drained a tenant's entire budget (the 250-token tenant below went
/// to zero in 50 replays) and then went on growing the trail for free, while
/// the key an operator would join on had cardinality 1 for the whole incident.
///
/// What was repaired: a `(tenant, request_id)` the deployment has already
/// decided returns `Forwarded` **without charging again**, and moves
/// `gateway.replayed`. Identical input — 10 000 replays of one id, against the
/// fattest and the thinnest budget in the fleet — opposite expectation: one
/// charge each, and a budget that repetition can no longer drain.
#[test]
fn a_replayed_request_id_is_charged_exactly_once() {
    let _guard = serialized();
    const REPLAYS: u64 = 10_000;
    const ID: &str = "the-one-and-only-id";
    let names = tenant_names();
    let mut d = fleet_deployment(&names);
    let alice = actor(FLEET_ORG, "alice", AuthStrength::Token);

    // (a) The fattest budget in the fleet (t-49: 250 + 49*400 = 20 050) against
    //     10 000 replays at 1 token: every replay is still *answered* — replay
    //     suppression returns the decision that was already made, it does not
    //     start refusing — but only the first one is billed.
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
            justification: None,
        });
        admitted += u64::from(out.is_forwarded());
    }
    assert_eq!(
        admitted, REPLAYS,
        "a suppressed replay must still be answered, not refused"
    );
    assert_eq!(
        d.spent(fat),
        Some(1),
        "one captured request, replayed {REPLAYS} times, bills the tenant once"
    );

    // (b) The same replay against the thinnest budget (t-00: 250) at 5 tokens
    //     used to drain it in 50 calls. It now costs 5 tokens, once, and the
    //     remaining 9 999 replays cost the tenant nothing at all.
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
            justification: None,
        });
        admitted_thin += u64::from(out.is_forwarded());
    }
    assert_eq!(admitted_thin, REPLAYS);
    assert_eq!(
        d.spent(thin),
        Some(5),
        "the replay must not drain the budget it used to drain"
    );
    assert!(
        spent_of(&d, thin) < limit_of(0),
        "the thin tenant must survive a replay flood with budget to spare"
    );

    // The journal still records every *attempt* — that is the incident an
    // operator needs to see — but the cost column tells them apart now, so one
    // id no longer means one indistinguishable smear of 20 000 charged rows.
    assert_eq!(d.audit().count() as u64, 2 * REPLAYS);
    assert_eq!(d.audit_dropped(), 0, "20 000 rows is well inside the cap");
    let same_id = d.audit().filter(|r| r.request_id == ID).count();
    assert_eq!(same_id, 2 * REPLAYS as usize);
    let billed: Vec<&AuditRecord> = d.audit().filter(|r| r.cost > 0).collect();
    assert_eq!(
        billed.len(),
        2,
        "exactly two of the {} rows were charged: one per tenant",
        2 * REPLAYS
    );
    assert_eq!(billed[0].cost, 1);
    assert_eq!(billed[1].cost, 5);
    let m = d.metrics();
    assert_eq!(
        metric(&m, "gateway.replayed"),
        2 * (REPLAYS - 1),
        "every suppressed replay must be announced on its own counter"
    );
    assert_eq!(metric(&m, "gateway.forwarded"), 2 * REPLAYS);
    assert_eq!(metric(&m, "gateway.refused"), 0);
}

/// **Finding 6 — REPAIRED; this is its regression guard.**
///
/// What the defect was: `spent` folded "no such tenant" into "spent nothing"
/// by returning a bare `0`. What it cost: a quota monitor pointed at a
/// mistyped tenant reported a perfectly healthy, perfectly idle tenant,
/// forever — the failure mode of a billing system that cannot fail loudly. It
/// returns `Option<u64>` now: `None` is "no such tenant", `Some(0)` is "spent
/// nothing", and the two can never be confused again.
#[test]
fn spent_distinguishes_an_unknown_tenant_from_an_idle_one() {
    let _guard = serialized();
    let names = tenant_names();
    let d = fleet_deployment(&names);
    assert_eq!(
        d.spent(&names[0]),
        Some(0),
        "a fresh tenant has spent nothing, and says so"
    );
    assert_eq!(
        d.spent("t-00 "),
        None,
        "a trailing space is a different name, and no tenant has it"
    );
    assert_eq!(d.spent("no-such-tenant"), None);
    assert_eq!(d.spent(""), None);
    // …the audit view still answers with silence rather than an error, which
    // is sound: an empty trail is a true statement about a tenant that does
    // not exist, and `spent` is now the accessor that distinguishes them.
    assert!(d.audit_of("no-such-tenant").is_empty());
    assert!(d.audit_of(&names[0]).is_empty());
}

/// **Finding 8 — still open.** The invariant this whole file rests on —
/// `spent(t)` equals the sum of admitted costs — is false for an "unlimited"
/// tenant. The budget saturates on the accounting side
/// (`crates/ccos-enterprise-policy/src/lib.rs:39`), which is the right call
/// against a wrapping ledger, but it means the deployment forwards work it
/// then declines to bill, permanently and without a signal anywhere.
///
/// One thing did change: the journal carries `cost` now, so the drift is at
/// last *provable* from the trail — the records add up to 1 006 tokens more
/// than the meter admits to. That makes it detectable. It does not make it
/// right, and nothing in the product raises it.
#[test]
fn unlimited_budget_stops_summing_admitted_costs() {
    let _guard = serialized();
    let mut d = Deployment::new();
    d.add_role("writer", &["memory.read", "memory.write"])
        .govern_tool("memory.ingest", "memory.write");
    let mut unlimited = TenantState::new(u64::MAX);
    unlimited.allow_model("claude-opus");
    assert!(d.add_tenant(FLEET_ORG, "infinite", unlimited));
    assert!(d.assign("alice", "writer"));
    let alice = actor(FLEET_ORG, "alice", AuthStrength::Token);

    let mut admitted_sum = 0u128;
    for (i, cost) in [u64::MAX - 1, 1_000, 7].into_iter().enumerate() {
        let req = request("infinite", "alice", "memory.ingest", &format!("r-{i}"));
        let out = d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: cost,
            variant: None,
            justification: None,
        });
        assert!(out.is_forwarded(), "an unlimited budget admits everything");
        admitted_sum += u128::from(cost);
    }

    assert_eq!(d.audit().count(), 3, "all three calls were journaled");
    let spent = u128::from(d.spent("infinite").expect("the tenant exists"));
    assert_eq!(spent, u128::from(u64::MAX));
    assert!(
        admitted_sum > spent,
        "the ledger should have fallen behind the admitted sum"
    );
    assert_eq!(
        admitted_sum - spent,
        1_006,
        "STILL OPEN: 1 006 tokens were admitted and never billed"
    );
    // What the repair did change: the journal says so. Every record carries
    // what `admit` believed it charged, and those add up to the truth the
    // meter lost — so the drift is detectable from the trail, by anyone who
    // thinks to look. Nothing in the product looks.
    let journalled: u128 = d.audit().map(|r| u128::from(r.cost)).sum();
    assert_eq!(
        journalled, admitted_sum,
        "the journal records the full admitted cost of all three calls"
    );
    assert_eq!(
        journalled - spent,
        1_006,
        "the journal can prove the 1 006-token gap the meter hides"
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
/// Release is recommended but not required: the memory table is byte-identical
/// in both profiles, because the counting allocator measures requested
/// layouts.
///
/// This run used to be the loudest statement of finding 1 — **1 150.9 MiB
/// retained for 5 000 000 calls**, 241 B per record, still climbing, no
/// plateau — and its determinism mirror had to be dropped early, because
/// holding two 5 000 000-record trails at once cost 2.3 GiB. Twenty-five times
/// the main run's scale now costs the same bounded window the main run does:
/// **31.6 MiB from call 500 000 to call 5 000 000, +0.0 MiB per additional
/// 250 000 calls at every one of the last eighteen checkpoints**, 40.2 s in
/// debug (8.03 us per admission, flat throughout). The mirror is still dropped
/// at 500 000 — the comparison is complete by then — but it is now a
/// convenience rather than a necessity: the first row of the table (64.5 MiB)
/// is the only one that holds two deployments, and two capped deployments cost
/// what two unbounded ones never could.
///
/// Note the one thing the cap costs here: checkpoints are 250 000 calls apart
/// and the buffer is 100 000 deep, so the rolling digest cannot be used — the
/// only history two deployments provably share is the window they both still
/// hold, and [`window_digest`] is what compares it.
#[test]
#[ignore = "5M admissions; run explicitly, see the doc comment for the command"]
fn endurance_five_million_admissions() {
    let _guard = serialized();
    const CHECK_EVERY: usize = 250_000;
    const MIRROR_UNTIL: usize = 500_000;

    let names = tenant_names();
    let principals: Vec<AuthenticatedActor> = PRINCIPALS
        .iter()
        .map(|(name, strength)| actor(FLEET_ORG, name, *strength))
        .collect();

    let mut a = fleet_deployment(&names);
    let mut mirror = Some(fleet_deployment(&names));
    let mut ledger = Ledger::new();
    let mut rng = Rng::new(0x5EED_0001_C0DE_F00D);
    let mut req = request("", "", "", "");
    let mut sample: Vec<AuditRecord> = Vec::new();
    let mut growth: Vec<(usize, usize)> = Vec::with_capacity(LONG_CALLS / CHECK_EVERY);

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
            justification: None,
        });
        if let Some(b) = mirror.as_mut() {
            let out_b = b.admit(Call {
                actor: &principals[step.principal],
                request: &req,
                model: MODELS[step.model],
                cost_tokens: step.cost,
                variant,
                justification: None,
            });
            assert_eq!(out, out_b, "call {seq}: the mirror deployment diverged");
        }
        ledger.record(&step, &out);

        if seq + 1 == MIRROR_UNTIL {
            let b = mirror.take().expect("mirror still running");
            assert_eq!(
                window_digest(&a),
                window_digest(&b),
                "audit digests diverged between two identical deployments"
            );
            assert_eq!(a.metrics(), b.metrics(), "metric exports diverged");
            assert_eq!(
                a.audit_dropped(),
                b.audit_dropped(),
                "two identical deployments shed different amounts"
            );
            drop(b);
        }

        if (seq + 1) % CHECK_EVERY == 0 {
            check_invariants(&a, &ledger, &names, seq + 1);
            if sample.is_empty() {
                let first = a.audit().next().expect("a non-empty journal").clone();
                let last = a.audit().last().expect("a non-empty journal").clone();
                sample.push(first);
                sample.push(last);
            }
            stable_or_dropped(&a, &sample, seq + 1);
            growth.push((seq + 1, live_bytes().saturating_sub(base)));
        }
    }
    let elapsed = started.elapsed();

    // THE REPAIR at 25x the scale: the cap engaged at call 100 000 and held
    // for the remaining 4 900 000.
    assert_eq!(
        a.audit().count(),
        DEFAULT_AUDIT_CAPACITY,
        "the cap must hold at five million"
    );
    assert_eq!(
        a.audit_dropped() as usize,
        LONG_CALLS - DEFAULT_AUDIT_CAPACITY,
        "and every one of the dropped records must be counted"
    );
    assert_eq!(ledger.tags.len(), 8);

    println!(
        "five-million-call endurance run in {elapsed:?} ({:.2} us/admit); \
         final window digest {} over {} retained records, {} dropped",
        elapsed.as_secs_f64() * 1e6 / LONG_CALLS as f64,
        window_digest(&a),
        a.audit().count(),
        a.audit_dropped(),
    );
    println!("  calls        retained MiB   B/call so far   MiB per additional 250k");
    let mut previous = 0usize;
    for (calls, bytes) in &growth {
        println!(
            "  {calls:>9}    {:>10.1}   {:>13.1}   {:>10.1}",
            mib(*bytes),
            *bytes as f64 / *calls as f64,
            mib(bytes.saturating_sub(previous)),
        );
        previous = *bytes;
    }

    // Flat all the way out: the last quarter of the run costs nothing the
    // first quarter did not already pay for. Nothing accumulates.
    let (_, first_quarter) = growth[growth.len() / 4 - 1];
    let (_, all) = growth[growth.len() - 1];
    assert!(
        all <= first_quarter + first_quarter / 8,
        "expected a plateau to five million: {first_quarter} B at 25%, {all} B at 100%"
    );
    assert!(
        all < 64 * LONG_CALLS,
        "expected the cap to hold five million calls under {} B, measured {all} B",
        64 * LONG_CALLS
    );
    assert!(
        all <= bounded_heap_ceiling(1),
        "retained heap must be a function of the caps, not of the call count: \
         measured {all} B against a ceiling of {} B",
        bounded_heap_ceiling(1)
    );
    assert!(
        all >= 64 * DEFAULT_AUDIT_CAPACITY,
        "expected >= 64 B retained per retained record, measured {all} B"
    );
}
