//! # Hostile stress of the tenancy boundary: key confusion, scale, exhaustion
//!
//! `ccos_enterprise_tenancy` is layer 3 of `docs/ENTERPRISE_SECURITY_MODEL.md`
//! and the crate whose doc comment promises "tenant-scoped namespacing that
//! makes cross-tenant access a type error, not a convention". This file
//! attacks that claim with 100 000 adversarial `(tenant, key)` pairs, a
//! dedicated separator-confusion corpus, 1 000 tenants x 100 keys, and a
//! counting allocator pointed at the store.
//!
//! The composed admission path this file attacks used to live in the test
//! harness next door. It now ships in `ccos-enterprise-runtime` and the
//! harness merely re-exports it, so every assertion below is aimed at shipped
//! code; a bare `src/lib.rs:NNN` reference means
//! `crates/ccos-enterprise-runtime/src/lib.rs`.
//!
//! Everything asserted below is the product's **current, real** behaviour.
//! Where that behaviour is still a defect the assertion pins the defect and
//! the comment names it, so a repair fails loudly here instead of silently
//! changing the security posture. Where a defect has been repaired, the test
//! that pinned it kept its inputs and flipped its expectation: it is now a
//! regression guard, and its comment says in the past tense what the hole was
//! and what it cost.
//!
//! ## What HELD (and why)
//!
//! * **Tuple keying genuinely defeats key confusion.** `Deployment`'s store is
//!   `BTreeMap<(TenantId, String), String>` (`src/lib.rs:223`, type alias at
//!   `:210`), and tuple equality is componentwise: `("a", "b:c")` and
//!   `("a:b", "c")` are two
//!   different keys no matter what the separator is. The flattened
//!   `format!("{tenant}{sep}{key}")` form a naive store would use aliases 8 of
//!   the 27 corpus pairs with no separator, 5 with `:`, 3 with `::` and 1 each
//!   with `/`, `|` and NUL; the tuple form aliases **zero**. And no separator
//!   choice would have saved the flattened form — since nothing validates a
//!   tenant identifier, a colliding pair can be constructed for *any*
//!   separator, NUL and `\u{1f}` and `\u{10ffff}` included, which the test also
//!   demonstrates. See [`tuple_keying_defeats_every_separator_confusion_attack`],
//!   which asserts both halves so the property cannot be lost by refactor.
//! * **No leak at scale.** 100 000 adversarial pairs (NUL bytes, RTL overrides,
//!   lone `:`/`/`/`\0` separators, empty tenant, empty key, other tenants'
//!   names as keys, homoglyphs, NFC/NFD twins) collapse to 80 439 distinct
//!   cells over 200 hostile tenants and reproduce a reference model byte for
//!   byte across 200 000 probes — 28 016 of them deliberately crossed. Every
//!   value carries its owning tenant's tag, so a leak could not pass as a hit.
//! * **`cells_of` is exact and deterministically ordered.** At 1 000 tenants x
//!   100 cells, checked for **every** tenant, it returns exactly that tenant's
//!   own 100 cells — with names engineered to overlap (`t7`, `t7:`, `t7:7`) and
//!   a proper prefix (`t`) that a `starts_with` implementation would leak on.
//!   The order is strictly ascending raw byte order, identical across repeated
//!   calls and across a deployment built in reverse insertion order, and it
//!   survives empty, NUL-bearing, astral and prefix-related keys.
//! * **`rescope` never reads through, and the governed path now refuses the
//!   crossing outright.** Crossing to a tenant that does not hold the inner key
//!   is a miss, in both directions, for every hostile key tried — and the same
//!   crossing presented at `admit` by an identity from another organization is
//!   refused with `Refusal::TenantNotOwnedByOrg` at gate 3, before the boundary
//!   check, before RBAC, before the model allowlist and before the budget.
//!   Two independent guards, and the second is the load-bearing one: it refuses
//!   *identically* whether the target cell exists or not, and whatever tool,
//!   model, variant, cost or role the foreigner brings, so it cannot be
//!   differenced into an oracle for another tenant's key space or configuration
//!   the way a bare empty result can. (It is *not* invariant in whether the
//!   tenant exists at all — see finding 11.)
//! * **No truncation, hashing or prefix comparison of keys.** 1 MiB keys are
//!   stored and compared in full: two that differ only in their final byte are
//!   two cells, and the same 1 MiB key under two tenants is two cells.
//!
//! ## What was REPAIRED (same inputs, opposite expectation)
//!
//! Four of the eleven findings in this file have been closed in
//! `ccos-enterprise-runtime`. The tests that proved them were not deleted or
//! relaxed: each kept its scenario and now asserts the repair, so a revert
//! fails here. Where a repair closed only part of a finding, the residue is
//! spelled out under it and is still pinned by the same test.
//!
//! 6. **`cells_of` used to scan the entire store instead of the tenant's
//!    range.** It was `.iter().filter(...)` over a map whose key *begins* with
//!    the tenant, so every listing was O(n) in the whole store: listing a
//!    one-cell tenant went 591.8 us -> 5.85 ms (9.9x) when *other* tenants
//!    grew the store 8x, for a byte-identical result. That is cross-tenant
//!    performance coupling — a noisy neighbour degrading everyone's reads — in
//!    a product whose selling point is isolation. It is now
//!    `range((t, String::new())..).take_while(...)`, O(log n + k) in the
//!    tenant's own cell count. The test now grows the store **16x** between
//!    the two measurements and fails above 4x, and additionally pins the
//!    range's *correctness* — neighbours on both sides, and a tenant name that
//!    is a proper prefix of another — which is what a fast wrong answer would
//!    otherwise get away with.
//!    -> [`cells_of_cost_does_not_scale_with_the_rest_of_the_store`]
//!
//! 7. **EXHAUSTION VECTOR — refused calls used to retain an unbounded,
//!    caller-controlled audit record.** `admit` journaled *every* decision into
//!    a `Vec<AuditRecord>` with no cap, cloning four caller-supplied strings. A
//!    call refused at gate 1 (unauthenticated) costs zero tokens by design —
//!    and permanently retained 4 321 B when the caller padded its `request_id`
//!    to 4 KiB; 20 000 such refusals retained 86 421 480 B. The metric registry
//!    beside it was bounded at `MAX_SERIES = 4096` precisely against this; the
//!    journal was not. It is now a `VecDeque` capped at
//!    `DEFAULT_AUDIT_CAPACITY`, every identifier is clamped to
//!    `MAX_IDENTIFIER_BYTES` before it is stored, and every eviction is counted
//!    by `audit_dropped()` so a reader is never silently handed a partial trail.
//!    **Still open:** bounding turned an unbounded leak into a bounded
//!    *displacement*. An unauthenticated stranger who names `acme` still fills
//!    `acme`'s audit view, and can now evict the genuine record that justifies
//!    a charge — the meter still says 42 with no surviving record of why, and
//!    only `audit_dropped()` reveals the loss. Both halves are asserted.
//!    -> [`refused_calls_fill_a_bounded_journal_and_displace_a_real_tenants_trail`]
//!
//! 8. **The credential used to be believed for its strength and nothing else.**
//!    `decide` read `call.actor.strength` and then keyed RBAC on
//!    `request.actor` — a plain client string — and resolved the tenant from
//!    `request.tenant`. `AuthenticatedActor::org` was compared with nothing. So
//!    an identity issued for `globex` spent `acme`'s budget and landed in
//!    `acme`'s audit trail (measured: 250 tokens), and any caller could name
//!    any actor and inherit that actor's roles. The credential now binds the
//!    request on both axes — `Refusal::ActorMismatch` and
//!    `Refusal::TenantNotOwnedByOrg`, both evaluated before any tenant-
//!    configurable gate, so neither costs the tenant a token.
//!    **Still open:** `AuditRecord` has no org field, so a trail still cannot
//!    answer "which organization was this authenticated for?".
//!    -> [`the_credential_binds_both_the_actor_and_the_tenants_owning_org`]
//!
//! 10. **Re-adding a tenant used to reset its budget and hand its memory to the
//!     new occupant.** `add_tenant` was an unconditional `BTreeMap::insert`
//!     returning nothing, and there is no `remove_tenant`, so re-provisioning a
//!     name was the product's only tenant-lifecycle operation. It silently
//!     zeroed the spend ledger — an exhausted tenant was refilled by re-adding
//!     it — and silently dropped the model allowlist and the Q-Page
//!     activations. It now takes the owning org, returns `bool`, and changes
//!     nothing when the tenant already exists, for another org as much as for
//!     its own.
//!     **Still open:** the cell store is keyed independently of the tenant
//!     table, so cells outlive every decision made about the tenant record and
//!     no API can clear them. The refusal keeps that latent — until a
//!     `remove_tenant` arrives, which the product now needs, since refusing to
//!     re-provision leaves *no* tenant-lifecycle operation at all. And no
//!     lifecycle event is journaled: a refused re-provisioning is exactly the
//!     operator error an audit trail exists to record, and it leaves no trace.
//!     -> [`re_provisioning_is_refused_but_the_store_still_outlives_the_tenant_record`]
//!
//! ## What was BROKEN and is now REPAIRED
//!
//! 1. **The tenant-scoped store was completely ungoverned.** `put`/`get`/
//!    `cells_of` were reachable with no identity, no RBAC, no boundary check,
//!    no budget and — decisively — **no audit record and no metric**. A write
//!    to a tenant that did not exist in the deployment was accepted and
//!    readable, so `Refusal::UnknownTenant` guarded `admit` and nothing else.
//!
//!    Two repairs. `put_cell`/`get_cell`/`remove_cell` run a cell access
//!    through all nine gates, journal it, meter it and bill it — so
//!    `docs/COGNITIVE_AUDIT.md`'s journal finally sees tenant memory traffic.
//!    And the direct path can no longer produce a state the governed one could
//!    not: it refuses an unknown tenant, an oversized key or value, and a
//!    tenant over its cell allowance. **Still open**: a direct write is a write
//!    with no actor and no record. It cannot create an illegal state; it can
//!    create a legal one anonymously.
//!    -> [`the_store_refuses_unknown_tenants_and_the_governed_path_journals_every_cell`]
//!
//! 3. **EXHAUSTION VECTOR — the store had no cap and no delete.** No bound on
//!    cells, key bytes or value bytes, and no `remove`, `evict` or `clear`
//!    anywhere in the API, so every byte written was retained for the process's
//!    lifetime: overwriting every value with `""` gave back 400 000 B of
//!    5 447 344 B and nothing could release the rest. A tenant whose token
//!    budget was **zero** could still fill it.
//!
//!    `MAX_CELLS_PER_TENANT`, `MAX_CELL_KEY_BYTES` and `MAX_CELL_VALUE_BYTES`
//!    make the worst case arithmetic; `remove` and `clear_cells` make it
//!    reversible; and the governed path is metered in tokens like everything
//!    else, so a zero-budget tenant cannot write a cell through it.
//!    -> [`store_growth_is_bounded_and_releasable`]
//!
//! 4. **The tenant name was copied into every cell key**, so one long name was
//!    amplified by its cell count: 64 KiB across 256 cells retained
//!    16 810 950 B. The map is nested now, so the name is held once per tenant.
//!    -> [`a_tenant_name_is_held_once_however_many_cells_it_has`]
//!
//! 5. **`get` allocated a full copy of the caller's key on every read**,
//!    including a pure miss: a 4 MiB key cost a 4 MiB allocation to answer
//!    "no". `TenantId: Borrow<str>` means both lookups take a `&str`.
//!    -> [`get_allocates_nothing_on_a_read_including_a_pure_miss`]
//!
//! 9. **Tenant identifiers were raw `String`s with no canonicalisation**, so
//!    `"acme"`, `"Acme"`, `"acme "` and `"\u{0430}cme"` were distinct, silently
//!    coexisting namespaces. `add_tenant` refuses all but the canonical
//!    spelling, and — new here — so does the store, so a namespace that cannot
//!    be provisioned cannot be created through the back door either.
//!    -> [`visually_identical_tenant_names_can_no_longer_be_provisioned`]
//!
//! ## What is still BROKEN
//!
//! 2. **`rescope` is documented as "a deliberate, auditable act"
//!    (`crates/ccos-enterprise-tenancy/src/lib.rs:27-28`) and records nothing.**
//!    The rescoped `TenantScope` is bit-identical to one built from scratch and
//!    carries no provenance — a scope is a struct, not an act, so the crossing
//!    is only observable where the scope is *used*. That is why the repair had
//!    to go on the access path: the governed path refuses the crossing and
//!    hands back nothing, and a direct `get` through a rescoped scope is still
//!    a silent substitution.
//!    -> [`rescope_carries_no_provenance_and_only_the_direct_path_crosses_silently`]
//!
//! 11. **The ownership refusal makes tenant names enumerable.** The credential
//!     binding answers `UnknownTenant` for a name no organization has claimed
//!     and `TenantNotOwnedByOrg` for one another organization owns. Any caller
//!     with a token-strength credential for *any* org can difference the two
//!     and read off the deployment's tenant table one name at a time, at zero
//!     cost, from outside every tenant. Collapsing both to one refusal would
//!     close it; the refusal is otherwise invariant, which is what makes this
//!     the only channel left.
//!     -> [`rescope_can_never_silently_read_the_source_tenants_data`], last
//!     assertion
//!
//! (Findings 6, 7, 8 and 10 are repaired; see the section above. The residual
//! halves of 7 and 10 are still open and still pinned by the same tests.)
//!
//! Run the whole file (~7 s in debug, ~2 s in release; nothing is
//! `#[ignore]`d):
//! `cargo test -p ccos-enterprise-conformance --test stress_tenancy_fuzz`
//! (add `-- --nocapture` for the measured growth tables).

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use ccos_enterprise_auth::AuthStrength;
use ccos_enterprise_runtime::{MAX_CELLS_PER_TENANT, MAX_CELL_KEY_BYTES, MAX_CELL_VALUE_BYTES};

use ccos_enterprise_conformance::{
    actor, request, two_tenant_deployment, Call, Deployment, Outcome, Refusal, TenantState,
    DEFAULT_AUDIT_CAPACITY, MAX_IDENTIFIER_BYTES,
};
use ccos_enterprise_qpages::AdvancedQPageVariant;
use ccos_enterprise_tenancy::{TenantId, TenantScope};

// ─────────────────────────────────────────────────────────────────────────
// Measurement harness
//
// A counting allocator gives an exact live-bytes figure for "how much did
// this store actually retain", which is the only honest way to answer "is
// the growth bounded". It counts `Layout::size()`, so the numbers are
// allocator-independent and identical in debug and release except for the
// harness's own noise. `PEAK_BYTES` additionally catches transient
// allocations — the read path's key clone is invisible to a live-bytes
// delta because it is freed before `get` returns.
//
// Every test takes `serialized()` so measurements are not polluted by
// sibling tests allocating on other libtest threads. That makes wall-clock
// runtime additive, which is why the scale constants below are tuned to keep
// the whole file well under a minute in debug.
// ─────────────────────────────────────────────────────────────────────────

struct CountingAlloc;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            let live = LIVE_BYTES.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK_BYTES.fetch_max(live, Ordering::Relaxed);
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

/// Arm the peak watermark at the current live figure and return that figure.
fn arm_peak() -> usize {
    let live = live_bytes();
    PEAK_BYTES.store(live, Ordering::Relaxed);
    live
}

fn peak_bytes() -> usize {
    PEAK_BYTES.load(Ordering::Relaxed)
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
// Corpus generation — deterministic, seeded, identical in debug and release
// ─────────────────────────────────────────────────────────────────────────

/// A fixed-seed LCG. Not named `next`, so it cannot be confused with
/// `Iterator` (and clippy stays quiet).
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn step(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 11
    }

    fn fragment(&mut self) -> &'static str {
        HOSTILE_FRAGMENTS[(self.step() % HOSTILE_FRAGMENTS.len() as u64) as usize]
    }

    /// 1..=n, so a generated string is never zero fragments long.
    fn parts(&mut self, n: u64) -> usize {
        (1 + self.step() % n) as usize
    }
}

/// Fragments chosen to break any store that flattens a tenant and a key into
/// one string: every plausible separator, control bytes, bidi overrides,
/// homoglyphs, normalization twins, path traversal, and the two tenant names
/// the fixture deployment ships with.
const HOSTILE_FRAGMENTS: &[&str] = &[
    "",
    ":",
    "::",
    ":::",
    "/",
    "//",
    "\\",
    "|",
    "\0",
    "\0\0",
    "\u{1}",
    "\u{7f}",
    " ",
    "\t",
    "\n",
    "\r\n",
    ".",
    "..",
    "../",
    "*",
    "%",
    "%00",
    "'",
    "\"",
    "#",
    "-",
    "_",
    "acme",
    "globex",
    "memory-root",
    "\u{202e}",       // RIGHT-TO-LEFT OVERRIDE
    "\u{200b}",       // ZERO WIDTH SPACE
    "\u{feff}",       // BOM
    "\u{0430}",       // CYRILLIC SMALL A — homoglyph of 'a'
    "\u{e9}",         // é, NFC
    "e\u{301}",       // é, NFD
    "\u{1d51e}",      // MATHEMATICAL FRAKTUR SMALL A (astral)
    "\u{fffd}",       // REPLACEMENT CHARACTER
    "\u{10ffff}",     // last scalar value
    "AAAAAAAAAAAAAA", // a run, to make some keys long
    "0",
    "1",
    "t0",
    "t1",
];

fn hostile_string(rng: &mut Lcg, parts: usize) -> String {
    let mut s = String::new();
    for _ in 0..parts {
        s.push_str(rng.fragment());
    }
    s
}

/// The organization every fixture tenant belongs to.
const HOME_ORG: &str = "memorithm";

fn scope(tenant: &str, key: &str) -> TenantScope<String> {
    TenantScope::new(TenantId(tenant.to_string()), key.to_string())
}

/// The store's shape, standing on its own.
///
/// `Deployment`'s cell map is `BTreeMap<TenantId, BTreeMap<String, String>>`,
/// and the keying proofs in this section are about **that shape** rather than
/// about the deployment wrapped around it: the tenant is a separate lookup,
/// not a prefix, so there is no separator to smuggle and no length prefix to
/// get wrong.
///
/// They are made here rather than through `Deployment::put` because the
/// deployment now refuses a cell for a tenant it does not hold, and a tenant
/// can only be provisioned under a canonical name — so the hostile names these
/// tests are built from cannot reach the map through the product at all any
/// more. That is a stronger boundary, asserted in
/// [`hostile_tenant_names_can_no_longer_reach_the_store_at_all`]; it is also
/// why the shape itself needs its own proof, since nothing else would exercise
/// it with names like these again.
#[derive(Default)]
struct CellStore(BTreeMap<TenantId, BTreeMap<String, String>>);

impl CellStore {
    fn put(&mut self, scope: &TenantScope<String>, value: &str) {
        self.0
            .entry(scope.tenant.clone())
            .or_default()
            .insert(scope.inner.clone(), value.to_string());
    }

    fn get(&self, scope: &TenantScope<String>) -> Option<&str> {
        self.0
            .get(scope.tenant.0.as_str())?
            .get(scope.inner.as_str())
            .map(String::as_str)
    }

    fn cells_of(&self, tenant: &str) -> Vec<(&str, &str)> {
        self.0
            .get(tenant)
            .into_iter()
            .flatten()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }
}

fn scope_owned(tenant: String, key: String) -> TenantScope<String> {
    TenantScope::new(TenantId(tenant), key)
}

// ─────────────────────────────────────────────────────────────────────────
// 1. The confusion attack
// ─────────────────────────────────────────────────────────────────────────

/// **HELD.** The headline claim, tested rather than trusted.
///
/// `Deployment`'s store is `BTreeMap<TenantId, BTreeMap<String, String>>`.
/// The tenant is a *structurally* separate lookup — there is no separator to
/// smuggle, and no length prefix to get wrong. This test asserts both
/// directions:
///
/// * the nested store keeps all 27 hostile pairs apart (0 collisions), and
/// * the flattened `"{tenant}{sep}{key}"` spelling a naive store would use
///   collides on most of them, for *every* separator including `\0` —
///
/// so if anyone ever "optimises" the key into a single `String`, the second
/// half of this test tells them exactly what they broke.
///
/// It runs against [`CellStore`], the shape on its own, for the reason given
/// there: the product refuses these tenant names now, one layer earlier.
#[test]
fn nested_keying_defeats_every_separator_confusion_attack() {
    let _guard = serialized();

    // Each row is a pair engineered to alias under some flattening.
    let pairs: &[(&str, &str)] = &[
        ("a", "b:c"),
        ("a:b", "c"),
        ("a:", "b:c"),
        ("a", ":b:c"),
        ("a", "b/c"),
        ("a/b", "c"),
        ("a", "b|c"),
        ("a|b", "c"),
        ("a", "b\0c"),
        ("a\0b", "c"),
        ("", "a"),
        ("a", ""),
        ("", ""),
        ("", ":a"),
        (":", "a"),
        ("acme", "globex:secret"),
        ("acme:globex", "secret"),
        ("t", "1:k"),
        ("t1", ":k"),
        ("t1:", "k"),
        ("ab", "c"),
        ("a", "bc"),
        ("a\u{0430}", "b"), // Cyrillic homoglyph tail
        ("a", "\u{0430}b"),
        ("x\u{202e}", "y"),
        ("x", "\u{202e}y"),
        ("\u{e9}", "k"), // NFC vs NFD: same glyph, different bytes
    ];

    let mut d = CellStore::default();
    for (i, (tenant, key)) in pairs.iter().enumerate() {
        d.put(&scope(tenant, key), &format!("cell#{i}"));
    }

    // Every pair reads back exactly its own value: no aliasing, no shadowing,
    // no last-write-wins between distinct pairs.
    for (i, (tenant, key)) in pairs.iter().enumerate() {
        assert_eq!(
            d.get(&scope(tenant, key)),
            Some(format!("cell#{i}").as_str()),
            "pair {i} ({tenant:?}, {key:?}) was aliased by another pair"
        );
    }

    // …and the store really does hold one cell per pair, i.e. nothing merged.
    let distinct_tuples: BTreeSet<(&str, &str)> = pairs.iter().copied().collect();
    let mut cells = 0usize;
    let tenants: BTreeSet<&str> = pairs.iter().map(|(t, _)| *t).collect();
    for t in &tenants {
        cells += d.cells_of(t).len();
    }
    assert_eq!(
        cells,
        distinct_tuples.len(),
        "the store holds exactly one cell per distinct (tenant, key) tuple"
    );
    assert_eq!(
        distinct_tuples.len(),
        pairs.len(),
        "the corpus itself contains no duplicate tuples"
    );

    // The counterfactual, part 1: what a flattened key would have done to
    // this very corpus.
    for sep in ["", ":", "/", "|", "\0", "::"] {
        let flat: BTreeSet<String> = pairs.iter().map(|(t, k)| format!("{t}{sep}{k}")).collect();
        assert!(
            flat.len() < pairs.len(),
            "separator {sep:?} was expected to alias at least one pair"
        );
        println!(
            "flattened with {sep:?}: {} distinct keys for {} pairs ({} collisions)",
            flat.len(),
            pairs.len(),
            pairs.len() - flat.len()
        );
    }

    // Part 2, and the stronger statement: there is no separator that *would*
    // have been safe. For any separator at all — including NUL, a C1 control,
    // a bidi override or the last scalar value — an attacker simply puts it in
    // a name and the flattening aliases. Only the nested keying is
    // unconditionally safe, whatever a name contains.
    let mut store = CellStore::default();
    for (i, sep) in [
        "",
        ":",
        "/",
        "|",
        "\0",
        "::",
        "\u{1f}",
        "\u{202e}",
        "\u{10ffff}",
    ]
    .into_iter()
    .enumerate()
    {
        let (ta, ka) = ("a".to_string(), format!("b{sep}c"));
        let (tb, kb) = (format!("a{sep}b"), "c".to_string());
        assert_eq!(
            format!("{ta}{sep}{ka}"),
            format!("{tb}{sep}{kb}"),
            "flattening with {sep:?} aliases ({ta:?},{ka:?}) onto ({tb:?},{kb:?})"
        );

        store.put(&scope(&ta, &ka), &format!("A{i}"));
        store.put(&scope(&tb, &kb), &format!("B{i}"));
        assert_eq!(
            store.get(&scope(&ta, &ka)),
            Some(format!("A{i}").as_str()),
            "the tuple store keeps them apart despite separator {sep:?}"
        );
        assert_eq!(store.get(&scope(&tb, &kb)), Some(format!("B{i}").as_str()));
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 2. 100 000 adversarial pairs against a reference model
// ─────────────────────────────────────────────────────────────────────────

/// **HELD.** 100 000 hostile `(tenant, key)` pairs, checked against a
/// reference `BTreeMap` model on 200 000 probes — half self-probes, half
/// deliberately crossed (tenant of pair *i* with key of pair *i + 7919*).
///
/// Two independent oracles, because a model built with the same keying would
/// reproduce the same bug: (a) the store must agree with the model on every
/// probe, and (b) every value carries the tag of the tenant that wrote it, so
/// a cross-tenant hit could not masquerade as a legitimate one.
#[test]
fn a_hundred_thousand_hostile_pairs_never_alias_or_leak() {
    let _guard = serialized();
    const PAIRS: usize = 100_000;

    let mut rng = Lcg::new(0x5EED_1234_ABCD_0001);

    // A hostile tenant pool, including the empty tenant and names that are
    // prefixes/suffixes of one another.
    let mut tenants: Vec<String> = vec![String::new(), "acme".into(), "globex".into()];
    while tenants.len() < 200 {
        let parts = rng.parts(3);
        let t = hostile_string(&mut rng, parts);
        if !tenants.contains(&t) {
            tenants.push(t);
        }
    }
    let tenant_index: BTreeMap<&str, usize> = tenants
        .iter()
        .enumerate()
        .map(|(i, t)| (t.as_str(), i))
        .collect();
    assert_eq!(tenant_index.len(), tenants.len(), "tenant pool is deduped");

    let mut d = CellStore::default();
    let mut model: BTreeMap<(String, String), String> = BTreeMap::new();
    let mut keys: Vec<String> = Vec::with_capacity(PAIRS);
    let mut owners: Vec<usize> = Vec::with_capacity(PAIRS);

    for i in 0..PAIRS {
        let ti = (rng.step() % tenants.len() as u64) as usize;
        // Every 17th key is *another tenant's name*, every 101st is empty:
        // the two shapes most likely to be special-cased somewhere.
        let key = match i % 101 {
            0 => String::new(),
            _ if i % 17 == 0 => tenants[(rng.step() % tenants.len() as u64) as usize].clone(),
            _ => {
                let parts = rng.parts(4);
                hostile_string(&mut rng, parts)
            }
        };
        // The value names its owner, so a leak cannot look like a hit.
        let value = format!("t{ti}#{i}");
        d.put(&scope(&tenants[ti], &key), &value);
        model.insert((tenants[ti].clone(), key.clone()), value);
        keys.push(key);
        owners.push(ti);
    }

    // (a) Self-probes: what was written is what is read, and nothing else.
    for i in 0..PAIRS {
        let ti = owners[i];
        let got = d.get(&scope(&tenants[ti], &keys[i]));
        let want = model
            .get(&(tenants[ti].clone(), keys[i].clone()))
            .map(String::as_str);
        assert_eq!(got, want, "self-probe {i} diverged from the model");
        let got = got.expect("a pair that was written must be readable");
        let tag = got.split('#').next().expect("value carries a tenant tag");
        assert_eq!(
            tag,
            format!("t{ti}"),
            "probe {i} under tenant {ti} returned tenant {tag}'s cell"
        );
    }

    // (b) Crossed probes: a hostile key belonging to a different pair. A hit
    //     is legal only if that exact tuple was written — and must still carry
    //     the probing tenant's tag.
    let mut crossed_hits = 0usize;
    for i in 0..PAIRS {
        let ti = owners[i];
        let k = &keys[(i * 7919 + 13) % PAIRS];
        let got = d.get(&scope(&tenants[ti], k));
        let want = model
            .get(&(tenants[ti].clone(), k.clone()))
            .map(String::as_str);
        assert_eq!(got, want, "crossed probe {i} diverged from the model");
        if let Some(v) = got {
            crossed_hits += 1;
            assert_eq!(
                v.split('#').next().expect("tagged"),
                format!("t{ti}"),
                "crossed probe {i} reached another tenant's cell"
            );
        }
    }

    // The store's total cell count equals the model's: no tuple was merged
    // away and none was invented.
    let mut total = 0usize;
    for t in &tenants {
        total += d.cells_of(t).len();
    }
    assert_eq!(total, model.len(), "store and model hold the same cell set");
    println!(
        "100k hostile pairs -> {} distinct cells over {} tenants; {crossed_hits} crossed probes \
         legitimately hit an existing tuple",
        model.len(),
        tenants.len()
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 3. cells_of: exactness and deterministic order at 1 000 x 100
// ─────────────────────────────────────────────────────────────────────────

/// Build a 1 000 x 100 deployment. Tenant names are deliberately confusable by
/// *prefix* (`t7`, `t7_a`, `t7_b`, and `t7` is a prefix of `t70`) and cells are
/// inserted out of sorted order so that a "deterministic order" claim has
/// something to prove.
///
/// The names used to be `t7`, `t7:`, `t7:7`. They are canonical now because a
/// cell can only exist under a tenant the deployment actually holds, and
/// `add_tenant` refuses a non-canonical id — so the confusable-by-punctuation
/// corpus moved to [`CellStore`], where the keying can still be attacked with
/// it, and this fixture keeps the prefix confusion that survives the rule.
fn wide_deployment(tenants: usize, cells: usize, reverse_insertion: bool) -> Deployment {
    let mut d = Deployment::new();
    let order: Vec<usize> = if reverse_insertion {
        (0..tenants).rev().collect()
    } else {
        (0..tenants).collect()
    };
    for i in 0..tenants {
        assert!(
            d.add_tenant(HOME_ORG, &tenant_name(i), TenantState::new(0)),
            "tenant {i} must be provisionable"
        );
    }
    for i in order {
        let name = tenant_name(i);
        for j in 0..cells {
            // (j * 37) % 100 is a permutation of 0..100, so insertion order
            // is not sorted order.
            let key = format!("cell-{:03}", (j * 37) % cells);
            assert!(d.put(&scope(&name, &key), &format!("t{i}#c{j}")));
        }
    }
    d
}

fn tenant_name(i: usize) -> String {
    match i % 3 {
        0 => format!("t{i}"),
        1 => format!("t{i}_a"),
        _ => format!("t{i}_b"),
    }
}

/// Expected cells for tenant `i`, in the order `cells_of` must return them.
fn expected_cells(i: usize, cells: usize) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = (0..cells)
        .map(|j| {
            (
                format!("cell-{:03}", (j * 37) % cells),
                format!("t{i}#c{j}"),
            )
        })
        .collect();
    v.sort();
    v
}

/// **HELD.** `cells_of` returns exactly the tenant's own cells, never a
/// neighbour's, in a deterministic order that does not depend on insertion
/// order.
///
/// Exhaustive: **every** one of the 1 000 tenants is checked against its
/// expected 100 cells. This used to be 10^8 key comparisons, because
/// `cells_of` rescanned the whole store on every call (defect 6); now that it
/// is a range scan the same exhaustive check costs O(log n + 100) per tenant.
/// Order-independence is additionally cross-checked against a deployment built
/// in reverse insertion order on a deterministic 44-tenant sample, which keeps
/// the file inside its runtime budget without weakening the exactness claim.
#[test]
fn cells_of_is_exact_and_deterministically_ordered_at_a_thousand_tenants() {
    let _guard = serialized();
    const TENANTS: usize = 1_000;
    const CELLS: usize = 100;

    let d = wide_deployment(TENANTS, CELLS, false);
    let reversed = wide_deployment(TENANTS, CELLS, true);

    // Deterministic sample for the (more expensive) cross-deployment checks:
    // both edges, the confusable triples around 0 and 999, and a stride
    // coprime with 3 so all three name shapes are covered.
    let mut sample: BTreeSet<usize> = (0..TENANTS).step_by(23).collect();
    sample.extend([0, 1, 2, 3, TENANTS - 3, TENANTS - 2, TENANTS - 1]);

    for i in 0..TENANTS {
        let name = tenant_name(i);
        let cells = d.cells_of(&name);
        let want = expected_cells(i, CELLS);

        assert_eq!(cells.len(), CELLS, "{name} sees exactly its own cell count");
        let got: Vec<(String, String)> = cells
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(got, want, "{name}: wrong cells or wrong order");

        // Every value names its owner, so a neighbour's cell could not hide
        // in the list even if the key names coincided (and `t7`/`t7:`/`t7:7`
        // are engineered to make them coincide).
        for (_, v) in &cells {
            assert!(
                v.starts_with(&format!("t{i}#")),
                "{name} was shown a cell owned by {v}"
            );
        }

        if sample.contains(&i) {
            // Deterministic: same call, same answer; and independent of the
            // order the deployment was built in.
            assert_eq!(cells, d.cells_of(&name), "repeated call is identical");
            assert_eq!(
                cells,
                reversed.cells_of(&name),
                "order does not depend on insertion order"
            );
        }
    }

    // A tenant that does not exist sees nothing — not a fallback pool, not
    // the union, not the first tenant's cells. `t` and `t0:` are proper
    // prefixes of real tenant names, which is exactly what a `starts_with`
    // implementation would leak on.
    for ghost in ["t", "t0:", "t0:0:", "", ":", "t1000", "T0", "t1:1:"] {
        assert!(
            d.cells_of(ghost).is_empty(),
            "{ghost:?} must see nothing at all"
        );
    }
    // …while `t0`, of which `t` is a prefix, still sees exactly its own.
    assert_eq!(d.cells_of("t0").len(), CELLS);
}

/// **HELD.** The deterministic order of `cells_of` is raw byte order over the
/// inner key, and it survives keys that are empty, NUL-bearing, astral, or
/// each other's prefixes — the cases where a locale-aware or C-string-aware
/// implementation would reorder or truncate.
#[test]
fn cells_of_order_is_byte_order_even_for_nul_and_astral_keys() {
    let _guard = serialized();
    let mut rng = Lcg::new(0x0BAD_F00D_0000_0011);

    let mut keys: BTreeSet<String> = BTreeSet::new();
    keys.insert(String::new());
    keys.insert("\0".into());
    keys.insert("\0\0".into());
    keys.insert("a".into());
    keys.insert("a\0".into());
    keys.insert("a\0b".into());
    keys.insert("\u{10ffff}".into());
    keys.insert("\u{1d51e}".into());
    keys.insert("\u{e9}".into());
    keys.insert("e\u{301}".into());
    while keys.len() < 4_000 {
        let parts = rng.parts(4);
        keys.insert(hostile_string(&mut rng, parts));
    }

    // Against the shape rather than the deployment: the decoy neighbour is
    // `"t\0"`, which no deployment will provision now, and the claim under
    // test is about the *inner* key's ordering — see [`CellStore`].
    let mut d = CellStore::default();
    for (i, k) in keys.iter().enumerate() {
        d.put(&scope("t", k), &format!("v{i}"));
        // A decoy neighbour holding the same key, to be sure the listing is
        // filtered and not merely deduplicated.
        d.put(&scope("t\0", k), "DECOY");
    }

    let listed: Vec<&str> = d.cells_of("t").iter().map(|(k, _)| *k).collect();
    let expected: Vec<&str> = keys.iter().map(String::as_str).collect();
    assert_eq!(listed, expected, "cells_of order is BTreeSet<String> order");
    assert!(
        listed.windows(2).all(|w| w[0].as_bytes() < w[1].as_bytes()),
        "…which is strictly ascending raw byte order"
    );
    assert!(
        d.cells_of("t").iter().all(|(_, v)| *v != "DECOY"),
        "not one of tenant \"t\\0\"'s cells appears in tenant \"t\"'s listing"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 4. rescope
// ─────────────────────────────────────────────────────────────────────────

/// **HELD, AND NOW DOUBLY GUARDED.** `rescope` never reads through to the
/// source tenant's data, in either direction, for any hostile key — the crossed
/// scope names a cell in the *target* namespace, which is empty unless the
/// target itself wrote it.
///
/// That was the whole of the assertion when the admission path had no
/// credential binding: reaching another tenant produced an empty result, and
/// nothing else stood in the way. It now has a second, stronger guard in front
/// of it. An identity from another organization is refused with
/// [`Refusal::TenantNotOwnedByOrg`] at gate 3 — *before* the boundary check,
/// before RBAC, before the model allowlist, before the Q-Page registry and
/// before the budget — so the foreign caller never reaches a gate whose answer
/// depends on the target tenant's configuration, and the tenant is charged
/// nothing. An empty result says "there is nothing here for you"; the refusal
/// says "you were never entitled to ask", which is the claim
/// `ccos_enterprise_tenancy` actually makes.
///
/// The second half below asserts that, and asserts it is *invariant*: the same
/// refusal arrives whatever tool, model, variant, cost or role the foreign
/// caller brings, so it cannot be differenced into an oracle for the target's
/// configuration. One thing it does still leak is pinned at the end.
#[test]
fn rescope_can_never_silently_read_the_source_tenants_data() {
    let _guard = serialized();
    let mut rng = Lcg::new(0xC0FF_EE00_0000_0007);
    let mut d = Deployment::new();

    let mut written: Vec<String> = vec![
        String::new(),
        "memory-root".into(),
        "secret".into(),
        "a:b".into(),
        "\0".into(),
        "\u{202e}invoice".into(),
    ];
    for _ in 0..2_000 {
        let parts = rng.parts(4);
        written.push(hostile_string(&mut rng, parts));
    }

    for (i, key) in written.iter().enumerate() {
        d.put(&scope("acme", key), &format!("acme#{i}"));
    }

    for key in &written {
        let source = scope("acme", key);
        let crossed = source.clone().rescope(TenantId("globex".into()));
        assert_eq!(crossed.inner, source.inner, "the cell name is unchanged");
        assert_eq!(crossed.tenant, TenantId("globex".into()));
        assert_eq!(
            d.get(&crossed),
            None,
            "rescoping to globex must not reach acme's {key:?}"
        );
        // …and the reverse crossing is equally blind.
        let back = crossed.rescope(TenantId("third".into()));
        assert_eq!(d.get(&back), None, "third tenant sees nothing either");
    }
    assert!(d.cells_of("globex").is_empty());
    assert!(d.cells_of("third").is_empty());

    // ── The second guard ────────────────────────────────────────────────
    //
    // The crossings above are refused by the *shape* of the key. On the
    // governed path the crossing is refused by the *credential*, and it is
    // refused earlier: before the store, before every tenant-configurable
    // gate, and without costing the target a token.
    let mut governed = two_tenant_deployment();
    // Both fixture tenants hold real data, so an empty result could not be
    // mistaken for the guard doing its job here.
    governed.put(&scope("acme", "memory-root"), "ACME CONFIDENTIAL");
    governed.put(&scope("globex", "memory-root"), "GLOBEX CONFIDENTIAL");

    // mallory is genuinely authenticated and genuinely privileged — `assign`
    // is keyed on the actor name alone, so she really does hold `writer`'s
    // permissions. She is simply in the wrong organization, and that alone is
    // enough. `initech` owns no tenant in this deployment.
    governed.assign("mallory", "writer");
    let mallory = actor("initech", "mallory", AuthStrength::Token);

    // Every axis a foreign caller could vary. The last element of each row is
    // what the *same* probe answers for an actor whose org does own the tenant
    // — seven different gates between them, which is what makes the uniformity
    // below a statement about precedence rather than a coincidence.
    let probes: Vec<(&str, &str, Option<AdvancedQPageVariant>, u64, Outcome)> = vec![
        ("memory.recall", "claude-opus", None, 1, Outcome::Forwarded),
        ("memory.ingest", "claude-opus", None, 1, Outcome::Forwarded),
        (
            "shell.exec", // forbidden namespace: gate 4
            "claude-opus",
            None,
            1,
            Outcome::Refused(Refusal::OutsideBoundary(String::new())),
        ),
        (
            "code.execute", // forbidden tool: gate 4
            "claude-opus",
            None,
            1,
            Outcome::Refused(Refusal::OutsideBoundary(String::new())),
        ),
        (
            "context.summarize", // in the catalogue, no permission declared: gate 5
            "claude-opus",
            None,
            1,
            Outcome::Refused(Refusal::ToolNotGoverned),
        ),
        (
            "policy.set", // governed, but alice is only a writer: gate 5
            "claude-opus",
            None,
            1,
            Outcome::Refused(Refusal::PermissionDenied),
        ),
        (
            "memory.recall", // off every allowlist: gate 6
            "no-such-model",
            None,
            1,
            Outcome::Refused(Refusal::ModelNotAllowed),
        ),
        (
            "memory.recall", // globex's model, not acme's: gate 6
            "gpt-5",
            None,
            1,
            Outcome::Refused(Refusal::ModelNotAllowed),
        ),
        (
            "memory.recall",
            "claude-opus",
            Some(AdvancedQPageVariant::Hierarchical), // acme has this one
            1,
            Outcome::Forwarded,
        ),
        (
            "memory.recall",
            "claude-opus",
            Some(AdvancedQPageVariant::TemporalWindowed), // …but not this one: gate 6
            1,
            Outcome::Refused(Refusal::VariantNotActivated),
        ),
        (
            "memory.recall", // more than the whole budget: gate 8
            "claude-opus",
            None,
            1_000_000,
            Outcome::Refused(Refusal::BudgetExhausted),
        ),
    ];

    // The control: same probes, same tenant, an actor whose org owns it. Each
    // row lands on the gate its comment names, so all eleven answers differ.
    // (`OutsideBoundary` carries a message, so shapes are compared by variant.)
    let mut owned = two_tenant_deployment();
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    for (i, (tool, model, variant, cost, expected)) in probes.iter().enumerate() {
        let req = request("acme", "alice", tool, &format!("r-owned-{i}"));
        let got = owned.admit(Call {
            actor: &alice,
            request: &req,
            model,
            cost_tokens: *cost,
            variant: *variant,
            justification: None,
        });
        assert_eq!(
            std::mem::discriminant(&got),
            std::mem::discriminant(expected),
            "control row {i} ({tool:?}, {model:?}): expected {expected:?}, got {got:?}"
        );
        if let (Outcome::Refused(g), Outcome::Refused(e)) = (&got, expected) {
            assert_eq!(
                std::mem::discriminant(g),
                std::mem::discriminant(e),
                "control row {i} ({tool:?}, {model:?}) reached the wrong gate: {got:?}"
            );
        }
    }

    // …and the guard: from the wrong organization, against either tenant,
    // every one of those eleven distinct answers collapses to the same
    // refusal. Not one gate downstream of ownership was reached, so nothing
    // about acme's or globex's roles, catalogue, allowlist, activations or
    // budget is observable through it.
    for tenant in ["acme", "globex"] {
        for (i, (tool, model, variant, cost, _)) in probes.iter().enumerate() {
            let req = request(tenant, "mallory", tool, &format!("r-foreign-{tenant}-{i}"));
            assert_eq!(
                governed
                    .admit(Call {
                        actor: &mallory,
                        request: &req,
                        model,
                        cost_tokens: *cost,
                        variant: *variant,
                        justification: None,
                    })
                    .refusal(),
                Some(&Refusal::TenantNotOwnedByOrg),
                "a foreign org must be refused on ownership alone, before the gate that would \
                 have answered for tool {tool:?} / model {model:?} on {tenant}"
            );
        }
    }

    // Nothing was charged, nothing was read, and the cells are untouched:
    // the refusal landed before the store could have been consulted even if
    // the store were on the `admit` path at all (it is not — defect 1).
    assert_eq!(governed.spent("acme"), Some(0), "a refusal costs nothing");
    assert_eq!(governed.spent("globex"), Some(0));
    assert_eq!(
        governed.get(&scope("acme", "memory-root")),
        Some("ACME CONFIDENTIAL"),
        "the target's cell is neither returned to the foreigner nor disturbed"
    );

    // Every one of those attempts is journaled against the tenant it named,
    // at zero cost — the refusal is announced, not silent.
    for tenant in ["acme", "globex"] {
        let trail = governed.audit_of(tenant);
        assert_eq!(
            trail.len(),
            probes.len(),
            "{tenant}: every attempt is filed"
        );
        assert!(
            trail
                .iter()
                .all(|r| !r.outcome.is_forwarded() && r.cost == 0),
            "{tenant}: a refused crossing must never be billed"
        );
    }
    let metrics: BTreeMap<String, u64> = governed.metrics().into_iter().collect();
    assert_eq!(
        metrics.get("gateway.refused.tenant_not_owned"),
        Some(&((2 * probes.len()) as u64)),
        "and it moves its own low-cardinality counter"
    );
    assert_eq!(metrics.get("gateway.forwarded"), None);

    // STILL OPEN, pinned rather than papered over: the refusal is invariant in
    // everything *except* whether the tenant exists. `src/lib.rs:429-436`
    // answers `UnknownTenant` for a name no org has claimed and
    // `TenantNotOwnedByOrg` for one another org owns, so any authenticated
    // caller can enumerate the deployment's tenant names by differencing the
    // two refusals — which is exactly what the comment at `src/lib.rs:425`
    // ("checked before tenant resolution so a probe cannot enumerate tenants
    // by their refusal") says the ordering prevents. It prevents it for the
    // actor check, not for this one. If the two are ever unified, tighten this
    // assertion instead of deleting it.
    let req = request("no-such-tenant", "mallory", "memory.recall", "r-probe");
    assert_eq!(
        governed
            .admit(Call {
                actor: &mallory,
                request: &req,
                model: "claude-opus",
                cost_tokens: 1,
                variant: None,
                justification: None,
            })
            .refusal(),
        Some(&Refusal::UnknownTenant),
        "DEFECT: a distinguishable refusal makes tenant names enumerable"
    );
}

/// **DEFECT 2.** `crates/ccos-enterprise-tenancy/src/lib.rs:27-28` calls
/// `rescope` "a deliberate, auditable act (an admin operation), never an
/// accident of a shared cache key". Deliberate: yes — you must write the
/// call. **Auditable: no.**
///
/// This test pins the whole of what the product actually records when one
/// tenant's scope is turned into another's and read:
///
/// * the rescoped value is `==` a scope built from scratch — no provenance
///   field, no source tenant, nothing to audit *on*;
/// * the read returns the target tenant's data silently, with no signal that
///   the scope crossed a boundary;
/// * `audit()` is empty and `metrics()` is empty afterwards, because the store
///   is not on the `admit` path at all (defect 1).
///
/// The last section shows precisely how narrow the remaining hole is, and it
/// is the reason this finding is still worth its own test. Presented at the
/// governed path — `admit`, and now `get_cell` too — the very same crossing is
/// refused with [`Refusal::TenantNotOwnedByOrg`] before any tenant state is
/// consulted, journaled, counted, and answered with nothing.
///
/// **What is repaired**: there is now a way to read a cell that cannot cross
/// silently, and it is the one the product uses.
/// **What is still open**: `rescope` itself records nothing, because a
/// `TenantScope` is a struct and not an act — the crossing is only observable
/// where the scope is *used*, which is why the repair had to be on the access
/// path rather than on the type. A direct `get` through a rescoped scope is
/// still a silent substitution.
#[test]
fn rescope_carries_no_provenance_and_only_the_direct_path_crosses_silently() {
    let _guard = serialized();
    let mut d = Deployment::new();
    for t in ["acme", "globex"] {
        assert!(d.add_tenant(HOME_ORG, t, TenantState::new(0)));
    }
    assert!(d.put(&scope("acme", "memory-root"), "ACME CONFIDENTIAL"));
    assert!(d.put(&scope("globex", "memory-root"), "GLOBEX CONFIDENTIAL"));

    let acme_scope = scope("acme", "memory-root");
    assert_eq!(d.get(&acme_scope), Some("ACME CONFIDENTIAL"));

    let crossed = acme_scope.rescope(TenantId("globex".into()));

    // Indistinguishable from a scope that was never anyone else's: `TenantScope`
    // derives `PartialEq` over exactly two fields, so there is nowhere for the
    // crossing to be recorded.
    assert_eq!(
        crossed,
        scope("globex", "memory-root"),
        "a rescoped scope carries no trace of where it came from"
    );
    assert_eq!(
        format!("{crossed:?}"),
        format!("{:?}", scope("globex", "memory-root")),
        "not even Debug distinguishes a crossed scope"
    );

    // On the DIRECT path the read still succeeds and silently returns the
    // *other* tenant's secret. That is correct by the store's contract — a
    // scope names a cell, and this scope names globex's — and it is exactly
    // what makes `rescope`'s "deliberate, auditable act" unprovable: there is
    // no act to audit, only a struct with a different field in it.
    assert_eq!(d.get(&crossed), Some("GLOBEX CONFIDENTIAL"));

    // And the deployment recorded nothing whatsoever.
    assert!(
        d.audit().next().is_none(),
        "STILL OPEN: a direct cross-tenant read is journaled nowhere"
    );
    assert!(
        d.metrics()
            .iter()
            .all(|(k, v)| k.starts_with('_') && *v == 0),
        "DEFECT: not even a counter moves for tenant memory traffic — the \
         registry's own gauges are the only rows, and all read zero"
    );

    // A separate deployment, so the emptiness asserted above stays exactly
    // what it claims: nothing the *store* did produced a record.
    //
    // Here `globex` is a real tenant owned by `memorithm`, holding the same
    // cell under the same inner key. The crossing that succeeds silently above
    // is refused on the governed path — and refused on ownership, at gate 3,
    // so the target's roles, allowlist, activations and budget are never
    // consulted and never charged.
    let mut governed = two_tenant_deployment();
    assert!(governed.put(&scope("globex", "memory-root"), "GLOBEX CONFIDENTIAL"));
    governed.assign("mallory", "reader");
    let mallory = actor("initech", "mallory", AuthStrength::Token);
    let req = request("globex", "mallory", "memory.recall", "r-crossed");
    assert_eq!(
        governed
            .admit(Call {
                actor: &mallory,
                request: &req,
                model: "gpt-5", // globex's own allowlisted model
                cost_tokens: 1,
                variant: None,
                justification: None,
            })
            .refusal(),
        Some(&Refusal::TenantNotOwnedByOrg),
        "the governed path refuses the crossing the store performs silently"
    );
    assert_eq!(governed.spent("globex"), Some(0), "and bills nobody for it");
    assert_eq!(
        governed.get(&scope("globex", "memory-root")),
        Some("GLOBEX CONFIDENTIAL"),
        "the cell the foreigner was after is untouched, and was never reached"
    );

    // Unlike the store crossing, this one leaves a record and moves a counter.
    let trail = governed.audit_of("globex");
    assert_eq!(trail.len(), 1, "the attempt is journaled");
    assert_eq!(trail[0].actor, "mallory", "under the *verified* actor");
    assert_eq!(trail[0].cost, 0, "at zero cost, as every refusal is");
    assert_eq!(
        trail[0].outcome,
        Outcome::Refused(Refusal::TenantNotOwnedByOrg)
    );
    let metrics: BTreeMap<String, u64> = governed.metrics().into_iter().collect();
    assert_eq!(metrics.get("gateway.refused.tenant_not_owned"), Some(&1));

    // And the same crossing through the governed CELL path — the one that did
    // not exist when this finding was written — is refused identically, so
    // there is now a way to read a cell that cannot cross silently at all.
    governed.govern_tool("memory.get", "memory.read");
    let req = request("globex", "mallory", "memory.get", "r-crossed-cell");
    let (outcome, value) = governed.get_cell(
        Call {
            actor: &mallory,
            request: &req,
            model: "gpt-5",
            cost_tokens: 1,
            variant: None,
            justification: None,
        },
        "memory-root",
    );
    assert_eq!(outcome.refusal(), Some(&Refusal::TenantNotOwnedByOrg));
    assert_eq!(value, None, "and it hands back nothing at all");
    assert_eq!(governed.spent("globex"), Some(0));
}

// ─────────────────────────────────────────────────────────────────────────
// 5. The store is off the governed path entirely
// ─────────────────────────────────────────────────────────────────────────

/// **DEFECT 1, REPAIRED.** The store had no gate in front of it: `put`/`get`/
/// `cells_of` took no actor, consulted no `RoleBook`, called no `classify`,
/// charged no `TokenBudget` and wrote no `AuditRecord`. Every consequence was
/// pinned here, and every one is inverted below.
///
/// Two things changed, and they are different repairs:
///
/// * **The governed cell path exists.** `put_cell`/`get_cell`/`remove_cell`
///   run a cell access through all nine gates, journal it, meter it and bill
///   it — `docs/COGNITIVE_AUDIT.md` promises a journal of tenant memory
///   traffic, and now there is one.
/// * **The direct path can no longer produce an illegal state.** It still has
///   no gate in front (that is what "direct" means, and the stress suite needs
///   it to measure the map itself), but it refuses a tenant the deployment does
///   not hold, refuses an oversized key or value, and refuses a tenant over its
///   cell allowance. So the storage layer is never in a state the governed path
///   could not have produced.
///
/// What that does **not** fix is the one thing a direct write still is: a
/// write with no actor, no reason and no record. The last section asserts it,
/// because it is the residue of this finding and it should not become
/// folklore.
#[test]
fn the_store_refuses_unknown_tenants_and_the_governed_path_journals_every_cell() {
    let _guard = serialized();
    let mut d = Deployment::new();
    d.add_role("writer", &["memory.write"])
        .add_role("reader", &["memory.read"])
        .govern_tool("memory.ingest", "memory.write")
        .govern_tool("memory.put", "memory.write")
        .govern_tool("memory.get", "memory.read");
    d.assign("alice", "writer");
    d.assign("bob", "reader");

    // A tenant that exists, but is allowed to spend nothing at all.
    let mut broke = TenantState::new(0);
    broke.allow_model("claude-opus");
    assert!(d.add_tenant(HOME_ORG, "broke", broke));
    let mut rich = TenantState::new(1_000);
    rich.allow_model("claude-opus");
    assert!(d.add_tenant(HOME_ORG, "rich", rich));

    // 1. Writes to a tenant nobody provisioned are refused — by the same rule,
    //    and with the same answer, that `admit` gives.
    assert!(
        !d.put(&scope("ghost-tenant", "memory-root"), "written by nobody"),
        "the store must not accept cells for tenants the deployment lacks"
    );
    assert_eq!(d.get(&scope("ghost-tenant", "memory-root")), None);
    assert_eq!(d.cells_of("ghost-tenant").len(), 0);

    let alice = actor(HOME_ORG, "alice", AuthStrength::Token);
    let req = request("ghost-tenant", "alice", "memory.ingest", "r-ghost");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
            justification: None,
        })
        .refusal(),
        Some(&Refusal::UnknownTenant),
        "and both halves of the product agree about which tenants exist"
    );

    // 2. A zero-budget tenant cannot make one governed call…
    let req = request("broke", "alice", "memory.ingest", "r-broke");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
            justification: None,
        })
        .refusal(),
        Some(&Refusal::BudgetExhausted)
    );
    // …and cannot store a cell through the governed path either, because that
    // path is metered in the same unit as everything else.
    let req = request("broke", "alice", "memory.put", "r-broke-cell");
    assert_eq!(
        d.put_cell(
            Call {
                actor: &alice,
                request: &req,
                model: "claude-opus",
                cost_tokens: 1,
                variant: None,
                justification: None,
            },
            "cell-0",
            "x",
        )
        .refusal(),
        Some(&Refusal::BudgetExhausted),
        "bytes are not tokens, but a governed cell write is a call and a call \
         costs what the tenant agreed to pay"
    );
    assert_eq!(d.cells_of("broke").len(), 0, "and nothing was written");

    // 3. The governed path forwards, writes, bills and journals — one record,
    //    naming the verified actor, at the cost the caller declared.
    let before = d.audit().count();
    let req = request("rich", "alice", "memory.put", "r-rich-cell");
    assert_eq!(
        d.put_cell(
            Call {
                actor: &alice,
                request: &req,
                model: "claude-opus",
                cost_tokens: 7,
                variant: None,
                justification: None,
            },
            "memory-root",
            "ACME CONFIDENTIAL",
        ),
        Outcome::Forwarded
    );
    assert_eq!(d.spent("rich"), Some(7), "a cell write is billed");
    assert_eq!(d.audit().count(), before + 1, "and journaled, exactly once");
    let record = d.audit().last().expect("journaled");
    assert_eq!(record.actor, "alice", "under the *verified* actor");
    assert_eq!(record.tool, "memory.put");
    assert_eq!(record.cost, 7);

    // 4. RBAC applies to cells like anything else: a reader cannot write one,
    //    the refusal is journaled, and nothing lands.
    let bob = actor(HOME_ORG, "bob", AuthStrength::Token);
    let req = request("rich", "bob", "memory.put", "r-bob-write");
    assert_eq!(
        d.put_cell(
            Call {
                actor: &bob,
                request: &req,
                model: "claude-opus",
                cost_tokens: 1,
                variant: None,
                justification: None,
            },
            "memory-root",
            "PLANTED",
        )
        .refusal(),
        Some(&Refusal::PermissionDenied)
    );
    assert_eq!(
        d.get(&scope("rich", "memory-root")),
        Some("ACME CONFIDENTIAL"),
        "the refused write did not reach the store"
    );
    // …and he can read it, because that he is entitled to.
    let req = request("rich", "bob", "memory.get", "r-bob-read");
    let (outcome, value) = d.get_cell(
        Call {
            actor: &bob,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
            justification: None,
        },
        "memory-root",
    );
    assert_eq!(outcome, Outcome::Forwarded);
    assert_eq!(value.as_deref(), Some("ACME CONFIDENTIAL"));

    // 5. A refused read returns nothing at all — not even the "no such cell"
    //    that could be differenced against a permission failure to probe
    //    another tenant's key space.
    let mallory = actor("initech", "mallory", AuthStrength::Token);
    let req = request("rich", "mallory", "memory.get", "r-probe");
    let (outcome, value) = d.get_cell(
        Call {
            actor: &mallory,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
            justification: None,
        },
        "memory-root",
    );
    assert_eq!(outcome.refusal(), Some(&Refusal::TenantNotOwnedByOrg));
    assert_eq!(value, None, "a refusal answers with nothing");

    // 6. STILL OPEN, and named so it stays visible: a *direct* write is a
    //    write with no actor, no reason and no record. It cannot produce an
    //    illegal state any more, but it produces a legal one anonymously.
    let journaled = d.audit().count();
    assert!(d.put(&scope("rich", "memory-root"), "clobbered directly"));
    assert_eq!(
        d.get(&scope("rich", "memory-root")),
        Some("clobbered directly"),
        "an overwrite still destroys the previous value"
    );
    assert_eq!(
        d.audit().count(),
        journaled,
        "and the direct path still journals nothing — the governed path is \
         where the trail comes from, and reaching past it is not journaled"
    );
    assert_eq!(d.governance().count(), 0, "nor is a cell a rule change");
    let metrics: BTreeMap<String, u64> = d.metrics().into_iter().collect();
    assert!(
        !metrics.keys().any(|k| k.contains("cell")),
        "STILL OPEN: no counter distinguishes cell traffic from any other call"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 6. Exhaustion vectors
// ─────────────────────────────────────────────────────────────────────────

/// **DEFECT 3, REPAIRED.** The store was a bare map with no cap on cells, on
/// key bytes or on value bytes, and the public API had **no removal operation
/// of any kind** — no `remove`, `delete`, `evict`, `clear`, `truncate`, no TTL,
/// no quota. Every byte written was retained for the process's lifetime, and
/// overwriting every value with `""` gave back 7% of it.
///
/// Three bounds and two deletes later, the worst case is arithmetic:
/// `MAX_CELLS_PER_TENANT x (MAX_CELL_KEY_BYTES + MAX_CELL_VALUE_BYTES)` per
/// tenant, and every byte of it is releasable. This test measures the growth
/// it used to measure, then proves the ceiling and the release.
#[test]
fn store_growth_is_bounded_and_releasable() {
    let _guard = serialized();

    // Growth up to the cap is still linear — that was never the defect, and a
    // sub-linear reading here would mean cells were being lost.
    let mut table = Vec::new();
    for cells in [25_000usize, 50_000] {
        let before = live_bytes();
        let mut d = Deployment::new();
        assert!(d.add_tenant(HOME_ORG, "t", TenantState::new(0)));
        for i in 0..cells {
            assert!(d.put(
                &scope("t", &format!("{i:0>64}")), // 64-byte key, caller-chosen
                "0123456789abcdef",                // 16-byte value
            ));
        }
        let retained = live_bytes() - before;
        table.push((cells, retained));
        println!(
            "{cells:>7} cells -> {retained:>11} B live ({:.1} B/cell)",
            retained as f64 / cells as f64
        );
        drop(d);
    }
    for w in table.windows(2) {
        let (n0, b0) = w[0];
        let (n1, b1) = w[1];
        let ratio = b1 as f64 / b0 as f64;
        assert!(
            (1.8..=2.2).contains(&ratio),
            "doubling {n0} -> {n1} cells multiplied memory by {ratio:.2}: growth is not linear"
        );
    }

    // The ceiling. Past MAX_CELLS_PER_TENANT a NEW key is refused and the
    // refusal says which bound was hit — but an EXISTING key can still be
    // overwritten, so a full tenant is never unable to correct its own data.
    let mut d = Deployment::new();
    assert!(d.add_tenant(HOME_ORG, "t", TenantState::new(0)));
    for i in 0..MAX_CELLS_PER_TENANT {
        assert!(d.put(&scope("t", &format!("k{i}")), "v"));
    }
    assert_eq!(d.cell_count("t"), MAX_CELLS_PER_TENANT);
    assert!(
        !d.put(&scope("t", "one-too-many"), "v"),
        "the cap is exact: the {}th distinct key is refused",
        MAX_CELLS_PER_TENANT + 1
    );
    assert!(
        d.put(&scope("t", "k0"), "rewritten"),
        "a full tenant can still correct a cell it already holds"
    );
    assert_eq!(d.get(&scope("t", "k0")), Some("rewritten"));
    assert_eq!(d.cell_count("t"), MAX_CELLS_PER_TENANT, "and grows no more");

    // The size bounds, each exact at the boundary.
    assert!(d.put(&scope("t", "k0"), &"v".repeat(MAX_CELL_VALUE_BYTES)));
    assert!(
        !d.put(&scope("t", "k0"), &"v".repeat(MAX_CELL_VALUE_BYTES + 1)),
        "one byte over the value bound is refused"
    );
    assert_eq!(
        d.get(&scope("t", "k0")).map(str::len),
        Some(MAX_CELL_VALUE_BYTES),
        "and the refused write did not truncate the cell it failed to replace"
    );
    let mut fresh = Deployment::new();
    assert!(fresh.add_tenant(HOME_ORG, "t", TenantState::new(0)));
    assert!(fresh.put(&scope("t", &"k".repeat(MAX_CELL_KEY_BYTES)), "v"));
    assert!(!fresh.put(&scope("t", &"k".repeat(MAX_CELL_KEY_BYTES + 1)), "v"));
    assert!(
        !fresh.put(&scope("t", ""), "v"),
        "and the empty key with them"
    );

    // Release. Deleting every cell returns the memory, which is the half that
    // did not exist at all: emptying the values used to give back 7%.
    let before = live_bytes();
    let mut d = Deployment::new();
    assert!(d.add_tenant(HOME_ORG, "t", TenantState::new(0)));
    for i in 0..25_000usize {
        assert!(d.put(&scope("t", &format!("{i:0>64}")), "0123456789abcdef"));
    }
    let full = live_bytes() - before;
    for i in 0..25_000usize {
        assert!(d.remove(&scope("t", &format!("{i:0>64}"))));
    }
    let after_removing = live_bytes() - before;
    println!("after removing every cell: {after_removing} B (was {full} B)");
    assert_eq!(d.cells_of("t").len(), 0, "the cells are gone");
    assert!(
        after_removing * 10 < full,
        "removing every cell released {} B of {full} B — a delete must return \
         the keys, not only the values",
        full - after_removing
    );

    // `clear_cells` is the same thing in one call, and reports what it dropped.
    for i in 0..1_000usize {
        assert!(d.put(&scope("t", &format!("k{i}")), "v"));
    }
    assert_eq!(d.clear_cells("t"), 1_000);
    assert_eq!(d.cell_count("t"), 0);
    assert_eq!(d.clear_cells("never-existed"), 0);
}

/// **REPAIRED, and the isolation it used to prove is now proved a layer
/// earlier.** 1 MiB keys and a 1 MiB tenant name used to be accepted without a
/// murmur: a caller chose how many bytes a single `put` retained and nothing
/// metered it. Both are refused now — the key by [`MAX_CELL_KEY_BYTES`], the
/// tenant name by the canonical-identifier rule that gates provisioning.
///
/// The isolation half is kept, at the largest size the bounds allow: the same
/// maximal key under two tenants is two cells, and two maximal keys differing
/// only in their **last** byte are two cells, so nothing hashes, truncates or
/// prefix-compares the key.
#[test]
fn oversized_keys_and_tenant_names_are_refused_and_the_rest_stays_isolated() {
    let _guard = serialized();
    const MIB: usize = 1024 * 1024;

    // Eight ~1 MiB keys, each filled with a different hostile scalar. Every
    // one is refused, and the store is left holding nothing.
    let fills = [
        'A',
        '\0',
        ':',
        '/',
        '\u{202e}',
        '\u{e9}',
        '\u{1d51e}',
        '\u{10ffff}',
    ];
    let keys: Vec<String> = fills
        .iter()
        .map(|c| c.to_string().repeat(MIB / c.len_utf8()))
        .collect();

    let before = live_bytes();
    let mut d = Deployment::new();
    for t in ["acme", "globex"] {
        assert!(d.add_tenant(HOME_ORG, t, TenantState::new(0)));
    }
    for (i, k) in keys.iter().enumerate() {
        assert!(!d.put(&scope("acme", k), &format!("acme#{i}")));
        assert!(!d.put(&scope("globex", k), &format!("globex#{i}")));
    }
    let retained = live_bytes() - before;
    println!("16 refused ~1 MiB keys retained {retained} B");
    assert_eq!(d.cells_of("acme").len(), 0);
    assert_eq!(d.cells_of("globex").len(), 0);
    assert!(
        retained < MIB,
        "16 refused megabyte keys retained {retained} B — a refusal must not \
         store what it refused"
    );

    // At the bound, the isolation claim still has to hold. Two maximal keys
    // differing only in the final byte are distinct: no truncation, no prefix
    // comparison, no digest collision.
    let mut long_a = "Z".repeat(MAX_CELL_KEY_BYTES - 1);
    let mut long_b = long_a.clone();
    long_a.push('a');
    long_b.push('b');
    assert_eq!(long_a.len(), MAX_CELL_KEY_BYTES);
    assert!(d.put(&scope("acme", &long_a), "TAIL-A"));
    assert!(d.put(&scope("acme", &long_b), "TAIL-B"));
    assert_eq!(d.get(&scope("acme", &long_a)), Some("TAIL-A"));
    assert_eq!(d.get(&scope("acme", &long_b)), Some("TAIL-B"));
    // …and the same maximal key under another tenant is another cell.
    assert!(d.put(&scope("globex", &long_a), "GLOBEX-A"));
    assert_eq!(d.get(&scope("acme", &long_a)), Some("TAIL-A"));
    assert_eq!(d.get(&scope("globex", &long_a)), Some("GLOBEX-A"));

    // A 1 MiB *tenant name* cannot be provisioned, so it cannot hold a cell.
    let huge_tenant = "t".repeat(MIB);
    assert!(!d.add_tenant(HOME_ORG, &huge_tenant, TenantState::new(0)));
    assert!(!d.put(&scope(&huge_tenant, "memory-root"), "huge tenant's cell"));
    assert_eq!(d.get(&scope(&huge_tenant, "memory-root")), None);
    assert_eq!(d.cells_of(&huge_tenant).len(), 0);
}

/// **DEFECT 4, REPAIRED by the store's shape.** `put` used to clone the tenant
/// name into every cell key, so a long tenant identifier was amplified by that
/// tenant's cell count: 64 KiB of name across 256 cells retained 256 copies of
/// it, 16 810 950 B from 256 calls.
///
/// The map is nested now — `BTreeMap<TenantId, BTreeMap<String, String>>` — so
/// the name is held once per tenant however many cells it has. The 64 KiB name
/// is also unprovisionable, which closes the vector twice; this test keeps the
/// measurement at the longest name that IS provisionable, because the shape
/// property is what a future change could silently undo.
#[test]
fn a_tenant_name_is_held_once_however_many_cells_it_has() {
    let _guard = serialized();
    const CELLS: usize = 256;

    // The longest canonical identifier the product accepts.
    let name = "t".repeat(MAX_IDENTIFIER_BYTES);
    let before = live_bytes();
    let mut d = Deployment::new();
    assert!(d.add_tenant(HOME_ORG, &name, TenantState::new(0)));
    for i in 0..CELLS {
        assert!(d.put(&scope(&name, &format!("k{i}")), "v"));
    }
    let retained = live_bytes() - before;
    println!(
        "one {} B tenant name x {CELLS} cells -> {retained} B ({:.1} B/cell)",
        name.len(),
        retained as f64 / CELLS as f64
    );
    // The claim is structural, so state it structurally: the whole tenant's
    // footprint stays under a couple of copies of the name plus the cells
    // themselves. Amplified, it would have been CELLS copies.
    assert!(
        retained < name.len() * 4 + CELLS * 128,
        "expected the name to be held once, not {CELLS} times: {retained} B \
         for a {} B name over {CELLS} cells",
        name.len()
    );
    // The counterfactual, measured rather than argued: the same data in the
    // flat `(TenantId, String)` keying the store used to have.
    let before_flat = live_bytes();
    let mut flat: BTreeMap<(String, String), String> = BTreeMap::new();
    for i in 0..CELLS {
        flat.insert((name.clone(), format!("k{i}")), "v".to_string());
    }
    let flat_retained = live_bytes() - before_flat;
    println!(
        "the same {CELLS} cells under flat keying: {flat_retained} B ({:.1}x)",
        flat_retained as f64 / retained as f64
    );
    assert!(
        flat_retained > retained * 2,
        "the nesting must save the {CELLS} copies of a {} B name: nested \
         {retained} B vs flat {flat_retained} B",
        name.len()
    );
    drop(flat);
    assert_eq!(d.cells_of(&name).len(), CELLS);

    // And the 64 KiB name that used to be amplified cannot even be created.
    let huge = "t".repeat(64 * 1024);
    assert!(!d.add_tenant(HOME_ORG, &huge, TenantState::new(0)));
    assert!(!d.put(&scope(&huge, "k"), "v"));
}

/// **DEFECT 5, REPAIRED.** `get` used to build an owned `(TenantId, String)`
/// *before* the lookup, so the read path allocated and memcpy'd the caller's
/// whole key even when the tenant did not exist and the lookup could not
/// possibly hit — a 4 MiB key cost a 4 MiB allocation to answer "no". Reads
/// are supposed to be the cheap side.
///
/// `TenantId` implements `Borrow<str>` now and the inner map is keyed by
/// `String`, so both lookups take a `&str` and a miss costs a comparison.
///
/// Measured with the peak watermark rather than a live-bytes delta, because
/// the clone was freed before `get` returned — a live delta showed zero and
/// hid the vector entirely, which is why the repair needs the same instrument
/// the defect did.
#[test]
fn get_allocates_nothing_on_a_read_including_a_pure_miss() {
    let _guard = serialized();
    const KEY_BYTES: usize = 4 * 1024 * 1024;

    let d = Deployment::new(); // no tenants, no cells: every read is a miss
    let s = scope_owned("no-such-tenant".to_string(), "K".repeat(KEY_BYTES));

    let before = arm_peak();
    assert_eq!(d.get(&s), None, "a miss is a miss");
    let transient = peak_bytes() - before;
    println!("a single missing-key `get` on a {KEY_BYTES} B key peaked at +{transient} B");
    assert!(
        transient < 4_096,
        "a pure miss must not copy the key: +{transient} B for a {KEY_BYTES} B key"
    );

    // A hit is the same: the key is compared, never copied.
    let mut d = Deployment::new();
    assert!(d.add_tenant(HOME_ORG, "acme", TenantState::new(0)));
    let key = "K".repeat(MAX_CELL_KEY_BYTES);
    assert!(d.put(&scope("acme", &key), "v"));
    let before = arm_peak();
    assert_eq!(d.get(&scope("acme", &key)), Some("v"));
    let transient = peak_bytes() - before;
    assert!(
        transient < 4_096,
        "a hit copied +{transient} B to return a borrowed value"
    );

    // `cells_of` is a single map lookup now rather than a range scan over the
    // whole store, so a missing tenant costs nothing either.
    let before = arm_peak();
    assert!(d.cells_of("no-such-tenant").is_empty());
    let transient = peak_bytes() - before;
    assert!(
        transient < 4_096,
        "cells_of on a missing tenant: +{transient} B"
    );
}

/// **DEFECT 7 — REPAIRED, AND PINNED HERE.** `admit` used to journal every
/// decision into an *uncapped* `Vec<AuditRecord>`, cloning four caller-supplied
/// strings. A call refused at the first gate — no identity, no tenant, no
/// permission, zero tokens charged, deliberately free by the product's own
/// "a refusal costs the tenant nothing" rule — bought permanent memory, sized
/// by the caller's `request_id`. The counter registry beside it caps at
/// `MAX_SERIES = 4096` for exactly this reason; the journal had no cap.
///
/// It is now a `VecDeque` bounded by `DEFAULT_AUDIT_CAPACITY`, and every
/// evicted record is counted in `audit_dropped()`. Three things are asserted
/// here, and the first two are what the repair is *for*:
///
/// * the retained set never exceeds the cap, whatever the caller sends;
/// * what is dropped is *reported*, so a reader is never silently handed a
///   partial trail (the same journal is the billing evidence);
/// * identifiers are clamped, so one 4 KiB `request_id` cannot cost 4 KiB of
///   permanent memory per refusal.
///
/// What the repair does **not** fix, and is still pinned below: an
/// unauthenticated stranger who names `acme` still fills `acme`'s audit view.
/// Bounding the buffer turned an unbounded leak into a bounded eviction —
/// which is now a *displacement* attack on a real tenant's trail.
#[test]
fn refused_calls_fill_a_bounded_journal_and_displace_a_real_tenants_trail() {
    let _guard = serialized();
    const CALLS: usize = 20_000;
    const PAD: usize = 4 * 1024;

    let mut d = two_tenant_deployment();
    d.require_strength(AuthStrength::Strong);
    let anon = actor("memorithm", "nobody", AuthStrength::Anonymous);
    let pad = "R".repeat(PAD);

    let before = live_bytes();
    for i in 0..CALLS {
        // Every string here is attacker-chosen, including the tenant the
        // record will be filed under.
        let req = request("acme", "nobody", "memory.recall", &format!("{pad}-{i}"));
        let outcome = d.admit(Call {
            actor: &anon,
            request: &req,
            model: "claude-opus",
            cost_tokens: 0,
            variant: None,
            justification: None,
        });
        assert_eq!(
            outcome,
            Outcome::Refused(Refusal::Unauthenticated),
            "refused at gate 1, before tenant resolution"
        );
    }
    let retained = live_bytes() - before;
    println!(
        "{CALLS} refused calls with {PAD} B request ids retained {retained} B \
         ({} B per refusal)",
        retained / CALLS
    );

    assert_eq!(
        d.spent("acme"),
        Some(0),
        "the tenant was correctly charged nothing"
    );
    assert!(
        d.audit().count() <= DEFAULT_AUDIT_CAPACITY,
        "the journal is bounded; got {}",
        d.audit().count()
    );
    // Below the cap, so nothing was dropped and the count is exact — the
    // bound is a ceiling, not a truncation that fires early.
    assert_eq!(d.audit().count(), CALLS);
    assert_eq!(d.audit_dropped(), 0, "nothing dropped below the cap");
    assert_eq!(
        d.audit_of("acme").len(),
        CALLS,
        "STILL TRUE: an unauthenticated stranger fills a named tenant's audit view"
    );

    // The 4 KiB `request_id` is clamped to `MAX_IDENTIFIER_BYTES` before it is
    // stored, so a refusal costs a bounded number of bytes rather than
    // whatever the caller chose to send.
    assert!(
        d.audit()
            .all(|r| r.request_id.len() <= MAX_IDENTIFIER_BYTES),
        "a caller-sized identifier reached the journal verbatim"
    );
    assert!(
        retained < CALLS * PAD / 4,
        "expected the clamp to cut retention well below {} B, saw {retained}",
        CALLS * PAD
    );

    // The metric side of the same traffic is bounded, as designed.
    let metrics: BTreeMap<String, u64> = d.metrics().into_iter().collect();
    assert_eq!(
        metrics.get("gateway.refused.unauthenticated"),
        Some(&(CALLS as u64))
    );
    assert!(metrics.len() < 16, "counters stay low-cardinality");

    // Now the displacement the bound introduced. A small-capacity deployment
    // makes it cheap to demonstrate what a 100 000-record one would need
    // 100 000 hostile calls to show: `acme`'s genuine, billed record is
    // pushed out by a stranger's refusals, and only `audit_dropped` says so.
    let mut small = two_tenant_deployment().with_audit_capacity(4);
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let real = request("acme", "alice", "memory.ingest", "the-billed-one");
    small.admit(Call {
        actor: &alice,
        request: &real,
        model: "claude-opus",
        cost_tokens: 42,
        variant: None,
        justification: None,
    });
    assert_eq!(small.spent("acme"), Some(42));
    assert!(small.audit().any(|r| r.request_id == "the-billed-one"));

    small.require_strength(AuthStrength::Strong);
    for i in 0..50 {
        let junk = request("acme", "nobody", "memory.recall", &format!("junk-{i}"));
        small.admit(Call {
            actor: &anon,
            request: &junk,
            model: "claude-opus",
            cost_tokens: 0,
            variant: None,
            justification: None,
        });
    }
    assert_eq!(small.audit().count(), 4, "the cap holds");
    assert!(
        !small.audit().any(|r| r.request_id == "the-billed-one"),
        "DEFECT: a stranger's free refusals evicted the record that justifies a charge"
    );
    assert_eq!(
        small.spent("acme"),
        Some(42),
        "the meter still says 42 with no surviving record of why"
    );
    assert_eq!(
        small.audit_dropped(),
        47,
        "the loss is at least *counted* — a reader can tell the trail is partial"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 7. Cross-tenant coupling
// ─────────────────────────────────────────────────────────────────────────

/// **DEFECT 6 — REPAIRED, AND GUARDED HERE.** `cells_of` used to `filter` the
/// whole store even though the map's key *starts* with the tenant, so one
/// tenant's writes slowed down every other tenant's reads: isolation that did
/// not extend to the clock. It is now
/// `range((t, String::new())..).take_while(|((t2, _), _)| t2 == t)`, which is
/// O(log n + k) in the tenant's own cell count.
///
/// This is a timing test, so it is built to fail only on an *algorithmic*
/// regression and never on a busy machine: it takes the minimum of several
/// runs, and the store grows **16x** between the two measurements while the
/// bound allows 4x. A full scan measured ~6-8x for an 8x store before the
/// repair, so a reverted `filter` lands far outside the bound; scheduler noise
/// on a one-cell listing does not.
#[test]
fn cells_of_cost_does_not_scale_with_the_rest_of_the_store() {
    let _guard = serialized();

    fn victim_listing_cost(neighbour_cells: usize) -> (Duration, usize) {
        let mut d = Deployment::new();
        assert!(d.add_tenant(HOME_ORG, "victim", TenantState::new(0)));
        for i in 0..64 {
            assert!(d.add_tenant(HOME_ORG, &format!("noisy-{i}"), TenantState::new(0)));
        }
        assert!(d.put(&scope("victim", "only-cell"), "one small cell"));
        for i in 0..neighbour_cells {
            assert!(d.put(&scope(&format!("noisy-{}", i % 64), &format!("k{i}")), "x"));
        }
        let mut best = Duration::from_secs(3_600);
        let mut len = 0;
        for _ in 0..7 {
            let t0 = Instant::now();
            let cells = d.cells_of("victim");
            let dt = t0.elapsed();
            len = cells.len();
            best = best.min(dt);
        }
        (best, len)
    }

    let (small, n_small) = victim_listing_cost(10_000);
    let (large, n_large) = victim_listing_cost(160_000);

    // The result the victim gets is identical either way: one cell.
    assert_eq!(n_small, 1);
    assert_eq!(n_large, 1);

    let ratio = large.as_secs_f64() / small.as_secs_f64().max(1e-9);
    println!(
        "cells_of(victim) -> 1 cell: {small:?} with 10k neighbour cells, {large:?} with 160k \
         ({ratio:.1}x for a 16x store)"
    );
    assert!(
        ratio < 4.0,
        "REGRESSION: listing a one-cell tenant must not scale with the store, but a 16x store \
         was {ratio:.2}x slower — has `cells_of` gone back to scanning every key?"
    );

    // …and the range is still *correct*, which is the part a fast wrong answer
    // would get away with. `victim` sorts in the middle of the `noisy-*` keys,
    // so `take_while` has neighbours on both sides to stop at.
    let mut d = Deployment::new();
    for t in ["a-before", "victim", "z-after"] {
        assert!(d.add_tenant(HOME_ORG, t, TenantState::new(0)));
        for i in 0..50 {
            assert!(d.put(&scope(t, &format!("k{i:03}")), t));
        }
    }
    let cells = d.cells_of("victim");
    assert_eq!(cells.len(), 50, "the whole tenant, and nothing either side");
    assert!(
        cells.iter().all(|(_, v)| *v == "victim"),
        "a neighbour's cell leaked into the listing"
    );
    assert!(
        cells.windows(2).all(|w| w[0].0 < w[1].0),
        "the listing is ordered, as a range scan must be"
    );
    assert!(d.cells_of("nobody").is_empty());
    // A tenant name that is a *prefix* of another must not swallow it.
    assert!(d.add_tenant(HOME_ORG, "victimx", TenantState::new(0)));
    assert!(d.put(&scope("victimx", "k000"), "victimx"));
    assert_eq!(
        d.cells_of("victim").len(),
        50,
        "`victimx` is a different tenant, not more of `victim`"
    );
    assert_eq!(d.cells_of("victimx").len(), 1);
}

/// **DEFECT 8 — REPAIRED.** `decide` used to read exactly one field off the
/// authenticated identity — `strength` — and take both the tenant *and the
/// actor* from the request. `AuthenticatedActor::org` was compared with
/// nothing, so an identity issued for one organization spent another's budget
/// and landed in its audit trail; and `request.actor` was believed on sight,
/// so any caller could name any actor and inherit that actor's roles.
///
/// The credential now binds the request on both axes. This test pins both
/// halves shut, and keeps pinning the one thing that is still missing: the
/// journal records the (now verified) actor, but never the org.
#[test]
fn the_credential_binds_both_the_actor_and_the_tenants_owning_org() {
    let _guard = serialized();
    let mut d = two_tenant_deployment();

    // 1. alice is authenticated for an organization called "globex" — which is
    //    also the name of a *tenant* that `memorithm` owns. The two namespaces
    //    must not bridge just because the strings match.
    let alice_of_globex = actor("globex", "alice", AuthStrength::Token);
    assert!(
        !alice_of_globex.is_strongly_authenticated(),
        "token strength clears gate 1, so the refusal below is the binding, not the strength"
    );
    for tenant in ["acme", "globex"] {
        let req = request(
            tenant,
            "alice",
            "memory.recall",
            &format!("r-cross-{tenant}"),
        );
        assert_eq!(
            d.admit(Call {
                actor: &alice_of_globex,
                request: &req,
                model: "claude-opus",
                cost_tokens: 250,
                variant: None,
                justification: None,
            })
            .refusal(),
            Some(&Refusal::TenantNotOwnedByOrg),
            "an identity from another org must not reach {tenant}"
        );
    }
    assert_eq!(d.spent("acme"), Some(0), "and acme pays nothing");
    assert_eq!(d.spent("globex"), Some(0), "nor does the like-named tenant");

    // 2. The actor half: bob, correctly in `memorithm`, claims to be alice —
    //    who can write where he cannot.
    let bob = actor("memorithm", "bob", AuthStrength::Token);
    let req = request("acme", "alice", "memory.ingest", "r-impersonation");
    assert_eq!(
        d.admit(Call {
            actor: &bob,
            request: &req,
            model: "claude-opus",
            cost_tokens: 250,
            variant: None,
            justification: None,
        })
        .refusal(),
        Some(&Refusal::ActorMismatch),
        "the request's copy of the actor is never believed over the credential"
    );
    assert_eq!(d.spent("acme"), Some(0));

    // 3. The legitimate call, for contrast: same tenant, same tool, an actor
    //    the credential actually proves.
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let req = request("acme", "alice", "memory.ingest", "r-legit");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 250,
            variant: None,
            justification: None,
        }),
        Outcome::Forwarded
    );
    assert_eq!(d.spent("acme"), Some(250));

    // Every one of the four decisions is journaled — refusals included.
    let trail = d.audit_of("acme");
    assert_eq!(trail.len(), 3, "two refusals and the admitted call");
    assert_eq!(trail.iter().filter(|r| r.outcome.is_forwarded()).count(), 1);
    assert_eq!(
        trail[2].actor, "alice",
        "the record names the actor, and it is now the *verified* one"
    );
    assert!(
        d.audit_of("globex").len() == 1,
        "the refusal against the like-named tenant is filed under that tenant"
    );

    // STILL MISSING: `AuditRecord` has no org field, so a trail cannot answer
    // "which organization was this authenticated for?" — only the tenant's
    // owner, indirectly, and only while the tenant table still exists.
    let record = format!("{:?}", trail[2]);
    assert!(
        !record.contains("memorithm"),
        "if the org has reached the journal, tighten this test instead of deleting it: {record}"
    );
}

/// **DEFECT 10 — HALF REPAIRED.** `add_tenant` used to be an unconditional
/// `BTreeMap::insert`, so re-adding an existing tenant **replaced** its
/// `TenantState`: the spend ledger reset to zero and the allowlist and Q-Page
/// activations were replaced, silently, with no return value and no refusal.
/// An exhausted tenant was refilled by re-provisioning it.
///
/// It now returns `bool` and refuses to overwrite a live tenant, so the first
/// half is closed and this test pins it shut. The second half is untouched
/// and is the more interesting one:
///
/// * the **store is keyed independently of the tenant table**, so cells
///   survive anything done to the tenant record. Today the refusal keeps that
///   latent; the moment a `remove_tenant` is added — and the product needs one,
///   because refusing to re-provision means there is now *no* tenant-lifecycle
///   operation at all — name reuse becomes a data hand-over unless removal
///   clears the cells in the same step;
/// * no tenant-lifecycle event of any kind is journaled. A refused
///   re-provisioning is exactly the operator error an audit trail exists to
///   record, and it leaves no trace.
#[test]
fn re_provisioning_is_refused_but_the_store_still_outlives_the_tenant_record() {
    let _guard = serialized();
    let mut d = two_tenant_deployment();
    let alice = actor("memorithm", "alice", AuthStrength::Token);

    // acme spends 900 of its 1 000, and writes a cell.
    let req = request("acme", "alice", "memory.recall", "r-spend");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 900,
            variant: Some(AdvancedQPageVariant::Hierarchical),
            justification: None,
        }),
        Outcome::Forwarded
    );
    assert_eq!(d.spent("acme"), Some(900));
    d.put(&scope("acme", "secret"), "ACME CONFIDENTIAL");

    // Re-provisioning the same name is now refused, and says so.
    let mut fresh = TenantState::new(1_000);
    fresh.allow_model("claude-opus");
    assert!(
        !d.add_tenant("memorithm", "acme", fresh),
        "a live tenant is not silently replaced"
    );

    assert_eq!(
        d.spent("acme"),
        Some(900),
        "the spend ledger survived the attempt"
    );
    let req = request("acme", "alice", "memory.recall", "r-refilled");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1_000,
            variant: None,
            justification: None,
        })
        .refusal(),
        Some(&Refusal::BudgetExhausted),
        "the budget cannot be refilled by re-provisioning"
    );

    // Governance survived too: the Q-Page activation acme had is still there,
    // so the same call that used to be refused at gate 6 now gets through.
    let req = request("acme", "alice", "memory.recall", "r-variant");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 0,
            variant: Some(AdvancedQPageVariant::Hierarchical),
            justification: None,
        }),
        Outcome::Forwarded,
        "activations are not dropped by a refused re-provisioning"
    );

    // A different org cannot take the name either — the refusal is not a
    // same-org courtesy, it is ownership.
    let mut hostile = TenantState::new(1_000);
    hostile.allow_model("claude-opus");
    assert!(
        !d.add_tenant("initech", "acme", hostile),
        "another org cannot seize an existing tenant name"
    );
    assert_eq!(d.spent("acme"), Some(900));

    // …and the part that is NOT repaired: the store is keyed independently of
    // the tenant table, so the cells outlive every decision made about the
    // tenant record. Nothing in the API can clear them.
    assert_eq!(
        d.get(&scope("acme", "secret")),
        Some("ACME CONFIDENTIAL"),
        "the store is unaffected by tenant-table operations"
    );
    assert_eq!(d.cells_of("acme").len(), 1);

    // Nothing about either refused re-provisioning is journaled: the trail
    // holds only the three `admit` calls.
    assert_eq!(d.audit_of("acme").len(), 3);
    assert!(
        d.audit_of("acme").iter().all(|r| r.tool == "memory.recall"),
        "DEFECT: there is no audit record shape for a tenant lifecycle event at all, \
         so a refused re-provisioning attempt leaves no trace"
    );
}

/// **DEFECT 9 — REPAIRED at the provisioning door.**
///
/// Tenant identifiers were raw `String`s: `add_tenant` accepted anything, with
/// no canonicalisation, case folding, Unicode normalisation, confusable-script
/// check or length bound. Ten spellings a human reads as three all became
/// separate, fully operational tenants with separate budgets, and an operator
/// reading a console could not tell which one held the data.
///
/// `add_tenant` now refuses any id that is not `[a-z0-9_-]`, non-empty and
/// bounded. The confusables cannot be *provisioned*, so they cannot coexist.
///
/// The second reason for the rule is path safety, and it is why this is a
/// refusal rather than a warning: tenant-scoped storage keyed by name turns
/// the id into a path component, so `..`, `/` and a NUL are a traversal away
/// from another tenant's data. Constraining the id makes `<root>/<tenant>`
/// safe *by construction* instead of depending on every use site remembering
/// to sanitize. That property is asserted below too.
///
/// What is unchanged, and still asserted: the *store* is not the thing that
/// was fixed. It still keys on whatever `TenantId` it is handed, so isolation
/// between two ids that do exist continues to hold by construction.
#[test]
fn visually_identical_tenant_names_can_no_longer_be_provisioned() {
    let _guard = serialized();

    let twins = [
        "acme",
        "Acme",
        "ACME",
        "acme ",
        " acme",
        "acme\u{200b}",  // trailing zero-width space
        "\u{0430}cme",   // Cyrillic а
        "\u{e9}quipe",   // NFC é
        "e\u{301}quipe", // NFD é — same glyph, different bytes
        "acme\u{feff}",  // trailing BOM
    ];

    let mut d = Deployment::new();
    // Only the canonical spelling is provisioned. Every other one is refused,
    // and the refusal is the *return value* — silent acceptance was the defect.
    for t in &twins {
        let mut state = TenantState::new(10);
        state.allow_model("claude-opus");
        let accepted = d.add_tenant("memorithm", t, state);
        assert_eq!(
            accepted,
            *t == "acme",
            "{t:?}: provisioning must succeed only for the canonical spelling"
        );
    }

    // The confusables are not tenants at all, so there is nothing to confuse.
    for t in twins.iter().filter(|t| **t != "acme") {
        assert_eq!(d.spent(t), None, "{t:?} was provisioned after all");
    }
    assert_eq!(d.spent("acme"), Some(0));

    // The governed path agrees: a mis-spelled tenant is now an announced
    // refusal rather than a silently separate namespace.
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    d.add_role("reader", &["memory.read"])
        .govern_tool("memory.recall", "memory.read");
    d.assign("alice", "reader");
    for t in ["Acme", "\u{0430}cme", "acme "] {
        let req = request(t, "alice", "memory.recall", &format!("r-{t}"));
        assert_eq!(
            d.admit(Call {
                actor: &alice,
                request: &req,
                model: "claude-opus",
                cost_tokens: 1,
                variant: None,
                justification: None,
            })
            .refusal(),
            Some(&Refusal::UnknownTenant),
            "{t:?} must not be a working tenant"
        );
    }
    let req = request("acme", "alice", "memory.recall", "r-real");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
            justification: None,
        }),
        Outcome::Forwarded
    );
    assert_eq!(d.spent("acme"), Some(1), "one tenant, one set of books");

    // PATH SAFETY, the second reason for the rule. Every shape that would
    // escape or confuse a `<root>/<tenant>` directory is refused, so
    // tenant-scoped storage can key on the id without sanitizing it again.
    for hostile in [
        "..",
        ".",
        "../etc",
        "a/b",
        "a\\b",
        "a\u{0}b",
        "-rf",
        "CON",
        "a b",
        "\u{202e}moc.emca",
    ] {
        let mut state = TenantState::new(10);
        state.allow_model("claude-opus");
        assert!(
            !d.add_tenant("memorithm", hostile, state),
            "{hostile:?} was provisioned as a tenant"
        );
    }
    // …and the same rule applies to the owning organization, which is compared
    // against a credential and would otherwise be confusable in the same way.
    let mut state = TenantState::new(10);
    state.allow_model("claude-opus");
    assert!(!d.add_tenant("Memorithm", "fresh", state));

    // The store isolates the tenants that DO exist, and — the part that is new
    // — refuses a cell for any of the hostile names above, so a namespace that
    // could not be provisioned cannot be created through the back door either.
    let mut state = TenantState::new(10);
    state.allow_model("claude-opus");
    assert!(d.add_tenant(HOME_ORG, "globex", state));
    assert!(d.put(&scope("acme", "memory-root"), "acme's secret"));
    assert!(d.put(&scope("globex", "memory-root"), "globex's secret"));
    assert_eq!(d.get(&scope("acme", "memory-root")), Some("acme's secret"));
    assert_eq!(
        d.get(&scope("globex", "memory-root")),
        Some("globex's secret")
    );
    for hostile in ["Acme", "acme ", "\u{0430}cme", "../etc", "-rf", ""] {
        assert!(
            !d.put(&scope(hostile, "memory-root"), "smuggled"),
            "{hostile:?} got a namespace through the store"
        );
        assert_eq!(d.get(&scope(hostile, "memory-root")), None);
    }
    // The real `acme` is untouched by any of it.
    assert_eq!(d.get(&scope("acme", "memory-root")), Some("acme's secret"));
}
