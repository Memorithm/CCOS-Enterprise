//! # Hostile stress of the tenancy boundary: key confusion, scale, exhaustion
//!
//! `ccos_enterprise_tenancy` is layer 3 of `docs/ENTERPRISE_SECURITY_MODEL.md`
//! and the crate whose doc comment promises "tenant-scoped namespacing that
//! makes cross-tenant access a type error, not a convention". This file
//! attacks that claim with 100 000 adversarial `(tenant, key)` pairs, a
//! dedicated separator-confusion corpus, 1 000 tenants x 100 keys, and a
//! counting allocator pointed at the store.
//!
//! Everything asserted below is the product's **current, real** behaviour.
//! Where that behaviour is a defect the assertion pins the defect and the
//! comment names it, so a repair fails loudly here instead of silently
//! changing the security posture.
//!
//! ## What HELD (and why)
//!
//! * **Tuple keying genuinely defeats key confusion.** `Deployment`'s store is
//!   `BTreeMap<(TenantId, String), String>` (`src/lib.rs:152`, `:161`), and
//!   tuple equality is componentwise: `("a", "b:c")` and `("a:b", "c")` are two
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
//! * **`rescope` never reads through.** Crossing to a tenant that does not hold
//!   the inner key is a miss, in both directions, for every hostile key tried.
//! * **No truncation, hashing or prefix comparison of keys.** 1 MiB keys are
//!   stored and compared in full: two that differ only in their final byte are
//!   two cells, and the same 1 MiB key under two tenants is two cells.
//!
//! ## What BROKE
//!
//! 1. **The tenant-scoped store is completely ungoverned.** `put`/`get`/
//!    `cells_of` (`src/lib.rs:228-252`) are reachable with no identity, no
//!    RBAC, no boundary check, no budget and — decisively — **no audit record
//!    and no metric**. A write to a tenant that does not exist in the
//!    deployment is accepted and readable, so `Refusal::UnknownTenant` guards
//!    `admit` and nothing else; an overwrite destroys the previous value with
//!    zero trace. `docs/COGNITIVE_AUDIT.md`'s journal never sees a byte of
//!    tenant memory traffic.
//!    -> [`the_store_is_ungoverned_and_unknown_tenants_are_writable`]
//!
//! 2. **`rescope` is documented as "a deliberate, auditable act"
//!    (`crates/ccos-enterprise-tenancy/src/lib.rs:27-28`) but nothing anywhere
//!    records it.** The rescoped `TenantScope` is bit-identical to one built
//!    from scratch, carries no provenance, and reading through it leaves the
//!    audit journal and the metric registry empty. When the target tenant
//!    happens to hold the same inner key the crossing silently returns the
//!    *other* tenant's data — correct by the store's contract, invisible by the
//!    crate's own promise.
//!    -> [`rescope_into_an_occupied_key_substitutes_silently_and_unaudited`]
//!
//! 3. **EXHAUSTION VECTOR — the store is an unbounded `BTreeMap` with no
//!    delete.** No cap on cells, on key bytes, on value bytes or on tenants;
//!    no `remove`, `delete`, `evict` or `clear` exists anywhere in the API, so
//!    every byte written is retained for the lifetime of the process. Growth is
//!    linear and caller-controlled: measured 218.0 / 217.9 / 217.9 B per cell
//!    at 25k / 50k / 100k cells (2.00x per doubling) for an 80-byte payload —
//!    a 2.7x overhead the caller does not pay for. Overwriting every value with
//!    `""` gives back 400 000 B of 5 447 344 B (92.7% still resident), and
//!    there is no API that releases the rest. A tenant whose token budget is
//!    **zero** can still fill it, because the budget meters tokens on `admit`
//!    and the store is not on that path at all.
//!    -> [`store_growth_is_unbounded_linear_and_irreversible`]
//!
//! 4. **The tenant name is copied into every cell key, so one long tenant name
//!    is amplified by its cell count.** `put` stores
//!    `(scope.tenant.clone(), scope.inner.clone())` (`src/lib.rs:229-232`): a
//!    64 KiB tenant name written to 256 keys retains 16 810 950 B from 256
//!    calls — 256x the name. Nothing validates or bounds a tenant identifier.
//!    -> [`a_long_tenant_name_is_copied_into_every_one_of_its_cells`]
//!
//! 5. **`get` allocates a full copy of the caller's key on every read,
//!    including a miss.** `src/lib.rs:238-240` builds an owned
//!    `(TenantId, String)` before looking anything up, so a 4 MiB key costs a
//!    4 MiB allocation + memcpy even when the tenant does not exist and the
//!    lookup cannot possibly hit — measured peak +4 194 318 B for one missing
//!    `get`. A read-only caller controls that size.
//!    -> [`get_clones_the_whole_key_on_every_read_including_a_pure_miss`]
//!
//! 6. **`cells_of` scans the entire store, not the tenant's range.**
//!    `src/lib.rs:245-252` uses `.iter().filter(...)` over a map whose key
//!    *begins* with the tenant, so the range is contiguous and a
//!    `range((t,"")..)` would be O(log n + k). As written it is O(n): listing
//!    a one-cell tenant went 591.8 us -> 5.85 ms (9.9x) when *other* tenants
//!    grew the store 8x, for a byte-identical result. Cross-tenant performance
//!    coupling — a noisy neighbour degrades everyone's reads, in a product
//!    whose selling point is isolation.
//!    -> [`cells_of_cost_scales_with_the_whole_store_not_with_the_tenant`]
//!
//! 7. **EXHAUSTION VECTOR — refused calls retain an unbounded, caller-controlled
//!    audit record.** `admit` journals *every* decision (`src/lib.rs:271-277`)
//!    into a `Vec<AuditRecord>` with no cap, cloning four caller-supplied
//!    strings. A call refused at gate 1 (unauthenticated) costs zero tokens by
//!    design — and permanently retains 4 321 B when the caller pads its
//!    `request_id` to 4 KiB. 20 000 such refusals retained 86 421 480 B, and
//!    all 20 000 land in `audit_of("acme")`: a stranger who cannot authenticate
//!    still fills a named tenant's audit view. The metric registry is bounded
//!    at `MAX_SERIES = 4096` precisely against this; the journal is not.
//!    -> [`refused_calls_retain_unbounded_caller_controlled_audit_records`]
//!
//! 8. **The authenticated actor's `org` is never bound to the tenant it
//!    addresses.** `decide` (`src/lib.rs:281-327`) reads `call.actor.strength`
//!    and nothing else off the identity; `call.actor.org` is dead weight. An
//!    actor authenticated for `globex` spends `acme`'s budget and writes into
//!    `acme`'s audit trail. Tenancy is asserted by the request, not proven by
//!    the identity.
//!    -> [`an_actors_org_is_never_bound_to_the_tenant_it_addresses`]
//!
//! 9. **Tenant identifiers are raw `String`s with no canonicalisation.**
//!    `"acme"`, `"Acme"`, `"acme "`, `"\u{0430}cme"` (Cyrillic a) and the NFC/NFD
//!    spellings of the same name are five distinct, silently coexisting
//!    namespaces. Isolation holds between them (that is the good news); the
//!    provisioning surface that lets two admins create indistinguishable
//!    tenants is the bad news, and `add_tenant` accepts all of them.
//!    -> [`visually_identical_tenant_names_are_distinct_silent_namespaces`]
//!
//! 10. **Re-adding a tenant resets its budget and hands its memory to the new
//!     occupant.** `add_tenant` is an unconditional insert
//!     (`src/lib.rs:190-193`) and there is no `remove_tenant`, so
//!     re-provisioning a name is the product's only tenant-lifecycle
//!     operation. It silently zeroes the spend ledger (an exhausted tenant is
//!     refilled by re-adding it), silently drops the model allowlist and the
//!     Q-Page activations, returns nothing a caller could check, and journals
//!     nothing. Worse, the cell store is keyed independently of the tenant
//!     table, so the new occupant of the name reads every cell the previous
//!     one wrote — and no API can clear them.
//!     -> [`re_adding_a_tenant_resets_its_budget_and_hands_over_its_memory`]
//!
//! Run the whole file (~14 s in debug, ~2 s in release; nothing is
//! `#[ignore]`d):
//! `cargo test -p ccos-enterprise-conformance --test stress_tenancy_fuzz`
//! (add `-- --nocapture` for the measured growth tables).

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use ccos_enterprise_auth::AuthStrength;
use ccos_enterprise_conformance::{
    actor, request, two_tenant_deployment, Call, Deployment, Outcome, Refusal, TenantState,
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

fn scope(tenant: &str, key: &str) -> TenantScope<String> {
    TenantScope::new(TenantId(tenant.to_string()), key.to_string())
}

fn scope_owned(tenant: String, key: String) -> TenantScope<String> {
    TenantScope::new(TenantId(tenant), key)
}

// ─────────────────────────────────────────────────────────────────────────
// 1. The confusion attack
// ─────────────────────────────────────────────────────────────────────────

/// **HELD.** The headline claim, tested rather than trusted.
///
/// `Deployment`'s store is `BTreeMap<(TenantId, String), String>`
/// (`src/lib.rs:152`, type alias at `:161`). Tuple `Eq`/`Ord` is
/// componentwise, so the tenant is a *structurally* separate field — there is
/// no separator to smuggle, and no length prefix to get wrong. This test
/// asserts both directions:
///
/// * the tuple store keeps all 27 hostile pairs apart (0 collisions), and
/// * the flattened `"{tenant}{sep}{key}"` spelling a naive store would use
///   collides on most of them, for *every* separator including `\0` —
///
/// so if anyone ever "optimises" the key into a single `String`, the second
/// half of this test tells them exactly what they broke.
#[test]
fn tuple_keying_defeats_every_separator_confusion_attack() {
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

    let mut d = Deployment::new();
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
    // have been safe. Nothing in this API validates a tenant identifier — not
    // its length, charset, or shape (see
    // `visually_identical_tenant_names_are_distinct_silent_namespaces`) — so
    // for any separator at all, including NUL, a C1 control, a bidi override
    // or the last scalar value, an attacker simply puts it in a name and the
    // flattening aliases. Only the tuple keying is unconditionally safe.
    let mut store = Deployment::new();
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

    let mut d = Deployment::new();
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

/// Build a 1 000 x 100 deployment. Tenant names are deliberately confusable
/// (`t7`, `t7:`, `t7:7`) and cells are inserted out of sorted order so that a
/// "deterministic order" claim has something to prove.
fn wide_deployment(tenants: usize, cells: usize, reverse_insertion: bool) -> Deployment {
    let mut d = Deployment::new();
    let order: Vec<usize> = if reverse_insertion {
        (0..tenants).rev().collect()
    } else {
        (0..tenants).collect()
    };
    for i in order {
        let name = tenant_name(i);
        for j in 0..cells {
            // (j * 37) % 100 is a permutation of 0..100, so insertion order
            // is not sorted order.
            let key = format!("cell-{:03}", (j * 37) % cells);
            d.put(&scope(&name, &key), &format!("t{i}#c{j}"));
        }
    }
    d
}

fn tenant_name(i: usize) -> String {
    match i % 3 {
        0 => format!("t{i}"),
        1 => format!("t{i}:"),
        _ => format!("t{i}:{i}"),
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
/// expected 100 cells — 10^8 key comparisons, because `cells_of` rescans the
/// whole store per call (defect 6). Order-independence is additionally
/// cross-checked against a deployment built in reverse insertion order on a
/// deterministic 44-tenant sample, which keeps the file inside its runtime
/// budget without weakening the exactness claim.
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

    let mut d = Deployment::new();
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

/// **HELD.** `rescope` never reads through to the source tenant's data, in
/// either direction, for any hostile key — the crossed scope names a cell in
/// the *target* namespace, which is empty unless the target itself wrote it.
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
#[test]
fn rescope_into_an_occupied_key_substitutes_silently_and_unaudited() {
    let _guard = serialized();
    let mut d = Deployment::new();
    d.put(&scope("acme", "memory-root"), "ACME CONFIDENTIAL");
    d.put(&scope("globex", "memory-root"), "GLOBEX CONFIDENTIAL");

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

    // The read succeeds and silently returns the *other* tenant's secret.
    assert_eq!(d.get(&crossed), Some("GLOBEX CONFIDENTIAL"));

    // And the deployment recorded nothing whatsoever.
    assert!(
        d.audit().is_empty(),
        "DEFECT: a cross-tenant read is journaled nowhere"
    );
    assert!(
        d.metrics().is_empty(),
        "DEFECT: not even a counter moves for tenant memory traffic"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 5. The store is off the governed path entirely
// ─────────────────────────────────────────────────────────────────────────

/// **DEFECT 1.** `put`/`get`/`cells_of` (`src/lib.rs:228-252`) take no actor,
/// consult no `RoleBook`, call no `classify`, charge no `TokenBudget` and
/// write no `AuditRecord`. This test pins every consequence at once:
///
/// * a tenant that does not exist in the deployment is writable and readable,
///   while the *same* tenant string is refused with `Refusal::UnknownTenant`
///   the moment it reaches `admit` — so the two halves of the product
///   disagree about which tenants exist;
/// * a tenant with a **zero** token budget stores as much as it likes;
/// * an overwrite destroys the previous value leaving no record of either;
/// * `audit()`, `audit_of()` and `metrics()` stay empty across all of it.
#[test]
fn the_store_is_ungoverned_and_unknown_tenants_are_writable() {
    let _guard = serialized();
    let mut d = Deployment::new();
    d.add_role("writer", &["memory.write"])
        .govern_tool("memory.ingest", "memory.write");
    d.assign("alice", "writer");

    // A tenant that exists, but is allowed to spend nothing at all.
    let mut broke = TenantState::new(0);
    broke.allow_model("claude-opus");
    d.add_tenant("broke", broke);

    // 1. Writes to a tenant nobody provisioned are accepted and readable.
    d.put(&scope("ghost-tenant", "memory-root"), "written by nobody");
    assert_eq!(
        d.get(&scope("ghost-tenant", "memory-root")),
        Some("written by nobody"),
        "DEFECT: the store accepts cells for tenants the deployment does not have"
    );
    assert_eq!(d.cells_of("ghost-tenant").len(), 1);

    // …yet `admit` refuses that very tenant.
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let req = request("ghost-tenant", "alice", "memory.ingest", "r-ghost");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::UnknownTenant),
        "the governed path knows the tenant is bogus; the store does not"
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
        })
        .refusal(),
        Some(&Refusal::BudgetExhausted)
    );
    // …but can store 1 000 cells, because bytes are not tokens and the store
    // is not metered in any unit at all.
    for i in 0..1_000 {
        d.put(&scope("broke", &format!("cell-{i}")), &"x".repeat(64));
    }
    assert_eq!(d.cells_of("broke").len(), 1_000);
    assert_eq!(d.spent("broke"), 0, "not one token was charged for 64 KiB");

    // 3. Overwrites are silent destruction.
    d.put(&scope("ghost-tenant", "memory-root"), "clobbered");
    assert_eq!(
        d.get(&scope("ghost-tenant", "memory-root")),
        Some("clobbered"),
        "the previous value is gone, with no version and no record"
    );

    // 4. Nothing above produced a single audit record or metric sample. The
    //    only journaled events are the two refused `admit` calls.
    assert_eq!(
        d.audit().len(),
        2,
        "DEFECT: 1 002 writes and 3 reads are journaled nowhere; only `admit` writes audit"
    );
    assert!(
        d.audit_of("ghost-tenant")
            .iter()
            .all(|r| !r.outcome.is_forwarded()),
        "the only ghost-tenant record is the refusal, not the write"
    );
    let metrics: BTreeMap<String, u64> = d.metrics().into_iter().collect();
    assert_eq!(metrics.get("gateway.requests"), Some(&2));
    assert!(
        !metrics
            .keys()
            .any(|k| k.contains("store") || k.contains("cell")),
        "DEFECT: there is no metric for tenant memory traffic at all"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 6. Exhaustion vectors
// ─────────────────────────────────────────────────────────────────────────

/// **DEFECT 3 — EXHAUSTION VECTOR.** The store is a bare
/// `BTreeMap<(TenantId, String), String>` with no cap on cells, on tenants, on
/// key bytes or on value bytes, and the public API has **no removal operation
/// of any kind** (no `remove`, `delete`, `evict`, `clear`, `truncate`, no TTL,
/// no quota). Every byte written is retained for the process's lifetime.
///
/// Measured live bytes for 25k / 50k / 100k cells of identical shape; growth
/// is exactly linear and entirely caller-controlled. The registry next door
/// (`CounterRegistry::MAX_SERIES = 4096`) exists precisely because "a label
/// explosion can never exhaust memory" — the store makes no such promise and
/// keeps none.
///
/// The second half shows there is no way back: overwriting every value with
/// `""` frees only the values; the keys, which are the larger half and the
/// half the caller chooses the size of, stay resident.
#[test]
fn store_growth_is_unbounded_linear_and_irreversible() {
    let _guard = serialized();

    let mut table = Vec::new();
    for cells in [25_000usize, 50_000, 100_000] {
        let before = live_bytes();
        let mut d = Deployment::new();
        for i in 0..cells {
            d.put(
                &scope("t", &format!("{i:0>64}")), // 64-byte key, caller-chosen
                "0123456789abcdef",                // 16-byte value
            );
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
    let (cells, retained) = table[table.len() - 1];
    assert!(
        retained > cells * 100,
        "each cell retains far more than the bytes the caller handed over"
    );

    // No delete: overwriting values with "" reclaims only the values. The
    // keys — 64 B each, caller-sized — are unreachable and unreleasable.
    let before = live_bytes();
    let mut d = Deployment::new();
    for i in 0..25_000usize {
        d.put(&scope("t", &format!("{i:0>64}")), "0123456789abcdef");
    }
    let full = live_bytes() - before;
    for i in 0..25_000usize {
        d.put(&scope("t", &format!("{i:0>64}")), "");
    }
    let after_emptying = live_bytes() - before;
    println!("after emptying every value: {after_emptying} B (was {full} B)");
    assert!(
        after_emptying * 100 >= full * 60,
        "DEFECT: emptying every value released {} B of {full} B — and there is no API that \
         releases the rest",
        full - after_emptying
    );
    assert_eq!(d.cells_of("t").len(), 25_000, "the cells are still there");
}

/// **HELD, with an unbounded edge.** 1 MiB keys and a 1 MiB tenant name are
/// accepted without a murmur — there is no length bound anywhere on either —
/// and isolation survives them: the same megabyte key under two tenants is two
/// cells, and two megabyte keys differing only in their **last** byte are two
/// cells, so nothing hashes, truncates or prefix-compares the key.
///
/// The size acceptance itself is the finding: a caller chooses how many bytes
/// a single `put` retains, and nothing meters it (defect 3).
#[test]
fn megabyte_keys_and_tenant_names_are_accepted_and_still_isolated() {
    let _guard = serialized();
    const MIB: usize = 1024 * 1024;

    // Eight ~1 MiB keys, each filled with a different hostile scalar.
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
    for (i, k) in keys.iter().enumerate() {
        d.put(&scope("acme", k), &format!("acme#{i}"));
        d.put(&scope("globex", k), &format!("globex#{i}"));
    }
    let retained = live_bytes() - before;
    println!(
        "16 cells with ~1 MiB keys retained {retained} B ({} B per cell)",
        retained / 16
    );

    for (i, k) in keys.iter().enumerate() {
        assert_eq!(d.get(&scope("acme", k)), Some(format!("acme#{i}").as_str()));
        assert_eq!(
            d.get(&scope("globex", k)),
            Some(format!("globex#{i}").as_str()),
            "the same megabyte key under another tenant is another cell"
        );
    }
    assert_eq!(d.cells_of("acme").len(), keys.len());
    assert_eq!(d.cells_of("globex").len(), keys.len());
    assert!(
        retained >= 16 * MIB,
        "every megabyte key is retained in full: expected >= {} B, saw {retained}",
        16 * MIB
    );

    // Two megabyte keys that differ only in the final byte are distinct: no
    // truncation, no prefix comparison, no digest collision.
    let mut long_a = "Z".repeat(MIB);
    let mut long_b = long_a.clone();
    long_a.push('a');
    long_b.push('b');
    d.put(&scope("acme", &long_a), "TAIL-A");
    d.put(&scope("acme", &long_b), "TAIL-B");
    assert_eq!(d.get(&scope("acme", &long_a)), Some("TAIL-A"));
    assert_eq!(d.get(&scope("acme", &long_b)), Some("TAIL-B"));

    // A 1 MiB *tenant name* is equally acceptable, and equally isolated.
    let huge_tenant = "T".repeat(MIB);
    d.put(&scope(&huge_tenant, "memory-root"), "huge tenant's cell");
    assert_eq!(
        d.get(&scope(&huge_tenant, "memory-root")),
        Some("huge tenant's cell")
    );
    assert_eq!(d.get(&scope("acme", "memory-root")), None);
    assert_eq!(d.cells_of(&huge_tenant).len(), 1);
}

/// **DEFECT 4.** `put` clones the tenant name into every cell key
/// (`src/lib.rs:229-232`), so a long tenant identifier is amplified by that
/// tenant's cell count: A tenants x K cells retain A x K copies of the name.
/// Nothing validates a tenant identifier's length, charset or shape — 64 KiB
/// of tenant name is as acceptable as `acme`.
#[test]
fn a_long_tenant_name_is_copied_into_every_one_of_its_cells() {
    let _guard = serialized();
    const NAME_BYTES: usize = 64 * 1024;
    const CELLS: usize = 256;

    let name = "T".repeat(NAME_BYTES);
    let before = live_bytes();
    let mut d = Deployment::new();
    for i in 0..CELLS {
        d.put(&scope(&name, &format!("k{i}")), "v");
    }
    let retained = live_bytes() - before;
    println!(
        "one {NAME_BYTES} B tenant name x {CELLS} cells -> {retained} B ({}x the name)",
        retained / NAME_BYTES
    );
    assert!(
        retained >= NAME_BYTES * CELLS,
        "expected >= {} B of amplification, saw {retained}",
        NAME_BYTES * CELLS
    );
    assert_eq!(d.cells_of(&name).len(), CELLS);
}

/// **DEFECT 5.** `get` builds an owned `(TenantId, String)` *before* the
/// lookup (`src/lib.rs:238-240`), so the read path allocates and memcpys the
/// caller's whole key even when the tenant does not exist and the lookup
/// cannot possibly hit. Reads are supposed to be the cheap side.
///
/// Measured with the peak watermark rather than a live-bytes delta, because
/// the clone is freed before `get` returns — a live delta would show zero and
/// hide the vector entirely.
#[test]
fn get_clones_the_whole_key_on_every_read_including_a_pure_miss() {
    let _guard = serialized();
    const KEY_BYTES: usize = 4 * 1024 * 1024;

    let d = Deployment::new(); // no tenants, no cells: every read is a miss
    let s = scope_owned("no-such-tenant".to_string(), "K".repeat(KEY_BYTES));

    let before = arm_peak();
    assert_eq!(d.get(&s), None, "a miss is a miss");
    let transient = peak_bytes() - before;
    println!("a single missing-key `get` on a {KEY_BYTES} B key peaked at +{transient} B");
    assert!(
        transient >= KEY_BYTES,
        "DEFECT expected: a pure miss should not copy the key, but only +{transient} B was seen"
    );

    // `cells_of` has the same shape: it allocates a `TenantId` from the &str
    // before scanning, but the far bigger cost is the scan itself (defect 6).
    let before = arm_peak();
    assert!(d.cells_of("no-such-tenant").is_empty());
    let _ = peak_bytes() - before;
}

/// **DEFECT 7 — EXHAUSTION VECTOR.** `admit` journals every decision into an
/// uncapped `Vec<AuditRecord>` (`src/lib.rs:271-277`), cloning four
/// caller-supplied strings. A call refused at the *first* gate — no identity,
/// no tenant, no permission, zero tokens charged, deliberately free by the
/// product's own "a refusal costs the tenant nothing" rule — still buys
/// permanent memory, sized by the caller's `request_id`.
///
/// The counter registry beside it caps at `MAX_SERIES = 4096` for exactly this
/// reason; the journal has no cap, no rotation and no eviction API.
#[test]
fn refused_calls_retain_unbounded_caller_controlled_audit_records() {
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
        0,
        "the tenant was correctly charged nothing"
    );
    assert_eq!(d.audit().len(), CALLS, "every refusal is retained forever");
    assert_eq!(
        d.audit_of("acme").len(),
        CALLS,
        "DEFECT: an unauthenticated stranger fills a named tenant's audit view"
    );
    assert!(
        retained >= CALLS * PAD,
        "expected >= {} B retained, saw {retained}",
        CALLS * PAD
    );
    // The metric side of the same traffic is bounded, as designed.
    let metrics: BTreeMap<String, u64> = d.metrics().into_iter().collect();
    assert_eq!(
        metrics.get("gateway.refused.unauthenticated"),
        Some(&(CALLS as u64))
    );
    assert!(metrics.len() < 16, "counters stay low-cardinality");
}

// ─────────────────────────────────────────────────────────────────────────
// 7. Cross-tenant coupling
// ─────────────────────────────────────────────────────────────────────────

/// **DEFECT 6.** `cells_of` filters the whole store (`src/lib.rs:245-252`)
/// even though the map's key *starts* with the tenant, so every tenant's
/// listing is contiguous and `range((t, String::new())..)` would be
/// O(log n + k). As written, one tenant's writes slow down every other
/// tenant's reads — isolation that does not extend to the clock.
///
/// The assertion is deliberately loose (>= 2x for an 8x store) and takes the
/// minimum of several runs, so it measures the algorithm rather than the
/// machine: the real ratio is ~6-8x in both debug and release.
#[test]
fn cells_of_cost_scales_with_the_whole_store_not_with_the_tenant() {
    let _guard = serialized();

    fn victim_listing_cost(neighbour_cells: usize) -> (Duration, usize) {
        let mut d = Deployment::new();
        d.put(&scope("victim", "only-cell"), "one small cell");
        for i in 0..neighbour_cells {
            d.put(&scope(&format!("noisy-{}", i % 64), &format!("k{i}")), "x");
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
    let (large, n_large) = victim_listing_cost(80_000);

    // The result the victim gets is identical either way: one cell.
    assert_eq!(n_small, 1);
    assert_eq!(n_large, 1);

    let ratio = large.as_secs_f64() / small.as_secs_f64().max(1e-9);
    println!(
        "cells_of(victim) -> 1 cell: {small:?} with 10k neighbour cells, {large:?} with 80k \
         ({ratio:.1}x for 8x store)"
    );
    assert!(
        ratio >= 2.0,
        "DEFECT expected: listing a one-cell tenant should not scale with the store, but the \
         8x store was only {ratio:.2}x slower — has `cells_of` become a range scan?"
    );
}

/// **DEFECT 8.** `decide` (`src/lib.rs:281-327`) reads exactly one field off
/// the authenticated identity — `strength` — and takes the tenant from the
/// *request*. `AuthenticatedActor::org` is never compared with anything, so an
/// identity issued for `globex` spends `acme`'s budget and lands in `acme`'s
/// audit trail under `acme`'s name.
#[test]
fn an_actors_org_is_never_bound_to_the_tenant_it_addresses() {
    let _guard = serialized();
    let mut d = two_tenant_deployment();

    // alice is authenticated for globex. She addresses acme.
    let alice_of_globex = actor("globex", "alice", AuthStrength::Token);
    assert!(
        !alice_of_globex.is_strongly_authenticated(),
        "and she is not even strongly authenticated — token strength is enough"
    );
    let req = request("acme", "alice", "memory.recall", "r-cross-org");
    let outcome = d.admit(Call {
        actor: &alice_of_globex,
        request: &req,
        model: "claude-opus", // acme's allowlist, not globex's
        cost_tokens: 250,
        variant: None,
    });

    assert_eq!(
        outcome,
        Outcome::Forwarded,
        "DEFECT: a globex identity is admitted against acme"
    );
    assert_eq!(d.spent("acme"), 250, "and acme pays for it");
    assert_eq!(d.spent("globex"), 0, "while globex's books stay clean");

    let trail = d.audit_of("acme");
    assert_eq!(trail.len(), 1);
    assert_eq!(
        trail[0].actor, "alice",
        "DEFECT: the record names the request's actor string; the org that authenticated her is \
         nowhere in the journal"
    );
    assert!(
        d.audit_of("globex").is_empty(),
        "nothing ties the call back to the org it was authenticated for"
    );
}

/// **DEFECT 10.** `add_tenant` is an unconditional `BTreeMap::insert`
/// (`src/lib.rs:190-193`), so re-adding an existing tenant **replaces** its
/// `TenantState` — and there is no `remove_tenant` anywhere, which makes this
/// the only tenant-lifecycle operation the product has. Two things follow, and
/// both are silent:
///
/// * the spend ledger is reset to zero and the allowlist/Q-Page activations
///   are replaced, with no return value, no refusal and no audit record — an
///   exhausted tenant is refilled by re-provisioning it;
/// * the **store is keyed independently of the tenant table**, so the new
///   occupant of the name inherits every cell the old one wrote. Tenant name
///   reuse is a data hand-over, and nothing in the API can clear the cells.
#[test]
fn re_adding_a_tenant_resets_its_budget_and_hands_over_its_memory() {
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
        }),
        Outcome::Forwarded
    );
    assert_eq!(d.spent("acme"), 900);
    d.put(&scope("acme", "secret"), "ACME CONFIDENTIAL");

    // The only lifecycle lever there is: re-provision the same name.
    let mut fresh = TenantState::new(1_000);
    fresh.allow_model("claude-opus");
    d.add_tenant("acme", fresh);

    assert_eq!(
        d.spent("acme"),
        0,
        "DEFECT: re-provisioning silently zeroes the spend ledger"
    );
    let req = request("acme", "alice", "memory.recall", "r-refilled");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1_000,
            variant: None,
        }),
        Outcome::Forwarded,
        "DEFECT: a full budget is available again immediately"
    );

    // Governance was replaced too — the Q-Page activation acme had is gone,
    // and the refusal arrives at gate 5, before the (now exhausted) budget.
    let req = request("acme", "alice", "memory.recall", "r-variant");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 0,
            variant: Some(AdvancedQPageVariant::Hierarchical),
        })
        .refusal(),
        Some(&Refusal::VariantNotActivated),
        "activations are silently dropped by re-provisioning"
    );

    // …and the decisive one: the new occupant reads the old one's memory.
    assert_eq!(
        d.get(&scope("acme", "secret")),
        Some("ACME CONFIDENTIAL"),
        "DEFECT: tenant name reuse hands the previous occupant's cells to the new one"
    );
    assert_eq!(d.cells_of("acme").len(), 1);

    // Nothing about the re-provisioning is journaled: the trail holds only
    // the three `admit` calls.
    assert_eq!(d.audit_of("acme").len(), 3);
    assert!(
        d.audit_of("acme").iter().all(|r| r.tool == "memory.recall"),
        "there is no audit record shape for a tenant lifecycle event at all"
    );
}

/// **DEFECT 9.** Tenant identifiers are raw `String`s: `add_tenant` and the
/// store accept anything, with no canonicalisation, case folding, Unicode
/// normalisation, confusable-script check or length bound.
///
/// Isolation between them **holds** — which is why this test asserts the
/// isolation *and* the provisioning hazard: five visually identical tenants
/// coexist silently, and an operator reading a console cannot tell which one
/// holds the data.
#[test]
fn visually_identical_tenant_names_are_distinct_silent_namespaces() {
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
    for (i, t) in twins.iter().enumerate() {
        let mut state = TenantState::new(10);
        state.allow_model("claude-opus");
        d.add_tenant(t, state); // every spelling is accepted
        d.put(&scope(t, "memory-root"), &format!("secret of #{i}"));
    }

    // Each twin sees exactly its own cell: the isolation invariant holds.
    for (i, t) in twins.iter().enumerate() {
        assert_eq!(
            d.get(&scope(t, "memory-root")),
            Some(format!("secret of #{i}").as_str()),
            "{t:?} must see only its own cell"
        );
        assert_eq!(d.cells_of(t).len(), 1, "{t:?}");
    }

    // …and the hazard: ten tenants that a human reads as three.
    let distinct: BTreeSet<&str> = twins.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        twins.len(),
        "every spelling is a separate namespace"
    );

    // The governed path agrees with the store here: a mis-spelled tenant is
    // simply a different tenant, not a refusal an operator would notice.
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    d.add_role("reader", &["memory.read"])
        .govern_tool("memory.recall", "memory.read");
    d.assign("alice", "reader");
    for t in ["acme", "Acme", "\u{0430}cme"] {
        let req = request(t, "alice", "memory.recall", "r-twin");
        assert_eq!(
            d.admit(Call {
                actor: &alice,
                request: &req,
                model: "claude-opus",
                cost_tokens: 1,
                variant: None,
            }),
            Outcome::Forwarded,
            "{t:?} is a fully operational tenant"
        );
    }
    // Three separate budgets were debited — one per spelling.
    for t in ["acme", "Acme", "\u{0430}cme"] {
        assert_eq!(d.spent(t), 1, "{t:?} keeps its own books");
    }
}
