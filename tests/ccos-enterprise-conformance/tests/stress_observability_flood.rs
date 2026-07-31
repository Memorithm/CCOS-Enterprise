//! # Hostile stress of the metrics registry: label flood, fold boundary, blinding
//!
//! `ccos_enterprise_observability::CounterRegistry` is the only bounded pool
//! in Enterprise. Its own doc comment states the contract this file attacks:
//!
//! > Maximum distinct series kept; beyond it, increments fold into
//! > `"overflow"` **so a label explosion can never exhaust memory**.
//!
//! and
//!
//! > A deterministic snapshot for exporters (Prometheus/OTel at the gateway)
//! > and **for audit diffing**: name/value pairs in `BTreeMap` order,
//! > **identical for identical histories**.
//!
//! Both sentences are load-bearing product claims, and both are only half
//! true. Everything asserted below is the product's **current, real**
//! behaviour: where that behaviour is a defect the assertion pins the defect
//! and the comment names it, so a repair fails loudly here instead of
//! silently changing what an operator can see.
//!
//! Run the whole file:
//! `cargo test -p ccos-enterprise-conformance --test stress_observability_flood`
//! (add `-- --nocapture` for the measured tables).
//!
//! ## What held
//!
//! * **The cardinality cap is exact and unconditional.** 5 000 000 increments
//!   across 1 000 000 distinct labels leave `series() == 4097` — precisely
//!   `MAX_SERIES + 1` — with `overflow == 4 979 520`, i.e. every one of the
//!   4 979 520 dropped increments accounted for to the unit. Measured
//!   retained heap: ~412 KB against 100 617 888 B for the same history in an
//!   unfolded `BTreeMap` — a 244x saving — and **exactly zero** net bytes are
//!   allocated across the last 4 000 000 increments, so the bound does not
//!   merely hold at the end, it stops growing entirely. The grand total is
//!   conserved to the unit: the fold *relocates* counts, it never drops them.
//!   → [`flood_five_million_increments_across_one_million_labels`]
//! * **The fold boundary is off-by-nothing.** The 4096th distinct name is
//!   admitted; the 4097th is the first to fold. A full registry keeps
//!   counting series it already knows — 100 000 increments on a known name
//!   all land, and `series()` never moves.
//!   → [`fold_engages_exactly_at_the_four_thousand_and_ninety_seventh_series`]
//! * **Saturation is total and deterministic**, for a normal series and for
//!   `overflow` alike: `u64::MAX` then `+1` stays `u64::MAX` in debug and
//!   release. No wrap, no panic.
//! * **`export()` is strictly sorted, `len() == series()`, and byte-identical**
//!   across repeated calls and across two registries fed the same sequence in
//!   the same order — including with empty, NUL-bearing, RTL and astral names
//!   in play, and including after the fold has engaged.
//! * **The composed path is immune to label explosion.**
//!   `Deployment::admit` folds every refusal through a `&'static str` tag, so
//!   3 015 hostile calls carrying 1 MiB tool names, unicode tenants and
//!   attacker-chosen actors produce exactly 11 series — all eight refusal
//!   tags saturated — and never `overflow`.
//!   → [`deployment_metrics_stay_low_cardinality_under_hostile_input`]
//!
//! ## What BROKE
//!
//! 1. **An attacker who can name one metric `overflow` before the registry
//!    fills BLINDS the drop counter permanently.** `inc` folds into
//!    `entry("overflow")` without distinguishing the fold bucket from a
//!    same-named ordinary series (`crates/ccos-enterprise-observability/src/lib.rs:25`).
//!    Seed `inc("overflow", u64::MAX)` on a fresh registry and every
//!    subsequent dropped series saturates against it: after 100 000 dropped
//!    labels the drop counter still reads `u64::MAX`, exactly what it read
//!    before the flood. Label-explosion detection — the entire point of the
//!    fold — is dead, and the seeding call needs no privilege beyond reaching
//!    any code path that names a metric.
//!    → [`attacker_seeded_overflow_corrupts_the_overflow_accounting`]
//!
//! 2. **Seeding `overflow` also silently changes the advertised cap.** With
//!    the name pre-seeded the registry tops out at 4096 keys, not 4097, and
//!    only 4095 attacker-visible series are ever admitted — the same code,
//!    the same input, two different caps depending on whether an attacker
//!    spoke first. Any monitor asserting `series() == MAX_SERIES + 1` is
//!    asserting attacker-controlled state. This is not a contrived reach:
//!    [`export_is_sorted_and_its_length_is_series`] tripped it by accident,
//!    merely by listing `"overflow"` among a set of adversarial names, and had
//!    to be corrected to the real (attacker-shifted) ceiling.
//!
//! 3. **"A label explosion can never exhaust memory" is false: the cap is on
//!    cardinality, not bytes.** `inc` stores `name.into()` verbatim with no
//!    length limit, so 4096 names of 4 KiB retain a measured 17 041 152 B
//!    behind a registry reporting 4097 series. At 1 MiB per name — accepted,
//!    verified, stored and exported byte-for-byte — the same 4097-series
//!    registry retains **4 294 967 296 B (4 GiB)**. The fold bounds the
//!    series count and nothing else, and nothing can release it: there is no
//!    removal, eviction or reset API.
//!    → [`label_length_is_unbounded_so_the_cardinality_cap_is_not_a_memory_cap`]
//!
//! 4. **First writer wins, forever: a flooded registry permanently refuses
//!    every later legitimate series.** There is no eviction, no TTL, no
//!    priority and no removal API. 4096 junk labels — free, since `inc(name, 0)`
//!    creates a series — and `gateway.requests` can never be registered
//!    again for the process lifetime: 1 000 000 subsequent increments leave
//!    `get("gateway.requests") == 0`. The fold protects the heap by
//!    discarding the operator's real telemetry.
//!    → [`a_flooded_registry_permanently_blocks_every_later_legitimate_series`]
//!
//! 5. **"Identical for identical histories" is order-dependent, so replicas
//!    diverge.** Two registries fed the *same multiset* of increments in
//!    different orders agree on the grand total but disagree on 4096 of 4097
//!    series names — they share exactly one key, `overflow` itself — because
//!    which names win the 4096 slots is decided by arrival order alone. Two
//!    replicas of the same service behind a load balancer
//!    therefore export different metrics from the same traffic, and the
//!    documented "audit diffing" use is unsound the moment a deployment
//!    crosses `MAX_SERIES`.
//!    → [`identical_multisets_in_different_orders_produce_different_metrics`]
//!
//! 6. **No metric-name validation whatsoever — an exporter injection vector
//!    is pre-loaded.** The registry accepts and re-exports verbatim names
//!    containing `\n`, spaces, `{`, `}`, `"`, `\\` and interior NUL bytes.
//!    `inc("x 1\nccos_licence_valid 1", 1)` round-trips intact, which is a
//!    forged series in Prometheus text-exposition format the day the
//!    documented exporter is wired at the gateway.
//!    → [`adversarial_label_names_are_stored_and_exported_verbatim`]
//!
//! 7. **Saturation silently destroys counts and no signal survives it.** Once
//!    any series pins at `u64::MAX` the registry's conservation property
//!    (total exported == total incremented) fails with no error, no separate
//!    saturation flag, and no way to distinguish "pinned" from "exactly
//!    `u64::MAX`".
//!    → [`counters_pin_at_u64_max_for_a_normal_series_and_for_overflow`]
//!
//! 8. **`overflow == 0` does not mean "nothing was dropped".** A zero
//!    increment on an unknown name still takes the fold path, so on a
//!    registry at exactly `MAX_SERIES` the bucket is *created holding 0*:
//!    `series()` jumps to 4097, the series that triggered it is gone, and the
//!    obvious alerting rule (`overflow > 0`) reports health. Combined with
//!    (4), an attacker squats every slot with `inc(name, 0)` at literally zero
//!    counted cost.
//!    → [`fold_engages_exactly_at_the_four_thousand_and_ninety_seventh_series`]
//!    and [`zero_valued_and_empty_labels_are_first_class_series`]

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

use ccos_enterprise_auth::AuthStrength;
use ccos_enterprise_conformance::{actor, request, two_tenant_deployment, Call};
use ccos_enterprise_observability::CounterRegistry;
use ccos_enterprise_qpages::AdvancedQPageVariant;

// ─────────────────────────────────────────────────────────────────────────
// Measurement harness
//
// A counting allocator is the only honest answer to "does the fold actually
// bound memory". It counts `Layout::size()`, so the numbers are
// allocator-independent and identical in debug and release but for harness
// noise. Every test takes `serialized()` so measurements are not polluted by
// sibling tests allocating on other libtest threads; that makes runtime
// additive, which is why the scale constants are tuned to stay well under a
// minute in debug.
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

const MAX: usize = CounterRegistry::MAX_SERIES;
const MIB: usize = 1024 * 1024;

/// The one name the fold overloads.
const FOLD: &str = "overflow";

/// Presence, not value. `get` returns 0 for both "absent" and "present with
/// value 0", so every existence claim in this file goes through `export`.
fn has_series(r: &CounterRegistry, name: &str) -> bool {
    r.export().iter().any(|(n, _)| *n == name)
}

/// Strictly increasing name order — proves sortedness *and* uniqueness in one
/// pass, which is what an exporter and an audit diff both rely on.
fn is_strictly_sorted(rows: &[(&str, u64)]) -> bool {
    rows.windows(2).all(|w| w[0].0 < w[1].0)
}

/// Grand total of every counter. Absent saturation this must equal the sum of
/// every `by` ever passed to `inc`: the fold *relocates* counts, it does not
/// discard them. `u128` so the invariant itself cannot overflow.
fn total(r: &CounterRegistry) -> u128 {
    r.export().iter().map(|(_, v)| u128::from(*v)).sum()
}

/// An unambiguous byte encoding of a snapshot. 0xFE/0xFF never occur in
/// UTF-8, so no series name can forge a record separator — comparing these
/// byte strings is a strictly stronger claim than comparing the tuples.
fn snapshot_bytes(r: &CounterRegistry) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in r.export() {
        out.extend_from_slice(name.as_bytes());
        out.push(0xff);
        out.extend_from_slice(&value.to_le_bytes());
        out.push(0xfe);
    }
    out
}

/// FNV-1a over a snapshot. Reduces "the export is deterministic" to a single
/// golden constant that is stable across debug/release, architectures and
/// runs — a `BTreeMap` has no iteration entropy to hide behind.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Feed `n` distinct names `{prefix}{i:07}`, one increment each.
fn fill_distinct(r: &mut CounterRegistry, prefix: &str, n: usize) {
    let mut buf = String::with_capacity(prefix.len() + 8);
    for i in 0..n {
        buf.clear();
        let _ = write!(buf, "{prefix}{i:07}");
        r.inc(&buf, 1);
    }
}

/// Fixed-seed LCG. No wall clock, no `rand`: identical stream in debug and
/// release, on every machine, forever.
fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

// ─────────────────────────────────────────────────────────────────────────
// 1. The flood
// ─────────────────────────────────────────────────────────────────────────

/// 5 000 000 increments across 1 000 000 distinct label values — the label
/// explosion the fold exists to survive — measured against the same history
/// replayed into an unfolded `BTreeMap`.
///
/// The cap holds exactly, and the drop accounting is exact to the unit:
/// 4096 names win slots (the first 4096 *distinct* names to arrive, i.e. the
/// first 4096 of round 0), each collecting one increment per round, and
/// everything else folds. Note what the fold costs the operator: the 4097th
/// name onward is not aggregated under a different key, it is **erased** —
/// `get` on it returns 0 forever, indistinguishable from a label that was
/// never seen.
#[test]
fn flood_five_million_increments_across_one_million_labels() {
    let _guard = serialized();

    const LABELS: usize = 1_000_000;
    const ROUNDS: usize = 5;

    let before = live_bytes();
    let started = Instant::now();
    let mut r = CounterRegistry::default();
    let mut buf = String::with_capacity(64);
    // Heap high-water mark taken after a full round, long after the fold
    // engaged (it engages at label 4096). If the fold holds, not one further
    // byte is retained across the remaining 4 000 000 increments. Taken at a
    // round boundary rather than early in round 0 so that libtest's own
    // thread-spawn bookkeeping cannot land inside the measured window: every
    // sibling test is parked on `TEST_LOCK` by then and none can complete, so
    // this process allocates nothing but what `inc` allocates.
    let mut settled = 0usize;
    for round in 0..ROUNDS {
        if round == 1 {
            settled = live_bytes();
        }
        for i in 0..LABELS {
            buf.clear();
            let _ = write!(buf, "flood.tenant.acme.label.{i:07}.value");
            r.inc(&buf, 1);
            // The ceiling is asserted *during* the flood, not only at the end:
            // a registry that spiked to 200 000 series and shed them later
            // would still pass an end-state check.
            if i % 250_000 == 0 {
                assert!(
                    r.series() <= MAX + 1,
                    "series() exceeded the ceiling mid-flood at round {round}, label {i}"
                );
            }
        }
    }
    let retained = live_bytes().saturating_sub(before);
    let elapsed = started.elapsed();

    // The fold holds *exactly*: zero net bytes retained across the last
    // 4 000 000 increments and 1 000 000 distinct labels.
    assert_eq!(
        live_bytes(),
        settled,
        "the registry allocated after the fold engaged — the bound leaks"
    );

    // The cap is exact, not approximate: MAX_SERIES real series plus the one
    // key the fold creates for itself.
    assert_eq!(
        r.series(),
        MAX + 1,
        "5M increments over 1M labels must leave exactly MAX_SERIES + 1 series"
    );
    assert!(
        r.series() <= MAX + 1,
        "the documented ceiling, restated as the product states it"
    );
    assert_eq!(r.export().len(), r.series(), "export length tracks series");

    // Exact drop accounting: 4096 admitted names x 5 rounds land, the rest
    // fold. No estimate, no tolerance.
    let admitted = MAX as u64 * ROUNDS as u64;
    let dropped = (LABELS * ROUNDS) as u64 - admitted;
    assert_eq!(dropped, 4_979_520);
    assert_eq!(
        r.get(FOLD),
        dropped,
        "every dropped increment is counted once in the fold bucket"
    );
    assert_eq!(
        total(&r),
        u128::from((LABELS * ROUNDS) as u64),
        "no increment is lost: the fold relocates counts, it does not drop them"
    );

    // Which names won: the first MAX_SERIES distinct names, in arrival order.
    assert_eq!(r.get("flood.tenant.acme.label.0000000.value"), 5);
    assert_eq!(r.get("flood.tenant.acme.label.0004095.value"), 5);
    // ...and the very next one is erased, not aggregated under its own name.
    assert_eq!(r.get("flood.tenant.acme.label.0004096.value"), 0);
    assert!(!has_series(&r, "flood.tenant.acme.label.0004096.value"));
    assert!(!has_series(&r, "flood.tenant.acme.label.0999999.value"));

    // Memory: bounded, and bounded *hard*. 4097 x (36-byte name + node slot).
    assert!(
        retained < MIB,
        "flooded registry retained {retained} B — the fold is supposed to \
         bound this to a few hundred KB"
    );

    // The counterfactual, measured rather than asserted from theory: the same
    // 1M names with no fold at all.
    let before_unfolded = live_bytes();
    let mut unfolded: BTreeMap<String, u64> = BTreeMap::new();
    let mut buf = String::with_capacity(64);
    for i in 0..LABELS {
        buf.clear();
        let _ = write!(buf, "flood.tenant.acme.label.{i:07}.value");
        *unfolded.entry(buf.clone()).or_default() += ROUNDS as u64;
    }
    let unfolded_retained = live_bytes().saturating_sub(before_unfolded);
    assert_eq!(unfolded.len(), LABELS);
    assert!(
        unfolded_retained > 50 * retained,
        "the fold must save at least an order of magnitude: folded {retained} B \
         vs unfolded {unfolded_retained} B"
    );
    drop(unfolded);

    eprintln!(
        "[flood] {}M increments / {}k labels in {elapsed:?}: series={} overflow={} \
         retained={retained} B (unfolded equivalent {unfolded_retained} B, {:.0}x)",
        (LABELS * ROUNDS) / 1_000_000,
        LABELS / 1_000,
        r.series(),
        r.get(FOLD),
        unfolded_retained as f64 / retained as f64,
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 2. The MAX_SERIES boundary, to the single series
// ─────────────────────────────────────────────────────────────────────────

/// Fill to exactly 4095, 4096, 4097 and 4098 distinct names and assert where
/// the fold engages.
///
/// The documented point: `MAX_SERIES` distinct names are admitted; the
/// **4097th** distinct name is the first to fold. The registry's true key
/// ceiling is therefore `MAX_SERIES + 1 = 4097`, because the fold bucket is
/// itself a key — a subtlety the `MAX_SERIES` doc comment ("maximum distinct
/// series kept") does not state, and which
/// [`attacker_seeded_overflow_corrupts_the_overflow_accounting`] shows is not
/// even stable.
#[test]
fn fold_engages_exactly_at_the_four_thousand_and_ninety_seventh_series() {
    let _guard = serialized();

    let mut r = CounterRegistry::default();

    // ── 4095: one short of the cap. Nothing folded, no fold key exists.
    fill_distinct(&mut r, "k.", MAX - 1);
    assert_eq!(r.series(), 4095);
    assert_eq!(r.series(), MAX - 1);
    assert!(!has_series(&r, FOLD), "no fold bucket before the cap");
    assert_eq!(r.get(FOLD), 0);

    // ── 4096: the cap itself. The 4096th distinct name is ADMITTED — the
    //    guard is `len() >= MAX_SERIES` evaluated *before* the insert, and at
    //    that moment len() is 4095.
    r.inc("k.the-4096th", 1);
    assert_eq!(r.series(), 4096);
    assert_eq!(r.series(), MAX);
    assert_eq!(r.get("k.the-4096th"), 1, "the 4096th name is a real series");
    assert!(!has_series(&r, FOLD), "still nothing folded at exactly MAX");
    assert_eq!(total(&r), u128::from(MAX as u64));

    // ── 4097: the first fold. The name is dropped; the bucket appears as the
    //    4097th KEY, which is why the ceiling is MAX_SERIES + 1.
    r.inc("k.the-4097th", 1);
    assert_eq!(r.series(), 4097);
    assert_eq!(r.series(), MAX + 1);
    assert!(has_series(&r, FOLD), "the fold engaged at the 4097th name");
    assert_eq!(r.get(FOLD), 1);
    assert_eq!(
        r.get("k.the-4097th"),
        0,
        "the 4097th distinct name is erased, not stored"
    );
    assert!(!has_series(&r, "k.the-4097th"));

    // ── 4098 and beyond: the key count never moves again.
    r.inc("k.the-4098th", 7);
    assert_eq!(r.series(), MAX + 1, "the ceiling is absolute");
    assert_eq!(r.get(FOLD), 8);

    // 50 000 more distinct names: still 4097 keys, and every increment is
    // still accounted for in the bucket.
    fill_distinct(&mut r, "later.", 50_000);
    assert_eq!(r.series(), MAX + 1);
    assert_eq!(r.get(FOLD), 8 + 50_000);
    assert_eq!(
        total(&r),
        u128::from(MAX as u64) + 1 + 7 + 50_000,
        "conservation still holds after 50k folded names"
    );

    // A sharp corner an alerting rule will get wrong: on a registry at exactly
    // MAX_SERIES, a *zero* increment on an unknown name still takes the fold
    // path, so the bucket is CREATED holding 0. `series()` jumps to 4097 while
    // `get("overflow")` reads 0 — the registry is saturated and losing series,
    // and the canonical `overflow > 0` alert says everything is fine.
    let mut r = CounterRegistry::default();
    fill_distinct(&mut r, "z.", MAX);
    assert_eq!(r.series(), MAX);
    assert!(!has_series(&r, FOLD));
    r.inc("dropped-silently", 0);
    assert_eq!(r.series(), MAX + 1, "the fold key exists...");
    assert!(has_series(&r, FOLD));
    assert_eq!(r.get(FOLD), 0, "...while reading zero");
    assert!(
        !has_series(&r, "dropped-silently"),
        "and the series is gone"
    );
}

/// A full registry must not stop counting what it already knows — otherwise a
/// label flood would take the *real* telemetry down with it.
///
/// This one holds: the guard short-circuits on `contains_key`, so known
/// series keep incrementing at full rate, and `series()` never moves. The
/// fold bucket itself is a known series once created, so it too can be
/// incremented directly — see
/// [`attacker_seeded_overflow_corrupts_the_overflow_accounting`] for why that
/// is not the harmless property it looks like.
#[test]
fn a_full_registry_keeps_counting_the_series_it_already_knows() {
    let _guard = serialized();

    let mut r = CounterRegistry::default();
    fill_distinct(&mut r, "known.", MAX);
    r.inc("push-it-over", 1); // creates the fold bucket
    assert_eq!(r.series(), MAX + 1);

    let known_first = "known.0000000";
    let known_last = "known.0004095";
    assert_eq!(r.get(known_first), 1);

    // 100 000 increments on a known series, interleaved with 100 000 brand
    // new names that all fold. The known series must absorb every one.
    let mut buf = String::with_capacity(32);
    for i in 0..100_000usize {
        r.inc(known_first, 1);
        r.inc(known_last, 2);
        buf.clear();
        let _ = write!(buf, "junk.{i:07}");
        r.inc(&buf, 1);
    }

    assert_eq!(
        r.get(known_first),
        100_001,
        "a full registry must keep counting a series it already knows"
    );
    assert_eq!(r.get(known_last), 200_001);
    assert_eq!(r.get(FOLD), 1 + 100_000);
    assert_eq!(r.series(), MAX + 1, "counting known series adds no keys");

    // Zero-valued increments on a known series are also fine, and — unlike on
    // an unknown name — create nothing.
    r.inc(known_first, 0);
    assert_eq!(r.get(known_first), 100_001);
    assert_eq!(r.series(), MAX + 1);
}

// ─────────────────────────────────────────────────────────────────────────
// 3. Saturation
// ─────────────────────────────────────────────────────────────────────────

/// `u64::MAX` then `+1` pins, for a normal series and for the fold bucket.
///
/// That is the documented behaviour and it holds exactly. The **defect** the
/// test also pins: saturation is silent. There is no error, no saturation
/// flag, no way to tell "pinned, counts are being destroyed" from "the true
/// value happens to be u64::MAX", and the registry's conservation property
/// (total exported == total incremented) fails from that moment on. For the
/// fold bucket specifically this is fatal — see
/// [`attacker_seeded_overflow_corrupts_the_overflow_accounting`].
#[test]
fn counters_pin_at_u64_max_for_a_normal_series_and_for_overflow() {
    let _guard = serialized();

    // ── A normal series.
    let mut r = CounterRegistry::default();
    r.inc("hot", u64::MAX);
    assert_eq!(r.get("hot"), u64::MAX);
    r.inc("hot", 1);
    assert_eq!(r.get("hot"), u64::MAX, "pinned, never wrapped");
    r.inc("hot", u64::MAX);
    assert_eq!(r.get("hot"), u64::MAX, "still pinned");
    // The count of increments is now unrecoverable: 3 calls totalling
    // 2*u64::MAX + 1 read back as u64::MAX, and nothing says so.
    assert_eq!(total(&r), u128::from(u64::MAX));
    assert!(
        total(&r) < u128::from(u64::MAX) * 2 + 1,
        "conservation BREAKS silently once a counter saturates"
    );

    // ── The fold bucket, reached only through the fold path.
    let mut r = CounterRegistry::default();
    fill_distinct(&mut r, "s.", MAX);
    assert_eq!(r.series(), MAX);
    assert!(!has_series(&r, FOLD));

    r.inc("brand.new.a", u64::MAX); // folds; creates the bucket at u64::MAX
    assert_eq!(r.series(), MAX + 1);
    assert_eq!(r.get(FOLD), u64::MAX);
    r.inc("brand.new.b", 1); // folds; saturates
    assert_eq!(r.get(FOLD), u64::MAX, "the fold bucket pins too");

    // And now the operator is blind: 100 000 further distinct labels are
    // dropped and the drop counter does not move by a single unit.
    let before_flood = r.get(FOLD);
    fill_distinct(&mut r, "invisible.", 100_000);
    assert_eq!(
        r.get(FOLD),
        before_flood,
        "100k dropped labels leave NO trace once the fold bucket saturates"
    );
    assert_eq!(r.series(), MAX + 1);
}

// ─────────────────────────────────────────────────────────────────────────
// 4. export(): order, length, byte identity
// ─────────────────────────────────────────────────────────────────────────

/// `export()` is strictly sorted, its length is `series()`, and both hold
/// with the nastiest names the type system allows in play.
#[test]
fn export_is_sorted_and_its_length_is_series() {
    let _guard = serialized();

    let mut r = CounterRegistry::default();
    let nasty = [
        "",
        "\u{0}",
        "a\u{0}b",
        "\u{7f}",
        "zzz",
        "ZZZ",
        FOLD,
        "\u{5d0}\u{5d1}\u{5d2}", // Hebrew, RTL
        "\u{e9}",                // é, NFC
        "e\u{301}",              // é, NFD — a *different* series
        "\u{1f600}",             // astral plane
        "\u{200b}zero-width",    // invisible prefix
        "gateway.requests",
        "gateway.requests\n",
        " gateway.requests",
    ];
    for (i, name) in nasty.iter().enumerate() {
        r.inc(name, i as u64 + 1);
    }
    // Plus enough ordinary names to cross the cap while the nasty ones hold
    // their slots.
    fill_distinct(&mut r, "pad.", MAX);

    let rows = r.export();
    assert_eq!(rows.len(), r.series(), "export length == series");
    assert!(
        is_strictly_sorted(&rows),
        "export must be strictly sorted by name"
    );
    assert_eq!(
        rows[0].0, "",
        "the empty name sorts first — and is a series"
    );

    // NOTE, and this is not a contrivance: `nasty` contains the literal name
    // `"overflow"`, so this registry caps at MAX_SERIES, not MAX_SERIES + 1.
    // Merely *listing* the fold's key among a set of adversarial names —
    // exactly what an unlucky product metric would do — moves the observable
    // ceiling. See `attacker_seeded_overflow_corrupts_the_overflow_accounting`.
    assert!(nasty.contains(&FOLD));
    assert_eq!(
        r.series(),
        MAX,
        "the fold key was already present, so it never becomes a 4097th key"
    );

    // Sorted means byte-lexicographic (BTreeMap<String>), which is codepoint
    // order for UTF-8 — so uppercase precedes lowercase and astral names sort
    // last. Pin it: an exporter that assumed case-insensitive or
    // locale-collated order would be wrong.
    let names: Vec<&str> = rows.iter().map(|(n, _)| *n).collect();
    let zzz = names.iter().position(|n| *n == "zzz").expect("zzz present");
    let caps = names.iter().position(|n| *n == "ZZZ").expect("ZZZ present");
    assert!(caps < zzz, "byte order: 'ZZZ' < 'zzz'");
}

/// Byte-identical across repeated calls, and across two registries fed the
/// same sequence in the same order — including once the fold has engaged.
#[test]
fn export_is_byte_identical_across_calls_and_across_registries() {
    let _guard = serialized();

    // A deterministic hostile stream: fixed-seed LCG, no wall clock.
    let mut seed = 0x5EED_0B5E_1234_ABCDu64;
    let mut names = Vec::with_capacity(20_000);
    for _ in 0..20_000 {
        let a = lcg(&mut seed);
        let b = lcg(&mut seed) % 97;
        names.push((format!("stream.{:016x}.{}", a % 8_000, a % 13), b + 1));
    }

    let mut a = CounterRegistry::default();
    let mut b = CounterRegistry::default();
    for (name, by) in &names {
        a.inc(name, *by);
    }
    for (name, by) in &names {
        b.inc(name, *by);
    }

    assert_eq!(a.series(), b.series());
    assert_eq!(a.export(), b.export(), "same sequence => same snapshot");
    assert_eq!(
        snapshot_bytes(&a),
        snapshot_bytes(&b),
        "byte-identical, not merely equal-looking"
    );

    // Repeated calls on one registry: stable, and stable again after a read
    // through a different accessor.
    let first = snapshot_bytes(&a);
    for _ in 0..8 {
        assert_eq!(snapshot_bytes(&a), first, "export is a pure function");
        assert_eq!(a.export().len(), a.series());
        let _ = a.get(FOLD);
    }

    // Push both past the cap with the same extra sequence and re-check.
    for i in 0..30_000usize {
        let n = format!("post.{i:07}");
        a.inc(&n, 1);
        b.inc(&n, 1);
    }
    assert_eq!(a.series(), b.series());
    assert_eq!(snapshot_bytes(&a), snapshot_bytes(&b));
    assert!(a.series() <= MAX + 1);

    // A golden digest, so "deterministic" is pinned to a value rather than to
    // a comparison between two things that could drift together. Stable in
    // debug and release, on any architecture: the input stream is a fixed-seed
    // LCG and the container is a `BTreeMap`, so there is no iteration entropy
    // anywhere in the pipeline.
    assert_eq!(a.series(), MAX + 1);
    assert_eq!(
        fnv1a(&snapshot_bytes(&a)),
        0x0c14_76e0_d7ef_5c2b,
        "the exported snapshot for this fixed history changed"
    );
}

/// **DEFECT.** The doc claims `export()` is "identical for identical
/// histories". It is only identical for identical *orderings*: the same
/// multiset of increments delivered in a different order produces a different
/// snapshot, because arrival order alone decides which 4096 names win slots.
///
/// Consequence in production: two replicas of the same service behind a load
/// balancer see the same requests in different orders and export different
/// series. The grand total agrees — the fold is conservative — but the
/// per-series breakdown, which is the only part an operator or an audit diff
/// actually reads, does not.
#[test]
fn identical_multisets_in_different_orders_produce_different_metrics() {
    let _guard = serialized();

    const N: usize = 12_000;
    let names: Vec<String> = (0..N).map(|i| format!("order.{i:07}")).collect();

    let mut forward = CounterRegistry::default();
    for n in &names {
        forward.inc(n, 3);
    }

    let mut backward = CounterRegistry::default();
    for n in names.iter().rev() {
        backward.inc(n, 3);
    }

    // Identical multiset, identical increment values, identical total.
    assert_eq!(forward.series(), backward.series());
    assert_eq!(forward.series(), MAX + 1);
    assert_eq!(
        total(&forward),
        total(&backward),
        "the fold IS conservative: the grand total is order-independent"
    );
    assert_eq!(total(&forward), (N as u128) * 3);

    // ...and yet the snapshots differ, catastrophically.
    assert_ne!(
        snapshot_bytes(&forward),
        snapshot_bytes(&backward),
        "identical histories in different orders MUST have matched, per the \
         export() doc comment — they do not"
    );

    let fwd: Vec<&str> = forward.export().iter().map(|(n, _)| *n).collect();
    let bwd: Vec<&str> = backward.export().iter().map(|(n, _)| *n).collect();
    let shared = fwd.iter().filter(|n| bwd.contains(n)).count();
    // Forward keeps order.0000000..0004095, backward keeps the top 4096
    // names; the only key both hold is the fold bucket itself.
    assert_eq!(
        shared, 1,
        "the two replicas agree on exactly one series name: {FOLD:?}"
    );
    assert!(fwd.contains(&FOLD) && bwd.contains(&FOLD));
    eprintln!(
        "[divergence] same multiset, reversed order: {}/{} series names differ",
        fwd.len() - shared,
        fwd.len()
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 5. Adversarial label names
// ─────────────────────────────────────────────────────────────────────────

/// `inc(name, 0)` CREATES a series, and `get` cannot tell "absent" from
/// "present with value 0". Two consequences, both pinned here: slot squatting
/// is free (see
/// [`a_flooded_registry_permanently_blocks_every_later_legitimate_series`]),
/// and the empty string is a perfectly ordinary, first-sorting metric name.
#[test]
fn zero_valued_and_empty_labels_are_first_class_series() {
    let _guard = serialized();

    let mut r = CounterRegistry::default();
    assert_eq!(r.series(), 0);
    assert_eq!(r.get("ghost"), 0, "absent reads as 0");

    r.inc("ghost", 0);
    assert_eq!(r.series(), 1, "a ZERO increment consumes a series slot");
    assert_eq!(r.get("ghost"), 0, "and reads back identically to absent");
    assert!(
        has_series(&r, "ghost"),
        "only export() can distinguish absent from zero"
    );

    r.inc("", 0);
    assert_eq!(r.series(), 2, "the empty string is a valid metric name");
    assert!(has_series(&r, ""));
    r.inc("", 41);
    assert_eq!(r.get(""), 41);

    // 4096 slots consumed with zero counted events — free from the attacker's
    // side, permanent from the operator's.
    let mut r = CounterRegistry::default();
    let mut buf = String::with_capacity(24);
    for i in 0..MAX {
        buf.clear();
        let _ = write!(buf, "squat.{i:07}");
        r.inc(&buf, 0);
    }
    assert_eq!(r.series(), MAX);
    assert_eq!(total(&r), 0, "4096 series holding zero events between them");
}

/// **DEFECT.** "A label explosion can never exhaust memory" is false: the cap
/// is on *cardinality*, not on bytes. `inc` stores `name.into()` verbatim with
/// no length limit and no truncation, so the retained heap is
/// `MAX_SERIES x (longest name an attacker can pass)`.
///
/// Measured here at 4 KiB per name (17.6 MB behind a registry reporting 4097
/// series) and verified byte-for-byte at 1 MiB for a single name. The
/// extrapolation the measurement licenses: **4096 x 1 MiB = 4 GiB of
/// permanently retained heap**, in a component whose stated purpose is to make
/// that impossible. Nothing in the API can release it — there is no removal,
/// eviction or reset.
///
/// The test deliberately stops at 4 KiB: proving the vector does not require
/// OOM-ing CI, and the arithmetic is linear and verified at both ends.
#[test]
fn label_length_is_unbounded_so_the_cardinality_cap_is_not_a_memory_cap() {
    let _guard = serialized();

    // ── A single 1 MiB name: accepted, stored, counted, exported verbatim.
    let huge = "M".repeat(MIB);
    let before_one = live_bytes();
    let mut r = CounterRegistry::default();
    r.inc(&huge, 7);
    let one_retained = live_bytes().saturating_sub(before_one);
    assert_eq!(r.series(), 1);
    assert_eq!(r.get(&huge), 7, "a 1 MiB metric name is a valid series");
    let rows = r.export();
    assert_eq!(rows[0].0.len(), MIB, "stored verbatim — no truncation");
    assert_eq!(rows[0].0, huge);
    assert!(
        one_retained >= MIB,
        "one 1 MiB label retained {one_retained} B"
    );
    drop(r);

    // ── The cap does not bound this. 4096 names of 4 KiB, all admitted.
    const NAME_BYTES: usize = 4096;
    let before = live_bytes();
    let mut r = CounterRegistry::default();
    let mut buf = String::with_capacity(NAME_BYTES + 16);
    for i in 0..MAX {
        buf.clear();
        let _ = write!(buf, "{i:07}.");
        while buf.len() < NAME_BYTES {
            buf.push('P');
        }
        r.inc(&buf, 1);
    }
    let retained = live_bytes().saturating_sub(before);

    assert_eq!(r.series(), MAX, "the registry reports a modest 4096 series");
    assert!(
        retained >= MAX * NAME_BYTES,
        "4096 x 4 KiB names retained {retained} B — the fold does not bound bytes"
    );
    // One more distinct name folds, so the *reported* cardinality is capped
    // while the *bytes* already stored stay put forever.
    r.inc(&"Q".repeat(NAME_BYTES), 1);
    assert_eq!(r.series(), MAX + 1);
    assert!(
        live_bytes().saturating_sub(before) >= MAX * NAME_BYTES,
        "nothing is ever released: there is no removal or eviction API"
    );

    let projected_1mib = MAX as u64 * MIB as u64;
    assert!(
        projected_1mib > 4_000_000_000,
        "projection: {MAX} series x 1 MiB names = {projected_1mib} B retained \
         behind a registry that still reports {} series",
        MAX + 1
    );
    eprintln!(
        "[bytes] {MAX} x {NAME_BYTES} B names => {retained} B retained at \
         series()={}; same registry at 1 MiB names => {projected_1mib} B (~4 GiB)",
        r.series()
    );
}

/// No metric-name validation of any kind. Every byte sequence that is valid
/// UTF-8 is a valid series name, and `export()` hands it back unchanged.
///
/// **DEFECT (latent).** The module docs promise "exporters (Prometheus/OTel)
/// are wired at the gateway in later milestones". Prometheus text exposition
/// is newline- and space-delimited, so a name carrying `\n` or a space is a
/// forged series the moment that exporter exists. The registry is the natural
/// place to reject non-canonical names — the sibling
/// `ccos_enterprise_gateway::classify` already rejects tool names with
/// whitespace or control bytes for exactly this reason — and it does not.
#[test]
fn adversarial_label_names_are_stored_and_exported_verbatim() {
    let _guard = serialized();

    let injections = [
        "x 1\nccos_licence_valid 1",
        "up{job=\"prod\"}",
        "a\tb",
        "a\rb",
        "series\\name",
        "n\u{0}ul",
        "\u{feff}bom",
        "\u{202e}rtl-override",
        "\u{7}bell",
    ];

    let mut r = CounterRegistry::default();
    for (i, name) in injections.iter().enumerate() {
        r.inc(name, i as u64 + 1);
    }
    assert_eq!(
        r.series(),
        injections.len(),
        "every hostile name was accepted as a distinct series"
    );

    let rows = r.export();
    for (i, name) in injections.iter().enumerate() {
        assert_eq!(r.get(name), i as u64 + 1);
        assert!(
            rows.iter().any(|(n, v)| n == name && *v == i as u64 + 1),
            "exported verbatim: {name:?}"
        );
    }
    // The injection payload survives byte-for-byte, newline included.
    let injected = rows
        .iter()
        .find(|(n, _)| n.contains('\n'))
        .expect("newline-bearing name survived export");
    assert!(injected.0.contains("\nccos_licence_valid 1"));
    assert!(is_strictly_sorted(&rows));

    // Unicode near-duplicates are distinct series, so a single visual label
    // multiplies cardinality: 6 renderings of "e" that a human reads as one.
    let mut r = CounterRegistry::default();
    for name in [
        "e",        // LATIN SMALL LETTER E
        "\u{e9}",   // é NFC
        "e\u{301}", // é NFD
        "\u{435}",  // Cyrillic е (homoglyph)
        "\u{ff45}", // fullwidth ｅ
        "\u{212f}", // script small e
    ] {
        r.inc(name, 1);
    }
    assert_eq!(
        r.series(),
        6,
        "no normalization and no homoglyph folding: one visual label, six slots"
    );
}

/// **THE ANSWER TO THE QUESTION.** Yes — an attacker who names a metric
/// `overflow` before the registry fills corrupts the overflow accounting, and
/// the worst case is total blindness.
///
/// `inc` has no notion of a reserved key
/// (`crates/ccos-enterprise-observability/src/lib.rs:25`): the fold does
/// `entry("overflow").or_default()`, which happily lands on a series an
/// attacker created earlier. Three distinct consequences, all pinned below:
///
/// * **(a) the advertised cap changes.** With `overflow` pre-seeded the
///   registry tops out at 4096 keys, not 4097, and admits only 4095
///   attacker-visible series. Same code, same input, different cap.
/// * **(b) the drop counter is no longer a drop counter.** It reads
///   `seed + drops`, and nothing records the seed, so the number an operator
///   pages on is attacker-offset by an unknown amount.
/// * **(c) with `u64::MAX` as the seed the drop counter is DEAD.** Every
///   subsequent dropped series saturates against it. 100 000 dropped labels
///   later the value is bit-identical to what it was before the flood: the
///   only signal that a label explosion is happening has been switched off
///   pre-emptively, with one increment, by anything that can name a metric.
#[test]
fn attacker_seeded_overflow_corrupts_the_overflow_accounting() {
    let _guard = serialized();

    // ── (a) + (b): seed the bucket, then fill.
    let mut r = CounterRegistry::default();
    r.inc(FOLD, 1_000_000); // the attacker speaks first
    assert_eq!(r.series(), 1);

    fill_distinct(&mut r, "real.", MAX - 1); // 4095 genuine series
    assert_eq!(r.series(), MAX, "the seed burned one of the 4096 slots");

    // The next genuine series is refused, one series EARLIER than the
    // unseeded registry would have refused it.
    r.inc("real.would-have-fit", 1);
    assert_eq!(
        r.series(),
        MAX,
        "with 'overflow' pre-seeded the cap is MAX_SERIES, not MAX_SERIES + 1 \
         — the observable ceiling is attacker-controlled"
    );
    assert!(
        !has_series(&r, "real.would-have-fit"),
        "and one fewer genuine series is admitted than the doc implies"
    );

    // The drop counter is now seed + drops, with no way to recover either.
    fill_distinct(&mut r, "dropped.", 5_000);
    assert_eq!(
        r.get(FOLD),
        1_000_000 + 1 + 5_000,
        "attacker-injected counts are indistinguishable from real drops"
    );

    // A clean registry given the identical genuine history reports a
    // different cap and a different drop count. Side by side:
    let mut clean = CounterRegistry::default();
    fill_distinct(&mut clean, "real.", MAX - 1);
    clean.inc("real.would-have-fit", 1);
    fill_distinct(&mut clean, "dropped.", 5_000);
    assert_eq!(clean.series(), MAX + 1);
    assert_eq!(clean.get(FOLD), 5_000);
    assert!(
        has_series(&clean, "real.would-have-fit"),
        "unseeded, the same genuine series IS admitted"
    );
    assert_ne!(
        r.series(),
        clean.series(),
        "one attacker increment changes the registry's advertised cardinality"
    );

    // ── (c) the kill shot: seed the bucket at u64::MAX.
    let mut r = CounterRegistry::default();
    r.inc(FOLD, u64::MAX);
    fill_distinct(&mut r, "real.", MAX - 1);
    assert_eq!(r.series(), MAX);

    let before_flood = r.get(FOLD);
    assert_eq!(before_flood, u64::MAX);
    fill_distinct(&mut r, "explosion.", 100_000);
    assert_eq!(
        r.get(FOLD),
        before_flood,
        "100 000 dropped labels move the drop counter by ZERO: the fold's own \
         alarm was disarmed before the flood started"
    );
    assert_eq!(r.series(), MAX, "and the key count never twitches either");

    // Nor does any other observable move: the snapshot before and after a
    // 100k-label explosion is byte-identical.
    let after = snapshot_bytes(&r);
    fill_distinct(&mut r, "explosion2.", 100_000);
    assert_eq!(
        snapshot_bytes(&r),
        after,
        "a 100k-label explosion is completely invisible in export()"
    );
}

/// **DEFECT.** First writer wins, permanently. A registry filled with junk
/// refuses every later series — including the ones the product itself
/// registers — and there is no eviction, no TTL, no priority list and no
/// removal API to recover.
///
/// This is the exhaustion vector that actually matters. The fold protects the
/// heap, at the price of the operator's telemetry: an attacker who can reach
/// any code path that names a metric (with `by = 0`, so at zero cost to
/// themselves) permanently deletes `gateway.requests`, `gateway.forwarded`
/// and every refusal counter from the process, and the only symptom is a
/// counter named `overflow` climbing — the counter
/// [`attacker_seeded_overflow_corrupts_the_overflow_accounting`] shows can be
/// disarmed in advance.
#[test]
fn a_flooded_registry_permanently_blocks_every_later_legitimate_series() {
    let _guard = serialized();

    // The metric names the composed path actually uses.
    let legitimate = [
        "gateway.requests",
        "gateway.forwarded",
        "gateway.refused",
        "gateway.refused.permission_denied",
        "gateway.refused.budget_exhausted",
    ];

    let mut r = CounterRegistry::default();
    fill_distinct(&mut r, "attacker.", MAX); // free: MAX_SERIES slots
    assert_eq!(r.series(), MAX);

    for name in legitimate {
        for _ in 0..100 {
            r.inc(name, 1);
        }
    }
    for name in legitimate {
        assert_eq!(
            r.get(name),
            0,
            "the product's own metric {name:?} can never be registered again"
        );
        assert!(!has_series(&r, name));
    }
    assert_eq!(r.get(FOLD), (legitimate.len() * 100) as u64);

    // A million more legitimate increments do not earn a slot back.
    for _ in 0..1_000_000u32 {
        r.inc("gateway.requests", 1);
    }
    assert_eq!(
        r.get("gateway.requests"),
        0,
        "1M increments, still no slot: there is no eviction and no priority"
    );
    assert_eq!(r.series(), MAX + 1);

    // And the attacker's junk is immortal — every one of the 4096 squatted
    // names is still there, still readable, with no API to remove it.
    assert_eq!(r.get("attacker.0000000"), 1);
    assert_eq!(r.get("attacker.0004095"), 1);
    assert_eq!(
        r.export()
            .iter()
            .filter(|(n, _)| n.starts_with("attacker."))
            .count(),
        MAX,
        "4096 attacker-owned series retained for the process lifetime"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 6. The composed path — what held
// ─────────────────────────────────────────────────────────────────────────

/// The product path is immune to all of the above, and this test is the proof
/// that keeps it that way.
///
/// `Deployment::admit` never lets caller-controlled text into a metric name:
/// refusals go through `tag()`, which returns a `&'static str` from a closed
/// set of eight. 3 000 hostile calls — 1 MiB tool names, unicode tenants,
/// attacker-chosen actors and request ids, every refusal class — produce
/// exactly 11 series, never `overflow`, and `requests == forwarded + refused`
/// holds throughout.
///
/// It is the *only* thing standing between the registry and the flood proven
/// above, and nothing enforces it but this assertion: `admit` builds its
/// refusal label with `format!`, so one future `format!("...{}", req.tool)`
/// hands the whole vector to the attacker.
#[test]
fn deployment_metrics_stay_low_cardinality_under_hostile_input() {
    let _guard = serialized();

    const CALLS: usize = 3_000;
    const HUGE_CALLS_EACH: usize = 5;

    let mut d = two_tenant_deployment();
    let mut seed = 0xC0FF_EE00_1234_5678u64;

    for i in 0..CALLS {
        // High bits only: an LCG's low bits have period 8 under `% 8`, which
        // silently starved three of the eight arms on the first run of this
        // test. Mixing errors in a fuzz harness are indistinguishable from
        // coverage, so the arm coverage is asserted at the end.
        let pick = (lcg(&mut seed) >> 40) % 8;
        let (tenant, who, tool, strength, model, variant) = match pick {
            0 => (
                "acme",
                "alice",
                "memory.recall",
                AuthStrength::Anonymous,
                "claude-opus",
                None,
            ),
            1 => (
                "does-not-exist\u{1f4a3}",
                "alice",
                "memory.recall",
                AuthStrength::Token,
                "claude-opus",
                None,
            ),
            2 => (
                "acme",
                "alice",
                "shell.exec",
                AuthStrength::Strong,
                "claude-opus",
                None,
            ),
            // Reaches `tool_not_governed`, which now requires a CANONICAL
            // name: this case used to spell it "context.<emoji><RTL>not-
            // governed", but the gateway's canonical-name rule refuses that
            // shape outright, so the hostile spelling was being counted as a
            // boundary refusal and this tag stopped being exercised at all.
            // A tool has to clear the boundary before "nobody governed it"
            // can be the answer. Hostile text still reaches the metric path
            // through the actor, the tenant, the request id and the 1 MiB
            // names below — that is what this test is measuring.
            3 => (
                "acme",
                "alice",
                "context.not_governed",
                AuthStrength::Strong,
                "claude-opus",
                None,
            ),
            4 => (
                "acme",
                "bob",
                "memory.ingest",
                AuthStrength::Token,
                "claude-opus",
                None,
            ),
            5 => (
                "acme",
                "alice",
                "memory.recall",
                AuthStrength::Token,
                "gpt-5",
                None,
            ),
            6 => (
                "acme",
                "alice",
                "memory.recall",
                AuthStrength::Token,
                "claude-opus",
                Some(AdvancedQPageVariant::CausalChain),
            ),
            _ => (
                "acme",
                "alice",
                "memory.recall",
                AuthStrength::Token,
                "claude-opus",
                None,
            ),
        };
        let a = actor("org\u{202e}", who, strength);
        let req = request(tenant, who, tool, &format!("rid-{i:09}-\u{1f600}"));
        let _ = d.admit(Call {
            actor: &a,
            request: &req,
            model,
            cost_tokens: (lcg(&mut seed) >> 40) % 64,
            variant,
        });
    }

    // A separate, deliberately small batch of 1 MiB tool names. Kept small
    // because `Deployment` retains every one verbatim in the audit journal
    // (a sibling finding, not this file's), so 16 of them already cost 16 MB;
    // the point here is only that a megabyte of caller text cannot become a
    // metric label. Both a boundary-violating and a catalogue-missing giant
    // are exercised, since they take different `format!` paths in `classify`.
    let a = actor("org", "alice", AuthStrength::Strong);
    for (i, prefix) in ["memory.", "shell.", "wat."].iter().enumerate() {
        let huge_tool = format!("{prefix}{}", "T".repeat(MIB));
        for k in 0..HUGE_CALLS_EACH {
            let req = request("acme", "alice", &huge_tool, &format!("huge-{i}-{k}"));
            let _ = d.admit(Call {
                actor: &a,
                request: &req,
                model: "claude-opus",
                cost_tokens: 1,
                variant: None,
            });
        }
    }

    let m = d.metrics();
    let names: Vec<&str> = m.iter().map(|(n, _)| n.as_str()).collect();

    assert!(
        names.len() <= 11,
        "the composed path must stay at fixed cardinality; got {names:?}"
    );
    assert!(
        !names.contains(&"overflow"),
        "the composed path must never reach MAX_SERIES: {names:?}"
    );
    for n in &names {
        assert!(
            *n == "gateway.requests"
                || *n == "gateway.forwarded"
                || *n == "gateway.refused"
                || n.starts_with("gateway.refused."),
            "unexpected metric name {n:?} — caller text reached a metric label"
        );
        assert!(
            n.len() < 64,
            "metric name {n:?} carries caller-controlled length"
        );
    }
    assert!(m.windows(2).all(|w| w[0].0 < w[1].0), "metrics are sorted");

    let val = |k: &str| m.iter().find(|(n, _)| n == k).map(|(_, v)| *v).unwrap_or(0);
    let calls = (CALLS + 3 * HUGE_CALLS_EACH) as u64;
    assert_eq!(val("gateway.requests"), calls);
    assert_eq!(
        val("gateway.forwarded") + val("gateway.refused"),
        val("gateway.requests"),
        "every admitted call is counted exactly once"
    );
    let by_reason: u64 = m
        .iter()
        .filter(|(n, _)| n.starts_with("gateway.refused."))
        .map(|(_, v)| *v)
        .sum();
    assert_eq!(
        by_reason,
        val("gateway.refused"),
        "refusal reasons partition the refusals"
    );
    assert_eq!(d.audit().len(), calls as usize);

    // All eight refusal tags plus requests/forwarded/refused: the closed set
    // is fully exercised, so `names.len() == 11` is this design's *saturated*
    // cardinality and not an artefact of thin coverage.
    let tags: Vec<&str> = names
        .iter()
        .filter_map(|n| n.strip_prefix("gateway.refused."))
        .collect();
    assert_eq!(
        tags,
        [
            "budget_exhausted",
            "model_not_allowed",
            "outside_boundary",
            "permission_denied",
            "tool_not_governed",
            "unauthenticated",
            "unknown_tenant",
            "variant_not_activated",
        ],
        "every refusal tag must be exercised"
    );
    assert_eq!(
        names.len(),
        11,
        "the composed path's metric cardinality is exactly 11, saturated"
    );
    eprintln!(
        "[composed] {calls} hostile calls => {} series: {names:?}",
        names.len()
    );
}
