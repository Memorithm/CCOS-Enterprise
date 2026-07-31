//! # Hostile stress of the metrics registry: label flood, cap boundary, blinding
//!
//! `ccos_enterprise_observability::CounterRegistry` is the only bounded pool
//! in Enterprise. Its own doc comment states the contract this file attacks:
//!
//! > Maximum distinct series kept. Beyond it an increment on an unseen name
//! > is dropped and counted in `dropped`, **so a label explosion can never
//! > exhaust memory**.
//!
//! and
//!
//! > A deterministic snapshot for exporters (Prometheus/OTel at the gateway)
//! > and **for audit diffing**: name/value pairs in `BTreeMap` order,
//! > preceded by the three out-of-band gauges.
//!
//! Everything asserted below is the product's **current, real** behaviour:
//! where that behaviour is a defect the assertion pins the defect and the
//! comment names it, so a repair fails loudly here instead of silently
//! changing what an operator can see.
//!
//! Run the whole file:
//! `cargo test -p ccos-enterprise-conformance --test stress_observability_flood`
//! (add `-- --nocapture` for the measured tables).
//!
//! ## What held
//!
//! * **The cardinality cap is exact and unconditional.** 5 000 000 increments
//!   across 1 000 000 distinct labels leave `series() == 4096` — precisely
//!   `MAX_SERIES`, no fold key, no attacker-dependent ceiling — with
//!   `dropped() == 4 979 520`, i.e. every one of the 4 979 520 dropped
//!   increments accounted for to the unit. Measured retained heap: ~412 KB
//!   against ~100 MB for the same history in an unfolded `BTreeMap` — a 244x
//!   saving — and **exactly zero** net bytes are allocated across the last
//!   4 000 000 increments, so the bound does not merely hold at the end, it
//!   stops growing entirely. The grand total is conserved to the unit:
//!   `total(series) + dropped_events() == every increment ever passed`.
//!   → [`flood_five_million_increments_across_one_million_labels`]
//! * **The cap boundary is off-by-nothing.** The 4096th distinct name is
//!   admitted; the 4097th is the first dropped, and dropping it adds no key.
//!   A full registry keeps counting series it already knows — 100 000
//!   increments on a known name all land, and `series()` never moves.
//!   → [`the_cap_is_exact_and_a_zero_valued_drop_is_still_visible`]
//! * **Saturation is total and deterministic**: `u64::MAX` then `+1` stays
//!   `u64::MAX` in debug and release. No wrap, no panic.
//! * **`export()` is strictly sorted, `len() == series() + GAUGES`, and
//!   byte-identical** across repeated calls and across two registries fed the
//!   same sequence in the same order — including after the cap is reached.
//! * **The composed path is immune to label explosion.**
//!   `Deployment::admit` folds every refusal through a `&'static str` tag, so
//!   3 015 hostile calls carrying 1 MiB tool names, unicode tenants and
//!   attacker-chosen actors produce exactly 17 rows — 14 series plus the three
//!   gauges — and never move `_dropped` or `_refused` off zero.
//!   → [`deployment_metrics_stay_low_cardinality_under_hostile_input`]
//!
//! ## What was BROKEN and is now REPAIRED
//!
//! Each of these was pinned here as a defect. The scenario is unchanged; the
//! assertion is inverted, and the test now guards the repair.
//!
//! 1. **The drop counter could be seeded, and at `u64::MAX` it was DEAD.**
//!    The fold used to do `entry("overflow").or_default()`, landing on a
//!    series an attacker could create first. It now lives out of band as a
//!    struct field exported under `_dropped`, a name `is_valid_name` refuses,
//!    so no caller can mint it, seed it or collide with it. Two counters, not
//!    one: `_dropped` moves by **one per dropped call** whatever `by` was, so
//!    it takes 2^64 calls to pin; `_dropped_events` carries the values and can
//!    still saturate. The alarm survives the saturation of the accounting.
//!    → [`the_drop_counters_cannot_be_seeded_or_disarmed`]
//! 2. **The advertised cap moved depending on whether an attacker spoke
//!    first** (4096 vs 4097 keys). There is no fold key any more: `series()`
//!    is `MAX_SERIES` exactly, always.
//! 3. **"A label explosion can never exhaust memory" was false** — the cap was
//!    on cardinality, not bytes, so 4096 x 1 MiB names retained 4 GiB.
//!    `MAX_NAME_BYTES = 128` makes the product `MAX_SERIES x MAX_NAME_BYTES`
//!    an arithmetic fact: **524 288 B of names**, measured here at 784 256 B
//!    retained including node overhead, with a 1 MiB name refused outright.
//!    → [`the_cardinality_cap_is_now_a_memory_cap`]
//! 4. **No metric-name validation whatsoever.** `inc("x 1\nccos_licence_valid
//!    1", 1)` round-tripped verbatim — a forged series in Prometheus text
//!    exposition the day the documented exporter is wired. Names are now
//!    dot-separated `[a-z0-9_]` with a leading letter; every injection is
//!    refused and counted in `_refused`. The same rule collapses the homoglyph
//!    vector: six renderings of "e" that a human reads as one used to buy six
//!    slots, and now buy one.
//!    → [`adversarial_label_names_are_refused_and_counted`]
//! 5. **`overflow == 0` did not mean "nothing was dropped".** A zero increment
//!    on an unknown name took the fold path and *created* the bucket holding
//!    0, so the obvious alerting rule reported health while the registry was
//!    shedding series. `_dropped` counts calls, so a zero-valued drop moves it
//!    by one; and it is always exported, so `_dropped == 0` is a statement
//!    rather than an absence.
//!    → [`the_cap_is_exact_and_a_zero_valued_drop_is_still_visible`]
//!
//! ## What is STILL BROKEN
//!
//! 6. **First writer wins, forever: a flooded registry permanently refuses
//!    every later legitimate series.** There is no eviction, no TTL, no
//!    priority and no removal API. 4096 junk labels — free, since
//!    `inc(name, 0)` creates a series — and `gateway.requests` can never be
//!    registered again for the process lifetime: 1 000 000 subsequent
//!    increments leave `get("gateway.requests") == 0`. The bound protects the
//!    heap by discarding the operator's real telemetry. What the repair bought
//!    is only that the alarm now fires and cannot be switched off; whether a
//!    metrics registry should be resettable is a design question this file
//!    does not get to answer.
//!    → [`a_flooded_registry_permanently_blocks_every_later_legitimate_series`]
//! 7. **"Identical for identical histories" is order-dependent, so replicas
//!    diverge.** Two registries fed the *same multiset* of increments in
//!    different orders agree on the grand total and on all three gauges, and
//!    disagree on **every one** of their 4096 series names — they now share
//!    not one, the old fold key having been the only thing they had in common.
//!    Which names win the 4096 slots is decided by arrival order alone, which
//!    is inherent to a first-N cap and cannot be fixed without unbounded
//!    memory. The `export()` doc no longer claims otherwise; it states the
//!    limitation instead.
//!    → [`identical_multisets_in_different_orders_produce_different_metrics`]
//! 8. **Saturation silently destroys counts.** Once a series pins at
//!    `u64::MAX` the conservation property fails with no error and no way to
//!    distinguish "pinned" from "exactly `u64::MAX`". Unchanged for series;
//!    for the drop accounting it is now survivable, see (1).
//!    → [`counters_pin_at_u64_max_but_the_drop_alarm_keeps_counting`]
//! 9. **Squatting is still free.** `inc(name, 0)` consumes a slot at zero
//!    counted cost to the attacker, and `get` still cannot tell "absent" from
//!    "present holding 0" — only `export()` can.
//!    → [`zero_valued_increments_are_first_class_but_the_empty_name_is_not`]

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
// A counting allocator is the only honest answer to "does the cap actually
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
const NAME_MAX: usize = CounterRegistry::MAX_NAME_BYTES;
const GAUGES: usize = CounterRegistry::GAUGES;
const MIB: usize = 1024 * 1024;

/// The three out-of-band gauge names, in the order `export()` emits them.
const GAUGE_NAMES: [&str; GAUGES] = ["_dropped", "_dropped_events", "_refused"];

/// The real series, with the gauges stripped.
///
/// `export()` always leads with the three gauges — they are not series, they
/// are never absent, and no caller can create them — so every claim about
/// *series* in this file goes through here. The gauges' presence and order are
/// checked once, in [`export_leads_with_the_gauges_and_is_strictly_sorted`].
fn series_rows(r: &CounterRegistry) -> Vec<(&str, u64)> {
    r.export().into_iter().skip(GAUGES).collect()
}

/// Presence, not value. `get` returns 0 for both "absent" and "present with
/// value 0", so every existence claim in this file goes through `export`.
fn has_series(r: &CounterRegistry, name: &str) -> bool {
    series_rows(r).iter().any(|(n, _)| *n == name)
}

/// Strictly increasing name order — proves sortedness *and* uniqueness in one
/// pass, which is what an exporter and an audit diff both rely on.
fn is_strictly_sorted(rows: &[(&str, u64)]) -> bool {
    rows.windows(2).all(|w| w[0].0 < w[1].0)
}

/// Grand total of every *series* counter, gauges excluded. Absent saturation
/// this plus `dropped_events()` must equal the sum of every `by` ever passed
/// to `inc`: what does not fit in a slot is counted, not discarded. `u128` so
/// the invariant itself cannot overflow.
fn total(r: &CounterRegistry) -> u128 {
    series_rows(r).iter().map(|(_, v)| u128::from(*v)).sum()
}

/// An unambiguous byte encoding of a snapshot, gauges included. 0xFE/0xFF
/// never occur in UTF-8, so no series name can forge a record separator —
/// comparing these byte strings is a strictly stronger claim than comparing
/// the tuples.
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
/// explosion the cap exists to survive — measured against the same history
/// replayed into an unbounded `BTreeMap`.
///
/// The cap holds exactly, and the drop accounting is exact to the unit:
/// 4096 names win slots (the first 4096 *distinct* names to arrive, i.e. the
/// first 4096 of round 0), each collecting one increment per round, and
/// everything else is dropped. Note what that costs the operator: the 4097th
/// name onward is not aggregated under a different key, it is **erased** —
/// `get` on it returns 0 forever, indistinguishable from a label that was
/// never seen. What the drop counters buy is that the *aggregate* is not lost
/// and cannot be hidden.
#[test]
fn flood_five_million_increments_across_one_million_labels() {
    let _guard = serialized();

    const LABELS: usize = 1_000_000;
    const ROUNDS: usize = 5;

    let before = live_bytes();
    let started = Instant::now();
    let mut r = CounterRegistry::default();
    let mut buf = String::with_capacity(64);
    // Heap high-water mark taken after a full round, long after the cap was
    // reached (it is reached at label 4096). If the bound holds, not one
    // further byte is retained across the remaining 4 000 000 increments.
    // Taken at a round boundary rather than early in round 0 so that libtest's
    // own thread-spawn bookkeeping cannot land inside the measured window:
    // every sibling test is parked on `TEST_LOCK` by then and none can
    // complete, so this process allocates nothing but what `inc` allocates.
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
                    r.series() <= MAX,
                    "series() exceeded the ceiling mid-flood at round {round}, label {i}"
                );
            }
        }
    }
    let retained = live_bytes().saturating_sub(before);
    let elapsed = started.elapsed();

    // The bound holds *exactly*: zero net bytes retained across the last
    // 4 000 000 increments and 1 000 000 distinct labels. A dropped increment
    // now allocates nothing at all — there is no bucket to create.
    assert_eq!(
        live_bytes(),
        settled,
        "the registry allocated after the cap was reached — the bound leaks"
    );

    // The cap is exact, not approximate, and there is no `+ 1` for a fold key
    // — which is what makes it independent of what an attacker named first.
    assert_eq!(
        r.series(),
        MAX,
        "5M increments over 1M labels must leave exactly MAX_SERIES series"
    );
    assert_eq!(
        r.export().len(),
        r.series() + GAUGES,
        "export is the series plus the three gauges, always"
    );

    // Exact drop accounting: 4096 admitted names x 5 rounds land, the rest are
    // dropped. No estimate, no tolerance.
    let admitted = MAX as u64 * ROUNDS as u64;
    let dropped = (LABELS * ROUNDS) as u64 - admitted;
    assert_eq!(dropped, 4_979_520);
    assert_eq!(
        r.dropped(),
        dropped,
        "every dropped call is counted once in _dropped"
    );
    assert_eq!(
        r.dropped_events(),
        dropped,
        "and every unit it carried in _dropped_events (by == 1 here)"
    );
    assert_eq!(r.refused(), 0, "every name in this flood is well-formed");
    assert_eq!(
        total(&r) + u128::from(r.dropped_events()),
        u128::from((LABELS * ROUNDS) as u64),
        "no increment is lost: what does not fit a slot is counted"
    );

    // Which names won: the first MAX_SERIES distinct names, in arrival order.
    assert_eq!(r.get("flood.tenant.acme.label.0000000.value"), 5);
    assert_eq!(r.get("flood.tenant.acme.label.0004095.value"), 5);
    // ...and the very next one is erased, not aggregated under its own name.
    assert_eq!(r.get("flood.tenant.acme.label.0004096.value"), 0);
    assert!(!has_series(&r, "flood.tenant.acme.label.0004096.value"));
    assert!(!has_series(&r, "flood.tenant.acme.label.0999999.value"));

    // Memory: bounded, and bounded *hard*. 4096 x (36-byte name + node slot).
    assert!(
        retained < MIB,
        "flooded registry retained {retained} B — the cap is supposed to \
         bound this to a few hundred KB"
    );

    // The counterfactual, measured rather than asserted from theory: the same
    // 1M names with no cap at all.
    let before_unbounded = live_bytes();
    let mut unbounded: BTreeMap<String, u64> = BTreeMap::new();
    let mut buf = String::with_capacity(64);
    for i in 0..LABELS {
        buf.clear();
        let _ = write!(buf, "flood.tenant.acme.label.{i:07}.value");
        *unbounded.entry(buf.clone()).or_default() += ROUNDS as u64;
    }
    let unbounded_retained = live_bytes().saturating_sub(before_unbounded);
    assert_eq!(unbounded.len(), LABELS);
    assert!(
        unbounded_retained > 50 * retained,
        "the cap must save at least an order of magnitude: bounded {retained} B \
         vs unbounded {unbounded_retained} B"
    );
    drop(unbounded);

    eprintln!(
        "[flood] {}M increments / {}k labels in {elapsed:?}: series={} dropped={} \
         retained={retained} B (unbounded equivalent {unbounded_retained} B, {:.0}x)",
        (LABELS * ROUNDS) / 1_000_000,
        LABELS / 1_000,
        r.series(),
        r.dropped(),
        unbounded_retained as f64 / retained as f64,
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 2. The MAX_SERIES boundary, to the single series
// ─────────────────────────────────────────────────────────────────────────

/// Fill to exactly 4095, 4096, 4097 and 4098 distinct names and assert where
/// the cap engages — then check the corner that used to defeat the obvious
/// alerting rule.
///
/// `MAX_SERIES` distinct names are admitted; the **4097th** is the first
/// dropped, and dropping it creates no key, so `series()` is `MAX_SERIES` and
/// stays there. The registry's key ceiling and its advertised cap are now the
/// same number, which is what
/// [`the_drop_counters_cannot_be_seeded_or_disarmed`] shows they were not.
///
/// **Repair of finding 5.** A *zero* increment on an unknown name is still a
/// dropped series — the caller asked for a slot and did not get one — and it
/// now moves `_dropped` by one while leaving `_dropped_events` at zero. The
/// canonical `_dropped > 0` alert fires. Before the repair the fold bucket was
/// created holding 0 and the same alert reported health.
#[test]
fn the_cap_is_exact_and_a_zero_valued_drop_is_still_visible() {
    let _guard = serialized();

    let mut r = CounterRegistry::default();

    // ── 4095: one short of the cap. Nothing dropped.
    fill_distinct(&mut r, "k.", MAX - 1);
    assert_eq!(r.series(), 4095);
    assert_eq!(r.series(), MAX - 1);
    assert_eq!(r.dropped(), 0, "nothing dropped before the cap");

    // ── 4096: the cap itself. The 4096th distinct name is ADMITTED — the
    //    guard is `len() >= MAX_SERIES` evaluated *before* the insert, and at
    //    that moment len() is 4095.
    r.inc("k.the_4096th", 1);
    assert_eq!(r.series(), 4096);
    assert_eq!(r.series(), MAX);
    assert_eq!(r.get("k.the_4096th"), 1, "the 4096th name is a real series");
    assert_eq!(r.dropped(), 0, "still nothing dropped at exactly MAX");
    assert_eq!(total(&r), u128::from(MAX as u64));

    // ── 4097: the first drop. The name is erased and NO key appears — the
    //    ceiling is MAX_SERIES, full stop.
    r.inc("k.the_4097th", 1);
    assert_eq!(r.series(), MAX, "the key count does not move");
    assert_eq!(r.dropped(), 1);
    assert_eq!(r.dropped_events(), 1);
    assert_eq!(
        r.get("k.the_4097th"),
        0,
        "the 4097th distinct name is erased, not stored"
    );
    assert!(!has_series(&r, "k.the_4097th"));

    // ── 4098 and beyond: the key count never moves again.
    r.inc("k.the_4098th", 7);
    assert_eq!(r.series(), MAX, "the ceiling is absolute");
    assert_eq!(r.dropped(), 2, "two calls dropped");
    assert_eq!(r.dropped_events(), 8, "carrying 1 + 7 units between them");

    // 50 000 more distinct names: still 4096 keys, and every increment is
    // still accounted for.
    fill_distinct(&mut r, "later.", 50_000);
    assert_eq!(r.series(), MAX);
    assert_eq!(r.dropped(), 2 + 50_000);
    assert_eq!(r.dropped_events(), 8 + 50_000);
    assert_eq!(
        total(&r) + u128::from(r.dropped_events()),
        u128::from(MAX as u64) + 1 + 7 + 50_000,
        "conservation still holds after 50k dropped names"
    );

    // The corner that used to defeat the alerting rule, now the other way
    // round: on a registry at exactly MAX_SERIES, a *zero* increment on an
    // unknown name moves `_dropped` even though it carries no events.
    let mut r = CounterRegistry::default();
    fill_distinct(&mut r, "z.", MAX);
    assert_eq!(r.series(), MAX);
    assert_eq!(r.dropped(), 0);
    r.inc("dropped_silently", 0);
    assert_eq!(r.series(), MAX, "no key appears...");
    assert_eq!(r.dropped(), 1, "...and the alarm fires anyway");
    assert_eq!(
        r.dropped_events(),
        0,
        "while the value-carrying counter correctly reads zero: nothing was \
         counted, but a series WAS lost"
    );
    assert!(!has_series(&r, "dropped_silently"));
    // `_dropped` is always exported, so "nothing was dropped" is a row an
    // operator can read rather than an absence they have to infer.
    assert_eq!(
        CounterRegistry::default().export()[0],
        ("_dropped", 0),
        "a fresh registry states its zero rather than omitting it"
    );
}

/// A full registry must not stop counting what it already knows — otherwise a
/// label flood would take the *real* telemetry down with it.
///
/// This one holds: the guard short-circuits on `contains_key`, so known
/// series keep incrementing at full rate, and `series()` never moves.
#[test]
fn a_full_registry_keeps_counting_the_series_it_already_knows() {
    let _guard = serialized();

    let mut r = CounterRegistry::default();
    fill_distinct(&mut r, "known.", MAX);
    r.inc("push_it_over", 1); // dropped
    assert_eq!(r.series(), MAX);
    assert_eq!(r.dropped(), 1);

    let known_first = "known.0000000";
    let known_last = "known.0004095";
    assert_eq!(r.get(known_first), 1);

    // 100 000 increments on a known series, interleaved with 100 000 brand
    // new names that are all dropped. The known series must absorb every one.
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
    assert_eq!(r.dropped(), 1 + 100_000);
    assert_eq!(r.series(), MAX, "counting known series adds no keys");

    // Zero-valued increments on a known series are also fine, and — unlike on
    // an unknown name — neither create a series nor count as a drop.
    r.inc(known_first, 0);
    assert_eq!(r.get(known_first), 100_001);
    assert_eq!(r.series(), MAX);
    assert_eq!(r.dropped(), 1 + 100_000, "a known series is never a drop");
}

// ─────────────────────────────────────────────────────────────────────────
// 3. Saturation
// ─────────────────────────────────────────────────────────────────────────

/// `u64::MAX` then `+1` pins, for a series and for the value-carrying drop
/// counter alike. That is the documented behaviour and it holds exactly.
///
/// The **defect that remains**: saturation is silent. There is no error, no
/// saturation flag, no way to tell "pinned, counts are being destroyed" from
/// "the true value happens to be `u64::MAX`", and the conservation property
/// fails from that moment on.
///
/// The **defect that does not**: saturating `_dropped_events` used to blind
/// the operator completely, because it *was* the drop counter. `_dropped`
/// counts calls, moving by exactly one however large `by` is, so an attacker
/// cannot pin it with a single `u64::MAX` — it would take 2^64 calls. The
/// alarm outlives the accounting.
#[test]
fn counters_pin_at_u64_max_but_the_drop_alarm_keeps_counting() {
    let _guard = serialized();

    // ── A normal series: pins, and conservation breaks silently.
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

    // ── The drop counters, reached only by overflowing the cap.
    let mut r = CounterRegistry::default();
    fill_distinct(&mut r, "s.", MAX);
    assert_eq!(r.series(), MAX);
    assert_eq!(r.dropped(), 0);

    r.inc("brand.new.a", u64::MAX); // dropped, carrying u64::MAX events
    assert_eq!(r.series(), MAX, "a drop still creates no key");
    assert_eq!(r.dropped(), 1);
    assert_eq!(r.dropped_events(), u64::MAX);
    r.inc("brand.new.b", 1); // dropped; the value counter saturates
    assert_eq!(r.dropped_events(), u64::MAX, "the event counter pins too");
    assert_eq!(r.dropped(), 2, "but the call counter does not");

    // And now the operator is NOT blind: 100 000 further distinct labels are
    // dropped, and although the event counter cannot move a unit, the alarm
    // records every single one.
    let events_before = r.dropped_events();
    fill_distinct(&mut r, "invisible.", 100_000);
    assert_eq!(
        r.dropped_events(),
        events_before,
        "the pinned value counter cannot record them"
    );
    assert_eq!(
        r.dropped(),
        2 + 100_000,
        "100k dropped labels are still visible, one by one, in _dropped"
    );
    assert_eq!(r.series(), MAX);

    // Pinning `_dropped` itself is not reachable: it moves by exactly one per
    // call whatever the caller offers, so it takes 2^64 calls to saturate.
    let mut r = CounterRegistry::default();
    fill_distinct(&mut r, "s.", MAX);
    let before = r.dropped();
    r.inc("one.more", u64::MAX);
    assert_eq!(
        r.dropped(),
        before + 1,
        "a u64::MAX increment moves the alarm by one, not by u64::MAX"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 4. export(): order, length, byte identity
// ─────────────────────────────────────────────────────────────────────────

/// `export()` leads with the three gauges, is strictly sorted throughout, and
/// its length is `series() + GAUGES`.
///
/// This is the one place the gauges' names and order are pinned; everything
/// else in this file reads series through `series_rows`. The gauges sort first
/// because `_` (0x5F) precedes every byte a valid name may start with — that
/// is not a coincidence to be preserved by luck, so it is asserted.
#[test]
fn export_leads_with_the_gauges_and_is_strictly_sorted() {
    let _guard = serialized();

    let mut r = CounterRegistry::default();
    // Names chosen to sit either side of every interesting byte boundary that
    // survives validation: `.` is 0x2E and `_` is 0x5F, so `a.b` sorts before
    // `a_b`. An exporter that maps `.` to `_` before sorting would disagree
    // with the registry about the order of its own rows.
    for (i, name) in [
        "zebra",
        "a.b",
        "a_b",
        "a",
        "gateway.requests",
        "gateway.requests_total",
        "s0",
        "s0.s0",
    ]
    .iter()
    .enumerate()
    {
        r.inc(name, i as u64 + 1);
    }
    // Plus enough ordinary names to reach the cap while the above hold slots.
    fill_distinct(&mut r, "pad.", MAX);

    let rows = r.export();
    assert_eq!(rows.len(), r.series() + GAUGES, "series plus three gauges");
    assert_eq!(r.series(), MAX, "the cap, with no fold key added to it");
    assert!(
        is_strictly_sorted(&rows),
        "export must be strictly sorted by name"
    );
    assert_eq!(
        rows[..GAUGES].iter().map(|(n, _)| *n).collect::<Vec<_>>(),
        GAUGE_NAMES,
        "the gauges lead, in this order"
    );

    // Byte-lexicographic, which is codepoint order for UTF-8. Pin the two
    // orderings an exporter is most likely to get wrong.
    let names: Vec<&str> = rows.iter().map(|(n, _)| *n).collect();
    let pos = |n: &str| names.iter().position(|x| *x == n);
    assert!(
        pos("a.b") < pos("a_b"),
        "byte order: '.' (0x2E) < '_' (0x5F)"
    );
    assert!(
        pos("gateway.requests") < pos("gateway.requests_total"),
        "a prefix sorts before its extension"
    );
    assert!(
        pos("_refused") < pos("a"),
        "every gauge precedes every series name"
    );
}

/// Byte-identical across repeated calls, and across two registries fed the
/// same sequence in the same order — including once the cap is reached.
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
        assert_eq!(a.export().len(), a.series() + GAUGES);
        let _ = a.dropped();
    }

    // Push both past the cap with the same extra sequence and re-check.
    for i in 0..30_000usize {
        let n = format!("post.{i:07}");
        a.inc(&n, 1);
        b.inc(&n, 1);
    }
    assert_eq!(a.series(), b.series());
    assert_eq!(a.dropped(), b.dropped());
    assert_eq!(snapshot_bytes(&a), snapshot_bytes(&b));
    assert_eq!(a.series(), MAX);

    // A golden digest, so "deterministic" is pinned to a value rather than to
    // a comparison between two things that could drift together. Stable in
    // debug and release, on any architecture: the input stream is a fixed-seed
    // LCG and the container is a `BTreeMap`, so there is no iteration entropy
    // anywhere in the pipeline. The gauges are inside the digest, so a change
    // to the drop accounting trips this too.
    assert_eq!(
        fnv1a(&snapshot_bytes(&a)),
        0xc572_db9c_fa73_ad39,
        "the exported snapshot for this fixed history changed"
    );
}

/// **DEFECT (unfixable as designed).** The registry is deterministic for a
/// given *order*, not for a given history: the same multiset of increments
/// delivered in a different order produces a different snapshot, because
/// arrival order alone decides which 4096 names win slots.
///
/// Consequence in production: two replicas of the same service behind a load
/// balancer see the same requests in different orders and export different
/// series. Everything aggregate agrees — the grand total, and all three gauges
/// — but the per-series breakdown, which is the only part an operator or an
/// audit diff actually reads, does not.
///
/// This is inherent to a first-N cap and cannot be repaired without unbounded
/// memory. The repair that *was* made is to stop claiming otherwise: the
/// `export()` doc comment used to promise snapshots "identical for identical
/// histories" and now states this limitation instead. The divergence also got
/// starker — the two replicas used to share exactly one key, the fold bucket,
/// and now share none at all.
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

    // Identical multiset, identical increment values, identical aggregates.
    assert_eq!(forward.series(), backward.series());
    assert_eq!(forward.series(), MAX);
    assert_eq!(
        total(&forward),
        total(&backward),
        "the aggregate IS order-independent"
    );
    assert_eq!(total(&forward), (MAX as u128) * 3);
    assert_eq!(forward.dropped(), backward.dropped());
    assert_eq!(forward.dropped_events(), backward.dropped_events());
    assert_eq!(forward.dropped(), (N - MAX) as u64);
    assert_eq!(
        total(&forward) + u128::from(forward.dropped_events()),
        (N as u128) * 3,
        "and conservation holds on both sides"
    );

    // ...and yet the snapshots differ, catastrophically.
    assert_ne!(
        snapshot_bytes(&forward),
        snapshot_bytes(&backward),
        "the same history in a different order produces a different snapshot"
    );

    let fwd: Vec<&str> = series_rows(&forward).iter().map(|(n, _)| *n).collect();
    let bwd: Vec<&str> = series_rows(&backward).iter().map(|(n, _)| *n).collect();
    let shared = fwd.iter().filter(|n| bwd.contains(n)).count();
    // Forward keeps order.0000000..0004095, backward keeps the top 4096
    // names, and the sets are disjoint: 4096 + 4096 <= 12 000.
    assert_eq!(
        shared, 0,
        "the two replicas agree on NOT ONE of their 4096 series names"
    );
    assert_eq!(fwd.len(), MAX);
    assert_eq!(bwd.len(), MAX);
    // The gauges, by contrast, agree exactly — the divergence is entirely in
    // which names survived, which is the part an operator reads.
    assert_eq!(
        forward.export()[..GAUGES],
        backward.export()[..GAUGES],
        "the aggregates agree while every series name disagrees"
    );
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
/// "present with value 0". Both are unchanged, and both are still exploitable:
/// slot squatting is free (see
/// [`a_flooded_registry_permanently_blocks_every_later_legitimate_series`]).
///
/// What did change: the empty string is no longer a metric name. It used to be
/// a perfectly ordinary, first-sorting series.
#[test]
fn zero_valued_increments_are_first_class_but_the_empty_name_is_not() {
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

    // The empty name is refused, and the refusal is counted rather than
    // silent — an operator can see that something tried.
    r.inc("", 0);
    assert_eq!(r.series(), 1, "the empty string is not a valid metric name");
    assert!(!has_series(&r, ""));
    assert_eq!(r.refused(), 1);
    r.inc("", 41);
    assert_eq!(r.get(""), 0);
    assert_eq!(r.refused(), 2);

    // 4096 slots consumed with zero counted events — free from the attacker's
    // side, permanent from the operator's. STILL OPEN.
    let mut r = CounterRegistry::default();
    let mut buf = String::with_capacity(24);
    for i in 0..MAX {
        buf.clear();
        let _ = write!(buf, "squat.{i:07}");
        r.inc(&buf, 0);
    }
    assert_eq!(r.series(), MAX);
    assert_eq!(total(&r), 0, "4096 series holding zero events between them");
    assert_eq!(r.dropped(), 0, "and not one of them counted as a drop");
}

/// **REPAIRED (finding 3).** "A label explosion can never exhaust memory" is
/// now true, because the cap is on bytes as well as on cardinality.
///
/// `MAX_NAME_BYTES` bounds every name, so the retained heap is at most
/// `MAX_SERIES x MAX_NAME_BYTES` plus `BTreeMap` node overhead — 512 KiB of
/// names, measured below at well under 1 MiB in total. The 1 MiB name that
/// used to be accepted, stored and exported byte-for-byte is refused and
/// counted; the old projection of 4096 x 1 MiB = 4 GiB is now unreachable
/// rather than merely undemonstrated.
///
/// There is still no removal, eviction or reset API, so the bound is a
/// high-water mark that is never released — but it is now a bound.
#[test]
fn the_cardinality_cap_is_now_a_memory_cap() {
    let _guard = serialized();

    // ── A single 1 MiB name: refused, and nothing retained.
    let huge = "m".repeat(MIB);
    let before_one = live_bytes();
    let mut r = CounterRegistry::default();
    r.inc(&huge, 7);
    let one_retained = live_bytes().saturating_sub(before_one);
    assert_eq!(r.series(), 0, "a 1 MiB metric name is not a series");
    assert_eq!(r.get(&huge), 0);
    assert_eq!(r.refused(), 1, "and the attempt is counted");
    assert!(
        one_retained < 1024,
        "a refused 1 MiB name retained {one_retained} B — it was stored"
    );
    // The boundary is exact: MAX_NAME_BYTES is admitted, one byte more is not.
    let at_limit = "m".repeat(NAME_MAX);
    r.inc(&at_limit, 1);
    assert_eq!(r.get(&at_limit), 1, "exactly MAX_NAME_BYTES is admitted");
    r.inc(&format!("{at_limit}m"), 1);
    assert_eq!(r.series(), 1, "one byte over is not");
    assert_eq!(r.refused(), 2);
    drop(r);

    // ── The worst case the API allows: MAX_SERIES names, each MAX_NAME_BYTES
    //    long. This is the product `MAX_SERIES x MAX_NAME_BYTES`, measured.
    let before = live_bytes();
    let mut r = CounterRegistry::default();
    let mut buf = String::with_capacity(NAME_MAX + 16);
    for i in 0..MAX {
        buf.clear();
        let _ = write!(buf, "p{i:07}.");
        while buf.len() < NAME_MAX {
            buf.push('p');
        }
        assert_eq!(buf.len(), NAME_MAX);
        r.inc(&buf, 1);
    }
    let retained = live_bytes().saturating_sub(before);

    assert_eq!(r.series(), MAX, "every one of them fits");
    assert!(
        retained < 2 * MAX * NAME_MAX,
        "the worst case retained {retained} B; the bound is \
         {MAX} x {NAME_MAX} = {} B of names plus node overhead",
        MAX * NAME_MAX
    );

    // Nothing an attacker does from here can grow it: 50 000 more names, all
    // at the length limit, retain not one further byte.
    let settled = live_bytes();
    for i in 0..50_000usize {
        buf.clear();
        let _ = write!(buf, "q{i:07}.");
        while buf.len() < NAME_MAX {
            buf.push('q');
        }
        r.inc(&buf, 1);
    }
    assert_eq!(
        live_bytes(),
        settled,
        "a full registry allocates nothing at all for a dropped name"
    );
    assert_eq!(r.series(), MAX);
    assert_eq!(r.dropped(), 50_000);

    eprintln!(
        "[bytes] worst case {MAX} x {NAME_MAX} B names => {retained} B retained \
         at series()={}; the pre-repair equivalent at 1 MiB names was {} B (~4 GiB)",
        r.series(),
        MAX as u64 * MIB as u64
    );
}

/// **REPAIRED (finding 4).** Metric names are validated, so the exporter
/// injection vector is closed at the registry rather than left for whoever
/// wires Prometheus.
///
/// Prometheus text exposition is newline- and space-delimited, so a name
/// carrying `\n` or a space is a forged series the moment that exporter
/// exists. `inc("x 1\nccos_licence_valid 1", 1)` used to round-trip intact.
/// Every injection below is now refused and counted in `_refused`, which is
/// the signal an operator needs: a registry that silently discards hostile
/// names tells nobody that something is probing it.
///
/// The same rule closes the homoglyph vector as a side effect: six renderings
/// of "e" that a human reads as one used to buy six slots.
#[test]
fn adversarial_label_names_are_refused_and_counted() {
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
        "",
        "_dropped",
        "_dropped_events",
        "_refused",
        "0leading",
        "Upper.case",
        "trailing.",
        ".leading",
        "double..dot",
        "dashed-name",
        "\u{1f600}",
    ];

    let mut r = CounterRegistry::default();
    for (i, name) in injections.iter().enumerate() {
        r.inc(name, i as u64 + 1);
    }
    assert_eq!(r.series(), 0, "not one hostile name became a series");
    assert_eq!(
        r.refused(),
        injections.len() as u64,
        "every hostile name was refused, and every refusal counted"
    );
    for name in &injections {
        assert!(!has_series(&r, name), "{name:?} is exported as a series");
        // `get` on a gauge name reads the gauge rather than a series, by
        // design — `get` and `export` must never disagree about a name. So a
        // caller who names `_refused` does get a number back; what they do
        // NOT get is any influence over it (it counts their own refusal, by
        // one, and nothing they passed).
        if GAUGE_NAMES.contains(name) {
            assert_eq!(
                r.get(name),
                r.export().iter().find(|(n, _)| n == name).unwrap().1
            );
        } else {
            assert_eq!(r.get(name), 0, "{name:?} is readable");
        }
    }
    // The export carries the gauges and nothing else — in particular, not one
    // byte of the injection payload.
    let rows = r.export();
    assert_eq!(rows.len(), GAUGES);
    assert!(is_strictly_sorted(&rows));
    assert!(
        !rows
            .iter()
            .any(|(n, _)| n.contains('\n') || n.contains(' ')),
        "a name that would forge a Prometheus series survived export"
    );
    assert_eq!(rows[2], ("_refused", injections.len() as u64));
    // The drop counters are untouched: a malformed name is refused, not
    // dropped, and the two are counted separately so an operator can tell
    // "something is probing me" from "I am out of slots".
    assert_eq!(r.dropped(), 0);
    assert_eq!(r.dropped_events(), 0);

    // Unicode near-duplicates: one visual label, one slot, five refusals.
    let mut r = CounterRegistry::default();
    for name in [
        "e",        // LATIN SMALL LETTER E — the only admissible one
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
        1,
        "only the ASCII rendering is a metric name now"
    );
    assert_eq!(r.refused(), 5, "the other five are refused, and counted");
    assert!(has_series(&r, "e"));

    // Everything the product itself registers is still admissible — the rule
    // is narrow, but not narrower than the caller it exists for.
    let mut r = CounterRegistry::default();
    for name in [
        "gateway.requests",
        "gateway.forwarded",
        "gateway.refused",
        "gateway.refused.variant_not_activated",
        "gateway.replayed",
        "audit.dropped",
        "mcp.requests",
    ] {
        r.inc(name, 1);
        assert!(
            has_series(&r, name),
            "{name} was refused by its own product"
        );
    }
    assert_eq!(r.refused(), 0);
}

/// **REPAIRED (findings 1 and 2).** The drop accounting is out of band, so it
/// cannot be seeded, cannot be disarmed, and does not move the advertised cap.
///
/// The old fold did `entry("overflow").or_default()`, which happily landed on
/// a series an attacker had created earlier. Three consequences followed, and
/// all three are gone:
///
/// * **(a) the advertised cap changed.** `series()` is now `MAX_SERIES`
///   whatever anyone named first — there is no fold key to be pre-empted.
/// * **(b) the drop counter read `seed + drops`.** `_dropped` is a struct
///   field; `inc` cannot reach it, because `is_valid_name` refuses a leading
///   `_`.
/// * **(c) seeding it at `u64::MAX` killed it.** Unreachable, and doubly so:
///   even a genuine saturation of `_dropped_events` leaves `_dropped`
///   counting (see
///   [`counters_pin_at_u64_max_but_the_drop_alarm_keeps_counting`]).
///
/// What an attacker *can* still do is occupy a slot, exactly as any other name
/// does — that is finding 6, and it is unchanged.
#[test]
fn the_drop_counters_cannot_be_seeded_or_disarmed() {
    let _guard = serialized();

    // ── The direct attack: name the gauges.
    let mut r = CounterRegistry::default();
    for gauge in GAUGE_NAMES {
        r.inc(gauge, u64::MAX);
    }
    assert_eq!(r.series(), 0, "a gauge name cannot become a series");
    assert_eq!(r.dropped(), 0, "and cannot be seeded");
    assert_eq!(r.dropped_events(), 0);
    assert_eq!(
        r.refused(),
        GAUGES as u64,
        "_refused counts the attempts, by one each — never by the u64::MAX \
         that was offered"
    );

    // ── The old attack, replayed: seed the name the fold used to overload.
    //    It is now an ordinary series with no special meaning whatsoever.
    let mut seeded = CounterRegistry::default();
    seeded.inc("overflow", 1_000_000);
    assert_eq!(seeded.series(), 1);
    assert_eq!(
        seeded.dropped(),
        0,
        "naming it does not touch the accounting"
    );

    fill_distinct(&mut seeded, "real.", MAX - 1); // 4095 genuine series
    assert_eq!(seeded.series(), MAX, "the ordinary series took one slot");
    seeded.inc("real.would_have_fit", 1);
    assert_eq!(seeded.series(), MAX, "the cap is MAX_SERIES, as advertised");
    assert_eq!(seeded.dropped(), 1, "and the drop is counted, once");
    fill_distinct(&mut seeded, "dropped.", 5_000);
    assert_eq!(seeded.dropped(), 5_001);
    assert_eq!(
        seeded.get("overflow"),
        1_000_000,
        "the attacker's counts stay in the attacker's own series, where an \
         operator can see them for what they are"
    );

    // A clean registry given the identical genuine history: the same cap, and
    // a drop count that differs by exactly one — the single slot the extra
    // series occupies, which is what ANY name would have cost. No amount of
    // seeding shifts the ceiling or corrupts the count.
    let mut clean = CounterRegistry::default();
    fill_distinct(&mut clean, "real.", MAX - 1);
    clean.inc("real.would_have_fit", 1);
    fill_distinct(&mut clean, "dropped.", 5_000);
    assert_eq!(clean.series(), MAX);
    assert_eq!(clean.series(), seeded.series(), "the cap is not negotiable");
    assert_eq!(clean.dropped(), 5_000);
    assert_eq!(
        seeded.dropped() - clean.dropped(),
        1,
        "one seeded name costs exactly one slot, and nothing else"
    );
    assert!(has_series(&clean, "real.would_have_fit"));

    // ── (c) the old kill shot, now inert: `u64::MAX` offered to the drop
    //    accounting through every reachable path.
    let mut r = CounterRegistry::default();
    r.inc("_dropped", u64::MAX);
    r.inc("overflow", u64::MAX);
    fill_distinct(&mut r, "real.", MAX - 1);
    assert_eq!(r.series(), MAX);
    assert_eq!(r.dropped(), 0, "nothing was dropped yet, and it says so");

    fill_distinct(&mut r, "explosion.", 100_000);
    assert_eq!(
        r.dropped(),
        100_000,
        "100 000 dropped labels move the alarm by 100 000: it could not be \
         disarmed in advance"
    );
    assert_eq!(r.series(), MAX);

    // And it is visible in the export, not merely in an accessor: the
    // snapshot before and after a further explosion differs.
    let before = snapshot_bytes(&r);
    fill_distinct(&mut r, "explosion2.", 100_000);
    assert_ne!(
        snapshot_bytes(&r),
        before,
        "a 100k-label explosion must be visible in export()"
    );
    assert_eq!(r.dropped(), 200_000);
}

/// **DEFECT, STILL OPEN.** First writer wins, permanently. A registry filled
/// with junk refuses every later series — including the ones the product
/// itself registers — and there is no eviction, no TTL, no priority list and
/// no removal API to recover.
///
/// This is the exhaustion vector that actually matters, and the one the repair
/// did *not* address. The bound protects the heap at the price of the
/// operator's telemetry: an attacker who can reach any code path that names a
/// metric (with `by = 0`, so at zero cost to themselves) permanently deletes
/// `gateway.requests`, `gateway.forwarded` and every refusal counter from the
/// process.
///
/// What the repair did buy is the symptom: `_dropped` climbs, cannot be
/// seeded, cannot be saturated in practice, and is always exported. Before, the
/// only symptom was a counter named `overflow` that
/// [`the_drop_counters_cannot_be_seeded_or_disarmed`] shows could be disarmed
/// in advance.
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
    assert_eq!(r.dropped(), (legitimate.len() * 100) as u64);

    // A million more legitimate increments do not earn a slot back.
    for _ in 0..1_000_000u32 {
        r.inc("gateway.requests", 1);
    }
    assert_eq!(
        r.get("gateway.requests"),
        0,
        "1M increments, still no slot: there is no eviction and no priority"
    );
    assert_eq!(r.series(), MAX);

    // And the attacker's junk is immortal — every one of the 4096 squatted
    // names is still there, still readable, with no API to remove it.
    assert_eq!(r.get("attacker.0000000"), 1);
    assert_eq!(r.get("attacker.0004095"), 1);
    assert_eq!(
        series_rows(&r)
            .iter()
            .filter(|(n, _)| n.starts_with("attacker."))
            .count(),
        MAX,
        "4096 attacker-owned series retained for the process lifetime"
    );

    // The alarm is loud, at least, and stays loud: 1 000 500 dropped calls,
    // every one counted, in a counter nothing in the API can reset.
    assert_eq!(r.dropped(), 500 + 1_000_000);
    assert_eq!(r.refused(), 0, "the junk names were all well-formed");
}

// ─────────────────────────────────────────────────────────────────────────
// 6. The composed path — what held
// ─────────────────────────────────────────────────────────────────────────

/// The product path is immune to all of the above, and this test is the proof
/// that keeps it that way.
///
/// `Deployment::admit` never lets caller-controlled text into a metric name:
/// refusals go through `tag()`, which returns a `&'static str` from a closed
/// set of eleven. 3 000 hostile calls — 1 MiB tool names, unicode tenants,
/// attacker-chosen actors and request ids, every refusal class — produce
/// exactly 14 series plus the registry's three gauges, and `requests ==
/// forwarded + refused` holds throughout.
///
/// It is the *only* thing standing between the registry and the flood proven
/// above, and nothing enforces it but this assertion: `admit` builds its
/// refusal label with `format!`, so one future `format!("...{}", req.tool)`
/// hands the whole vector to the attacker. The gauges are the second line of
/// defence and they are asserted at zero: if caller text ever did reach a
/// metric name, `_refused` would move even before the cardinality did.
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
        let pick = (lcg(&mut seed) >> 40) % 11;
        // Each arm targets ONE gate. The credential now BINDS the request, so
        // an arm that wants to reach a deep gate must present a consistent
        // pair: this file used to build every credential with a hostile org
        // (`"org\u{202e}"`), which after the repair is refused at the binding
        // gate, so eight of the eleven tags stopped being exercised at all.
        // The hostile text now lives where it is the thing under test — arms
        // 7, 8 and 9 — and in the request ids and 1 MiB tool names below.
        let (org, cred_actor, tenant, req_actor, tool, strength, model, variant) = match pick {
            0 => (
                "memorithm",
                "alice",
                "acme",
                "alice",
                "memory.recall",
                AuthStrength::Anonymous,
                "claude-opus",
                None,
            ),
            1 => (
                "memorithm",
                "alice",
                "does-not-exist\u{1f4a3}",
                "alice",
                "memory.recall",
                AuthStrength::Token,
                "claude-opus",
                None,
            ),
            2 => (
                "memorithm",
                "alice",
                "acme",
                "alice",
                "shell.exec",
                AuthStrength::Strong,
                "claude-opus",
                None,
            ),
            // Reaches `tool_not_governed`, which requires a CANONICAL name:
            // this case used to spell it "context.<emoji><RTL>not-governed",
            // but the gateway's canonical-name rule refuses that shape
            // outright, so the hostile spelling was counted as a boundary
            // refusal and this tag stopped being exercised. A tool has to
            // clear the boundary before "nobody governed it" can be the
            // answer.
            3 => (
                "memorithm",
                "alice",
                "acme",
                "alice",
                "context.not_governed",
                AuthStrength::Strong,
                "claude-opus",
                None,
            ),
            4 => (
                "memorithm",
                "bob",
                "acme",
                "bob",
                "memory.ingest",
                AuthStrength::Token,
                "claude-opus",
                None,
            ),
            5 => (
                "memorithm",
                "alice",
                "acme",
                "alice",
                "memory.recall",
                AuthStrength::Token,
                "gpt-5",
                None,
            ),
            6 => (
                "memorithm",
                "alice",
                "acme",
                "alice",
                "memory.recall",
                AuthStrength::Token,
                "claude-opus",
                Some(AdvancedQPageVariant::CausalChain),
            ),
            // The three gates the credential binding added. Hostile text is
            // deliberate here: a rejected org must not reach a metric label
            // any more than a rejected tool name does.
            7 => (
                "memorithm",
                "alice",
                "acme",
                "mallory",
                "memory.recall",
                AuthStrength::Token,
                "claude-opus",
                None,
            ),
            8 => (
                "initech\u{202e}\u{1f600}",
                "alice",
                "acme",
                "alice",
                "memory.recall",
                AuthStrength::Token,
                "claude-opus",
                None,
            ),
            9 => (
                "memorithm",
                "alice",
                "acme",
                "",
                "memory.recall",
                AuthStrength::Token,
                "claude-opus",
                None,
            ),
            _ => (
                "memorithm",
                "alice",
                "acme",
                "alice",
                "memory.recall",
                AuthStrength::Token,
                "claude-opus",
                None,
            ),
        };
        let a = actor(org, cred_actor, strength);
        let req = request(tenant, req_actor, tool, &format!("rid-{i:09}-\u{1f600}"));
        let _ = d.admit(Call {
            actor: &a,
            request: &req,
            model,
            cost_tokens: (lcg(&mut seed) >> 40) % 64,
            variant,
            justification: None,
        });
    }

    // A separate, deliberately small batch of 1 MiB tool names. Kept small
    // because `Deployment` retains every one verbatim in the audit journal
    // (a sibling finding, not this file's), so 16 of them already cost 16 MB;
    // the point here is only that a megabyte of caller text cannot become a
    // metric label. Both a boundary-violating and a catalogue-missing giant
    // are exercised, since they take different `format!` paths in `classify`.
    let a = actor("memorithm", "alice", AuthStrength::Strong);
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
                justification: None,
            });
        }
    }

    let m = d.metrics();
    let names: Vec<&str> = m.iter().map(|(n, _)| n.as_str()).collect();
    let val = |k: &str| m.iter().find(|(n, _)| n == k).map(|(_, v)| *v).unwrap_or(0);

    assert!(
        names.len() <= 14 + GAUGES,
        "the composed path must stay at fixed cardinality; got {names:?}"
    );
    for n in &names {
        assert!(
            *n == "gateway.requests"
                || *n == "gateway.forwarded"
                || *n == "gateway.refused"
                || n.starts_with("gateway.refused.")
                || GAUGE_NAMES.contains(n),
            "unexpected metric name {n:?} — caller text reached a metric label"
        );
        assert!(
            n.len() < 64,
            "metric name {n:?} carries caller-controlled length"
        );
    }
    assert!(m.windows(2).all(|w| w[0].0 < w[1].0), "metrics are sorted");

    // The second line of defence, at zero: the registry was never asked to
    // refuse a name and never ran out of slots. A future `format!` leaking a
    // tool name would move `_refused` long before it moved the cardinality.
    for gauge in GAUGE_NAMES {
        assert_eq!(
            val(gauge),
            0,
            "{gauge} moved: caller text reached the registry"
        );
    }

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
    assert_eq!(d.audit().count(), calls as usize);

    // All eleven refusal tags plus requests/forwarded/refused: the closed set
    // is fully exercised, so `names.len() == 14 + GAUGES` is this design's
    // *saturated* cardinality and not an artefact of thin coverage.
    let tags: Vec<&str> = names
        .iter()
        .filter_map(|n| n.strip_prefix("gateway.refused."))
        .collect();
    assert_eq!(
        tags,
        [
            "actor_mismatch",
            "budget_exhausted",
            "malformed_request",
            "model_not_allowed",
            "outside_boundary",
            "permission_denied",
            "tenant_not_owned",
            "tool_not_governed",
            "unauthenticated",
            "unknown_tenant",
            "variant_not_activated",
        ],
        "every refusal tag must be exercised"
    );
    assert_eq!(
        names.len(),
        14 + GAUGES,
        "the composed path's metric cardinality is exactly 14, saturated, \
         plus the registry's three gauges"
    );
    eprintln!(
        "[composed] {calls} hostile calls => {} rows: {names:?}",
        names.len()
    );
}
