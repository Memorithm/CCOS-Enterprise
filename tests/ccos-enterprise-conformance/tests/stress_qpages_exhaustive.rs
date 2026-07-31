//! # Hostile stress: the advanced Q-Page registry, exhausted
//!
//! The product line is sold on "ten advanced Q-Page variants, policy-activated
//! per tenant" (`README.md` "Product boundary"; `docs/ENTERPRISE_COGNITIVE_GOVERNANCE.md`
//! "which Q-Page variants a tenant may activate"). Ten variants is a small
//! enough space to leave nothing to sampling, so this suite is *exhaustive*
//! rather than representative: every one of the 2^10 = 1024 activation subsets
//! is built, probed on all ten variants, serialized, round-tripped, and driven
//! through the composed admission path.
//!
//! What that exhaustion establishes is not flattering. The registry is a
//! `BTreeSet<AdvancedQPageVariant>` and **nothing more**: set membership is
//! the entire observable behaviour of all ten "advanced variants". The tests
//! below assert the *current, real* behaviour — including the places where it
//! falls short of what the documentation promises — and each such place is
//! flagged with a `FINDING:` comment naming what a buyer would expect instead.
//!
//! Summary of what this file pins (details at each test):
//!
//! - F1 (missing-behaviour) — activation carries **no semantics**: a
//!   deployment with all ten variants active is byte-for-byte indistinguishable
//!   from one with none, for every call that does not name a variant.
//! - F2 (missing-behaviour) — the audit journal never records **which** variant
//!   a forwarded call used; two calls, one on `ExperimentalBridge` and one on
//!   Core's standard primitives, produce *equal* `AuditRecord`s.
//! - F3 (spec-violation) — the crate doc calls activation "an explicit,
//!   auditable tenant decision"; activating all ten leaves **zero** audit
//!   records, zero metrics, needs no permission, no authenticated actor and no
//!   approval.
//! - F4 (bug) — the serde wire format is not canonical: duplicate and
//!   out-of-order entries are silently accepted and rewritten, and a struct-as-
//!   sequence spelling is accepted too, so distinct bytes map to one state.
//! - F5 (bug) — `{}` fails to deserialize (`missing field 'active'`) even
//!   though the empty registry is the documented default, while an *unknown*
//!   field is silently ignored: the format is strict where it should be lax
//!   and lax where it should be strict.
//! - F6 (exhaustion-vector) — a `VariantNotActivated` refusal costs the tenant
//!   nothing but appends an unbounded audit record; refusals are free to the
//!   attacker and unbounded in memory for the operator.
//! - F7 (missing-behaviour) — the variant is **caller-declared**: nothing binds
//!   a tool to a variant, so omitting `variant` skips the gate entirely.
//! - F8 (missing-behaviour) — no `ALL`/iterator/`FromStr`/`Display` on the
//!   enum, no way to *list* a tenant's activations, and no read-only accessor
//!   for tenant state (`tenant_mut` is the only door).
//! - F9 (bug) — `Deployment::add_tenant` is a bare `insert`: re-provisioning an
//!   existing tenant silently discards its activation set *and resets its spend
//!   ledger to zero*, which is a quota bypass that touches no gate.
//!
//! Everything here is deterministic: fixed masks, a fixed-seed LCG, no clock,
//! no threads, no RNG. It passes identically in debug and release.

use ccos_enterprise_auth::AuthStrength;
use ccos_enterprise_conformance::{
    actor, request, Call, Deployment, Outcome, Refusal, TenantState,
};
use ccos_enterprise_qpages::{AdvancedQPageVariant, QPageRegistry};
use ccos_enterprise_tenancy::{TenantId, TenantScope};

// ── The variant space ────────────────────────────────────────────────────

/// The ten variants in declaration order (which is also `Ord` order, which is
/// also `BTreeSet` iteration order, which is also serialization order).
///
/// FINDING F8 (missing-behaviour): `ccos-enterprise-qpages` exports no
/// `AdvancedQPageVariant::ALL`, no `iter()`, no `Display`/`FromStr` and no
/// `Hash`. Every consumer — this suite included — must hand-maintain the list
/// of ten, and an eleventh variant would silently escape every table-driven
/// check written against a hand-maintained list. `exhaustiveness_is_compiler_enforced`
/// below buys that guarantee back with a total `match`; the *crate* should be
/// providing it.
const ALL: [AdvancedQPageVariant; 10] = [
    AdvancedQPageVariant::Hierarchical,
    AdvancedQPageVariant::CausalChain,
    AdvancedQPageVariant::Probabilistic,
    AdvancedQPageVariant::MultiTenantFederated,
    AdvancedQPageVariant::TemporalWindowed,
    AdvancedQPageVariant::AuthorityWeighted,
    AdvancedQPageVariant::ConsensusMediated,
    AdvancedQPageVariant::CostBounded,
    AdvancedQPageVariant::ComplianceTagged,
    AdvancedQPageVariant::ExperimentalBridge,
];

/// Every subset of ten variants.
const SUBSETS: u32 = 1 << 10;

/// A total `match`: adding an eleventh variant to the enum stops this file
/// compiling, which is the only way a hand-maintained `ALL` can be trusted.
fn index_of(v: AdvancedQPageVariant) -> usize {
    match v {
        AdvancedQPageVariant::Hierarchical => 0,
        AdvancedQPageVariant::CausalChain => 1,
        AdvancedQPageVariant::Probabilistic => 2,
        AdvancedQPageVariant::MultiTenantFederated => 3,
        AdvancedQPageVariant::TemporalWindowed => 4,
        AdvancedQPageVariant::AuthorityWeighted => 5,
        AdvancedQPageVariant::ConsensusMediated => 6,
        AdvancedQPageVariant::CostBounded => 7,
        AdvancedQPageVariant::ComplianceTagged => 8,
        AdvancedQPageVariant::ExperimentalBridge => 9,
    }
}

fn bit(mask: u32, i: usize) -> bool {
    (mask & (1u32 << i)) != 0
}

/// Build the registry for `mask`, activating in ascending declaration order.
fn registry_for(mask: u32) -> QPageRegistry {
    let mut r = QPageRegistry::default();
    for (i, v) in ALL.iter().enumerate() {
        if bit(mask, i) {
            r.activate(*v);
        }
    }
    r
}

fn json(r: &QPageRegistry) -> String {
    serde_json::to_string(r).expect("QPageRegistry is Serialize and infallible")
}

/// The JSON a canonical registry for `mask` must produce, spelled out
/// independently of the registry: `{"active":[<names in declaration order>]}`.
fn expected_json(mask: u32) -> String {
    let names: Vec<String> = ALL
        .iter()
        .enumerate()
        .filter(|(i, _)| bit(mask, *i))
        .map(|(_, v)| format!("\"{v:?}\""))
        .collect();
    format!("{{\"active\":[{}]}}", names.join(","))
}

// ── The composed path ────────────────────────────────────────────────────

/// A single-tenant deployment whose tenant has activated exactly `mask`.
/// Budget deliberately huge so the Q-Page gate, not the budget, decides; the
/// per-call cost is 1 so `spent()` counts forwarded calls exactly.
fn deployment_activating(mask: u32) -> Deployment {
    let mut d = Deployment::new();
    d.add_role("writer", &["memory.read", "memory.write"])
        .add_role("reader", &["memory.read"])
        .govern_tool("memory.recall", "memory.read")
        .govern_tool("memory.ingest", "memory.write")
        .govern_tool("ccos.qpage.read", "memory.read");
    let mut t = TenantState::new(1_000_000);
    t.allow_model("claude-opus");
    for (i, v) in ALL.iter().enumerate() {
        if bit(mask, i) {
            t.activate(*v);
        }
    }
    d.add_tenant("acme", t);
    d.assign("alice", "writer");
    d.assign("bob", "reader");
    d
}

/// One `memory.recall` by alice, optionally naming a variant.
fn recall(
    d: &mut Deployment,
    who: &str,
    id: &str,
    variant: Option<AdvancedQPageVariant>,
    cost: u64,
) -> Outcome {
    let a = actor("acme-org", who, AuthStrength::Token);
    let req = request("acme", who, "memory.recall", id);
    d.admit(Call {
        actor: &a,
        request: &req,
        model: "claude-opus",
        cost_tokens: cost,
        variant,
    })
}

// ─────────────────────────────────────────────────────────────────────────
// 1. The 1024 subsets
// ─────────────────────────────────────────────────────────────────────────

/// `ALL` really is all ten, each exactly once, in `Ord` order. Guarded by a
/// total `match` so this cannot silently rot (FINDING F8).
#[test]
fn exhaustiveness_is_compiler_enforced() {
    for (i, v) in ALL.iter().enumerate() {
        assert_eq!(index_of(*v), i, "ALL[{i}] = {v:?} is out of place");
    }
    // Ord agrees with declaration order, which is what makes every ordering
    // assertion in this file meaningful.
    for w in ALL.windows(2) {
        assert!(w[0] < w[1], "{:?} must sort before {:?}", w[0], w[1]);
    }
    let mut distinct: Vec<AdvancedQPageVariant> = ALL.to_vec();
    distinct.sort();
    distinct.dedup();
    assert_eq!(distinct.len(), 10, "exactly ten distinct variants");
}

/// Every one of the 1024 subsets, probed on all ten variants: `is_active`
/// matches the subset exactly, and `active_count` is the popcount. No
/// sampling, no shortcuts.
#[test]
fn all_1024_subsets_report_membership_exactly() {
    for mask in 0..SUBSETS {
        let r = registry_for(mask);
        for (i, v) in ALL.iter().enumerate() {
            assert_eq!(
                r.is_active(*v),
                bit(mask, i),
                "mask {mask:#012b}: is_active({v:?}) disagrees with the subset"
            );
        }
        assert_eq!(
            r.active_count(),
            mask.count_ones() as usize,
            "mask {mask:#012b}: active_count is not the popcount"
        );
    }
}

/// Insertion order must not be observable. For every subset, building it
/// ascending, descending and rotated yields the same membership *and* the same
/// bytes — the registry is a set, not a log. (This one holds.)
#[test]
fn insertion_order_is_not_observable_in_any_subset() {
    for mask in 0..SUBSETS {
        let ascending = registry_for(mask);

        let mut descending = QPageRegistry::default();
        for (i, v) in ALL.iter().enumerate().rev() {
            if bit(mask, i) {
                descending.activate(*v);
            }
        }

        // A rotation that also re-activates each variant a second time.
        let mut rotated = QPageRegistry::default();
        for step in 0..ALL.len() {
            let i = (step * 7 + 3) % ALL.len();
            if bit(mask, i) {
                rotated.activate(ALL[i]);
                rotated.activate(ALL[i]);
            }
        }

        let a = json(&ascending);
        assert_eq!(json(&descending), a, "mask {mask:#012b}: order leaked");
        assert_eq!(json(&rotated), a, "mask {mask:#012b}: order leaked");
        assert_eq!(descending.active_count(), ascending.active_count());
        assert_eq!(rotated.active_count(), ascending.active_count());
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 2. Idempotence
// ─────────────────────────────────────────────────────────────────────────

/// For every subset: activating an already-active variant changes nothing,
/// and deactivating an inactive one is a no-op — including on the empty and
/// the full registry, and including a double deactivation. (This one holds.)
#[test]
fn activation_and_deactivation_are_idempotent_across_all_1024_subsets() {
    for mask in 0..SUBSETS {
        let mut r = registry_for(mask);
        let before = json(&r);
        let count = r.active_count();

        for (i, v) in ALL.iter().enumerate() {
            if bit(mask, i) {
                r.activate(*v); // already active
                r.activate(*v);
            } else {
                r.deactivate(*v); // never was active
                r.deactivate(*v);
            }
        }
        assert_eq!(json(&r), before, "mask {mask:#012b}: not idempotent");
        assert_eq!(r.active_count(), count, "mask {mask:#012b}: count moved");

        // Deactivating everything empties it, twice over, and the empty
        // registry serializes canonically.
        for v in ALL {
            r.deactivate(v);
            r.deactivate(v);
        }
        assert_eq!(r.active_count(), 0);
        assert_eq!(json(&r), r#"{"active":[]}"#);
    }
}

/// 100_000 activate/deactivate cycles across all ten variants leave the
/// registry byte-identical to where it started, with no drift in `active_count`
/// at any point. Runs in well under a second — the registry is a ten-element
/// set, so there is nothing here to degrade. (This one holds.)
#[test]
fn a_hundred_thousand_cycles_leave_the_registry_identical() {
    let start_mask = 0b0101010101u32;
    let mut r = registry_for(start_mask);
    let before = json(&r);
    let count_before = r.active_count();

    for step in 0..100_000u32 {
        let i = (step as usize) % ALL.len();
        let v = ALL[i];
        let was_active = bit(start_mask, i);

        r.activate(v);
        assert!(r.is_active(v), "step {step}: activate did not take");
        // Restore whatever the invariant state was: an activate for the
        // variants that belong, a deactivate for the ones that do not.
        if was_active {
            r.activate(v);
        } else {
            r.deactivate(v);
        }
        assert_eq!(r.is_active(v), was_active, "step {step}: cycle drifted");

        if step % 10_000 == 0 {
            assert_eq!(json(&r), before, "step {step}: bytes drifted");
            assert_eq!(r.active_count(), count_before, "step {step}: count drifted");
        }
    }

    assert_eq!(json(&r), before, "100k cycles must be a no-op");
    assert_eq!(r.active_count(), count_before);
}

// ─────────────────────────────────────────────────────────────────────────
// 3. Determinism and ordering
// ─────────────────────────────────────────────────────────────────────────

/// For every subset: serialization is byte-stable across repeats, the bytes
/// are exactly the canonical declaration-ordered form, and the round-trip is
/// lossless in membership, count and bytes. (This one holds — the *encoder*
/// is canonical. The decoder is not; see the next test.)
#[test]
fn serde_roundtrip_is_lossless_and_byte_identical_for_every_subset() {
    for mask in 0..SUBSETS {
        let r = registry_for(mask);

        let first = json(&r);
        let second = json(&r);
        assert_eq!(
            first, second,
            "mask {mask:#012b}: serialization is unstable"
        );
        assert_eq!(
            first,
            expected_json(mask),
            "mask {mask:#012b}: not the canonical BTreeSet ordering"
        );

        let back: QPageRegistry =
            serde_json::from_str(&first).expect("our own output must deserialize");
        for (i, v) in ALL.iter().enumerate() {
            assert_eq!(
                back.is_active(*v),
                bit(mask, i),
                "mask {mask:#012b}: {v:?} lost in the round-trip"
            );
        }
        assert_eq!(back.active_count(), r.active_count());
        assert_eq!(
            json(&back),
            first,
            "mask {mask:#012b}: round-trip re-encoded"
        );

        // A second and third generation must not drift either.
        let gen3: QPageRegistry = serde_json::from_str(&json(&back)).expect("stable");
        assert_eq!(
            json(&gen3),
            first,
            "mask {mask:#012b}: drift at generation 3"
        );
    }
}

/// FINDING F4 (bug) + F5 (bug): the accepted wire format is neither canonical
/// nor strict, so "the registry round-trips" does not mean "the bytes on disk
/// determine the state, and only one spelling does".
///
/// A backup digest (`ccos-enterprise-backup::BackupManifest::digest`) taken
/// over a serialized registry therefore proves nothing about the *state*: an
/// attacker can permute or pad the array, or switch to the sequence spelling,
/// and land on the same activation set with different bytes — or hide fields
/// in a document that still loads. This test asserts the real behaviour.
#[test]
fn the_wire_format_is_neither_canonical_nor_strict() {
    // F4a: duplicates are silently deduplicated…
    let dup: QPageRegistry =
        serde_json::from_str(r#"{"active":["Probabilistic","Hierarchical","Hierarchical"]}"#)
            .expect("duplicates are accepted today");
    assert_eq!(dup.active_count(), 2, "three entries became two, silently");
    // …and the input bytes are not what comes back out (re-ordered, deduped).
    assert_eq!(json(&dup), r#"{"active":["Hierarchical","Probabilistic"]}"#);

    // F4b: an entirely different spelling — serde's struct-as-sequence form —
    // is also accepted, so two unrelated byte strings denote one state.
    let as_seq: QPageRegistry =
        serde_json::from_str(r#"[["Hierarchical"]]"#).expect("sequence form is accepted today");
    assert!(as_seq.is_active(AdvancedQPageVariant::Hierarchical));
    assert_eq!(as_seq.active_count(), 1);
    let as_map: QPageRegistry = serde_json::from_str(r#"{"active":["Hierarchical"]}"#).unwrap();
    assert_eq!(json(&as_seq), json(&as_map), "two spellings, one state");

    // F5a: an unknown field is ignored (no `deny_unknown_fields`), so a
    // document carrying junk — or carrying a *newer* field this build does not
    // understand — loads as if it were clean.
    let extra: QPageRegistry =
        serde_json::from_str(r#"{"active":["CostBounded"],"tenant":"attacker","tier":"free"}"#)
            .expect("unknown fields are ignored today");
    assert_eq!(extra.active_count(), 1);
    assert!(extra.is_active(AdvancedQPageVariant::CostBounded));

    // F5b: …but the *empty* document fails, even though `QPageRegistry:
    // Default` and the crate documents "standard primitives work with an empty
    // registry". The field is not `#[serde(default)]`, so the one document a
    // rollback or a pre-registry snapshot would produce is the one rejected.
    let err = serde_json::from_str::<QPageRegistry>("{}").expect_err("`{}` is rejected today");
    assert!(
        err.to_string().contains("missing field `active`"),
        "unexpected error: {err}"
    );
    // The lax/strict asymmetry, stated as one assertion: junk loads, empty does not.
    assert!(serde_json::from_str::<QPageRegistry>(r#"{"nonsense":true}"#).is_err());
    assert!(serde_json::from_str::<QPageRegistry>(r#"{"active":[],"nonsense":true}"#).is_ok());

    // HELD: an unknown *variant* is refused (fail closed), and the error names
    // the ten legal spellings. Matching is case-sensitive.
    for bad in [
        r#"{"active":["Nope"]}"#,
        r#"{"active":["hierarchical"]}"#,
        r#"{"active":["HIERARCHICAL"]}"#,
        r#"{"active":["Hierarchical "]}"#,
        r#"{"active":[0]}"#,
        r#"{"active":null}"#,
    ] {
        assert!(
            serde_json::from_str::<QPageRegistry>(bad).is_err(),
            "must not deserialize: {bad}"
        );
    }

    // HELD (bounded state): a hostile document repeating one variant 50_000
    // times still collapses to a ten-element set — the registry itself is not
    // an amplification vector, whatever the input size.
    let flood = format!(
        r#"{{"active":[{}]}}"#,
        vec![r#""ExperimentalBridge""#; 50_000].join(",")
    );
    let flooded: QPageRegistry = serde_json::from_str(&flood).expect("dedupes");
    assert_eq!(flooded.active_count(), 1, "50k entries collapse to one");
    assert!(
        json(&flooded).len() < 64,
        "state stays tiny: {}",
        json(&flooded)
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 4. Per-tenant independence at scale
// ─────────────────────────────────────────────────────────────────────────

/// Fixed-seed LCG. No `rand`, no clock: the same 10_000 masks in debug, in
/// release, and on every machine.
fn lcg_next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn mask_for_tenant(seed: u64, tenant: u32) -> u32 {
    let mut s = seed ^ (u64::from(tenant).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    lcg_next(&mut s);
    ((lcg_next(&mut s) >> 33) as u32) % SUBSETS
}

/// 10_000 tenants in one real `Deployment`, each with a pseudo-random (fixed
/// seed) activation set. No tenant's set is disturbed by any other's; mutating
/// a sample of tenants leaves the other 9_900 exactly as they were; and clones
/// taken beforehand do not alias the live state. (This one holds — the sets
/// are plain owned `BTreeSet`s, so there is no sharing to break.)
#[test]
fn ten_thousand_tenants_keep_disjoint_activation_sets() {
    const N: u32 = 10_000;
    const SEED: u64 = 0x0BADC0DE_DEADBEEF;

    let mut d = Deployment::new();
    d.add_role("reader", &["memory.read"])
        .govern_tool("memory.recall", "memory.read");
    for t in 0..N {
        let mut state = TenantState::new(10);
        state.allow_model("claude-opus");
        let mask = mask_for_tenant(SEED, t);
        for (i, v) in ALL.iter().enumerate() {
            if bit(mask, i) {
                state.activate(*v);
            }
        }
        d.add_tenant(&format!("t-{t:05}"), state);
    }

    // Pass 1: every tenant reports exactly its own mask, and a snapshot clone
    // is taken while the deployment is live.
    let mut clones: Vec<QPageRegistry> = Vec::with_capacity(N as usize);
    for t in 0..N {
        let mask = mask_for_tenant(SEED, t);
        let state = d
            .tenant_mut(&format!("t-{t:05}"))
            .unwrap_or_else(|| panic!("tenant t-{t:05} vanished"));
        for (i, v) in ALL.iter().enumerate() {
            assert_eq!(
                state.qpages.is_active(*v),
                bit(mask, i),
                "t-{t:05}: {v:?} does not match its own seeded mask"
            );
        }
        assert_eq!(state.qpages.active_count(), mask.count_ones() as usize);
        clones.push(state.qpages.clone());
    }

    // Pass 2: hammer a strided sample — activate everything on every 97th
    // tenant, and clear everything on every 101st.
    for t in (0..N).step_by(97) {
        let state = d.tenant_mut(&format!("t-{t:05}")).unwrap();
        for v in ALL {
            state.activate(v);
        }
    }
    for t in (0..N).step_by(101) {
        let state = d.tenant_mut(&format!("t-{t:05}")).unwrap();
        for v in ALL {
            state.qpages.deactivate(v);
        }
    }

    // Pass 3: every untouched tenant is untouched; every touched tenant
    // changed in exactly the way it was told to; and no clone moved.
    for t in 0..N {
        let mask = mask_for_tenant(SEED, t);
        let saturated = t % 97 == 0;
        let cleared = t % 101 == 0;
        let state = d.tenant_mut(&format!("t-{t:05}")).unwrap();
        for (i, v) in ALL.iter().enumerate() {
            // The clearing pass runs second, so it wins where both hit.
            let want = if cleared {
                false
            } else if saturated {
                true
            } else {
                bit(mask, i)
            };
            assert_eq!(
                state.qpages.is_active(*v),
                want,
                "t-{t:05} (saturated={saturated}, cleared={cleared}): {v:?} was disturbed"
            );
        }
    }
    for (t, clone) in clones.iter().enumerate() {
        let mask = mask_for_tenant(SEED, t as u32);
        assert_eq!(
            json(clone),
            expected_json(mask),
            "clone of t-{t:05} aliased the live registry"
        );
    }
}

/// A clone is a copy, not a view — mutating either side leaves the other
/// alone, in both directions, for every subset. (This one holds.)
#[test]
fn cloning_a_registry_never_aliases_it() {
    for mask in 0..SUBSETS {
        let mut original = registry_for(mask);
        let mut copy = original.clone();
        assert_eq!(json(&copy), json(&original));

        for v in ALL {
            original.activate(v);
        }
        assert_eq!(
            json(&copy),
            expected_json(mask),
            "mutating the original moved the clone"
        );

        for v in ALL {
            copy.deactivate(v);
        }
        assert_eq!(copy.active_count(), 0);
        assert_eq!(
            original.active_count(),
            10,
            "mutating the clone moved the original"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 5. The composed path: all ten variants, both directions
// ─────────────────────────────────────────────────────────────────────────

/// The requirement, stated literally: for each of the ten variants, a tenant
/// that activated *exactly* that one forwards a call naming it and refuses a
/// call naming any of the other nine with `VariantNotActivated` — 10 x 10, both
/// directions. Refusals cost nothing; the one forward costs exactly its tokens.
/// (This one holds.)
#[test]
fn each_variant_is_refused_unless_that_exact_variant_is_activated() {
    for (activated_i, activated) in ALL.iter().enumerate() {
        let mut d = deployment_activating(1u32 << activated_i);
        for (probed_i, probed) in ALL.iter().enumerate() {
            let out = recall(
                &mut d,
                "alice",
                &format!("r-{activated_i}-{probed_i}"),
                Some(*probed),
                7,
            );
            if probed_i == activated_i {
                assert!(
                    out.is_forwarded(),
                    "tenant activated {activated:?} but a call naming it was {out:?}"
                );
            } else {
                assert_eq!(
                    out.refusal(),
                    Some(&Refusal::VariantNotActivated),
                    "tenant activated only {activated:?}; a call naming {probed:?} must be refused"
                );
            }
        }
        assert_eq!(
            d.spent("acme"),
            7,
            "exactly one call forwarded; the nine refusals must be free"
        );
    }
}

/// The exhaustive version of the same thing: all 1024 activation subsets, each
/// probed with all ten variants on the composed path. 10_240 admissions, and
/// the tenant's spend must equal the popcount of its subset — refusals are
/// free, forwards are billed once. (This one holds.)
#[test]
fn all_1024_subsets_gate_the_composed_path_exactly() {
    for mask in 0..SUBSETS {
        let mut d = deployment_activating(mask);
        for (i, v) in ALL.iter().enumerate() {
            let out = recall(&mut d, "alice", &format!("r-{mask}-{i}"), Some(*v), 1);
            if bit(mask, i) {
                assert!(
                    out.is_forwarded(),
                    "mask {mask:#012b}: {v:?} is active but {out:?}"
                );
            } else {
                assert_eq!(
                    out.refusal(),
                    Some(&Refusal::VariantNotActivated),
                    "mask {mask:#012b}: {v:?} is inactive and must be refused"
                );
            }
        }
        assert_eq!(
            d.spent("acme"),
            u64::from(mask.count_ones()),
            "mask {mask:#012b}: spend must equal the number of forwarded calls"
        );
        assert_eq!(d.audit().len(), 10, "every decision is journaled");
    }
}

/// FINDING F7 (missing-behaviour): the variant is **caller-declared**. Nothing
/// in the product binds a tool, a permission or a payload to a variant, so the
/// same governed tool call sails through with `variant: None` on a tenant that
/// has activated *nothing* — including a tool literally named for the feature.
/// The Q-Page gate is opt-in for the caller, which is the wrong party.
#[test]
fn omitting_the_variant_bypasses_the_gate_entirely() {
    let mut d = deployment_activating(0); // nothing activated at all
    let a = actor("acme-org", "alice", AuthStrength::Token);

    // A tool named for the feature, on a tenant with zero activations: forwarded.
    let req = request("acme", "alice", "ccos.qpage.read", "q-none");
    let out = d.admit(Call {
        actor: &a,
        request: &req,
        model: "claude-opus",
        cost_tokens: 1,
        variant: None,
    });
    assert!(
        out.is_forwarded(),
        "a Q-Page tool traverses without any activation when the caller stays quiet: {out:?}"
    );

    // The *same* tool, same tenant, same actor — refused only because the
    // caller volunteered the variant. Honesty is the only thing being gated.
    let req = request("acme", "alice", "ccos.qpage.read", "q-declared");
    let out = d.admit(Call {
        actor: &a,
        request: &req,
        model: "claude-opus",
        cost_tokens: 1,
        variant: Some(AdvancedQPageVariant::Hierarchical),
    });
    assert_eq!(out.refusal(), Some(&Refusal::VariantNotActivated));
    assert_eq!(d.spent("acme"), 1, "only the bypassing call was billed");
}

/// FINDING F1 (missing-behaviour): activation has no semantics. Two
/// deployments — one with all ten variants active, one with none — produce
/// *identical* outcomes, identical spend and identical metrics for a script of
/// calls that does not name a variant. `CostBounded` does not bound cost,
/// `TemporalWindowed` opens no window, `AuthorityWeighted` weighs nothing.
/// A buyer paying for "ten advanced Q-Page variants" is buying ten booleans.
#[test]
fn ten_active_variants_are_indistinguishable_from_none() {
    let script: [(&str, &str, &str, u64); 6] = [
        ("alice", "memory.recall", "claude-opus", 10), // forwarded
        ("alice", "memory.ingest", "claude-opus", 10), // forwarded
        ("bob", "memory.ingest", "claude-opus", 10),   // permission denied
        ("alice", "memory.recall", "gpt-5", 10),       // model not allowed
        ("alice", "shell.exec", "claude-opus", 10),    // outside boundary
        ("alice", "memory.recall", "claude-opus", 999_999), // budget exhausted
    ];

    let run = |mask: u32| -> (Vec<Outcome>, u64, Vec<(String, u64)>) {
        let mut d = deployment_activating(mask);
        let outcomes = script
            .iter()
            .enumerate()
            .map(|(i, (who, tool, model, cost))| {
                let a = actor("acme-org", who, AuthStrength::Token);
                let req = request("acme", who, tool, &format!("s-{i}"));
                d.admit(Call {
                    actor: &a,
                    request: &req,
                    model,
                    cost_tokens: *cost,
                    variant: None,
                })
            })
            .collect();
        (outcomes, d.spent("acme"), d.metrics())
    };

    let (none_out, none_spent, none_metrics) = run(0);
    let (all_out, all_spent, all_metrics) = run(SUBSETS - 1);

    assert_eq!(
        none_out, all_out,
        "activating all ten advanced variants changed no outcome"
    );
    assert_eq!(none_spent, all_spent, "activation changed no cost");
    assert_eq!(none_metrics, all_metrics, "activation changed no metric");
    // And the outcomes really were a meaningful spread, not six refusals.
    assert!(none_out[0].is_forwarded() && none_out[1].is_forwarded());
    assert_eq!(none_out[2].refusal(), Some(&Refusal::PermissionDenied));
    assert_eq!(none_out[3].refusal(), Some(&Refusal::ModelNotAllowed));
    assert!(matches!(
        none_out[4].refusal(),
        Some(Refusal::OutsideBoundary(_))
    ));
    assert_eq!(none_out[5].refusal(), Some(&Refusal::BudgetExhausted));
}

/// FINDING F2 (missing-behaviour): the audit journal does not record which
/// variant a call used. Here two calls — one on `ExperimentalBridge`, one on
/// Core's standard primitives — are journaled as *equal* `AuditRecord`s.
/// `docs/COGNITIVE_AUDIT.md` and the crate's own "auditable tenant decision"
/// cannot be satisfied by a record that omits the governed attribute.
#[test]
fn the_audit_trail_cannot_tell_an_experimental_call_from_a_standard_one() {
    let mut d = deployment_activating(SUBSETS - 1);
    let a = actor("acme-org", "alice", AuthStrength::Token);

    // Deliberately the same request_id, so the records are comparable in full.
    let req = request("acme", "alice", "memory.recall", "same-id");
    let experimental = d.admit(Call {
        actor: &a,
        request: &req,
        model: "claude-opus",
        cost_tokens: 1,
        variant: Some(AdvancedQPageVariant::ExperimentalBridge),
    });
    let standard = d.admit(Call {
        actor: &a,
        request: &req,
        model: "claude-opus",
        cost_tokens: 1,
        variant: None,
    });
    assert!(experimental.is_forwarded() && standard.is_forwarded());

    let records = d.audit();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records[0], records[1],
        "the journal is blind to the variant: an ExperimentalBridge call and a \
         standard-primitive call are the same record"
    );

    // …and the replay is not idempotent either, despite `request_id` being
    // documented as an "idempotency/correlation key": the same id was billed
    // twice.
    assert_eq!(d.spent("acme"), 2, "the same request_id was charged twice");
}

/// FINDING F3 (spec-violation): the crate documents activation as "an
/// explicit, auditable tenant decision" and the README as "policy-activated".
/// In fact activating all ten variants requires no authenticated actor, no
/// permission, no policy evaluation and no approval, and leaves no audit
/// record and no metric behind. The `policy.set` tool is governed by
/// `policy.admin`; the API that actually changes policy is not governed at all.
#[test]
fn activation_needs_no_privilege_and_leaves_no_trace() {
    let mut d = deployment_activating(0);

    // No actor, no permission check, no `PolicyDecision`, no approval.
    let state = d.tenant_mut("acme").expect("tenant exists");
    for v in ALL {
        state.activate(v);
    }
    assert_eq!(d.tenant_mut("acme").unwrap().qpages.active_count(), 10);

    assert!(
        d.audit().is_empty(),
        "activating ten advanced variants produced {} audit records; the \
         documented 'auditable tenant decision' journals nothing",
        d.audit().len()
    );
    assert!(
        d.metrics().is_empty(),
        "activation is invisible to observability too: {:?}",
        d.metrics()
    );

    // And a plain `reader` — the least privileged role in the fixture — can
    // then use the experimental bridge. Variants are orthogonal to RBAC: there
    // is no `qpage.experimental` permission to hold or withhold.
    let out = recall(
        &mut d,
        "bob",
        "bob-experimental",
        Some(AdvancedQPageVariant::ExperimentalBridge),
        1,
    );
    assert!(
        out.is_forwarded(),
        "a reader reached ExperimentalBridge: {out:?}"
    );
}

/// FINDING F6 (exhaustion-vector): a `VariantNotActivated` refusal is free to
/// the caller — the budget is charged last, so nothing is billed — but it
/// appends an `AuditRecord` (four owned `String`s) to an unbounded `Vec`.
/// 25_000 refusals here; there is no cap, no rotation and no sampling, so an
/// unauthenticated-but-token-bearing client that knows one variant a tenant has
/// not activated can grow operator memory without limit at zero cost to itself.
///
/// The metrics registry, by contrast, holds: refusal tags are low-cardinality,
/// so the counter set stays at a handful of series (`CounterRegistry::MAX_SERIES`
/// is never approached). The journal is the vector, not the counters.
#[test]
fn free_refusals_grow_the_audit_journal_without_bound() {
    const N: usize = 25_000;
    let mut d = deployment_activating(0);

    for i in 0..N {
        let out = recall(
            &mut d,
            "alice",
            &format!("flood-{i}"),
            Some(AdvancedQPageVariant::ConsensusMediated),
            1_000_000_000,
        );
        if i % 5_000 == 0 {
            assert_eq!(out.refusal(), Some(&Refusal::VariantNotActivated));
        }
    }

    assert_eq!(
        d.spent("acme"),
        0,
        "25k refused calls cost the tenant nothing"
    );
    assert_eq!(
        d.audit().len(),
        N,
        "every free refusal is retained forever: the journal is unbounded"
    );
    assert_eq!(d.audit_of("acme").len(), N);

    let metrics = d.metrics();
    let refused = metrics
        .iter()
        .find(|(k, _)| k == "gateway.refused.variant_not_activated")
        .map(|(_, v)| *v);
    assert_eq!(refused, Some(N as u64));
    assert!(
        metrics.len() <= 4,
        "refusal tags stay low-cardinality (held): {metrics:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 6. What activation must never do
// ─────────────────────────────────────────────────────────────────────────

/// No activation — not all ten at once — widens the namespace boundary, the
/// model allowlist or the budget. The boundary is checked before any
/// tenant-configurable gate, and Q-Pages are tenant-configurable. (This one
/// holds, and is the single most important thing in this file.)
#[test]
fn no_activation_can_widen_the_boundary_the_allowlist_or_the_budget() {
    let mut d = deployment_activating(SUBSETS - 1);
    let a = actor("acme-org", "alice", AuthStrength::Token);

    for tool in [
        "rsi.status",
        "forge.run",
        "shell.exec",
        "self.modify",
        "patch.promote",
        "code.execute",
        "repository.modify",
        "slha.q",
        "octa.x",
    ] {
        for variant in [None, Some(AdvancedQPageVariant::ExperimentalBridge)] {
            let req = request("acme", "alice", tool, "boundary");
            let out = d.admit(Call {
                actor: &a,
                request: &req,
                model: "claude-opus",
                cost_tokens: 1,
                variant,
            });
            assert!(
                matches!(out.refusal(), Some(Refusal::OutsideBoundary(_))),
                "{tool} traversed with variants active: {out:?}"
            );
        }
    }

    // The model allowlist is likewise untouched by activation.
    let req = request("acme", "alice", "memory.recall", "model");
    let out = d.admit(Call {
        actor: &a,
        request: &req,
        model: "gpt-5",
        cost_tokens: 1,
        variant: Some(AdvancedQPageVariant::CostBounded),
    });
    assert_eq!(out.refusal(), Some(&Refusal::ModelNotAllowed));

    // …and so is the budget: `CostBounded` bounds nothing.
    let mut tight = Deployment::new();
    tight
        .add_role("writer", &["memory.read"])
        .govern_tool("memory.recall", "memory.read");
    let mut t = TenantState::new(5);
    t.allow_model("claude-opus");
    for v in ALL {
        t.activate(v);
    }
    tight.add_tenant("acme", t);
    tight.assign("alice", "writer");
    let out = recall(
        &mut tight,
        "alice",
        "over",
        Some(AdvancedQPageVariant::CostBounded),
        6,
    );
    assert_eq!(out.refusal(), Some(&Refusal::BudgetExhausted));
    assert_eq!(tight.spent("acme"), 0);
    assert_eq!(d.spent("acme"), 0, "nothing above was ever forwarded");
}

/// FINDING F1 (cont.): `MultiTenantFederated` is the one variant whose name
/// makes an explicit cross-tenant promise — `docs/TENANCY_MODEL.md`:
/// "Cross-tenant federation is opt-in per Q-Page variant policy". Activating
/// it on *both* tenants federates nothing: the memory scopes stay disjoint.
/// That is the safe failure (no leak), but the feature does not exist.
#[test]
fn multi_tenant_federated_federates_nothing_and_leaks_nothing() {
    let scope =
        |tenant: &str, key: &str| TenantScope::new(TenantId(tenant.to_string()), key.to_string());

    let mut d = Deployment::new();
    d.add_role("writer", &["memory.read", "memory.write"])
        .govern_tool("memory.recall", "memory.read");
    for tenant in ["acme", "globex"] {
        let mut t = TenantState::new(100);
        t.allow_model("claude-opus")
            .activate(AdvancedQPageVariant::MultiTenantFederated);
        d.add_tenant(tenant, t);
    }
    d.assign("alice", "writer");

    d.put(&scope("acme", "shared"), "acme's note");
    d.put(&scope("globex", "shared"), "globex's note");

    assert_eq!(d.get(&scope("acme", "shared")), Some("acme's note"));
    assert_eq!(d.get(&scope("globex", "shared")), Some("globex's note"));
    assert_eq!(d.cells_of("acme"), vec![("shared", "acme's note")]);
    assert_eq!(d.cells_of("globex"), vec![("shared", "globex's note")]);

    // Federation is not merely absent from the store — it is absent from the
    // admission path too: acme's activation grants globex's caller nothing,
    // and each tenant's registry is still its own.
    assert!(d
        .tenant_mut("globex")
        .unwrap()
        .qpages
        .is_active(AdvancedQPageVariant::MultiTenantFederated));
    assert!(!d
        .tenant_mut("globex")
        .unwrap()
        .qpages
        .is_active(AdvancedQPageVariant::Hierarchical));
    let a = actor("acme-org", "alice", AuthStrength::Token);
    let req = request("globex", "alice", "memory.recall", "fed");
    let out = d.admit(Call {
        actor: &a,
        request: &req,
        model: "claude-opus",
        cost_tokens: 1,
        variant: Some(AdvancedQPageVariant::Hierarchical),
    });
    assert_eq!(
        out.refusal(),
        Some(&Refusal::VariantNotActivated),
        "one tenant's activation must never satisfy another's gate"
    );
}

/// A deactivated variant stops working immediately on the composed path —
/// there is no cached admission, and the gate re-reads the live registry every
/// call. Exercised for all ten, both transitions. (This one holds.)
#[test]
fn deactivation_takes_effect_on_the_very_next_call() {
    for (i, v) in ALL.iter().enumerate() {
        let mut d = deployment_activating(1u32 << i);
        assert!(recall(&mut d, "alice", "before", Some(*v), 1).is_forwarded());

        d.tenant_mut("acme").unwrap().qpages.deactivate(*v);
        assert_eq!(
            recall(&mut d, "alice", "after", Some(*v), 1).refusal(),
            Some(&Refusal::VariantNotActivated),
            "{v:?} kept working after deactivation"
        );

        d.tenant_mut("acme").unwrap().activate(*v);
        assert!(
            recall(&mut d, "alice", "again", Some(*v), 1).is_forwarded(),
            "{v:?} did not come back"
        );
        assert_eq!(
            d.spent("acme"),
            2,
            "only the two forwarded calls were billed"
        );
    }
}

/// FINDING F9 (bug): `Deployment::add_tenant` is an unconditional
/// `BTreeMap::insert`, so re-adding an existing tenant — exactly what an
/// idempotent provisioning script does on a re-run — **silently discards its
/// entire Q-Page activation set**, its model allowlist, and its spend ledger.
/// There is no upsert/merge, no error, no audit record; the second call
/// returns `&mut Self` for chaining just like the first.
///
/// The ledger reset is the sharper edge: a tenant that had spent its whole
/// budget is returned to zero spend by a re-provision, which is a quota bypass
/// reachable without touching any gate.
#[test]
fn re_adding_a_tenant_silently_wipes_its_activations_and_its_ledger() {
    let mut d = deployment_activating(SUBSETS - 1);
    assert!(recall(
        &mut d,
        "alice",
        "spend",
        Some(AdvancedQPageVariant::CausalChain),
        900
    )
    .is_forwarded());
    assert_eq!(d.spent("acme"), 900);
    assert_eq!(d.tenant_mut("acme").unwrap().qpages.active_count(), 10);

    // A provisioning re-run: same name, fresh state. No error, no warning.
    let mut fresh = TenantState::new(1_000_000);
    fresh.allow_model("claude-opus");
    d.add_tenant("acme", fresh);

    assert_eq!(
        d.tenant_mut("acme").unwrap().qpages.active_count(),
        0,
        "ten activations vanished on re-provision"
    );
    assert_eq!(
        d.spent("acme"),
        0,
        "the spend ledger was reset by a re-provision: quota bypass"
    );
    // The tenant now refuses the variants it held a second ago…
    assert_eq!(
        recall(
            &mut d,
            "alice",
            "after",
            Some(AdvancedQPageVariant::CausalChain),
            1
        )
        .refusal(),
        Some(&Refusal::VariantNotActivated)
    );
    // …and the audit journal is the only place the old state is remembered at
    // all — it still shows the forwarded call whose spend has been erased.
    assert_eq!(d.audit().len(), 2);
    assert!(
        d.audit()[0].outcome.is_forwarded(),
        "the erased 900-token spend is still journaled as forwarded"
    );
}

/// FINDING F5 (cont.) + F8 (cont.): the *only* public way to enumerate a
/// tenant's activations is to serialize the registry and read the private
/// field's name back out of the JSON — there is no `active()`, no `iter()`, no
/// `Vec<AdvancedQPageVariant>` accessor. An operator dashboard listing "what
/// has this tenant switched on" is therefore coupled to a private field name
/// (`active`) that no API contract protects.
///
/// The same lax decoder (F4/F5) is what makes this consequential: `qpages` is
/// a public field on `TenantState`, so an attacker-shaped document — unknown
/// fields, duplicates, wrong order — deserializes and can be installed
/// wholesale onto a live tenant, and the composed path then honours it.
#[test]
fn enumeration_goes_through_a_private_field_name_and_junk_documents_install_cleanly() {
    let r = registry_for(0b1000000001); // Hierarchical + ExperimentalBridge
    let value: serde_json::Value = serde_json::to_value(&r).expect("Serialize");
    let listed: Vec<&str> = value["active"]
        .as_array()
        .expect("the only enumeration path is the private field's wire name")
        .iter()
        .map(|v| v.as_str().expect("variants encode as strings"))
        .collect();
    assert_eq!(listed, ["Hierarchical", "ExperimentalBridge"]);

    // A document that is out of order, duplicated, and carrying junk fields
    // loads without complaint and is installed on a live tenant.
    let hostile = r#"{"tier":"free","active":["ExperimentalBridge","ExperimentalBridge",
                      "ConsensusMediated"],"signature":"none"}"#;
    let injected: QPageRegistry = serde_json::from_str(hostile).expect("accepted today");
    let mut d = deployment_activating(0);
    d.tenant_mut("acme").unwrap().qpages = injected;

    assert!(recall(
        &mut d,
        "alice",
        "injected",
        Some(AdvancedQPageVariant::ExperimentalBridge),
        1
    )
    .is_forwarded());
    assert_eq!(
        recall(
            &mut d,
            "alice",
            "not-injected",
            Some(AdvancedQPageVariant::Hierarchical),
            1
        )
        .refusal(),
        Some(&Refusal::VariantNotActivated)
    );

    // HELD: the decoder does not blow the stack on a pathological document —
    // serde_json's recursion limit refuses deep nesting rather than crashing.
    let deep = format!("{}{}", "[".repeat(2_000), "]".repeat(2_000));
    assert!(
        serde_json::from_str::<QPageRegistry>(&deep).is_err(),
        "deeply nested input must be refused, not crash"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 7. Deep soak
// ─────────────────────────────────────────────────────────────────────────

/// Ten million activate/deactivate cycles plus a full re-serialization every
/// million: the registry must be exactly where it started. Kept in the default
/// run because a ten-element `BTreeSet` makes it cheap — ~1.8 s in debug,
/// ~0.1 s in release — and because "no drift under sustained churn" is worth
/// asserting at a scale a human would not repeat by hand.
///
/// Nothing in this file is `#[ignore]`d: the whole suite (22 tests, 1024
/// subsets, 10_000 tenants, 25_000 admissions, 10.1M cycles) finishes in about
/// two seconds in debug.
///
///   cargo test -p ccos-enterprise-conformance --test stress_qpages_exhaustive
#[test]
fn ten_million_cycles_leave_the_registry_identical() {
    let start_mask = 0b1100110011u32;
    let mut r = registry_for(start_mask);
    let before = json(&r);

    for step in 0..10_000_000u64 {
        let i = (step as usize) % ALL.len();
        let v = ALL[i];
        r.activate(v);
        if !bit(start_mask, i) {
            r.deactivate(v);
        }
        if step % 1_000_000 == 0 {
            assert_eq!(json(&r), before, "step {step}: drift");
        }
    }
    assert_eq!(json(&r), before);
    assert_eq!(r.active_count(), start_mask.count_ones() as usize);
}
