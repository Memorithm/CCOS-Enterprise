//! # Hostile stress: the advanced Q-Page registry, exhausted
//!
//! The product line is sold on "ten advanced Q-Page variants, policy-activated
//! per tenant" (`README.md` "Product boundary"; `docs/ENTERPRISE_COGNITIVE_GOVERNANCE.md`
//! "which Q-Page variants a tenant may activate"). Ten variants is a small
//! enough space to leave nothing to sampling, so this suite is *exhaustive*
//! rather than representative: every one of the 2^10 = 1024 activation subsets
//! is built, probed on all ten variants, serialized, round-tripped, and driven
//! through the composed admission path — which now lives in the shipped
//! `ccos-enterprise-runtime` crate rather than in a test harness, so everything
//! below guards code a customer actually runs.
//!
//! What that exhaustion establishes is still not flattering. The registry is a
//! `BTreeSet<AdvancedQPageVariant>` and **nothing more**: set membership is
//! the entire observable behaviour of all ten "advanced variants". The tests
//! below assert the *current, real* behaviour — including the places where it
//! falls short of what the documentation promises — and each such place is
//! flagged with a `FINDING:` comment naming what a buyer would expect instead.
//!
//! ## What was repaired (these tests are now regression guards)
//!
//! Each of the following pinned a defect that has since been fixed in the move
//! into `ccos-enterprise-runtime`. The scenario is unchanged and the inputs are
//! unchanged; only the expectation is flipped, so the repair cannot regress
//! without failing here.
//!
//! - **F9 (bug, REPAIRED)** — `Deployment::add_tenant` was a bare `insert`, so
//!   re-provisioning a live tenant silently discarded its activation set and
//!   **reset its spend ledger to zero** — a quota bypass that touched no gate.
//!   It now takes the owning org, returns `false` and changes nothing. Guarded
//!   by `re_adding_a_live_tenant_is_refused_and_keeps_its_activations_and_ledger`.
//! - **The credential/request hole (REPAIRED)** — the deployment authenticated
//!   one identity and authorized a *different, caller-supplied* one: the
//!   credential's org was carried and read by nothing, so every fixture in this
//!   file reached tenant `acme` with an org that owned nothing, and would have
//!   reached any other tenant just as easily. A request must now name the actor
//!   its credential proves ([`Refusal::ActorMismatch`]) and a tenant that
//!   actor's org owns ([`Refusal::TenantNotOwnedByOrg`]). Guarded by
//!   `no_credential_reaches_a_variant_it_does_not_own`, and by the ownership
//!   half of `re_adding_a_live_tenant_is_refused_and_keeps_its_activations_and_ledger`.
//! - **Replay double-billing (REPAIRED)** — `request_id` is documented as an
//!   "idempotency/correlation key" and was read by nothing, so a retried
//!   request was charged again every time. A `(tenant, request_id)` already
//!   decided now returns `Forwarded` without charging. Guarded by
//!   `a_replayed_request_id_is_never_billed_twice`; it used to be an aside in
//!   the F2 test, which now uses distinct ids so it keeps measuring F2.
//! - **F6 (exhaustion-vector, REPAIRED IN PART)** — a free `VariantNotActivated`
//!   refusal used to append an `AuditRecord` to an *unbounded* `Vec`, so a
//!   token-bearing client that knew one unactivated variant could grow operator
//!   memory without limit at zero cost. The journal is now a bounded buffer
//!   that drops its oldest records and **counts what it dropped**
//!   (`Deployment::audit_dropped`, plus an `audit.dropped` counter). What
//!   survives — refusals are still free to the attacker, and now cost the
//!   operator *journal completeness* instead of memory — is pinned by
//!   `free_refusals_are_bounded_by_the_journal_cap_and_counted`.
//! - **F5 (cont.) (REPAIRED)** — `TenantState::qpages` was `pub`, so a hostile
//!   registry document (unknown fields, duplicates, wrong order) could be
//!   deserialized and installed *wholesale* onto a live tenant, and the
//!   composed path honoured it. The field is private and there is no setter:
//!   the only door into a tenant's activation set is the typed builder, one
//!   variant at a time. Guarded by
//!   `enumeration_goes_through_a_private_field_name_and_hostile_documents_no_longer_install`.
//!
//! ## What is still open
//!
//! - F1 (missing-behaviour) — activation carries **no semantics**: a
//!   deployment with all ten variants active is byte-for-byte indistinguishable
//!   from one with none, for every call that does not name a variant.
//! - F2 (missing-behaviour) — the audit journal never records **which** variant
//!   a forwarded call used; two calls, one on `ExperimentalBridge` and one on
//!   Core's standard primitives, produce records that differ only in their
//!   sequence and their request id.
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
//! - F7 (missing-behaviour) — the variant is **caller-declared**: nothing binds
//!   a tool to a variant, so omitting `variant` skips the gate entirely.
//! - F8 (missing-behaviour, WIDENED) — no `ALL`/iterator/`FromStr`/`Display` on
//!   the enum, and no way to *list* a tenant's activations. Closing F5 (cont.)
//!   closed the read path too: `TenantState` now exposes `activate` and nothing
//!   that reads back, so a tenant's activation set is observable only by
//!   driving admissions against it and watching which ones are refused. That is
//!   what several tests below now do, and it is not what an operator dashboard
//!   can do.
//! - F10 (missing-behaviour, NEW) — **revocation is unreachable**. `TenantState`
//!   has `activate` and no `deactivate`, `qpages` is private, and `add_tenant`
//!   now refuses to replace a live tenant — so once a tenant activates a
//!   variant, nothing in the shipped API takes it away short of rebuilding the
//!   whole `Deployment`. `QPageRegistry::deactivate` still exists; no live
//!   tenant can be reached through it. Pinned by
//!   `activation_takes_effect_on_the_very_next_call_but_revocation_is_unreachable`.
//!
//! Everything here is deterministic: fixed masks, a fixed-seed LCG, no clock,
//! no threads, no RNG. It passes identically in debug and release.

use ccos_enterprise_auth::AuthStrength;
use ccos_enterprise_conformance::{
    actor, request, AuditRecord, Call, Deployment, Outcome, Refusal, TenantState,
    DEFAULT_AUDIT_CAPACITY,
};
use ccos_enterprise_qpages::{AdvancedQPageVariant, QPageRegistry};
use ccos_enterprise_tenancy::{TenantId, TenantScope};

/// The organization that owns every tenant this file provisions.
///
/// It exists because the credential now binds the request: an actor reaches a
/// tenant only if its credential's org owns that tenant. Before the repair this
/// file passed `"acme-org"` at every call site and the deployment never read
/// it, which is precisely the hole
/// `no_credential_reaches_a_variant_it_does_not_own` now guards.
const ORG: &str = "memorithm";

/// An organization that owns nothing in these fixtures, for the refusal side.
const FOREIGN_ORG: &str = "initech";

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

/// Build a **standalone** registry for `mask`, activating in ascending
/// declaration order. The pure set-semantics tests use this and never build a
/// `Deployment`: a `TenantState`'s registry is private now, and set semantics
/// never needed an admission path to be interesting.
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
    deployment_activating_capped(mask, DEFAULT_AUDIT_CAPACITY)
}

/// As above, with an explicit journal capacity. The journal is a **bounded**
/// buffer now (see F6 in the header), so a test that cares about the bound
/// picks a capacity it can reach, and a test that does not care about the
/// journal at all picks one that keeps its memory flat.
fn deployment_activating_capped(mask: u32, audit_capacity: usize) -> Deployment {
    let mut d = Deployment::new().with_audit_capacity(audit_capacity);
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
    assert!(
        d.add_tenant(ORG, "acme", t),
        "a fresh deployment must accept its first tenant"
    );
    d.assign("alice", "writer");
    d.assign("bob", "reader");
    d
}

/// One `memory.recall` against `tenant`, optionally naming a variant.
///
/// The credential names the same actor the request does and belongs to the org
/// that owns the tenant, because that is now the *only* way to reach a gate at
/// all. Disagreeing pairs are the subject of
/// `no_credential_reaches_a_variant_it_does_not_own`, not of the fixture.
fn recall_on(
    d: &mut Deployment,
    tenant: &str,
    who: &str,
    id: &str,
    variant: Option<AdvancedQPageVariant>,
    cost: u64,
) -> Outcome {
    let a = actor(ORG, who, AuthStrength::Token);
    let req = request(tenant, who, "memory.recall", id);
    d.admit(Call {
        actor: &a,
        request: &req,
        model: "claude-opus",
        cost_tokens: cost,
        variant,
        justification: None,
    })
}

/// `recall_on` against this file's default tenant, `acme`.
fn recall(
    d: &mut Deployment,
    who: &str,
    id: &str,
    variant: Option<AdvancedQPageVariant>,
    cost: u64,
) -> Outcome {
    recall_on(d, "acme", who, id, variant, cost)
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
/// sampling, no shortcuts. Pure set semantics — no `Deployment` involved.
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

/// FINDING F4 (bug) + F5 (bug), both still open: the accepted wire format is
/// neither canonical nor strict, so "the registry round-trips" does not mean
/// "the bytes on disk determine the state, and only one spelling does".
///
/// A backup digest (`ccos-enterprise-backup::BackupManifest::digest`) taken
/// over a serialized registry therefore proves nothing about the *state*: an
/// attacker can permute or pad the array, or switch to the sequence spelling,
/// and land on the same activation set with different bytes — or hide fields
/// in a document that still loads. This test asserts the real behaviour.
///
/// What has changed is the blast radius, not the decoder: a decoded document
/// can no longer be installed on a live tenant (see
/// `enumeration_goes_through_a_private_field_name_and_hostile_documents_no_longer_install`),
/// so this is now a backup/restore-integrity finding rather than an injection
/// one.
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

fn tenant_name(t: u32) -> String {
    format!("t-{t:05}")
}

/// 10_000 tenants in one real `Deployment`, each with a pseudo-random (fixed
/// seed) activation set. No tenant's set is disturbed by any other's, and
/// mutating a strided sample leaves every other tenant exactly as it was.
/// (This one holds — the sets are plain owned `BTreeSet`s, so there is no
/// sharing to break.)
///
/// FINDING F8 (cont.): every assertion here used to read `state.qpages`
/// directly. That field is private now, and `TenantState` grew no reader, so
/// the only way to observe a tenant's activations is to drive an admission per
/// variant and watch which ones are refused — 100_000 admissions per pass to
/// learn 100_000 booleans that the process already holds in memory. The
/// clone-aliasing half of this test is no longer expressible at all (a live
/// tenant's registry cannot be cloned); `cloning_a_registry_never_aliases_it`
/// covers that exhaustively on standalone registries instead.
///
/// FINDING F10 (cont.): the old "clear everything on every 101st tenant" pass
/// is gone for the same reason — `TenantState` has no `deactivate`. Only the
/// saturating pass survives, because activation is the only direction the
/// shipped API offers.
#[test]
fn ten_thousand_tenants_keep_disjoint_activation_sets() {
    const N: u32 = 10_000;
    const SEED: u64 = 0x0BADC0DE_DEADBEEF;

    // The journal is not what this test measures, and 200_000 records is not a
    // useful thing for it to hold: keep none of them.
    let mut d = Deployment::new().with_audit_capacity(0);
    d.add_role("reader", &["memory.read"])
        .govern_tool("memory.recall", "memory.read");
    d.assign("alice", "reader");
    for t in 0..N {
        let mut state = TenantState::new(100);
        state.allow_model("claude-opus");
        let mask = mask_for_tenant(SEED, t);
        for (i, v) in ALL.iter().enumerate() {
            if bit(mask, i) {
                state.activate(*v);
            }
        }
        assert!(
            d.add_tenant(ORG, &tenant_name(t), state),
            "t-{t:05} must be provisioned exactly once"
        );
    }

    // Pass 1: every tenant reports exactly its own mask, and nothing else.
    for t in 0..N {
        let mask = mask_for_tenant(SEED, t);
        let name = tenant_name(t);
        for (i, v) in ALL.iter().enumerate() {
            let out = recall_on(&mut d, &name, "alice", &format!("p1-{t}-{i}"), Some(*v), 1);
            assert_eq!(
                out.is_forwarded(),
                bit(mask, i),
                "t-{t:05}: {v:?} does not match its own seeded mask: {out:?}"
            );
        }
        assert_eq!(
            d.spent(&name),
            Some(u64::from(mask.count_ones())),
            "t-{t:05}: spend must equal the number of active variants"
        );
    }

    // Pass 2: hammer a strided sample — activate everything on every 97th
    // tenant. (Clearing is unreachable; see F10 above.)
    for t in (0..N).step_by(97) {
        let state = d.tenant_mut(&tenant_name(t)).expect("provisioned above");
        for v in ALL {
            state.activate(v);
        }
    }

    // Pass 3: every untouched tenant is untouched, and every touched tenant
    // changed in exactly the way it was told to.
    for t in 0..N {
        let mask = mask_for_tenant(SEED, t);
        let saturated = t % 97 == 0;
        let name = tenant_name(t);
        for (i, v) in ALL.iter().enumerate() {
            let want = saturated || bit(mask, i);
            let out = recall_on(&mut d, &name, "alice", &format!("p3-{t}-{i}"), Some(*v), 1);
            assert_eq!(
                out.is_forwarded(),
                want,
                "t-{t:05} (saturated={saturated}): {v:?} was disturbed: {out:?}"
            );
        }
        let expected = if saturated {
            u64::from(mask.count_ones()) + 10
        } else {
            2 * u64::from(mask.count_ones())
        };
        assert_eq!(
            d.spent(&name),
            Some(expected),
            "t-{t:05}: another tenant's traffic was billed here"
        );
    }

    // A tenant this deployment never had is distinguishable from one that
    // spent nothing — `spent` returns `Option` for exactly this reason.
    assert_eq!(d.spent("t-99999"), None);
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
            Some(7),
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
            Some(u64::from(mask.count_ones())),
            "mask {mask:#012b}: spend must equal the number of forwarded calls"
        );
        assert_eq!(d.audit().count(), 10, "every decision is journaled");
        // The journal reconciles the meter, decision by decision: only the
        // forwarded calls carry a cost, and they sum to the tenant's spend.
        let billed: u64 = d.audit().map(|r| r.cost).sum();
        assert_eq!(Some(billed), d.spent("acme"));
    }
}

/// FINDING F7 (missing-behaviour), still open: the variant is
/// **caller-declared**. Nothing in the product binds a tool, a permission or a
/// payload to a variant, so the same governed tool call sails through with
/// `variant: None` on a tenant that has activated *nothing* — including a tool
/// literally named for the feature. The Q-Page gate is opt-in for the caller,
/// which is the wrong party.
#[test]
fn omitting_the_variant_bypasses_the_gate_entirely() {
    let mut d = deployment_activating(0); // nothing activated at all
    let a = actor(ORG, "alice", AuthStrength::Token);

    // A tool named for the feature, on a tenant with zero activations: forwarded.
    let req = request("acme", "alice", "ccos.qpage.read", "q-none");
    let out = d.admit(Call {
        actor: &a,
        request: &req,
        model: "claude-opus",
        cost_tokens: 1,
        variant: None,
        justification: None,
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
        justification: None,
    });
    assert_eq!(out.refusal(), Some(&Refusal::VariantNotActivated));
    assert_eq!(
        d.spent("acme"),
        Some(1),
        "only the bypassing call was billed"
    );
}

/// FINDING F1 (missing-behaviour), still open: activation has no semantics.
/// Two deployments — one with all ten variants active, one with none — produce
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

    let run = |mask: u32| -> (Vec<Outcome>, Option<u64>, Vec<(String, u64)>) {
        let mut d = deployment_activating(mask);
        let outcomes = script
            .iter()
            .enumerate()
            .map(|(i, (who, tool, model, cost))| {
                let a = actor(ORG, who, AuthStrength::Token);
                let req = request("acme", who, tool, &format!("s-{i}"));
                d.admit(Call {
                    actor: &a,
                    request: &req,
                    model,
                    cost_tokens: *cost,
                    variant: None,
                    justification: None,
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

/// FINDING F2 (missing-behaviour), still open: the audit journal does not
/// record which variant a call used. Here two calls — one on
/// `ExperimentalBridge`, one on Core's standard primitives — are journaled as
/// records that differ **only** in the two fields that identify the *call*
/// (its sequence and its request id) and in nothing that identifies what was
/// governed. `docs/COGNITIVE_AUDIT.md` and the crate's own "auditable tenant
/// decision" cannot be satisfied by a record that omits the governed attribute.
///
/// The record grew `sequence` and `cost` in the repair, which is why this test
/// no longer compares the two records with a bare `==`: those two fields now
/// carry real information, and the point being made is that *none* of it is
/// about the variant. The two calls also carry distinct request ids now — the
/// old spelling reused one id to make the records comparable in full, which
/// replay suppression would today turn into a test of replay rather than of
/// the journal (that is `a_replayed_request_id_is_never_billed_twice`).
#[test]
fn the_audit_trail_cannot_tell_an_experimental_call_from_a_standard_one() {
    let mut d = deployment_activating(SUBSETS - 1);
    let a = actor(ORG, "alice", AuthStrength::Token);

    let experimental_req = request("acme", "alice", "memory.recall", "variant-experimental");
    let experimental = d.admit(Call {
        actor: &a,
        request: &experimental_req,
        model: "claude-opus",
        cost_tokens: 1,
        variant: Some(AdvancedQPageVariant::ExperimentalBridge),
        justification: None,
    });
    let standard_req = request("acme", "alice", "memory.recall", "variant-standard");
    let standard = d.admit(Call {
        actor: &a,
        request: &standard_req,
        model: "claude-opus",
        cost_tokens: 1,
        variant: None,
        justification: None,
    });
    assert!(experimental.is_forwarded() && standard.is_forwarded());

    let trail: Vec<&AuditRecord> = d.audit().collect();
    assert_eq!(trail.len(), 2);
    assert_eq!(trail[0].tenant, trail[1].tenant);
    assert_eq!(trail[0].actor, trail[1].actor);
    assert_eq!(trail[0].tool, trail[1].tool);
    assert_eq!(trail[0].cost, trail[1].cost, "same tokens, same charge");
    assert_eq!(trail[0].outcome, trail[1].outcome);

    // Stated as one assertion: rewrite the two call-identifying fields and the
    // records are indistinguishable. Nothing in an `AuditRecord` names a
    // variant, so no journal reader can tell these two calls apart.
    let mut normalized = trail[0].clone();
    normalized.sequence = trail[1].sequence;
    normalized.request_id.clone_from(&trail[1].request_id);
    assert_eq!(
        &normalized, trail[1],
        "the journal is blind to the variant: an ExperimentalBridge call and a \
         standard-primitive call are the same record"
    );

    // The sequence is monotonic and the meter reconciles against the journal —
    // both of which the record gained in the repair.
    assert_eq!(trail[0].sequence + 1, trail[1].sequence);
    assert_eq!(d.spent("acme"), Some(2));
    let billed: u64 = trail.iter().map(|r| r.cost).sum();
    assert_eq!(Some(billed), d.spent("acme"));
}

/// REPAIRED (was an aside in the F2 test above, asserting the defect): the
/// `request_id` is documented as an "idempotency/correlation key" and nothing
/// read it, so **the same id was charged on every retry** — a client whose
/// connection dropped mid-call paid twice for one decision, and a retry loop
/// could drain a tenant's budget without ever presenting a new request.
///
/// A `(tenant, request_id)` already decided now returns its prior outcome
/// without charging again. This test is the regression guard: same inputs —
/// one id, five calls — opposite expectation.
#[test]
fn a_replayed_request_id_is_never_billed_twice() {
    let mut d = deployment_activating(SUBSETS - 1);
    let a = actor(ORG, "alice", AuthStrength::Token);
    let req = request("acme", "alice", "memory.recall", "same-id");
    for attempt in 0..5 {
        let out = d.admit(Call {
            actor: &a,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1,
            variant: Some(AdvancedQPageVariant::ExperimentalBridge),
            justification: None,
        });
        assert!(
            out.is_forwarded(),
            "attempt {attempt}: a replay returns the prior outcome, not a refusal: {out:?}"
        );
    }
    assert_eq!(
        d.spent("acme"),
        Some(1),
        "billed once, replayed four times: the same request_id is not a new call"
    );

    // Suppression is a billing rule, not a silence: every attempt is journaled,
    // and only the one that was charged carries a cost.
    assert_eq!(d.audit().count(), 5, "every attempt is still journaled");
    let costs: Vec<u64> = d.audit().map(|r| r.cost).collect();
    assert_eq!(costs, vec![1, 0, 0, 0, 0]);
    let billed: u64 = costs.iter().sum();
    assert_eq!(Some(billed), d.spent("acme"), "the journal reconciles");

    let replayed = d
        .metrics()
        .into_iter()
        .find(|(k, _)| k == "gateway.replayed")
        .map(|(_, v)| v);
    assert_eq!(replayed, Some(4), "and the suppression is observable");
}

/// FINDING F3 (spec-violation), still open: the crate documents activation as
/// "an explicit, auditable tenant decision" and the README as
/// "policy-activated". In fact activating all ten variants requires no
/// authenticated actor, no permission, no policy evaluation and no approval,
/// and leaves no audit record and no metric behind. The `policy.set` tool is
/// governed by `policy.admin`; the API that actually changes policy is not
/// governed at all.
#[test]
fn activation_needs_no_privilege_and_leaves_no_trace() {
    let mut d = deployment_activating(0);

    // No actor, no permission check, no `PolicyDecision`, no approval.
    let state = d.tenant_mut("acme").expect("tenant exists");
    for v in ALL {
        state.activate(v);
    }

    let journaled = d.audit().count();
    assert_eq!(
        journaled, 0,
        "activating ten advanced variants produced {journaled} audit records; the \
         documented 'auditable tenant decision' journals nothing",
    );
    assert!(
        d.metrics().is_empty(),
        "activation is invisible to observability too: {:?}",
        d.metrics()
    );

    // And a plain `reader` — the least privileged role in the fixture — can
    // then use every one of them, the experimental bridge included. Variants
    // are orthogonal to RBAC: there is no `qpage.experimental` permission to
    // hold or withhold. (Ten forwarded calls is also the only way left to
    // observe that all ten really did activate — F8.)
    for (i, v) in ALL.iter().enumerate() {
        let out = recall(&mut d, "bob", &format!("bob-{i}"), Some(*v), 1);
        assert!(out.is_forwarded(), "a reader reached {v:?}: {out:?}");
    }
    assert_eq!(d.spent("acme"), Some(10));
}

/// FINDING F6 (exhaustion-vector), REPAIRED IN PART — this test is now the
/// regression guard for the bound.
///
/// A `VariantNotActivated` refusal is free to the caller: the budget is charged
/// last, so nothing is billed. That half was correct and still is. What was
/// wrong is what it cost the *operator*: every refusal appended an
/// `AuditRecord` (four owned `String`s) to an unbounded `Vec`, so a
/// token-bearing client that knew one variant a tenant had not activated could
/// grow operator memory without limit at zero cost to itself — 25_000 refusals
/// here, and nothing capped it at 25 million.
///
/// The journal is now a bounded buffer: it drops its oldest records and says
/// exactly how many, through `audit_dropped()` and an `audit.dropped` counter.
/// The 25_000 free refusals still happen — that is F7/F1 territory, not this
/// test's — but they now cost bounded memory and an *announced* loss of journal
/// completeness rather than unbounded memory and a silent one.
///
/// The metrics registry holds, as it did: refusal tags are low-cardinality, so
/// the counter set stays at a handful of series (`CounterRegistry::MAX_SERIES`
/// is never approached).
#[test]
fn free_refusals_are_bounded_by_the_journal_cap_and_counted() {
    const N: usize = 25_000;
    const CAP: usize = 4_096;
    let mut d = deployment_activating_capped(0, CAP);

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
        Some(0),
        "25k refused calls still cost the tenant nothing"
    );
    assert_eq!(
        d.audit().count(),
        CAP,
        "the journal never grows past its cap: this is what was unbounded"
    );
    assert_eq!(
        d.audit_dropped(),
        (N - CAP) as u64,
        "and the loss is announced, not silent"
    );
    assert_eq!(d.audit_of("acme").len(), CAP);
    // The retained window is the newest, and still in decision order.
    let seqs: Vec<u64> = d.audit().map(|r| r.sequence).collect();
    assert_eq!(seqs, ((N - CAP) as u64..N as u64).collect::<Vec<_>>());
    // Every retained record is a free refusal: bounded memory did not start
    // billing anybody.
    for r in d.audit() {
        assert_eq!(r.outcome.refusal(), Some(&Refusal::VariantNotActivated));
        assert_eq!(r.cost, 0, "a refusal is never billed");
    }

    let metrics = d.metrics();
    let counter = |name: &str| {
        metrics
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| *v)
            .unwrap_or_default()
    };
    assert_eq!(counter("gateway.refused.variant_not_activated"), N as u64);
    assert_eq!(counter("audit.dropped"), (N - CAP) as u64);
    assert!(
        metrics.len() <= 4,
        "refusal tags stay low-cardinality (held): {metrics:?}"
    );

    // Below the cap nothing is dropped at all — the bound is the only thing
    // that truncates the journal, and the default cap is far above this run.
    let mut small = deployment_activating(0);
    for i in 0..1_000 {
        recall(
            &mut small,
            "alice",
            &format!("small-{i}"),
            Some(AdvancedQPageVariant::ConsensusMediated),
            1,
        );
    }
    let retained = small.audit().count();
    assert!(
        retained < DEFAULT_AUDIT_CAPACITY,
        "this run must stay under the default cap for the drop count to mean anything"
    );
    assert_eq!(retained, 1_000, "every decision below the cap is retained");
    assert_eq!(small.audit_dropped(), 0, "nothing is dropped below the cap");
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
    let a = actor(ORG, "alice", AuthStrength::Token);

    for (n, tool) in [
        "rsi.status",
        "forge.run",
        "shell.exec",
        "self.modify",
        "patch.promote",
        "code.execute",
        "repository.modify",
        "slha.q",
        "octa.x",
    ]
    .iter()
    .enumerate()
    {
        for (m, variant) in [None, Some(AdvancedQPageVariant::ExperimentalBridge)]
            .into_iter()
            .enumerate()
        {
            let req = request("acme", "alice", tool, &format!("boundary-{n}-{m}"));
            let out = d.admit(Call {
                actor: &a,
                request: &req,
                model: "claude-opus",
                cost_tokens: 1,
                variant,
                justification: None,
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
        justification: None,
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
    assert!(tight.add_tenant(ORG, "acme", t));
    tight.assign("alice", "writer");
    let out = recall(
        &mut tight,
        "alice",
        "over",
        Some(AdvancedQPageVariant::CostBounded),
        6,
    );
    assert_eq!(out.refusal(), Some(&Refusal::BudgetExhausted));
    assert_eq!(tight.spent("acme"), Some(0));
    assert_eq!(d.spent("acme"), Some(0), "nothing above was ever forwarded");
}

/// REPAIRED — the credential now binds the request, and no activation widens
/// that either.
///
/// Every fixture in this file used to hand `admit` a credential for the org
/// `"acme-org"`, which owned nothing, and a request naming whatever tenant and
/// whatever actor it liked. The deployment read only the credential's
/// *strength*: it then keyed RBAC on `request.actor` — a plain client string —
/// and resolved the tenant from `request.tenant`. Nothing bound them, so a
/// token-bearing principal could present another actor's name and another
/// tenant's id and act with their permissions, against their budget, over their
/// activated variants. Neither call below reached the Q-Page gate at all now,
/// and neither cost the tenant anything.
///
/// This is the most valuable assertion in the file: the impersonations are kept
/// verbatim and asserted to be refused.
#[test]
fn no_credential_reaches_a_variant_it_does_not_own() {
    let mut d = deployment_activating(SUBSETS - 1); // acme has all ten active
    d.assign("mallory", "writer");

    // 1. bob authenticates honestly and then claims to be alice, who can write
    //    — and asks for a variant acme really has activated.
    let bob = actor(ORG, "bob", AuthStrength::Token);
    let impersonation = request("acme", "alice", "memory.recall", "impersonation");
    let out = d.admit(Call {
        actor: &bob,
        request: &impersonation,
        model: "claude-opus",
        cost_tokens: 1,
        variant: Some(AdvancedQPageVariant::Hierarchical),
        justification: None,
    });
    assert_eq!(
        out.refusal(),
        Some(&Refusal::ActorMismatch),
        "a request may not name an actor its credential does not prove"
    );

    // 2. mallory is genuinely authenticated, and genuinely in another org.
    //    `MultiTenantFederated` being active on acme buys her nothing.
    let mallory = actor(FOREIGN_ORG, "mallory", AuthStrength::Token);
    let cross_org = request("acme", "mallory", "memory.recall", "cross-org");
    let out = d.admit(Call {
        actor: &mallory,
        request: &cross_org,
        model: "claude-opus",
        cost_tokens: 1,
        variant: Some(AdvancedQPageVariant::MultiTenantFederated),
        justification: None,
    });
    assert_eq!(
        out.refusal(),
        Some(&Refusal::TenantNotOwnedByOrg),
        "an org may not reach a tenant it does not own, however federated"
    );

    // 3. An unauthenticated caller does not get there either, activation or no.
    let anon = actor(ORG, "alice", AuthStrength::Anonymous);
    let anon_req = request("acme", "alice", "memory.recall", "anon");
    let out = d.admit(Call {
        actor: &anon,
        request: &anon_req,
        model: "claude-opus",
        cost_tokens: 1,
        variant: Some(AdvancedQPageVariant::Hierarchical),
        justification: None,
    });
    assert_eq!(out.refusal(), Some(&Refusal::Unauthenticated));

    // None of the three was billed, and none of them reached the Q-Page gate:
    // the credential is checked before any tenant state is touched, so the
    // refusal never says whether the variant was activated.
    assert_eq!(d.spent("acme"), Some(0), "impersonation costs nothing");
    for r in d.audit() {
        assert_eq!(r.cost, 0);
        assert_ne!(
            r.outcome.refusal(),
            Some(&Refusal::VariantNotActivated),
            "the credential gates run before the variant gate"
        );
    }
    let metrics = d.metrics();
    let counter = |name: &str| {
        metrics
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| *v)
            .unwrap_or_default()
    };
    assert_eq!(counter("gateway.refused.actor_mismatch"), 1);
    assert_eq!(counter("gateway.refused.tenant_not_owned"), 1);
    assert_eq!(counter("gateway.refused.unauthenticated"), 1);
    assert_eq!(counter("gateway.forwarded"), 0);
}

/// FINDING F1 (cont.), still open: `MultiTenantFederated` is the one variant
/// whose name makes an explicit cross-tenant promise —
/// `docs/TENANCY_MODEL.md`: "Cross-tenant federation is opt-in per Q-Page
/// variant policy". Activating it on *both* tenants federates nothing: the
/// memory scopes stay disjoint. That is the safe failure (no leak), but the
/// feature does not exist.
///
/// Both tenants are owned by one org here, exactly as the shipped
/// `two_tenant_deployment` fixture has it, so alice legitimately reaches both
/// — the point being made is about *activation*, not about ownership, and a
/// caller who is refused at the credential gate would prove nothing about
/// federation. (Ownership is `no_credential_reaches_a_variant_it_does_not_own`.)
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
        assert!(d.add_tenant(ORG, tenant, t));
    }
    d.assign("alice", "writer");

    d.put(&scope("acme", "shared"), "acme's note");
    d.put(&scope("globex", "shared"), "globex's note");

    assert_eq!(d.get(&scope("acme", "shared")), Some("acme's note"));
    assert_eq!(d.get(&scope("globex", "shared")), Some("globex's note"));
    assert_eq!(d.cells_of("acme"), vec![("shared", "acme's note")]);
    assert_eq!(d.cells_of("globex"), vec![("shared", "globex's note")]);

    // Federation is not merely absent from the store — it is absent from the
    // admission path too. Each tenant's registry is still its own: globex
    // honours the variant globex activated…
    assert!(recall_on(
        &mut d,
        "globex",
        "alice",
        "fed-own",
        Some(AdvancedQPageVariant::MultiTenantFederated),
        1
    )
    .is_forwarded());
    // …and nothing else, however federated either side claims to be.
    assert_eq!(
        recall_on(
            &mut d,
            "globex",
            "alice",
            "fed",
            Some(AdvancedQPageVariant::Hierarchical),
            1
        )
        .refusal(),
        Some(&Refusal::VariantNotActivated),
        "one tenant's activation must never satisfy another's gate"
    );
    // Activating Hierarchical on acme does not retroactively satisfy globex's
    // gate either: the registries are per-tenant, and stay that way.
    d.tenant_mut("acme")
        .expect("acme exists")
        .activate(AdvancedQPageVariant::Hierarchical);
    assert_eq!(
        recall_on(
            &mut d,
            "globex",
            "alice",
            "fed-after",
            Some(AdvancedQPageVariant::Hierarchical),
            1
        )
        .refusal(),
        Some(&Refusal::VariantNotActivated),
        "acme's activation leaked into globex's registry"
    );
    assert!(recall_on(
        &mut d,
        "acme",
        "alice",
        "own-after",
        Some(AdvancedQPageVariant::Hierarchical),
        1
    )
    .is_forwarded());
    // Each tenant paid for exactly its own forwarded call.
    assert_eq!(d.spent("acme"), Some(1));
    assert_eq!(d.spent("globex"), Some(1));
}

/// The gate re-reads the tenant's live registry on every call: there is no
/// cached admission, so an activation applied between two calls takes effect on
/// the very next one. Exercised for all ten. (This one holds.)
///
/// FINDING F10 (missing-behaviour, NEW): the *reverse* transition — which this
/// test used to drive, because `TenantState::qpages` was public — is no longer
/// expressible. `TenantState` exposes `activate` and no `deactivate`, `qpages`
/// is private, and `add_tenant` now refuses to replace a live tenant, so once a
/// tenant has activated a variant nothing in the shipped API takes it away
/// short of rebuilding the whole `Deployment`. Revocation is a routine operator
/// action — a trial expires, a variant is withdrawn, a tenant downgrades — and
/// the product has no way to perform it. The set itself still supports it
/// (`QPageRegistry::deactivate`, asserted below on a standalone registry); no
/// live tenant can be reached through it, which is asserted here too.
#[test]
fn activation_takes_effect_on_the_very_next_call_but_revocation_is_unreachable() {
    for (i, v) in ALL.iter().enumerate() {
        // Everything active EXCEPT v, so only v's transition is under test.
        let mut d = deployment_activating((SUBSETS - 1) & !(1u32 << i));
        assert_eq!(
            recall(&mut d, "alice", "before", Some(*v), 1).refusal(),
            Some(&Refusal::VariantNotActivated),
            "{v:?} was refused before it was activated"
        );

        d.tenant_mut("acme").expect("tenant exists").activate(*v);
        assert!(
            recall(&mut d, "alice", "after", Some(*v), 1).is_forwarded(),
            "{v:?} did not take effect on the very next call"
        );
        assert_eq!(
            d.spent("acme"),
            Some(1),
            "only the one forwarded call was billed"
        );

        // F10: the only `deactivate` the product exposes is on a standalone
        // registry, which no live tenant can be reached through — revoking a
        // variant on a copy leaves the tenant using it.
        let mut standalone = registry_for(1u32 << i);
        standalone.deactivate(*v);
        assert!(!standalone.is_active(*v), "the set itself can revoke");
        assert!(
            recall(&mut d, "alice", "still-live", Some(*v), 1).is_forwarded(),
            "{v:?} was revoked on a copy nobody can install, and stayed live"
        );
        assert_eq!(d.spent("acme"), Some(2));
    }
}

/// FINDING F9 (bug), REPAIRED — this test is now the regression guard.
///
/// `Deployment::add_tenant` was an unconditional `BTreeMap::insert`, so
/// re-adding an existing tenant — exactly what an idempotent provisioning
/// script does on a re-run — **silently discarded its entire Q-Page activation
/// set**, its model allowlist, and its spend ledger. There was no upsert, no
/// merge, no error and no audit record; the second call returned `&mut Self`
/// for chaining just like the first. The ledger reset was the sharper edge: a
/// tenant that had spent its whole budget was returned to zero spend by a
/// re-provision, which is a quota bypass reachable without touching any gate.
///
/// It now takes the owning org, returns `false` for a tenant that already
/// exists, and changes nothing. Same scenario, same inputs, opposite
/// expectation — including the ownership half, which is new: a second
/// `add_tenant` under a *different* org cannot re-home a live tenant either,
/// which would otherwise have been a way to hand a tenant to an attacker's org.
#[test]
fn re_adding_a_live_tenant_is_refused_and_keeps_its_activations_and_ledger() {
    let mut d = deployment_activating(SUBSETS - 1);
    assert!(recall(
        &mut d,
        "alice",
        "spend",
        Some(AdvancedQPageVariant::CausalChain),
        900
    )
    .is_forwarded());
    assert_eq!(d.spent("acme"), Some(900));

    // A provisioning re-run: same name, fresh state. Refused, loudly.
    let mut fresh = TenantState::new(1_000_000);
    fresh.allow_model("claude-opus");
    assert!(
        !d.add_tenant(ORG, "acme", fresh),
        "a live tenant is never silently replaced"
    );

    assert_eq!(
        d.spent("acme"),
        Some(900),
        "the spend ledger survived the re-provision: no quota bypass"
    );
    // The activations survived too — the variant it held a moment ago still
    // forwards, where the old behaviour refused it.
    assert!(
        recall(
            &mut d,
            "alice",
            "after",
            Some(AdvancedQPageVariant::CausalChain),
            1
        )
        .is_forwarded(),
        "ten activations must not vanish on a re-provision"
    );
    assert_eq!(d.spent("acme"), Some(901), "the meter kept counting");

    // Nor can a re-provision re-home the tenant into another org: ownership is
    // established once, by the call that created the tenant.
    let mut hijack = TenantState::new(1_000_000);
    hijack.allow_model("claude-opus");
    assert!(
        !d.add_tenant(FOREIGN_ORG, "acme", hijack),
        "a live tenant is not re-homed by re-provisioning it"
    );
    d.assign("mallory", "writer");
    let mallory = actor(FOREIGN_ORG, "mallory", AuthStrength::Token);
    let req = request("acme", "mallory", "memory.recall", "hijack");
    assert_eq!(
        d.admit(Call {
            actor: &mallory,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
            justification: None,
        })
        .refusal(),
        Some(&Refusal::TenantNotOwnedByOrg),
        "the tenant still belongs to the org that provisioned it"
    );

    // The journal shows all three decisions, and the 900-token spend it
    // recorded is still the spend the meter reports.
    let trail: Vec<&AuditRecord> = d.audit().collect();
    assert_eq!(trail.len(), 3);
    assert!(trail[0].outcome.is_forwarded());
    assert_eq!(trail[0].cost, 900);
    let billed: u64 = trail.iter().map(|r| r.cost).sum();
    assert_eq!(Some(billed), d.spent("acme"), "the journal reconciles");
}

/// FINDING F8 (cont.), still open — and FINDING F5 (cont.), REPAIRED.
///
/// Still open: the *only* public way to enumerate a registry's activations is
/// to serialize it and read the private field's name back out of the JSON —
/// there is no `active()`, no `iter()`, no `Vec<AdvancedQPageVariant>`
/// accessor. An operator dashboard listing "what has this tenant switched on"
/// is therefore coupled to a private field name (`active`) that no API contract
/// protects — and, since `TenantState::qpages` went private with no reader, a
/// dashboard cannot get at a live tenant's registry to serialize in the first
/// place.
///
/// Repaired: that same laxness used to be an injection vector.
/// `TenantState::qpages` was `pub`, so an attacker-shaped document — unknown
/// fields, duplicates, wrong order — deserialized and could be installed
/// *wholesale* onto a live tenant, and the composed path then honoured it. The
/// field is private and there is no setter: the only door into a tenant's
/// activation set is `TenantState::activate`, which takes a typed enum, one
/// variant at a time. The hostile document still decodes — that is F4/F5, and
/// it still matters for backup integrity — but decoding it now grants nothing.
#[test]
fn enumeration_goes_through_a_private_field_name_and_hostile_documents_no_longer_install() {
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
    // still loads without complaint…
    let hostile = r#"{"tier":"free","active":["ExperimentalBridge","ExperimentalBridge",
                      "ConsensusMediated"],"signature":"none"}"#;
    let injected: QPageRegistry = serde_json::from_str(hostile).expect("accepted today");
    assert_eq!(injected.active_count(), 2, "the decoder is still lax");
    assert!(injected.is_active(AdvancedQPageVariant::ExperimentalBridge));
    assert!(injected.is_active(AdvancedQPageVariant::ConsensusMediated));

    // …and buys nothing: there is no way to attach it to a live tenant, so a
    // tenant that activated nothing still refuses every variant the document
    // claimed.
    let mut d = deployment_activating(0);
    assert_eq!(
        recall(
            &mut d,
            "alice",
            "injected",
            Some(AdvancedQPageVariant::ExperimentalBridge),
            1
        )
        .refusal(),
        Some(&Refusal::VariantNotActivated),
        "a decoded document must not become a tenant's policy"
    );
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
    assert_eq!(
        d.spent("acme"),
        Some(0),
        "a decoded hostile document buys the caller nothing at all"
    );

    // The typed builder is the only door, and it is the one that works.
    d.tenant_mut("acme")
        .expect("tenant exists")
        .activate(AdvancedQPageVariant::ExperimentalBridge);
    assert!(recall(
        &mut d,
        "alice",
        "typed",
        Some(AdvancedQPageVariant::ExperimentalBridge),
        1
    )
    .is_forwarded());

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
/// Nothing in this file is `#[ignore]`d: the whole suite (24 tests, 1024
/// subsets, 10_000 tenants, 200_000 admissions, 10.1M cycles) finishes well
/// inside a minute in debug.
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
