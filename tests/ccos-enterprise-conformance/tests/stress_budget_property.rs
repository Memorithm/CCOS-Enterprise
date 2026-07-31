//! # Hostile property test of the budget ledger
//!
//! `ccos_enterprise_policy::TokenBudget` is the product's meter. Everything
//! commercial rests on it: quota enforcement, per-tenant billing, and the
//! `Refusal::BudgetExhausted` gate that `ccos_enterprise_runtime`'s module
//! docs call "charged **last**, so a call refused for any other reason costs
//! the tenant nothing".
//!
//! This file attacks the meter with hand-rolled property tests (fixed-seed
//! SplitMix64, no new dependencies, no wall-clock in any assertion) plus a
//! hand-built table of arithmetic edges, and then re-runs the same attacks
//! through the composed admission path — which now ships, in
//! `ccos_enterprise_runtime`, rather than living in this suite's own harness.
//!
//! ## The invariants under test
//!
//! 1. `spent` never exceeds `limit`;
//! 2. `spent` is monotonically non-decreasing;
//! 3. a `Deny` never moves `spent`;
//! 4. **equivalence** — after any sequence, the exact sum of every `Allow`ed
//!    charge equals `spent`.
//!
//! ## VERDICT
//!
//! Invariants 1–3 survive one million random charges against ten different
//! limits, including every saturation edge. **Invariant 4 is still BROKEN in
//! `TokenBudget` itself**, and it is still reachable from a single
//! caller-declared number. What was repaired is everything the *composition*
//! owned: who may spend a tenant's budget, whether a retry is billed twice,
//! whether the journal can check the meter, and whether the ledger can be
//! rewound behind the journal's back.
//!
//! ## What was repaired — every row below is now a REGRESSION GUARD
//!
//! | # | the defect, in the past tense | guard |
//! |---|-------------------------------|-------|
//! | 3 | `TenantState::budget` was `pub`, so `tenant_mut(..).budget.spent = 0` rewound the meter with nothing journaled; `add_tenant` was a bare `insert`, so re-provisioning a live tenant silently discarded its ledger. The ledger is now private and `add_tenant` returns `false` rather than clobbering. | [`the_ledger_is_private_and_a_live_tenant_is_never_reprovisioned`] |
//! | 4 | `AuditRecord` carried no cost, so **no** amount of auditing could reconcile the meter. It now carries `cost` (always `0` for a refusal) and a monotonic `sequence`. | [`the_audit_trail_reconciles_the_ledger`] |
//! | 5 | `request_id` was documented as an "Idempotency/correlation key" and nothing read it: a client-side retry after a timeout was admitted again and **billed** again. A decided `(tenant, request_id)` is now Forwarded without charging. | [`a_replayed_request_id_is_billed_once`] |
//! | 7 | The authenticated identity was never bound to `request.actor`/`request.tenant`, so any token-strength principal could drain **any** tenant's budget by naming it. The request must now name the actor its credential proves ([`Refusal::ActorMismatch`]) and a tenant that actor's org owns ([`Refusal::TenantNotOwnedByOrg`]). | [`no_authenticated_actor_can_drain_another_tenants_budget`] |
//! | 8 | `Deployment::spent` folded "no such tenant" into `0`, indistinguishable from "spent nothing". It now returns `Option<u64>`. | [`spent_distinguishes_an_unknown_tenant_from_an_empty_one`] |
//!
//! ## What is still BROKEN
//!
//! | # | defect | where |
//! |---|--------|-------|
//! | 1 | `limit == u64::MAX` ⇒ the ledger silently under-counts without bound: charges keep being `Allow`ed while `spent` stays pinned at `u64::MAX`. One call is enough to pin it forever. | [`unlimited_budget_undercounts_without_bound`] |
//! | 2 | `charge(0)` is `Allow` on an exhausted budget, so `cost_tokens: 0` is admitted for ever. The cost is **caller-declared** and never reconciled, so the budget gate is opt-in for an honest client. | [`a_zero_charge_is_allowed_forever_even_when_exhausted`] |
//! | 3b | The *unit-level* half of defect 3 survives the repair: `TokenBudget::{limit, spent}` are still `pub` in `ccos-enterprise-policy`, so the type can still be driven to `spent > limit`. The composed path no longer exposes that (the runtime's ledger is private), but any other holder of a `TokenBudget` can. | [`a_ledger_pushed_over_its_limit_denies_even_a_zero_charge`] |
//! | 6 | `TokenBudget` deserializes with no invariant check: a persisted/restored ledger may hold `spent > limit`, a state `charge` can never produce. This is now the *only* remaining route to that state. | [`a_deserialized_ledger_has_no_invariants`] |
//! | 9 | Case folding is inconsistent across the request path: the gateway folds tool names, the model allowlist and the governance map do not. | [`the_allowlist_is_case_sensitive_but_the_gateway_is_not`] |
//! | 10 | A refused charge is free and distinguishable, so the gate is still a zero-cost comparison oracle: ~20 probes read a tenant's exact remaining balance (and drain it). The credential binding **narrowed the blast radius to one organization** — a stranger's probe is now refused identically whatever it costs, which is asserted here — but any actor who shares the tenant still reads the number for free. | [`the_budget_gate_leaks_the_balance_to_anyone_who_shares_the_tenant`] |
//!
//! ## What is announced rather than fixed
//!
//! The audit journal is a **bounded** in-memory buffer now: past
//! `DEFAULT_AUDIT_CAPACITY` the oldest records are dropped and counted. That
//! is a deliberate, announced loss and not an audit story on its own, so this
//! file pins the half of it that is a *budget* question — the meter stays
//! exact across records the journal has thrown away, and the drop count is
//! what says the trail is incomplete rather than the tenant frugal. See
//! [`the_journal_is_bounded_and_the_meter_is_not`].
//!
//! Everything asserted below is the product's **current, real** behaviour.
//! Where that behaviour is a defect the assertion pins the defect and the
//! comment names it, so a future repair fails loudly here instead of silently
//! changing the accounting. Where a defect was repaired the assertion is
//! inverted and the scenario kept, so a regression fails just as loudly.

use std::collections::BTreeSet;

use ccos_enterprise_auth::AuthStrength;
use ccos_enterprise_conformance::{
    actor, request, two_tenant_deployment, AuditRecord, Call, Deployment, Outcome, Refusal,
    TenantState,
};
use ccos_enterprise_gateway::{classify, Disposition};
use ccos_enterprise_policy::{ModelAllowlist, PolicyDecision, TokenBudget};
use ccos_enterprise_qpages::AdvancedQPageVariant;

// ── Deterministic generator ──────────────────────────────────────────────
//
// SplitMix64. Fixed seed, no wall-clock, no OS entropy: identical sequence in
// debug and release, on every host, for ever.

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

    /// Uniform-enough in `0..n`; `n == 0` yields `0`.
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }
}

/// The seed every property test in this file starts from.
const SEED: u64 = 0x5EED_B0D9_1CE4_E5B9;

/// Limits chosen to hit every branch of `spent.saturating_add(t) > limit`:
/// the degenerate ones, a couple of ordinary ones, and the three that sit on
/// the saturation boundary.
const LIMITS: &[u64] = &[
    0,
    1,
    2,
    7,
    63,
    1_000,
    65_536,
    u32::MAX as u64,
    u64::MAX - 1,
    u64::MAX,
];

/// Charge magnitudes biased toward the edges: zero, one, tiny, "just over the
/// limit", "half the limit", `u64::MAX` and its neighbours, and full-range
/// noise. A uniform `u64` alone would essentially never produce an affordable
/// charge and the whole space would collapse to `Deny`.
fn charge_of(rng: &mut Rng, limit: u64) -> u64 {
    match rng.below(8) {
        0 => 0,
        1 => 1,
        2 => rng.below(16),
        3 => limit.saturating_add(1).max(1),
        4 => (limit / 2).saturating_add(rng.below(4)),
        5 => u64::MAX,
        6 => u64::MAX - rng.below(4),
        _ => rng.next_u64(),
    }
}

// ── 1. One million random charges ────────────────────────────────────────

/// One million random charges over twenty thousand independent ledgers,
/// against every limit in [`LIMITS`], checked against an independent `u128`
/// oracle that cannot overflow.
///
/// Invariants 1–3 hold everywhere. Invariant 4 — *sum of `Allow`ed charges ==
/// `spent`* — holds **iff** the ledger never saturated, and the test proves
/// that saturation is possible for exactly one limit: `u64::MAX`. Every
/// oracle divergence is forced to have that exact shape, so a divergence of
/// any other shape (a wrap, a fail-open at a finite limit, a `Deny` that
/// moves the meter) fails here immediately.
#[test]
fn one_million_random_charges_hold_the_ledger_invariants() {
    const TOTAL_CHARGES: u64 = 1_000_000;
    const SEQUENCE_LEN: u64 = 50;

    let mut rng = Rng::new(SEED);
    let mut charges = 0u64;
    let mut sequences = 0u64;
    let mut allows = 0u64;
    let mut denies = 0u64;
    let mut zero_charges = 0u64;
    let mut zero_charges_denied = 0u64;
    let mut divergences = 0u64;
    let mut exact_sequences = 0u64;
    let mut undercounted_sequences = 0u64;

    while charges < TOTAL_CHARGES {
        let limit = LIMITS[rng.below(LIMITS.len() as u64) as usize];
        let mut budget = TokenBudget::new(limit);
        assert_eq!(budget.spent, 0, "a fresh ledger starts empty");
        assert_eq!(budget.limit, limit, "and remembers its limit verbatim");

        // The exact, un-saturating sum of everything the gate admitted.
        let mut admitted: u128 = 0;
        let mut saturated = false;

        for _ in 0..SEQUENCE_LEN {
            let before = budget.spent;
            let tokens = charge_of(&mut rng, limit);
            if tokens == 0 {
                zero_charges += 1;
            }

            // Independent oracle in u128: no overflow is possible here, so it
            // states what the gate *should* decide, unconditionally.
            let oracle = if u128::from(before) + u128::from(tokens) > u128::from(limit) {
                PolicyDecision::Deny
            } else {
                PolicyDecision::Allow
            };

            let got = budget.charge(tokens);
            charges += 1;

            // (1) spent never exceeds limit.
            assert!(
                budget.spent <= budget.limit,
                "ledger overran its limit: {} > {} after charging {tokens}",
                budget.spent,
                budget.limit
            );
            // (2) monotonically non-decreasing — a charge never refunds.
            assert!(
                budget.spent >= before,
                "ledger went backwards: {before} -> {} on charge {tokens}",
                budget.spent
            );
            // The limit is immutable for the ledger's whole life.
            assert_eq!(budget.limit, limit, "charge() must not move the limit");

            match got {
                PolicyDecision::Allow => {
                    allows += 1;
                    admitted += u128::from(tokens);
                }
                PolicyDecision::Deny => {
                    denies += 1;
                    if tokens == 0 {
                        zero_charges_denied += 1;
                    }
                    // (3) a Deny never moves the meter.
                    assert_eq!(
                        budget.spent, before,
                        "a denied charge of {tokens} moved the ledger"
                    );
                }
                PolicyDecision::RequireApproval => {
                    panic!("the budget gate is binary; RequireApproval is not one of its outcomes")
                }
            }

            // The meter can never run ahead of what was admitted.
            assert!(
                admitted >= u128::from(budget.spent),
                "ledger billed more than it admitted: spent {} > admitted {admitted}",
                budget.spent
            );

            if got != oracle {
                divergences += 1;
                saturated = true;
                // DEFECT 1 (high, billing integrity). The ONLY way the gate
                // disagrees with exact arithmetic is the `u64::MAX` limit:
                // `spent.saturating_add(t)` caps at `u64::MAX`, which is not
                // `> u64::MAX`, so the guard cannot fire and the charge is
                // admitted while the meter stays pinned.
                assert_eq!(
                    limit,
                    u64::MAX,
                    "a finite limit diverged from exact arithmetic: \
                     limit {limit}, spent {before}, charge {tokens}"
                );
                assert_eq!(
                    got,
                    PolicyDecision::Allow,
                    "divergence is always fail-OPEN, never fail-closed"
                );
                assert!(
                    u128::from(before) + u128::from(tokens) > u128::from(u64::MAX),
                    "divergence requires the true sum to overflow u64"
                );
                assert_eq!(
                    budget.spent,
                    u64::MAX,
                    "and the meter is pinned at u64::MAX from then on"
                );
            }
        }

        // (4) Equivalence. Exact everywhere the ledger did not saturate;
        // strictly under-counting the moment it did.
        if saturated {
            undercounted_sequences += 1;
            assert_eq!(budget.spent, u64::MAX);
            assert!(
                admitted > u128::from(budget.spent),
                "a saturated ledger under-counts: admitted {admitted}, spent {}",
                budget.spent
            );
        } else {
            exact_sequences += 1;
            assert_eq!(
                admitted,
                u128::from(budget.spent),
                "sum of all Allowed charges must equal spent exactly"
            );
        }
        sequences += 1;
    }

    // The generator actually exercised what it claims to (fixed seed, so
    // these numbers are stable; they are lower bounds, not equalities, so an
    // unrelated edit to the shapes above does not turn this into a tautology).
    assert_eq!(charges, TOTAL_CHARGES);
    assert_eq!(sequences, TOTAL_CHARGES / SEQUENCE_LEN);
    assert!(allows > 100_000, "allows exercised: {allows}");
    assert!(denies > 100_000, "denies exercised: {denies}");
    assert!(
        zero_charges > 50_000,
        "zero charges exercised: {zero_charges}"
    );
    assert!(
        divergences > 1_000,
        "the u64::MAX under-count must actually be reached: {divergences}"
    );
    assert!(
        exact_sequences > 10_000,
        "and most ledgers must still be exact: {exact_sequences}"
    );
    assert!(undercounted_sequences > 100);

    // DEFECT 2 (high, exhaustion vector). Not one zero-token charge was ever
    // refused, at any limit, at any point in any sequence — including limit 0
    // and including a fully exhausted ledger.
    assert_eq!(
        zero_charges_denied, 0,
        "charge(0) was refused somewhere — the documented truth changed"
    );
}

/// The same property at 50× the volume — a full **one million independent
/// charge sequences**, 50 charges each — for a nightly soak. Kept out of the
/// default run to hold the suite under a minute; run it with
///
/// ```text
/// cargo test -p ccos-enterprise-conformance --release \
///     --test stress_budget_property -- --ignored --nocapture
/// ```
#[test]
#[ignore = "50M-charge soak; see the doc comment for the command"]
fn fifty_million_random_charges_hold_the_ledger_invariants() {
    let mut rng = Rng::new(SEED ^ 0xDEAD_BEEF_DEAD_BEEF);
    let mut divergences = 0u64;
    for _ in 0..1_000_000u32 {
        let limit = LIMITS[rng.below(LIMITS.len() as u64) as usize];
        let mut budget = TokenBudget::new(limit);
        let mut admitted: u128 = 0;
        let mut saturated = false;
        for _ in 0..50 {
            let before = budget.spent;
            let tokens = charge_of(&mut rng, limit);
            let decision = budget.charge(tokens);
            assert!(budget.spent <= limit);
            assert!(budget.spent >= before);
            if decision == PolicyDecision::Allow {
                admitted += u128::from(tokens);
                if u128::from(before) + u128::from(tokens) > u128::from(u64::MAX) {
                    saturated = true;
                    divergences += 1;
                    assert_eq!(limit, u64::MAX);
                }
            } else {
                assert_eq!(budget.spent, before);
            }
        }
        if saturated {
            assert!(admitted > u128::from(budget.spent));
        } else {
            assert_eq!(admitted, u128::from(budget.spent));
        }
    }
    assert!(divergences > 0);
}

/// The same invariants on a **single, long-lived** ledger rather than twenty
/// thousand short ones: one million charges against one 1 000 000-token
/// budget, the shape a real tenant actually has. Equivalence is exact here
/// because the limit is finite.
#[test]
fn a_long_lived_ledger_stays_exact_over_a_million_charges() {
    let mut rng = Rng::new(SEED ^ 0xA5A5_A5A5_A5A5_A5A5);
    let mut budget = TokenBudget::new(1_000_000);
    let mut admitted: u128 = 0;
    let mut last = 0u64;
    let mut allows = 0u64;
    let mut denies = 0u64;

    for _ in 0..1_000_000u32 {
        let tokens = rng.below(7); // 0..=6: fine-grained, so the boundary is met exactly
        let before = budget.spent;
        match budget.charge(tokens) {
            PolicyDecision::Allow => {
                allows += 1;
                admitted += u128::from(tokens);
            }
            PolicyDecision::Deny => {
                denies += 1;
                assert_eq!(budget.spent, before, "denied charge moved the meter");
            }
            PolicyDecision::RequireApproval => panic!("not a budget outcome"),
        }
        assert!(budget.spent >= last, "ledger went backwards");
        assert!(budget.spent <= budget.limit, "ledger overran its limit");
        last = budget.spent;
    }

    assert_eq!(
        admitted,
        u128::from(budget.spent),
        "sum of Allowed == spent, exactly, after a million charges"
    );
    assert!(allows > 0 && denies > 0, "both outcomes exercised");
    // The ledger ends full to within one charge of the largest denomination, so
    // the boundary really was met, not merely approached.
    assert!(
        budget.spent >= budget.limit - 6,
        "the budget was actually driven to exhaustion: {}",
        budget.spent
    );
}

// ── 2. Arithmetic edges ──────────────────────────────────────────────────

/// The degenerate and saturating limits, stated one assertion at a time.
///
/// The two answers this table pins:
/// * **`charge(0)` is always `Allow`** while `spent <= limit` — including on a
///   `limit == 0` budget and on a fully exhausted one. It is admitted and it
///   is billed nothing.
/// * **`charge(u64::MAX)`** is denied by every finite limit and admitted by
///   `u64::MAX`, where it pins the meter for good.
#[test]
fn arithmetic_edges_of_the_gate() {
    // limit = 0: a tenant with no budget at all.
    let mut zero = TokenBudget::new(0);
    assert_eq!(
        zero.charge(0),
        PolicyDecision::Allow,
        "TRUTH: a zero charge is admitted even by a zero budget"
    );
    assert_eq!(zero.spent, 0, "and bills nothing");
    assert_eq!(
        zero.charge(1),
        PolicyDecision::Deny,
        "one token is too many"
    );
    assert_eq!(zero.charge(u64::MAX), PolicyDecision::Deny);
    assert_eq!(zero.spent, 0);
    for _ in 0..1_000 {
        assert_eq!(
            zero.charge(0),
            PolicyDecision::Allow,
            "and it stays admitted, for ever"
        );
    }
    assert_eq!(zero.spent, 0);

    // limit = 1: the smallest ledger that can move at all.
    let mut one = TokenBudget::new(1);
    assert_eq!(one.charge(0), PolicyDecision::Allow);
    assert_eq!(one.spent, 0);
    assert_eq!(one.charge(2), PolicyDecision::Deny, "2 > 1");
    assert_eq!(one.spent, 0, "the refusal is free");
    assert_eq!(one.charge(1), PolicyDecision::Allow, "the only token");
    assert_eq!(one.spent, 1);
    assert_eq!(one.charge(1), PolicyDecision::Deny, "exhausted");
    assert_eq!(
        one.charge(0),
        PolicyDecision::Allow,
        "TRUTH: exhausted is not closed — a zero charge still passes"
    );
    assert_eq!(one.spent, 1);

    // limit = u64::MAX - 1: the largest limit whose guard still works.
    let mut edge = TokenBudget::new(u64::MAX - 1);
    assert_eq!(
        edge.charge(u64::MAX),
        PolicyDecision::Deny,
        "MAX > MAX-1, and saturating_add(0, MAX) == MAX catches it"
    );
    assert_eq!(edge.spent, 0);
    assert_eq!(edge.charge(u64::MAX - 1), PolicyDecision::Allow);
    assert_eq!(edge.spent, u64::MAX - 1);
    assert_eq!(
        edge.charge(1),
        PolicyDecision::Deny,
        "exact at the boundary"
    );
    assert_eq!(
        edge.charge(0),
        PolicyDecision::Allow,
        "zero still passes at the very top of the u64 range"
    );
    assert_eq!(edge.spent, u64::MAX - 1, "and still bills nothing");

    // limit = u64::MAX: the guard can no longer fire. See defect 1.
    let mut unlimited = TokenBudget::new(u64::MAX);
    assert_eq!(unlimited.charge(u64::MAX), PolicyDecision::Allow);
    assert_eq!(unlimited.spent, u64::MAX);
    assert_eq!(
        unlimited.charge(u64::MAX),
        PolicyDecision::Allow,
        "DEFECT: a second full-range charge is admitted too"
    );
    assert_eq!(
        unlimited.spent,
        u64::MAX,
        "…and the meter did not move: 2 * u64::MAX billed as u64::MAX"
    );
}

/// Alternating maximal charges: the ledger is asked for `u64::MAX` a thousand
/// times in a row, alternating with `1`, at both saturating limits.
///
/// At `u64::MAX - 1` every charge is refused and the meter never moves —
/// fail-closed, which is the correct posture. At `u64::MAX` every charge is
/// admitted for ever and the under-count grows without bound.
#[test]
fn alternating_maximal_charges_saturate_one_way_only() {
    let mut edge = TokenBudget::new(u64::MAX - 1);
    for i in 0..1_000 {
        let tokens = if i % 2 == 0 { u64::MAX } else { 1 };
        let decision = edge.charge(tokens);
        if tokens == u64::MAX {
            assert_eq!(decision, PolicyDecision::Deny, "MAX never fits in MAX-1");
        } else {
            assert_eq!(decision, PolicyDecision::Allow);
        }
    }
    assert_eq!(edge.spent, 500, "only the 500 single tokens were billed");

    let mut unlimited = TokenBudget::new(u64::MAX);
    let mut admitted: u128 = 0;
    for i in 0..1_000 {
        let tokens = if i % 2 == 0 { u64::MAX } else { 1 };
        assert_eq!(
            unlimited.charge(tokens),
            PolicyDecision::Allow,
            "an unlimited budget admits everything"
        );
        admitted += u128::from(tokens);
    }
    assert_eq!(
        unlimited.spent,
        u64::MAX,
        "pinned from the very first charge"
    );
    assert!(
        admitted > u128::from(u64::MAX) * 499,
        "true consumption was ~500 * u64::MAX"
    );
    // The gap is the size of the lie the meter is telling.
    assert!(admitted - u128::from(unlimited.spent) > u128::from(u64::MAX) * 498);
}

// ── 3. Defect 1: the unlimited ledger under-counts ───────────────────────

/// **DEFECT 1 (high, billing integrity).** `charge` is fail-open on
/// saturation, so a `limit == u64::MAX` ledger stops counting after the first
/// overflow while continuing to admit. `spent` — the number
/// `Deployment::spent` reports, the only number the product has for billing —
/// then disagrees with the sum of admitted calls by an unbounded amount.
///
/// The trigger is one caller-declared number. `Call::cost_tokens` is supplied
/// by the caller and never validated, so a single call declaring `u64::MAX`
/// pins an "unlimited" tenant's meter permanently; every later call is
/// admitted *and* invisible to accounting.
///
/// `crates/ccos-enterprise-policy/src/lib.rs::unlimited_budget_never_wraps_the_ledger`
/// asserts the saturation as a *feature* ("spent saturates instead of
/// wrapping"). Saturating beats wrapping, but both break the accounting: the
/// only non-lying option at that limit is to refuse the overflowing charge.
#[test]
fn unlimited_budget_undercounts_without_bound() {
    let mut b = TokenBudget::new(u64::MAX);
    let mut admitted: u128 = 0;

    // One call is enough to pin the meter.
    assert_eq!(b.charge(u64::MAX), PolicyDecision::Allow);
    admitted += u128::from(u64::MAX);
    assert_eq!(b.spent, u64::MAX);

    // Every subsequent charge, of any size, is admitted and free.
    for i in 1..=10_000u64 {
        assert_eq!(b.charge(i), PolicyDecision::Allow, "admitted after the pin");
        admitted += u128::from(i);
        assert_eq!(b.spent, u64::MAX, "and never metered again");
    }
    assert_eq!(
        admitted - u128::from(b.spent),
        50_005_000,
        "50 005 000 tokens consumed off-meter"
    );

    // The same thing through the whole composed path: a tenant provisioned
    // "unlimited" the obvious way. Every call is Forwarded, the audit trail
    // shows 11 admitted calls, and the ledger reports one call's worth.
    //
    // Distinct request ids throughout, so replay suppression never fires and
    // all eleven calls are genuinely decided: the under-count below is the
    // ledger's, not the deduplicator's.
    let mut d = Deployment::new();
    d.add_role("writer", &["memory.write"])
        .govern_tool("memory.ingest", "memory.write");
    let mut t = TenantState::new(u64::MAX);
    t.allow_model("m");
    assert!(d.add_tenant("o", "unlimited", t));
    assert!(d.assign("a", "writer"));
    let who = actor("o", "a", AuthStrength::Token);

    let mut declared: u128 = 0;
    for i in 0..11u64 {
        let req = request("unlimited", "a", "memory.ingest", &format!("r-{i}"));
        let cost = u64::MAX / 2;
        let outcome = d.admit(Call {
            actor: &who,
            request: &req,
            model: "m",
            cost_tokens: cost,
            variant: None,
        });
        assert_eq!(outcome, Outcome::Forwarded, "call {i} was admitted");
        declared += u128::from(cost);
    }
    assert_eq!(d.audit_of("unlimited").len(), 11);
    assert_eq!(
        d.spent("unlimited"),
        Some(u64::MAX),
        "the meter pinned on the third call and never moved again"
    );
    let metered = d.spent("unlimited").expect("the tenant exists");
    assert!(
        declared - u128::from(metered) > u128::from(u64::MAX) * 4,
        "DEFECT: the deployment under-bills by more than 4 * u64::MAX tokens"
    );

    // Defect 4's repair does not fix this — it makes it DETECTABLE, which is
    // the whole point of journaling the cost. Reconciling the trail against
    // the meter now produces a number, and the number is wrong: eleven
    // forwarded records each carrying `u64::MAX / 2`, against a meter that
    // reports one `u64::MAX`. Before the repair the two sides could not even
    // be compared, so this shortfall had no observable form at all.
    let journaled: u128 = d
        .audit_of("unlimited")
        .iter()
        .map(|r| u128::from(r.cost))
        .sum();
    assert_eq!(
        journaled, declared,
        "the journal records every token the caller declared"
    );
    assert!(
        journaled > u128::from(metered) * 4,
        "DEFECT 1, now visible: the journal says {journaled}, the meter says {metered}"
    );
}

// ── 4. Defect 2: charge(0) is a free pass, for ever ──────────────────────

/// **DEFECT 2 (high, exhaustion vector).** The documented truth, asked for by
/// name: *is `charge(0)` on an exhausted budget `Allow` or `Deny`?*
///
/// **`Allow`.** The guard is `spent + tokens > limit`; at exhaustion
/// `spent == limit`, so `limit + 0 > limit` is false and the charge passes.
/// It is billed nothing, which is arithmetically honest — but it means
/// `Refusal::BudgetExhausted` can never fire for a zero-cost call, and
/// `Call::cost_tokens` is **declared by the caller and never reconciled
/// against anything Core actually did**.
///
/// So the budget gate is opt-in: a client that declares `0` gets unlimited
/// admission through the whole governed path, on any tenant, at any limit,
/// before and after exhaustion. 100 000 such calls are run here; every one is
/// `Forwarded`, the tenant's meter never moves, and the deployment's own
/// counters agree that it forwarded 100 000 requests to Core.
///
/// Every free call carries a **distinct** `request_id`, so replay suppression
/// never fires: each of the 100 000 is a genuinely new decision that reached
/// the budget gate and was admitted by it. (Reusing one id would make this
/// test pass for the wrong reason — see
/// [`a_replayed_request_id_is_billed_once`].)
#[test]
fn a_zero_charge_is_allowed_forever_even_when_exhausted() {
    // Unit level: exhaust exactly, then hammer with zeros.
    let mut b = TokenBudget::new(10);
    assert_eq!(b.charge(10), PolicyDecision::Allow);
    assert_eq!(b.spent, 10, "exhausted");
    assert_eq!(
        b.charge(1),
        PolicyDecision::Deny,
        "one more token is refused"
    );
    for _ in 0..10_000 {
        assert_eq!(
            b.charge(0),
            PolicyDecision::Allow,
            "TRUTH: charge(0) on an exhausted budget is ALLOW"
        );
    }
    assert_eq!(b.spent, 10, "and is never billed");

    // Composed level: drain acme's 1 000 tokens, then keep going for free.
    let mut d = two_tenant_deployment();
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let drain = request("acme", "alice", "memory.ingest", "drain");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &drain,
            model: "claude-opus",
            cost_tokens: 1_000,
            variant: None,
        }),
        Outcome::Forwarded
    );
    assert_eq!(d.spent("acme"), Some(1_000), "the whole budget is gone");

    // A one-token call is now refused…
    let costly = request("acme", "alice", "memory.ingest", "costly");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &costly,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::BudgetExhausted)
    );

    // …but 100 000 zero-cost calls sail straight through to Core.
    const FREE_CALLS: usize = 100_000;
    for i in 0..FREE_CALLS {
        let req = request("acme", "alice", "memory.recall", &format!("free-{i}"));
        let outcome = d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 0,
            variant: None,
        });
        assert_eq!(
            outcome,
            Outcome::Forwarded,
            "EXHAUSTION VECTOR: free call {i} was admitted past an exhausted budget"
        );
    }
    assert_eq!(d.spent("acme"), Some(1_000), "the meter never moved");
    let metrics = d.metrics();
    let forwarded = metrics
        .iter()
        .find(|(k, _)| k == "gateway.forwarded")
        .map(|(_, v)| *v)
        .expect("forwarded counter exists");
    assert_eq!(
        forwarded,
        FREE_CALLS as u64 + 1,
        "the deployment's own counters admit it forwarded 100 001 calls on a 1 000-token budget"
    );
    assert_eq!(
        metrics
            .iter()
            .find(|(k, _)| k == "gateway.replayed")
            .map(|(_, v)| *v),
        None,
        "not one of those admissions was a suppressed replay — every free call \
         reached the budget gate and was admitted by it"
    );
}

// ── 5. Defect 3, REPAIRED: the ledger is private and never clobbered ─────

/// **DEFECT 3 (high, governance) — REPAIRED; this test is the guard.**
///
/// `TokenBudget::{limit, spent}` and `TenantState::budget` were both `pub`,
/// and `Deployment::tenant_mut` hands out `&mut TenantState` to anyone holding
/// the deployment. The meter could therefore be rewound, or the limit raised,
/// with no permission check, no `AdminAction` and no audit record — while the
/// journal still showed the forwarded calls that produced the old value. An
/// exhausted tenant became a free one in one assignment, and the only two
/// artefacts the product has for billing disagreed with each other with
/// nothing to say which was right.
///
/// `Deployment::add_tenant` was the same defect with a friendlier face: an
/// unconditional `insert`, so re-registering an existing tenant — a
/// provisioning replay, a config reload, a duplicated line in a bootstrap
/// script — silently discarded its ledger, its allowlist and its activations.
///
/// Both are closed. `TenantState`'s fields are private and expose only
/// `spent()`/`limit()` reads plus builders that cannot touch the meter, so
/// **the rewind in this test's original body no longer compiles** — which is
/// the strongest possible form of this guard. `add_tenant` returns `false` and
/// changes nothing when the tenant exists, so the scenario below is kept
/// verbatim with the opposite expectation: the live ledger must survive.
#[test]
fn the_ledger_is_private_and_a_live_tenant_is_never_reprovisioned() {
    let mut d = two_tenant_deployment();
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let spend = |d: &mut Deployment, cost: u64, id: &str| {
        let req = request("acme", "alice", "memory.ingest", id);
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: cost,
            variant: None,
        })
    };

    assert_eq!(spend(&mut d, 1_000, "r-1"), Outcome::Forwarded);
    assert_eq!(d.spent("acme"), Some(1_000));
    assert_eq!(
        spend(&mut d, 1, "r-2").refusal(),
        Some(&Refusal::BudgetExhausted)
    );
    let audit_before = d.audit().count();

    // (a) The meter is read-only from outside. `tenant_mut` still hands out
    //     `&mut TenantState` — configuration is legitimately mutable — but the
    //     ledger is not reachable through it. The two assignments this test
    //     used to make,
    //
    //         d.tenant_mut("acme").unwrap().budget.spent = 0;
    //         d.tenant_mut("acme").unwrap().budget.limit = u64::MAX;
    //
    //     are compile errors now: `budget` is private. What remains are the
    //     builders, and exercising every one of them must not move the meter.
    {
        let t = d.tenant_mut("acme").expect("tenant");
        assert_eq!(t.spent(), 1_000, "the ledger is readable…");
        assert_eq!(t.limit(), 1_000, "…and so is the ceiling…");
        t.allow_model("another-model")
            .activate(AdvancedQPageVariant::CausalChain);
        assert_eq!(t.spent(), 1_000, "…but configuration cannot rewind it");
        assert_eq!(t.limit(), 1_000, "…nor widen it");
    }
    assert_eq!(
        d.audit().count(),
        audit_before,
        "and no decision was journaled by reconfiguring"
    );
    assert_eq!(
        spend(&mut d, 1, "r-3").refusal(),
        Some(&Refusal::BudgetExhausted),
        "REGRESSION GUARD: exhausted stays exhausted — there is no way back \
         to a free tenant that does not go through provisioning"
    );

    // (b) Re-provisioning a live tenant is refused outright. Same call the
    //     original defect used to zero the ledger with; it now returns false
    //     and changes nothing at all.
    let mut fresh = TenantState::new(u64::MAX);
    fresh.allow_model("claude-opus");
    assert!(
        !d.add_tenant("memorithm", "acme", fresh),
        "REGRESSION GUARD: add_tenant refuses to overwrite a live tenant"
    );
    assert_eq!(
        d.spent("acme"),
        Some(1_000),
        "REGRESSION GUARD: the ledger survived re-provisioning"
    );
    assert_eq!(
        d.tenant_mut("acme").expect("tenant").limit(),
        1_000,
        "…and so did the ceiling: the u64::MAX limit was not adopted"
    );
    assert_eq!(
        spend(&mut d, 1, "r-4").refusal(),
        Some(&Refusal::BudgetExhausted),
        "…so the tenant is still exhausted, not silently unlimited"
    );

    // (c) Nor can re-provisioning transfer ownership. A second organization
    //     claiming an existing tenant is refused, and the tenant stays where
    //     it was — otherwise `add_tenant` would be a cross-org takeover
    //     primitive rather than a provisioning one.
    assert!(
        !d.add_tenant("initech", "acme", TenantState::new(50)),
        "REGRESSION GUARD: a foreign org cannot re-home a live tenant"
    );
    d.assign("mallory", "writer");
    let mallory = actor("initech", "mallory", AuthStrength::Token);
    let takeover = request("acme", "mallory", "memory.ingest", "r-5");
    assert_eq!(
        d.admit(Call {
            actor: &mallory,
            request: &takeover,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::TenantNotOwnedByOrg),
        "acme still belongs to memorithm"
    );

    // (d) The journal and the meter now agree, which was the whole point:
    //     every forwarded record's cost sums to exactly what the meter says.
    let trail = d.audit_of("acme");
    let forwarded = trail.iter().filter(|r| r.outcome.is_forwarded()).count();
    assert_eq!(forwarded, 1, "one forwarded call, and only one");
    let billed: u64 = trail.iter().map(|r| r.cost).sum();
    assert_eq!(
        Some(billed),
        d.spent("acme"),
        "REGRESSION GUARD: journal and meter reconcile to the token"
    );
}

/// A ledger driven above its own limit closes completely: `charge(0)` is the
/// one and only case where a zero charge is refused, because `spent > limit`
/// already.
///
/// This is the fail-closed half of defect 3, and it is now the **residual** of
/// it. The composed path can no longer produce this state — the runtime's
/// ledger is private (see
/// [`the_ledger_is_private_and_a_live_tenant_is_never_reprovisioned`]) — but
/// `TokenBudget::{limit, spent}` are still `pub` in `ccos-enterprise-policy`,
/// so any other holder of the type can, as can deserialization (see
/// [`a_deserialized_ledger_has_no_invariants`]). Kept pinning the real
/// behaviour: a corrupted meter refuses everything rather than admitting
/// everything, which is the right direction to fail in, and the assignment
/// below is the proof that the field is still assignable.
#[test]
fn a_ledger_pushed_over_its_limit_denies_even_a_zero_charge() {
    let mut b = TokenBudget::new(100);
    b.spent = 101; // the state `charge` can never produce
    assert_eq!(
        b.charge(0),
        PolicyDecision::Deny,
        "the ONLY way to make charge(0) deny: spent already exceeds limit"
    );
    assert_eq!(b.charge(1), PolicyDecision::Deny);
    assert_eq!(b.spent, 101, "and the denials do not move it further");
}

// ── 6. Defect 6: persistence has no invariants ───────────────────────────

/// **DEFECT 6 (medium, state integrity).** `TokenBudget` derives
/// `Deserialize` with no validation, so any persisted or restored ledger —
/// backup, config, replicated state — can carry `spent > limit`, or a limit
/// silently widened to `u64::MAX`, and the type accepts it.
///
/// The direction of failure differs, which is the interesting part: an
/// over-spent ledger fails *closed*, a widened one fails *open* into
/// defect 1's under-count. Neither is detectable after the fact, because
/// nothing records what the limit was supposed to be.
#[test]
fn a_deserialized_ledger_has_no_invariants() {
    let over: TokenBudget =
        serde_json::from_str(r#"{"limit":10,"spent":18446744073709551615}"#).expect("accepted");
    assert_eq!(over.limit, 10);
    assert_eq!(
        over.spent,
        u64::MAX,
        "DEFECT: spent > limit round-trips with no complaint"
    );

    let mut widened: TokenBudget =
        serde_json::from_str(r#"{"limit":18446744073709551615,"spent":0}"#).expect("accepted");
    assert_eq!(widened.charge(u64::MAX), PolicyDecision::Allow);
    assert_eq!(widened.charge(u64::MAX), PolicyDecision::Allow);
    assert_eq!(
        widened.spent,
        u64::MAX,
        "…and lands straight in the saturating under-count"
    );

    // Round-tripping a live ledger is at least faithful.
    let mut live = TokenBudget::new(500);
    assert_eq!(live.charge(321), PolicyDecision::Allow);
    let wire = serde_json::to_string(&live).expect("serializes");
    let back: TokenBudget = serde_json::from_str(&wire).expect("deserializes");
    assert_eq!((back.limit, back.spent), (500, 321));
}

// ── 7. Composed equivalence: does the deployment ledger add up? ──────────

/// The end-to-end form of invariant 4, over 20 000 pseudo-random governed
/// calls across two tenants, with **every** refusal cause mixed in: bad model,
/// ungoverned tool, forbidden namespace, anonymous caller, unknown tenant,
/// unactivated variant, genuine budget exhaustion, and — new since the
/// credential binding landed — a spoofed actor name, a foreign organization
/// and a malformed identifier.
///
/// This is the one that **holds**: with finite limits the deployment's meter
/// equals the exact sum of the costs of the calls it forwarded, per tenant,
/// with no cross-charging and no refusal ever billed. Since `AuditRecord`
/// gained `cost`, it also holds *against the journal*, which is asserted at
/// the end: 20 000 decisions, and the two artefacts agree to the token.
#[test]
fn the_composed_ledger_equals_the_sum_of_forwarded_costs() {
    let mut d = Deployment::new();
    d.add_role("writer", &["memory.read", "memory.write"])
        .govern_tool("memory.ingest", "memory.write")
        .govern_tool("memory.recall", "memory.read")
        // Governed, but for a permission `a` does not hold: the difference
        // between "no such tool" and "not for you".
        .govern_tool("policy.set", "policy.admin");
    let mut acme = TenantState::new(4_000_000);
    acme.allow_model("m")
        .activate(AdvancedQPageVariant::Hierarchical);
    assert!(d.add_tenant("o", "acme", acme));
    // globex activates nothing: the same variant is billable for one tenant
    // and refused for the other.
    let mut globex = TenantState::new(250_000);
    globex.allow_model("m");
    assert!(d.add_tenant("o", "globex", globex));
    assert!(d.assign("a", "writer"));
    // `b` holds the same role, so the impersonation shape below is refused for
    // the identity mismatch and not merely for want of a permission.
    assert!(d.assign("b", "writer"));

    let strong = actor("o", "a", AuthStrength::Token);
    let anon = actor("o", "a", AuthStrength::Anonymous);
    // Same actor name, same role, different organization: everything about
    // this credential is genuine except the tenant it reaches for.
    let foreign = actor("other-org", "a", AuthStrength::Token);

    let mut rng = Rng::new(SEED ^ 0xC0FF_EE00_C0FF_EE00);
    let mut expect_acme: u64 = 0;
    let mut expect_globex: u64 = 0;
    let mut forwarded = 0u64;
    let mut refusals = [0u64; 11];

    for i in 0..20_000u64 {
        // Pick a shape: mostly-legitimate calls, salted with every refusal.
        let shape = rng.below(13);
        let tenant = if rng.below(3) == 0 { "globex" } else { "acme" };
        let tool = match shape {
            6 => "policy.set",   // governed for a permission `a` lacks
            7 => "shell.exec",   // outside the boundary
            8 => "memory.purge", // never governed
            _ => "memory.ingest",
        };
        let model = if shape == 5 { "other" } else { "m" };
        let named_tenant = if shape == 9 { "nosuch" } else { tenant };
        let who = match shape {
            4 => &anon,     // → Unauthenticated
            11 => &foreign, // → TenantNotOwnedByOrg
            _ => &strong,
        };
        // shape 10 spoofs a *different* actor's name in the request body —
        // the exact move defect 7 made free. It must now be refused.
        let named_actor = if shape == 10 { "b" } else { "a" };
        // shape 12 sends an empty request id: an identifier the runtime
        // refuses before it consults anything at all.
        let request_id = if shape == 12 {
            String::new()
        } else {
            format!("r-{i}")
        };
        let variant = match rng.below(12) {
            0 => Some(AdvancedQPageVariant::Hierarchical), // acme only
            1 => Some(AdvancedQPageVariant::CausalChain),  // nobody
            _ => None,
        };
        let cost = match rng.below(4) {
            0 => 0,
            1 => rng.below(64),
            2 => rng.below(10_000),
            _ => rng.below(400_000), // big enough to hit real exhaustion
        };

        let before_acme = d.spent("acme");
        let before_globex = d.spent("globex");
        let req = request(named_tenant, named_actor, tool, &request_id);
        let outcome = d.admit(Call {
            actor: who,
            request: &req,
            model,
            cost_tokens: cost,
            variant,
        });

        match &outcome {
            Outcome::Forwarded => {
                forwarded += 1;
                if tenant == "acme" {
                    expect_acme += cost;
                } else {
                    expect_globex += cost;
                }
            }
            Outcome::Refused(r) => {
                refusals[refusal_index(r)] += 1;
                assert_eq!(d.spent("acme"), before_acme, "a refusal billed acme");
                assert_eq!(d.spent("globex"), before_globex, "a refusal billed globex");
            }
        }

        // No call ever moves the other tenant's meter.
        if named_tenant != "acme" {
            assert_eq!(d.spent("acme"), before_acme, "cross-tenant charge to acme");
        }
        if named_tenant != "globex" {
            assert_eq!(
                d.spent("globex"),
                before_globex,
                "cross-tenant charge to globex"
            );
        }
    }

    assert_eq!(
        d.spent("acme"),
        Some(expect_acme),
        "acme's meter must equal the exact sum of its forwarded costs"
    );
    assert_eq!(
        d.spent("globex"),
        Some(expect_globex),
        "globex's meter must equal the exact sum of its forwarded costs"
    );
    assert_eq!(d.audit().count(), 20_000, "every decision is journaled");
    assert_eq!(
        d.audit_dropped(),
        0,
        "20 000 records fit inside the default bound, so the count above is \
         the whole story and not a window onto it"
    );
    assert!(forwarded > 1_000, "forwards exercised: {forwarded}");
    // Every refusal cause was actually reached, so the "no refusal is billed"
    // half of this test is not vacuous for any of them — including the three
    // the credential binding introduced.
    for (i, count) in refusals.iter().enumerate() {
        assert!(*count > 0, "refusal cause {i} never exercised");
    }

    // The journal reconciles the meter, per tenant, over the whole run. This
    // is defect 4's repair at scale: every refusal is journaled at cost 0, and
    // the forwarded costs sum to exactly what each tenant was billed.
    for (name, expected) in [("acme", expect_acme), ("globex", expect_globex)] {
        let trail = d.audit_of(name);
        let billed: u64 = trail.iter().map(|r| r.cost).sum();
        assert_eq!(
            billed, expected,
            "REGRESSION GUARD: {name}'s journal must reconcile its meter"
        );
        assert!(
            trail
                .iter()
                .all(|r| r.outcome.is_forwarded() || r.cost == 0),
            "REGRESSION GUARD: a refusal is journaled at cost 0"
        );
    }
    // Sequence numbers are assigned at decision time and never repeat, so a
    // journal collected concurrently can be replayed in the order the
    // deployment actually decided.
    let sequences: Vec<u64> = d.audit().map(|r| r.sequence).collect();
    assert_eq!(sequences, (0..20_000).collect::<Vec<_>>());
}

/// Index for the refusal histogram above. Kept exhaustive on purpose: a new
/// refusal cause must be classified here rather than silently folded away.
fn refusal_index(r: &Refusal) -> usize {
    match r {
        Refusal::Unauthenticated => 0,
        Refusal::UnknownTenant => 1,
        Refusal::OutsideBoundary(_) => 2,
        Refusal::ToolNotGoverned => 3,
        Refusal::PermissionDenied => 4,
        Refusal::ModelNotAllowed => 5,
        Refusal::VariantNotActivated => 6,
        Refusal::BudgetExhausted => 7,
        Refusal::ActorMismatch => 8,
        Refusal::TenantNotOwnedByOrg => 9,
        Refusal::MalformedRequest(_) => 10,
    }
}

// ── 8. Defects 4 and 5, REPAIRED: the journal checks the meter ───────────

/// **DEFECT 4 (medium, auditability) — REPAIRED; this test is the guard.**
///
/// `AuditRecord` recorded `{request_id, tenant, actor, tool, outcome}` — and
/// no cost. Two forwarded calls that differed by three orders of magnitude in
/// price produced byte-identical records apart from the request id.
///
/// The consequence was that the meter was unverifiable: defects 1, 2, 3 and 6
/// all change what a tenant is billed, and **none** of them left a trace in
/// the one artefact the product offers for reconciliation.
/// `docs/COGNITIVE_AUDIT.md`'s "audit-correlated by request id" was true and
/// insufficient — you could join a charge to a request id, but you could not
/// recover the charge.
///
/// The record now carries `cost` (always `0` for a refusal) and a monotonic
/// `sequence`. The scenario below is unchanged — the same 1-token and
/// 999-token calls — with the opposite expectation: the journal must tell them
/// apart, and the trail must add up to the meter.
#[test]
fn the_audit_trail_reconciles_the_ledger() {
    let mut d = two_tenant_deployment();
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    for (id, cost) in [("cheap", 1u64), ("dear", 999u64)] {
        let req = request("acme", "alice", "memory.ingest", id);
        assert_eq!(
            d.admit(Call {
                actor: &alice,
                request: &req,
                model: "claude-opus",
                cost_tokens: cost,
                variant: None,
            }),
            Outcome::Forwarded
        );
    }
    assert_eq!(d.spent("acme"), Some(1_000));

    let trail = d.audit_of("acme");
    assert_eq!(trail.len(), 2);
    let (cheap, dear) = (trail[0], trail[1]);
    // The fields that used to be the *whole* record still agree — same tenant,
    // same actor, same tool, both forwarded…
    assert_eq!(
        (
            &cheap.tenant,
            &cheap.actor,
            &cheap.tool,
            cheap.outcome.is_forwarded()
        ),
        (
            &dear.tenant,
            &dear.actor,
            &dear.tool,
            dear.outcome.is_forwarded()
        ),
    );
    // …and that is precisely why the price has to be in the record.
    assert_ne!(cheap.request_id, dear.request_id);
    assert_eq!(
        (cheap.cost, dear.cost),
        (1, 999),
        "REGRESSION GUARD: a 1-token call and a 999-token call are \
         distinguishable in the journal"
    );
    assert!(
        cheap.sequence < dear.sequence,
        "REGRESSION GUARD: decision order is recoverable from the journal alone"
    );
    let billed: u64 = trail.iter().map(|r| r.cost).sum();
    assert_eq!(
        Some(billed),
        d.spent("acme"),
        "REGRESSION GUARD: the journal reconciles the meter exactly"
    );

    // A refusal is journaled, and journaled at zero: the reconciliation above
    // cannot be fooled by an expensive call that never reached Core.
    let refused = request("acme", "alice", "shell.exec", "forbidden");
    assert!(d
        .admit(Call {
            actor: &alice,
            request: &refused,
            model: "claude-opus",
            cost_tokens: 500,
            variant: None,
        })
        .refusal()
        .is_some());
    let trail = d.audit_of("acme");
    assert_eq!(trail.len(), 3, "the refusal is journaled too");
    assert_eq!(
        trail[2].cost, 0,
        "REGRESSION GUARD: a refusal is journaled at cost 0, whatever it declared"
    );
    let billed: u64 = trail.iter().map(|r| r.cost).sum();
    assert_eq!(Some(billed), d.spent("acme"), "…and still reconciles");
}

/// **DEFECT 5 (medium, billing integrity) — REPAIRED; this test is the
/// guard.**
///
/// `GatewayRequest::request_id` is documented as an "Idempotency/correlation
/// key for audit joins", and nothing on the path read it. Replaying the
/// identical request — the ordinary consequence of a client-side retry after a
/// timeout — was admitted again and **billed** again: ten replays of one id
/// drained ten times the budget and left ten audit records that all claimed to
/// be the same request, so an operator could not tell a retried call from ten
/// real ones.
///
/// A decided `(tenant, request_id)` is now Forwarded without being charged.
/// The scenario is kept verbatim — the same ten replays of one id, at the same
/// 100 tokens each — with the opposite expectation: billed once.
#[test]
fn a_replayed_request_id_is_billed_once() {
    let mut d = two_tenant_deployment();
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let req = request("acme", "alice", "memory.ingest", "the-same-request");

    for i in 0..10 {
        assert_eq!(
            d.admit(Call {
                actor: &alice,
                request: &req,
                model: "claude-opus",
                cost_tokens: 100,
                variant: None,
            }),
            Outcome::Forwarded,
            "replay {i} keeps returning the prior outcome"
        );
    }
    assert_eq!(
        d.spent("acme"),
        Some(100),
        "REGRESSION GUARD: one request id, one charge — not the whole budget"
    );
    let trail = d.audit_of("acme");
    assert_eq!(trail.len(), 10, "every attempt is still journaled");
    assert!(
        trail.iter().all(|r| r.request_id == "the-same-request"),
        "…under the id the client sent…"
    );
    let costs: Vec<u64> = trail.iter().map(|r| r.cost).collect();
    assert_eq!(
        costs,
        vec![100, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        "…and the journal now says which one of the ten was the real charge"
    );
    let billed: u64 = costs.iter().sum();
    assert_eq!(
        Some(billed),
        d.spent("acme"),
        "journal reconciles the meter"
    );

    // The eleventh replay is Forwarded and free, not refused: the budget was
    // never drained, so there is nothing for `BudgetExhausted` to fire on.
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 100,
            variant: None,
        }),
        Outcome::Forwarded
    );
    assert_eq!(d.spent("acme"), Some(100));

    // Dedup is on the id, not on the shape: a genuinely new request with the
    // same tenant, actor, tool and price is billed. Otherwise this guard would
    // be satisfied by a deployment that simply stopped charging.
    let fresh = request("acme", "alice", "memory.ingest", "a-different-request");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &fresh,
            model: "claude-opus",
            cost_tokens: 100,
            variant: None,
        }),
        Outcome::Forwarded
    );
    assert_eq!(
        d.spent("acme"),
        Some(200),
        "a distinct id is a distinct decision, and is charged"
    );

    // Replay suppression is per tenant: the same id under another tenant is a
    // different decision, so it cannot be used to get a free call elsewhere.
    let bob = actor("memorithm", "bob", AuthStrength::Token);
    let elsewhere = request("globex", "bob", "memory.recall", "the-same-request");
    assert_eq!(
        d.admit(Call {
            actor: &bob,
            request: &elsewhere,
            model: "gpt-5",
            cost_tokens: 50,
            variant: None,
        }),
        Outcome::Forwarded
    );
    assert_eq!(
        d.spent("globex"),
        Some(50),
        "REGRESSION GUARD: the replay key is (tenant, request_id), not request_id"
    );
}

// ── 9. Defect 7, REPAIRED: whose budget is it? ───────────────────────────

/// **DEFECT 7 (critical, authorization + budget drain) — REPAIRED; this test
/// is the guard, and it is the most valuable assertion in this file.**
///
/// The predecessor's `decide` took identity from `call.actor` but took the
/// actor *name* and the tenant from the request: it checked
/// `roles.allows(&call.request.actor, …)` and charged `call.request.tenant`'s
/// budget. The authenticated principal was never compared with either.
///
/// The budget consequence was total: any principal that could authenticate at
/// all could drain **every** tenant's budget, by naming that tenant and any
/// privileged actor name in the request body. There is no rate limit and no
/// per-actor sub-quota, so the whole quota went in a handful of calls — and
/// the journal recorded the *spoofed* name, so the real principal was
/// unrecoverable after the fact.
///
/// Two gates close it, and the order matters: a request must name the actor
/// its credential proves ([`Refusal::ActorMismatch`]) and reach a tenant its
/// credential's organization owns ([`Refusal::TenantNotOwnedByOrg`]), both
/// **before** any tenant state is touched. The attack below is kept exactly as
/// it was — same stranger, same spoofed names, same tenants, same prices — and
/// every step of it is now asserted to be refused, free, and journaled as an
/// attempt.
#[test]
fn no_authenticated_actor_can_drain_another_tenants_budget() {
    let mut d = two_tenant_deployment();
    // A nobody: authenticated, holds no role, belongs to no tenant.
    let mallory = actor("evil-corp", "mallory", AuthStrength::Token);

    // Under her own name she gets nothing. The refusal changed shape with the
    // repair — it is no longer PermissionDenied but TenantNotOwnedByOrg,
    // because the org gate is evaluated *before* RBAC, deliberately: a
    // stranger must not be able to enumerate a tenant's role configuration by
    // the refusal it hands back.
    let honest = request("acme", "mallory", "memory.ingest", "m-1");
    assert_eq!(
        d.admit(Call {
            actor: &mallory,
            request: &honest,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::TenantNotOwnedByOrg)
    );
    assert_eq!(d.spent("acme"), Some(0), "and it costs the tenant nothing");

    // Claiming to be `alice` in the request body was enough. It is now the
    // first thing checked against the credential.
    let spoofed = request("acme", "alice", "memory.ingest", "m-2");
    assert_eq!(
        d.admit(Call {
            actor: &mallory,
            request: &spoofed,
            model: "claude-opus",
            cost_tokens: 1_000,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::ActorMismatch),
        "REGRESSION GUARD: an unrelated principal may not be admitted as alice"
    );
    assert_eq!(
        d.spent("acme"),
        Some(0),
        "REGRESSION GUARD: and acme's budget is untouched"
    );

    // The same call against globex — one authenticated stranger, every
    // tenant's quota — is refused identically.
    let cross = request("globex", "bob", "memory.recall", "m-3");
    assert_eq!(
        d.admit(Call {
            actor: &mallory,
            request: &cross,
            model: "gpt-5",
            cost_tokens: 500,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::ActorMismatch)
    );
    assert_eq!(
        d.spent("globex"),
        Some(0),
        "REGRESSION GUARD: globex is not drained either"
    );

    // Impersonation is refused *inside* the organization too. This is the
    // sharper half: `insider` is a genuine memorithm principal whose org does
    // own acme, so the org gate cannot help here — only the actor binding can.
    d.assign("insider", "reader");
    let insider = actor("memorithm", "insider", AuthStrength::Token);
    let elevated = request("acme", "alice", "memory.ingest", "m-4");
    assert_eq!(
        d.admit(Call {
            actor: &insider,
            request: &elevated,
            model: "claude-opus",
            cost_tokens: 1_000,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::ActorMismatch),
        "REGRESSION GUARD: an in-org principal may not borrow alice's permissions"
    );
    assert_eq!(d.spent("acme"), Some(0));

    // …and RBAC still does its own job underneath: under her real name the
    // insider is refused for want of the permission, not for the binding. This
    // is the coverage the original test had before the org gate shadowed it.
    let honest_insider = request("acme", "insider", "memory.ingest", "m-5");
    assert_eq!(
        d.admit(Call {
            actor: &insider,
            request: &honest_insider,
            model: "claude-opus",
            cost_tokens: 1_000,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::PermissionDenied),
        "a reader may not ingest, credential binding or not"
    );
    assert_eq!(d.spent("acme"), Some(0), "still nothing billed");

    // Nothing was forwarded, and the journal blames nobody: every attempt is
    // recorded under the name the caller *claimed*, with a refusal attached —
    // so the impersonation is visible as an attempt instead of being
    // indistinguishable from alice's own work.
    let trail = d.audit_of("acme");
    assert!(
        !trail.iter().any(|r| r.outcome.is_forwarded()),
        "REGRESSION GUARD: not one of these calls reached Core"
    );
    assert!(
        trail
            .iter()
            .any(|r| r.actor == "alice" && r.outcome.refusal() == Some(&Refusal::ActorMismatch)),
        "the spoofed name is journaled — as a refused attempt"
    );
    assert!(
        trail.iter().all(|r| r.cost == 0),
        "and none of it was billed"
    );

    // The legitimate holder of the name is entirely unaffected: alice, with
    // alice's credential, still works.
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let genuine = request("acme", "alice", "memory.ingest", "m-6");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &genuine,
            model: "claude-opus",
            cost_tokens: 1_000,
            variant: None,
        }),
        Outcome::Forwarded,
        "the binding refuses impersonation, not the real principal"
    );
    assert_eq!(d.spent("acme"), Some(1_000));
}

/// **DEFECT 8 (low, observability) — REPAIRED; this test is the guard.**
///
/// `Deployment::spent` folded "no such tenant" into `0`. A quota dashboard or
/// an invoice run that misspelled a tenant reported zero usage for ever
/// instead of failing, and there was no way to tell an empty meter from a
/// missing one — the same shape as defect 3: the meter was trusted and could
/// not be questioned.
///
/// It returns `Option<u64>` now. The probes below are the original ones, with
/// the opposite expectation: every spelling that names no tenant answers
/// `None`, and a tenant that exists and has spent nothing answers `Some(0)`,
/// which is a different answer.
#[test]
fn spent_distinguishes_an_unknown_tenant_from_an_empty_one() {
    let mut d = two_tenant_deployment();
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let req = request("acme", "alice", "memory.ingest", "r-1");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 42,
            variant: None,
        }),
        Outcome::Forwarded
    );
    assert_eq!(d.spent("acme"), Some(42));
    // Tenant ids are still exact, byte for byte — that has not changed and
    // should not. What changed is that a near-miss now says so.
    assert_eq!(d.spent("ACME"), None, "tenant ids are case-sensitive…");
    assert_eq!(d.spent("acme "), None, "…and whitespace-sensitive…");
    assert_eq!(
        d.spent("no-such-tenant"),
        None,
        "REGRESSION GUARD: a tenant that does not exist is not reported as one \
         that spent nothing"
    );
    assert_eq!(
        d.spent("globex"),
        Some(0),
        "REGRESSION GUARD: …and a real tenant that spent nothing says Some(0), \
         which is a different answer"
    );
    assert_ne!(d.spent("globex"), d.spent("no-such-tenant"));
}

// ── 10. ModelAllowlist ───────────────────────────────────────────────────

/// An empty allowlist denies everything — including the empty string, every
/// whitespace variant, and 50 000 random byte strings. This is the one
/// fail-closed default in the policy crate and it holds without exception.
#[test]
fn an_empty_allowlist_denies_everything_including_the_empty_string() {
    let empty = ModelAllowlist::default();
    for probe in [
        "",
        " ",
        "\0",
        "\n",
        "claude-opus",
        "gpt-5",
        "*",
        "%",
        ".*",
        "null",
        "undefined",
        "default",
        "\u{202e}claude-opus",
        "claude-opus\u{200d}",
    ] {
        assert_eq!(
            empty.evaluate(probe),
            PolicyDecision::Deny,
            "empty allowlist admitted {probe:?}"
        );
    }

    let mut rng = Rng::new(SEED ^ 0x1234_5678_9ABC_DEF0);
    for _ in 0..50_000 {
        let len = rng.below(12) as usize;
        let s: String = (0..len)
            .map(|_| char::from(b'!' + (rng.below(93) as u8)))
            .collect();
        assert_eq!(
            empty.evaluate(&s),
            PolicyDecision::Deny,
            "empty allowlist admitted {s:?}"
        );
    }

    // …and the same through the composed path: a tenant with no allowlist
    // cannot call anything, so no call of theirs can ever reach the meter.
    let mut d = Deployment::new();
    d.add_role("writer", &["memory.write"])
        .govern_tool("memory.ingest", "memory.write");
    assert!(d.add_tenant("o", "bare", TenantState::new(1_000)));
    assert!(d.assign("a", "writer"));
    let who = actor("o", "a", AuthStrength::Token);
    for (i, model) in ["", "claude-opus", "gpt-5"].into_iter().enumerate() {
        let req = request("bare", "a", "memory.ingest", &format!("r-{i}"));
        assert_eq!(
            d.admit(Call {
                actor: &who,
                request: &req,
                model,
                cost_tokens: 1,
                variant: None,
            })
            .refusal(),
            Some(&Refusal::ModelNotAllowed),
            "model {model:?}"
        );
    }
    assert_eq!(d.spent("bare"), Some(0), "and none of it was billed");
}

/// A 100 000-entry allowlist: every listed name is admitted, every near-miss
/// is refused, and lookup is exact. `BTreeSet<String>` ordering means this is
/// `O(log n)` string comparisons, so the size is not itself a vector.
///
/// The near-misses are the interesting half: a trailing space, a trailing NUL,
/// a case flip and a one-character truncation are all refused. The allowlist
/// does no canonicalization at all — it is raw byte equality.
#[test]
fn a_hundred_thousand_entry_allowlist_is_exact() {
    const N: usize = 100_000;
    let mut set = BTreeSet::new();
    for i in 0..N {
        set.insert(format!("vendor/model-{i:06}"));
    }
    let al = ModelAllowlist(set);
    assert_eq!(al.0.len(), N);

    let mut rng = Rng::new(SEED ^ 0x0F0F_0F0F_0F0F_0F0F);
    for _ in 0..20_000 {
        let i = rng.below(N as u64);
        let hit = format!("vendor/model-{i:06}");
        assert_eq!(
            al.evaluate(&hit),
            PolicyDecision::Allow,
            "listed model {hit} was refused"
        );
        for miss in [
            format!("{hit} "),
            format!(" {hit}"),
            format!("{hit}\0"),
            format!("{hit}\n"),
            hit.to_uppercase(),
            hit[..hit.len() - 1].to_string(),
            format!("{hit}0"),
            hit.replace('/', "\\"),
        ] {
            assert_eq!(
                al.evaluate(&miss),
                PolicyDecision::Deny,
                "near-miss {miss:?} was admitted"
            );
        }
    }
    // Names outside the generated range are refused whatever they look like.
    for miss in [
        "vendor/model-999999",
        "vendor/model-",
        "vendor/",
        "model-000001",
    ] {
        assert_eq!(al.evaluate(miss), PolicyDecision::Deny, "{miss}");
    }

    // A 1 MiB model name is refused without incident: `BTreeSet` comparison is
    // O(log n) string compares and each compare stops at the first differing
    // byte, so an oversized name is not an amplification vector. (The
    // allowlist does not bound entry length either — see
    // `the_allowlist_accepts_non_canonical_entries` — but nothing here
    // degrades super-linearly.)
    let huge = "v".repeat(1 << 20);
    assert_eq!(al.evaluate(&huge), PolicyDecision::Deny);
    let mut adversarial = "vendor/model-000000".to_string();
    adversarial.push_str(&"0".repeat(1 << 20)); // maximal shared prefix
    assert_eq!(al.evaluate(&adversarial), PolicyDecision::Deny);
}

/// **DEFECT 9 (medium, footgun).** The two gates on the same request path
/// disagree about case. `ccos_enterprise_gateway::classify` lowercases the
/// tool name on purpose — its own docs say "matching is case-insensitive so
/// `RSI.x` cannot slip past a case-normalizing router downstream".
/// `ModelAllowlist::evaluate` is raw `BTreeSet::contains`: byte equality, no
/// folding.
///
/// The model side fails *closed* (`Claude-Opus` is refused when `claude-opus`
/// is listed), so this is not a hole on its own. It is a footgun in two ways:
/// an operator who lists `Claude-Opus` because that is how the vendor spells
/// it silently refuses every real call; and a deployment that normalizes model
/// names anywhere upstream changes the meaning of the allowlist without
/// touching it. The exact same argument the gateway makes for tools applies to
/// models, and is not applied.
#[test]
fn the_allowlist_is_case_sensitive_but_the_gateway_is_not() {
    let al = ModelAllowlist(["claude-opus".to_string()].into_iter().collect());
    assert_eq!(al.evaluate("claude-opus"), PolicyDecision::Allow);
    for variant in [
        "Claude-Opus",
        "CLAUDE-OPUS",
        "claude-Opus",
        "cLaUdE-oPuS",
        "claude-opus ",
    ] {
        assert_eq!(
            al.evaluate(variant),
            PolicyDecision::Deny,
            "TRUTH: the model allowlist is case- and byte-SENSITIVE: {variant}"
        );
    }

    // The gateway, on the identical request, folds case without hesitation.
    let mut folded = 0;
    for tool in ["memory.recall", "MEMORY.RECALL", "Memory.Recall"] {
        let req = request("acme", "alice", tool, "r-1");
        assert_eq!(
            classify(&req),
            Disposition::Forward,
            "the boundary folds case for tools: {tool}"
        );
        folded += 1;
    }
    assert_eq!(folded, 3);

    // And end to end: same tenant, same tool, one capital letter apart.
    let mut d = two_tenant_deployment();
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let req = request("acme", "alice", "MEMORY.INGEST", "r-cased");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "Claude-Opus",
            cost_tokens: 10,
            variant: None,
        })
        .refusal(),
        // NOT ModelNotAllowed: the *tool* name survived case folding at the
        // boundary but not the governance map, which is another raw
        // `BTreeMap<String, _>` lookup. Three lookups, two folding rules.
        Some(&Refusal::ToolNotGoverned),
        "the boundary admits MEMORY.INGEST; the governance map has never heard of it"
    );
    assert_eq!(d.spent("acme"), Some(0), "at least the refusal is free");

    // The sharp edge of the same disagreement. Because the boundary treats
    // `MEMORY.INGEST` and `memory.ingest` as one tool but the governance map
    // treats them as two, a deployment can hold two different permissions for
    // what the boundary considers the same capability — and the weaker one
    // wins for anyone who types it. Here `bob` holds only `memory.read`, is
    // correctly refused `memory.ingest`, and gets the identical capability
    // through a capitalised spelling. It is a configuration mistake to make,
    // but nothing in the product can detect or refuse it: `govern_tool` is a
    // raw `insert`, so the collision is silent.
    d.govern_tool("MEMORY.INGEST", "memory.read");
    let bob = actor("memorithm", "bob", AuthStrength::Token);
    let denied = request("acme", "bob", "memory.ingest", "r-lower");
    assert_eq!(
        d.admit(Call {
            actor: &bob,
            request: &denied,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::PermissionDenied),
        "a reader may not ingest"
    );
    let escalated = request("acme", "bob", "MEMORY.INGEST", "r-upper");
    assert_eq!(
        d.admit(Call {
            actor: &bob,
            request: &escalated,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
        }),
        Outcome::Forwarded,
        "FOOTGUN: the same capability, one capital letter apart, under a weaker permission"
    );
    assert_eq!(
        d.spent("acme"),
        Some(10),
        "and it is billed like any other call"
    );
}

/// The allowlist accepts entries the gateway would refuse outright for a tool:
/// the empty string, whitespace, control bytes. Nothing canonicalizes an
/// allowlist entry on the way in, so `allow_model("")` really does make the
/// empty model name a governed, billable model.
///
/// Not a hole by itself — you have to configure it — but it is the mirror of
/// the gateway's canonicality check, which exists precisely because "the
/// boundary never forwards what it cannot classify".
#[test]
fn the_allowlist_accepts_non_canonical_entries() {
    let mut d = Deployment::new();
    d.add_role("writer", &["memory.write"])
        .govern_tool("memory.ingest", "memory.write");
    let mut t = TenantState::new(100);
    t.allow_model("").allow_model(" ").allow_model("a\nb");
    assert!(d.add_tenant("o", "acme", t));
    assert!(d.assign("a", "writer"));
    let who = actor("o", "a", AuthStrength::Token);

    for (i, model) in ["", " ", "a\nb"].into_iter().enumerate() {
        let req = request("acme", "a", "memory.ingest", &format!("r-{i}"));
        assert_eq!(
            d.admit(Call {
                actor: &who,
                request: &req,
                model,
                cost_tokens: 1,
                variant: None,
            }),
            Outcome::Forwarded,
            "TRUTH: {model:?} is a perfectly good model name to the allowlist"
        );
    }
    assert_eq!(d.spent("acme"), Some(3), "and all three calls were billed");

    // The gateway refuses exactly these spellings for a tool name.
    for tool in ["", " ", "a\nb"] {
        let req = request("acme", "a", tool, "r");
        assert!(
            matches!(classify(&req), Disposition::Reject(_)),
            "the boundary refuses non-canonical tool {tool:?} — the allowlist does not"
        );
    }
}

// ── 11. Ordering: the gate is greedy, and greed is observable ────────────

/// The gate is first-come-first-served with no reservation, so the *order* of
/// a fixed multiset of charges decides how much of it is admitted. Two
/// permutations of the same three charges bill 100 and 3 tokens respectively.
///
/// Documented rather than filed as a defect — greedy is a legitimate design —
/// but it is worth pinning, because it means a large job can be starved
/// indefinitely by a stream of small ones while the meter stays under the
/// limit, and no refusal ever reserves anything for the caller that hit it.
#[test]
fn the_gate_is_greedy_and_order_dependent() {
    let charges = [100u64, 3, 1];

    let mut big_first = TokenBudget::new(100);
    let mut admitted_big = 0u64;
    for c in charges {
        if big_first.charge(c) == PolicyDecision::Allow {
            admitted_big += c;
        }
    }
    assert_eq!(admitted_big, 100, "the big charge took everything");
    assert_eq!(big_first.spent, 100);

    let mut small_first = TokenBudget::new(100);
    let mut admitted_small = 0u64;
    for c in [3u64, 1, 100] {
        if small_first.charge(c) == PolicyDecision::Allow {
            admitted_small += c;
        }
    }
    assert_eq!(
        admitted_small, 4,
        "the same multiset, reordered, admits 4 tokens and starves the big job"
    );
    assert_eq!(small_first.spent, 4);

    // Starvation is permanent: the big job is refused for ever while the
    // budget still has 96 tokens of headroom.
    for _ in 0..1_000 {
        assert_eq!(small_first.charge(100), PolicyDecision::Deny);
    }
    assert_eq!(
        small_first.spent, 4,
        "and none of those refusals cost anything"
    );
    assert_eq!(
        small_first.limit - small_first.spent,
        96,
        "96 tokens of headroom the starved caller can never reach"
    );
}

// ── 12. The gate is a free oracle for another tenant's balance ───────────

/// **DEFECT 10 (medium, information disclosure) — STILL OPEN, but narrowed.**
/// `charge` is a *free* comparison oracle: a refused charge costs nothing and
/// is distinguishable from every other refusal (`Refusal::BudgetExhausted`),
/// and it answers exactly one question — "is `cost` greater than what this
/// tenant has left?"
///
/// Combined with defect 7 (nothing bound the caller to the tenant it named),
/// this let **any authenticated stranger** interrogate **any** tenant's
/// remaining balance. That half is repaired, and the first section below is
/// the regression guard for it: the stranger's probe is now refused *before*
/// the budget gate, and refused **identically whatever it costs**, so it
/// carries no signal at all. That is the property that matters for an oracle —
/// not merely that the probe fails, but that its failure is independent of the
/// secret.
///
/// What remains is the oracle itself, for a caller who legitimately shares the
/// tenant. The blast radius is now one organization instead of the whole
/// deployment, but inside it the leak is unchanged, and it is worth keeping
/// pinned: a low-trust automation that holds one governed tool can read the
/// tenant's exact remaining balance without spending a token, and the same
/// twenty calls that read the number also drain it.
///
/// The two phases are deliberately separated:
/// * **free phase** — a descending ladder of refused probes proves a bound on
///   the tenant's balance while `spent` never moves;
/// * **paid phase** — running the search to completion recovers the balance
///   *exactly*, and costs exactly the balance.
///
/// Rate limiting would not help: `ccos_license_server::TokenBucket` exists in
/// this workspace, and the admission path does not use it. Every probe carries
/// a distinct `request_id`, so replay suppression is not what is being
/// measured here.
#[test]
fn the_budget_gate_leaks_the_balance_to_anyone_who_shares_the_tenant() {
    const LIMIT: u64 = 1_000_000;
    const SECRET_SPEND: u64 = 618_034; // unknown to the attacker
    let remaining_truth = LIMIT - SECRET_SPEND;

    let mut d = Deployment::new();
    d.add_role("writer", &["memory.write"])
        .govern_tool("memory.ingest", "memory.write");
    let mut victim = TenantState::new(LIMIT);
    victim.allow_model("m");
    assert!(d.add_tenant("victim-corp", "victim", victim));
    assert!(d.assign("insider", "writer"));

    let insider = actor("victim-corp", "insider", AuthStrength::Token);
    let legit = request("victim", "insider", "memory.ingest", "legit");
    assert_eq!(
        d.admit(Call {
            actor: &insider,
            request: &legit,
            model: "m",
            cost_tokens: SECRET_SPEND,
            variant: None,
        }),
        Outcome::Forwarded
    );

    // ── REGRESSION GUARD: the outside attacker gets no signal.
    //
    // The original attack: a stranger from another org, spoofing the insider's
    // name in the request body. Both spellings of it are refused now, and —
    // the part that kills the oracle — the refusal does not depend on the
    // probe's cost. A probe for 1 token and a probe for u64::MAX come back
    // byte-identical, so no sequence of them can bracket the balance.
    let mallory = actor("evil-corp", "mallory", AuthStrength::Token);
    for cost in [0u64, 1, remaining_truth, remaining_truth + 1, u64::MAX] {
        let spoofed = request("victim", "insider", "memory.ingest", &format!("s-{cost}"));
        assert_eq!(
            d.admit(Call {
                actor: &mallory,
                request: &spoofed,
                model: "m",
                cost_tokens: cost,
                variant: None,
            })
            .refusal(),
            Some(&Refusal::ActorMismatch),
            "REGRESSION GUARD: the refusal must not vary with the probe's cost"
        );
        let honest = request("victim", "mallory", "memory.ingest", &format!("h-{cost}"));
        assert_eq!(
            d.admit(Call {
                actor: &mallory,
                request: &honest,
                model: "m",
                cost_tokens: cost,
                variant: None,
            })
            .refusal(),
            Some(&Refusal::TenantNotOwnedByOrg),
            "REGRESSION GUARD: nor when the stranger probes under her own name"
        );
    }
    assert_eq!(
        d.spent("victim"),
        Some(SECRET_SPEND),
        "REGRESSION GUARD: ten cross-org probes moved nothing and learned nothing"
    );

    // ── The residual, still open: an actor who shares the tenant.
    // `insider` holds exactly one governed tool and no admin capability — the
    // shape of a low-trust automation — and that is enough.
    let mut probes = 0u32;
    let mut probe = |d: &mut Deployment, cost: u64| -> bool {
        probes += 1;
        let req = request(
            "victim",
            "insider",
            "memory.ingest",
            &format!("probe-{probes}"),
        );
        d.admit(Call {
            actor: &insider,
            request: &req,
            model: "m",
            cost_tokens: cost,
            variant: None,
        })
        .is_forwarded()
    };

    // ── Free phase: refused probes only. Every one is free.
    let mut free_probes = 0u32;
    let mut known_upper_bound = LIMIT;
    let mut ladder = LIMIT;
    while ladder > remaining_truth {
        let before = d.spent("victim");
        assert!(
            !probe(&mut d, ladder),
            "a probe above the balance must be refused"
        );
        assert_eq!(
            d.spent("victim"),
            before,
            "INFORMATION LEAK: the refused probe cost the prober nothing"
        );
        known_upper_bound = ladder;
        free_probes += 1;
        ladder = ladder * 3 / 4;
    }
    assert!(free_probes >= 3, "free probes issued: {free_probes}");
    assert_eq!(
        d.spent("victim"),
        Some(SECRET_SPEND),
        "the whole reconnaissance is invisible in the meter"
    );
    // What the prober now knows, for free and with certainty.
    assert!(
        known_upper_bound <= remaining_truth * 4 / 3 + 1,
        "the free bound is tight: balance < {known_upper_bound}"
    );
    // …and invisible in the journal's cost column too: the refused probes are
    // journaled, at zero, exactly like any other refusal. The repaired audit
    // record makes the *attempts* countable, which is the only handle an
    // operator has on this — but it does not close the leak.
    let recon: Vec<&AuditRecord> = d.audit_of("victim");
    assert!(
        recon
            .iter()
            .filter(|r| r.request_id.starts_with("probe-"))
            .all(|r| r.cost == 0),
        "every reconnaissance probe is journaled at zero cost"
    );

    // ── Paid phase: binary search to the exact token.
    // Invariant: the true original balance R0 lies in [lo, hi], and `lo` is
    // exactly what the prober has spent so far, so the next probe is always
    // affordable to compute.
    let (mut lo, mut hi) = (0u64, LIMIT);
    let mut paid = 0u64;
    while lo < hi {
        let target = lo + (hi - lo).div_ceil(2);
        let cost = target - paid;
        let before = d.spent("victim").expect("the tenant exists");
        if probe(&mut d, cost) {
            lo = target;
            paid += cost;
            assert_eq!(
                d.spent("victim"),
                Some(before + cost),
                "an admitted probe is billed"
            );
        } else {
            hi = target - 1;
            assert_eq!(d.spent("victim"), Some(before), "a refused probe is free");
        }
        assert_eq!(lo, paid, "search invariant");
    }

    assert_eq!(
        lo, remaining_truth,
        "DEFECT: the prober recovered the tenant's exact balance"
    );
    assert!(
        probes <= 30,
        "…in {probes} calls, logarithmic in the limit, not linear"
    );
    assert_eq!(
        d.spent("victim"),
        Some(LIMIT),
        "…and the same search drained the tenant to the last token"
    );
}

// ── 13. Cross-check: the metrics and the meter tell different stories ────

/// The deployment exports `gateway.forwarded` and `gateway.refused.*`
/// counters, and a meter. Nothing ties them together: with `cost_tokens: 0`
/// the counters climb without bound while the meter stays flat, and with a
/// `u64::MAX` limit the counters climb while the meter is pinned. An operator
/// watching either number alone cannot detect either condition.
///
/// This test pins the divergence at a small, readable size so a future repair
/// (a cost in the audit record, a reconciliation, a non-saturating gate) fails
/// here and gets read.
#[test]
fn counters_and_meter_can_be_made_to_disagree_arbitrarily() {
    let mut d = two_tenant_deployment();
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    for i in 0..500 {
        let req = request("acme", "alice", "memory.recall", &format!("r-{i}"));
        assert_eq!(
            d.admit(Call {
                actor: &alice,
                request: &req,
                model: "claude-opus",
                cost_tokens: 0,
                variant: None,
            }),
            Outcome::Forwarded
        );
    }
    let metrics = d.metrics();
    let get = |name: &str| {
        metrics
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    };
    assert_eq!(get("gateway.requests"), 500);
    assert_eq!(get("gateway.forwarded"), 500);
    assert_eq!(get("gateway.refused"), 0);
    assert_eq!(get("gateway.replayed"), 0, "500 distinct decisions");
    assert_eq!(
        d.spent("acme"),
        Some(0),
        "500 calls reached Core and the tenant was billed nothing"
    );
    // The journal now agrees with the meter rather than with the counters,
    // which is the repair working exactly as intended and *not* a fix for
    // defect 2: 500 records, 500 zero costs, one honest total of zero. The
    // gap an operator has to watch is between `gateway.forwarded` and the
    // journal's row count on one side, and the cost column on the other.
    let trail = d.audit_of("acme");
    assert_eq!(trail.len(), 500);
    let billed: u64 = trail.iter().map(|r| r.cost).sum();
    assert_eq!(Some(billed), d.spent("acme"));
}

// ── 14. The audit buffer is bounded, and says what it dropped ────────────

/// The predecessor's journal was an unbounded `Vec`: every decision, forwarded
/// or refused, was retained for ever, so an unauthenticated caller could make
/// the deployment hold 1.15 GiB across five million refused calls — and the
/// identifiers were recorded verbatim, so each record could be made a
/// megabyte wide.
///
/// The buffer is bounded now ([`Deployment::with_audit_capacity`], defaulting
/// to `DEFAULT_AUDIT_CAPACITY`), the oldest records are dropped, and
/// `audit_dropped()` counts them. Dropping is the honest failure mode for a
/// bounded buffer and it is **not** an audit story on its own: a
/// compliance-grade deployment must flush to durable storage, and a non-zero
/// drop count is exactly the signal that it has not.
///
/// This is the budget file's stake in that bound: the meter must stay exact
/// across records the journal has thrown away, so an operator can still tell
/// that the journal is incomplete rather than that the tenant spent less.
#[test]
fn the_journal_is_bounded_and_the_meter_is_not() {
    const CAP: usize = 64;
    const CALLS: u64 = 5_000;

    let mut d = Deployment::new().with_audit_capacity(CAP);
    d.add_role("writer", &["memory.write"])
        .govern_tool("memory.ingest", "memory.write");
    let mut t = TenantState::new(CALLS);
    t.allow_model("m");
    assert!(d.add_tenant("o", "acme", t));
    assert!(d.assign("a", "writer"));
    let who = actor("o", "a", AuthStrength::Token);

    for i in 0..CALLS {
        let req = request("acme", "a", "memory.ingest", &format!("r-{i}"));
        assert_eq!(
            d.admit(Call {
                actor: &who,
                request: &req,
                model: "m",
                cost_tokens: 1,
                variant: None,
            }),
            Outcome::Forwarded
        );
    }

    assert_eq!(
        d.audit().count(),
        CAP,
        "the buffer never grows past the capacity it was given"
    );
    assert_eq!(
        d.audit_dropped(),
        CALLS - CAP as u64,
        "…and says exactly how many records it lost"
    );
    // The retained window is the newest, and still in decision order.
    let sequences: Vec<u64> = d.audit().map(|r| r.sequence).collect();
    assert_eq!(
        sequences,
        (CALLS - CAP as u64..CALLS).collect::<Vec<_>>(),
        "the window is contiguous, newest-last, and its sequence numbers say \
         where the missing records were"
    );
    // The meter counted every one of them, including the 4 936 the journal
    // dropped: a truncated journal under-reports the trail, never the bill.
    assert_eq!(d.spent("acme"), Some(CALLS));
    let retained: u64 = d.audit().map(|r| r.cost).sum();
    assert_eq!(retained, CAP as u64, "the window reconciles only itself…");
    assert!(
        Some(retained) < d.spent("acme"),
        "…and the drop count is what says so: {} records missing",
        d.audit_dropped()
    );
}
