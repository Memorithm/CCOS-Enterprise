//! # Hostile stress of the authorization layer: scale, edges, privilege bleed
//!
//! `ccos_enterprise_rbac::RoleBook` is layer 2 of
//! `docs/ENTERPRISE_SECURITY_MODEL.md` ("Authorization — RBAC with
//! fail-closed unknown-role refusal") and the only thing standing between an
//! authenticated caller and a governed tool in
//! `ccos_enterprise_conformance::Deployment::admit`. This file attacks it at
//! 200k–500k scale, at every name edge a hostile admin API could reach, and
//! along the composed path.
//!
//! Everything asserted below is the product's **current, real** behaviour.
//! Where that behaviour is a defect the assertion pins the defect and the
//! comment names it, so a repair fails loudly here instead of silently
//! changing the security posture.
//!
//! ## What held
//!
//! * **Fail-closed on unknown roles.** `assign` to a role that does not exist
//!   returns `false`, stores nothing at all (not even an empty entry), and —
//!   critically — creating that role afterwards does **not** retro-grant it.
//! * **No permission bleed.** An actor holding N roles gets exactly the union
//!   of their permission sets, never a byte more: no wildcards, no prefix
//!   matching, no case folding, no `Ord`-adjacency leakage. Verified at
//!   N = 512 and sampled across 500 000.
//! * **Linear memory in the number of roles and actors.** Measured 845.9 B
//!   per (role + its assignment) at n = 12 500 / 25 000 / 50 000 / 100 000 —
//!   flat to one decimal place, 2.00x per doubling; 200k roles + 200k
//!   assignments retain 169 177 179 B and build in ~1.3 s (debug).
//!   See [`rolebook_memory_growth_is_linear_in_role_count`].
//!
//! ## What BROKE
//!
//! 1. **`Deployment::admit` authorizes the actor string the *request* carries,
//!    never the authenticated identity** (`src/lib.rs:303`). `AuthenticatedActor`
//!    is consulted for `strength` and then discarded; `call.actor.actor` is
//!    never compared with `call.request.actor`, and `call.actor.org` is never
//!    compared with the tenant. A token-strength reader impersonates a writer
//!    by typing their name — and the audit journal records the *typed* name
//!    (`src/lib.rs:274`), so the real caller is unrecoverable. This voids
//!    layer 1 of the security model and `docs/AGENT_IDENTITY_MODEL.md`'s
//!    "every journaled decision/action names its agent".
//!    → [`authorization_trusts_the_request_supplied_actor_string`]
//!
//! 2. **`add_role` silently REPLACES a same-named role**, rewriting the grant
//!    of every actor already holding it — downward (silent mass revocation)
//!    and upward (silent mass escalation). It returns `()`, so a caller
//!    cannot even detect the collision, and `Deployment::add_role` journals
//!    nothing: escalating every `reader` to `policy.admin` leaves an empty
//!    audit trail, and no `ccos_enterprise_admin::JUSTIFICATION_REQUIRED`
//!    entry covers role mutation.
//!    → [`add_role_silently_replaces_and_rewrites_every_holders_grant`]
//!
//! 3. **`RoleBook` is unbounded in every dimension.** No cap on roles, on
//!    actors, on roles-per-actor, or on name length — while the sibling
//!    `CounterRegistry` caps itself at `MAX_SERIES = 4096` precisely so "a
//!    label explosion can never exhaust memory". One actor absorbs 500 000
//!    roles without a single refusal (246 950 557 B, 493 B per role +
//!    assignment), and 500 000 distinct principals cost 195 980 545 B — none
//!    of which can ever be removed, since no removal API exists.
//!
//!    Worse than the memory: `allows()` is an O(assignments) scan that a
//!    denied check cannot short-circuit, so after that one admin burst
//!    **every** admission decision for the victim walks all 500 000 entries.
//!    Measured per denied check: 319 ns → 80.1 ms in **release**
//!    (251 130x), 1.96 us → 553 ms in debug. 80 ms of CPU per request caps
//!    that actor at ~12 requests/second/core — a durable denial of service
//!    installed by one admin call and paid by the request path forever.
//!    → [`rolebook_has_no_cap_one_actor_absorbs_half_a_million_roles`]
//!
//! 4. **Quadratic memory amplification per admin call.** `assign` stores a
//!    full `String` copy of the (unbounded, caller-chosen) role name in the
//!    actor's set, so A actors × R roles retains A·R copies from A+R calls.
//!    Measured with 1 KiB role names: 200 admin calls retain 11 108 417 B and
//!    400 retain 43 628 376 B — 3.93x for 2x calls, i.e. quadratic, at
//!    109 070 B *per admin call*. A single 1 MiB role name assigned to 64
//!    actors retains 69 233 569 B (33x the stored role).
//!    → [`assignment_storage_is_quadratic_in_admin_calls`] and
//!    [`megabyte_names_are_accepted_and_every_assignment_copies_them_whole`]
//!
//! 5. **Grants are deployment-global, not tenant-scoped.** `RoleBook`'s API
//!    has no `TenantId` anywhere, so one namespace of role names is shared by
//!    every tenant: `alice` carries her `acme` grant into `globex`, and one
//!    tenant's admin redefining `writer` rewrites the other tenant's writers.
//!    → [`role_grants_are_deployment_global_not_tenant_scoped`]
//!
//! 6. **No de-provisioning path exists.** There is no `unassign`, `revoke`,
//!    `remove_role` or `remove_actor`. Once assigned, an actor holds a role
//!    for the lifetime of the process; the only lever is redefining the role,
//!    which hits every holder (defect 2).
//!    → [`a_grant_can_never_be_withdrawn_from_a_single_actor`]
//!
//! 7. **Empty strings are valid principals and valid roles.** `""` names a
//!    grantable role and a grantable actor; a `GatewayRequest` with
//!    `actor: ""` is then authorized by the composed path.
//!    → [`the_empty_string_is_a_grantable_role_and_a_grantable_principal`]
//!
//! Run the whole file:
//! `cargo test -p ccos-enterprise-conformance --test stress_rbac_scale`
//! (add `-- --nocapture` for the measured growth tables).

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

use ccos_enterprise_auth::AuthStrength;
use ccos_enterprise_conformance::{
    actor, request, two_tenant_deployment, Call, Outcome, Refusal, TenantState,
};
use ccos_enterprise_observability::CounterRegistry;
use ccos_enterprise_rbac::{Permission, Role, RoleBook};

// ─────────────────────────────────────────────────────────────────────────
// Measurement harness
//
// A counting allocator gives an exact live-bytes figure for "how much did
// this RoleBook actually retain", which is the only honest way to answer
// "does memory explode superlinearly". It counts `Layout::size()`, so the
// numbers are allocator-independent and identical in debug and release
// except for the harness's own noise.
//
// Every test in this file takes `serialized()` so the measurements are not
// polluted by sibling tests allocating on other libtest threads. That makes
// wall-clock runtime additive, which is why the scale constants are tuned to
// keep the whole file well under a minute.
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

fn perm(name: &str) -> Permission {
    Permission(name.to_string())
}

fn role(name: &str, permissions: &[&str]) -> Role {
    Role {
        name: name.to_string(),
        permissions: permissions.iter().map(|p| perm(p)).collect(),
    }
}

/// `RoleBook`'s fields are private, but it derives `Serialize` — so the
/// stored shape is observable without inventing an API. Only ever called on
/// small books (a `serde_json::Value` of a 500k-role book would dwarf the
/// book itself).
fn snapshot(book: &RoleBook) -> serde_json::Value {
    serde_json::to_value(book).expect("RoleBook derives Serialize")
}

fn stored_role_names(book: &RoleBook) -> BTreeSet<String> {
    snapshot(book)["roles"]
        .as_object()
        .expect("roles is a map")
        .keys()
        .cloned()
        .collect()
}

fn stored_actors(book: &RoleBook) -> BTreeSet<String> {
    snapshot(book)["assignments"]
        .as_object()
        .expect("assignments is a map")
        .keys()
        .cloned()
        .collect()
}

/// `n` roles (`role-{i}` granting `perm.{i}`) and `n` actors, one role each.
fn book_of(n: usize) -> RoleBook {
    let mut book = RoleBook::default();
    for i in 0..n {
        book.add_role(role(&format!("role-{i:06}"), &[&format!("perm.{i:06}")]));
    }
    for i in 0..n {
        assert!(
            book.assign(&format!("actor-{i:06}"), &format!("role-{i:06}")),
            "known role must assign"
        );
    }
    book
}

// ─────────────────────────────────────────────────────────────────────────
// 1. Scale: 200 000 roles, 200 000 assignments — correctness first
// ─────────────────────────────────────────────────────────────────────────

/// 200k roles and 200k actor assignments, then exhaustive-by-stride lookup
/// checks: every actor resolves to exactly its own permission and to nothing
/// else. This is the baseline the rest of the file attacks: at this scale the
/// lookup semantics are *correct* — the defects below are all about what the
/// structure lets an administrator (or a compromised admin API) do to it.
#[test]
fn two_hundred_thousand_roles_and_assignments_resolve_exactly() {
    let _guard = serialized();
    const N: usize = 200_000;

    let before = live_bytes();
    let built = Instant::now();
    let book = book_of(N);
    let build_ms = built.elapsed().as_millis();
    let retained = live_bytes().saturating_sub(before);

    // Reported, never asserted: wall clock is not a test oracle.
    println!(
        "[scale] {N} roles + {N} assignments: {retained} B retained \
         ({} B/role incl. its assignment), built in {build_ms} ms",
        retained / N
    );

    // Positive lookups across the whole key range, including both BTreeMap
    // extremes. The stride is coprime-ish with N so the sample is spread.
    let mut checked = 0usize;
    for i in (0..N).step_by(1_777) {
        let a = format!("actor-{i:06}");
        assert!(
            book.allows(&a, &perm(&format!("perm.{i:06}"))),
            "actor-{i:06} lost its own grant at scale"
        );
        // …and exactly nothing else: the neighbour's permission, the
        // permission of a far-away role, and a prefix of its own.
        let neighbour = (i + 1) % N;
        assert!(
            !book.allows(&a, &perm(&format!("perm.{neighbour:06}"))),
            "actor-{i:06} bled into its neighbour's permission"
        );
        assert!(
            !book.allows(&a, &perm(&format!("perm.{:06}", (i + N / 2) % N))),
            "actor-{i:06} bled across the tree"
        );
        assert!(
            !book.allows(&a, &perm("perm.")),
            "a permission prefix is not a wildcard"
        );
        checked += 1;
    }
    assert!(checked > 100, "the sample must actually cover the range");

    for edge in [0usize, 1, N - 2, N - 1] {
        assert!(
            book.allows(
                &format!("actor-{edge:06}"),
                &perm(&format!("perm.{edge:06}"))
            ),
            "edge actor-{edge:06} must resolve"
        );
    }

    // Unknown actors hold nothing, however close their names sit in the tree.
    for stranger in [
        "actor-",
        "actor-000000 ",
        "actor-0000000",
        "",
        "actor-999999",
    ] {
        assert!(
            !book.allows(stranger, &perm("perm.000000")),
            "{stranger:?} must hold nothing"
        );
    }

    // Deep no-bleed probe on one actor: 0 of 2 000 foreign permissions.
    let alone = "actor-000000";
    let bled = (1..2_001)
        .filter(|i| book.allows(alone, &perm(&format!("perm.{i:06}"))))
        .count();
    assert_eq!(bled, 0, "one role must grant exactly one permission");
}

// ─────────────────────────────────────────────────────────────────────────
// 2. Growth: linear in role/actor count (this one HOLDS)…
// ─────────────────────────────────────────────────────────────────────────

/// Doubling the number of roles-and-actors must roughly double the retained
/// bytes. It does — the `BTreeMap`s are honest — so the scale defect is not
/// "the container is inefficient" but "nothing ever stops filling it"
/// (see [`rolebook_has_no_cap_one_actor_absorbs_half_a_million_roles`]) and
/// "one admin call can retain unboundedly many bytes"
/// (see [`assignment_storage_is_quadratic_in_admin_calls`]).
#[test]
fn rolebook_memory_growth_is_linear_in_role_count() {
    let _guard = serialized();

    let mut curve: Vec<(usize, usize)> = Vec::new();
    for n in [12_500usize, 25_000, 50_000, 100_000] {
        let before = live_bytes();
        let book = book_of(n);
        let retained = live_bytes().saturating_sub(before);
        curve.push((n, retained));
        drop(book);
        // The structure frees everything it took: no leak on drop.
        assert!(
            live_bytes().saturating_sub(before) < retained / 8,
            "dropping the book must return the memory"
        );
    }

    println!("[growth] n, bytes, bytes/n, ratio-to-previous");
    let mut previous: Option<(usize, usize)> = None;
    for &(n, bytes) in &curve {
        let per = bytes as f64 / n as f64;
        match previous {
            None => println!("[growth] {n}, {bytes}, {per:.1}, -"),
            Some((pn, pb)) => {
                let ratio = bytes as f64 / pb as f64;
                println!(
                    "[growth] {n}, {bytes}, {per:.1}, {ratio:.2}x for {:.2}x n",
                    n as f64 / pn as f64
                );
                assert!(
                    ratio < 3.0,
                    "growth {ratio:.2}x for a 2x input is not linear \
                     (quadratic would be ~4x): {curve:?}"
                );
            }
        }
        assert!(
            per < 4_096.0,
            "{per:.1} B per role+assignment is far beyond the data stored: {curve:?}"
        );
        previous = Some((n, bytes));
    }

    // Per-item cost must not drift upward with size, which is what a
    // superlinear structure would show.
    let first = curve[0].1 as f64 / curve[0].0 as f64;
    let last = curve[curve.len() - 1].1 as f64 / curve[curve.len() - 1].0 as f64;
    assert!(
        last < first * 2.0,
        "per-item cost grew from {first:.1} B to {last:.1} B with size"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 3. EXHAUSTION VECTOR: nothing is ever capped
// ─────────────────────────────────────────────────────────────────────────

/// **FINDING (exhaustion-vector).** `RoleBook` has no cap on roles, on
/// actors, or on roles-per-actor, and no way to remove any of them. Half a
/// million roles land on one actor without a single refusal.
///
/// The workspace knows this pattern and applies it elsewhere:
/// `CounterRegistry::MAX_SERIES` (4096) exists so "a label explosion can
/// never exhaust memory", and folds the overflow. `RoleBook` — reachable from
/// exactly the same admin surface, and holding attacker-chosen `String`s —
/// has no equivalent.
///
/// Second-order: `allows()` is `assignments[actor] × roles-lookup`, so after
/// this one admin burst *every* admission decision for that actor walks half
/// a million entries before it can deny. The cost is paid on
/// `Deployment::admit`'s hot path, by the victim, forever.
#[test]
fn rolebook_has_no_cap_one_actor_absorbs_half_a_million_roles() {
    let _guard = serialized();
    const N: usize = 500_000;

    // The cap that does exist, next to the cap that does not.
    assert_eq!(
        CounterRegistry::MAX_SERIES,
        4_096,
        "the metrics registry caps itself; RoleBook does not"
    );

    let before = live_bytes();
    let mut book = RoleBook::default();
    for i in 0..N {
        book.add_role(role(&format!("r{i:06}"), &[&format!("p{i:06}")]));
    }

    let mut refusals = 0usize;
    for i in 0..N {
        if !book.assign("mallory", &format!("r{i:06}")) {
            refusals += 1;
        }
    }
    let retained = live_bytes().saturating_sub(before);

    assert_eq!(
        refusals, 0,
        "no cap: every one of {N} assignments to a single actor was accepted"
    );
    assert!(
        retained > 20_000_000,
        "one actor + one admin loop retained {retained} B — the point is that \
         nothing bounds it, so a smaller figure would mean the build changed"
    );
    println!(
        "[exhaustion] one actor holds {N} roles: {retained} B retained \
         ({} B per assignment+role). No cap, no eviction, no removal API.",
        retained / N
    );

    // The grant really is all half a million of them (sampled), and still
    // exact — the growth is unbounded, not merely sloppy.
    for i in (0..N).step_by(9_973) {
        assert!(
            book.allows("mallory", &perm(&format!("p{i:06}"))),
            "assignment {i} was accepted but does not grant"
        );
    }
    assert!(
        !book.allows("mallory", &perm("p999999")),
        "no bleed at 500k"
    );

    // Hot-path cost, REPORTED not asserted (wall clock is never a test
    // oracle). A denied check is the worst case: `allows` is
    // `assignments[actor].filter_map(roles.get).any(..)`, so a refusal cannot
    // short-circuit and walks the whole assignment set. Measured on this
    // machine: ~600 ns with one role, ~570 ms with 500 000 — a ~10^6 factor,
    // paid by `Deployment::admit` on every single request for that actor.
    // Two samples only, because each one costs half a second in debug.
    const SAMPLES: u128 = 2;
    let mut lean = RoleBook::default();
    lean.add_role(role("only", &["p000000"]));
    assert!(lean.assign("victim", "only"));
    let t = Instant::now();
    for _ in 0..SAMPLES {
        assert!(!lean.allows("victim", &perm("nope")));
    }
    let lean_ns = t.elapsed().as_nanos().max(1);
    let t = Instant::now();
    for _ in 0..SAMPLES {
        assert!(!book.allows("mallory", &perm("nope")));
    }
    let fat_ns = t.elapsed().as_nanos().max(1);
    println!(
        "[exhaustion] one denied allows(): {} ns with 1 role vs {} ns with {N} \
         roles ({}x) — an O(assignments) scan on every admission decision",
        lean_ns / SAMPLES,
        fat_ns / SAMPLES,
        fat_ns / lean_ns
    );
}

/// The other half of the same vector: distinct *actors* are uncapped too, and
/// an actor entry is created by the first successful `assign` and never
/// removed. 500 000 principals, none of whom can ever be deleted.
#[test]
fn rolebook_has_no_cap_on_distinct_actors_and_none_can_be_removed() {
    let _guard = serialized();
    const N: usize = 500_000;

    let before = live_bytes();
    let mut book = RoleBook::default();
    book.add_role(role("reader", &["memory.read"]));
    for i in 0..N {
        assert!(
            book.assign(&format!("ghost-{i:07}"), "reader"),
            "no cap on principals"
        );
    }
    let retained = live_bytes().saturating_sub(before);
    println!(
        "[exhaustion] {N} distinct principals from one role: {retained} B \
         ({} B/principal). `RoleBook` exposes no way to remove any of them.",
        retained / N
    );
    assert!(
        retained > 10_000_000,
        "500k principals retained {retained} B"
    );

    for i in (0..N).step_by(9_973) {
        assert!(book.allows(&format!("ghost-{i:07}"), &perm("memory.read")));
    }

    // The only lever an operator has is redefining the shared role, which
    // de-provisions all 500 000 at once — see
    // `a_grant_can_never_be_withdrawn_from_a_single_actor`.
    book.add_role(role("reader", &[]));
    assert!(!book.allows("ghost-0000000", &perm("memory.read")));
    assert!(!book.allows("ghost-0499999", &perm("memory.read")));
}

/// **FINDING (exhaustion-vector).** `assign` stores a full `String` copy of
/// the role name in the actor's set, and neither name length nor assignment
/// count is bounded. Retained bytes are therefore Θ(A·R·len) for A+R admin
/// calls: quadratic amplification, with the constant chosen by the caller.
#[test]
fn assignment_storage_is_quadratic_in_admin_calls() {
    let _guard = serialized();
    const NAME_LEN: usize = 1_024;

    let measure = |actors: usize, roles: usize| -> usize {
        let before = live_bytes();
        let mut book = RoleBook::default();
        let names: Vec<String> = (0..roles)
            .map(|r| format!("{r:06}{}", "x".repeat(NAME_LEN - 6)))
            .collect();
        for name in &names {
            book.add_role(role(name, &["memory.read"]));
        }
        for a in 0..actors {
            let who = format!("a{a:06}");
            for name in &names {
                assert!(book.assign(&who, name));
            }
        }
        let retained = live_bytes().saturating_sub(before);
        drop(book);
        retained
    };

    let small = measure(100, 100);
    let large = measure(200, 200);

    println!(
        "[amplification] {NAME_LEN} B role names: 200 admin calls retain {small} B, \
         400 admin calls retain {large} B ({:.2}x for 2x calls)",
        large as f64 / small as f64
    );

    // Doubling the number of admin calls more than doubles the memory: this
    // IS the superlinear explosion, measured.
    assert!(
        large as f64 / small as f64 > 3.0,
        "expected ~4x (quadratic) for 2x admin calls, got {small} -> {large}"
    );
    let per_call = large / 400;
    assert!(
        per_call > 50_000,
        "each of the 400 admin calls retained {per_call} B on average"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 4. Duplicate role names: silent replacement
// ─────────────────────────────────────────────────────────────────────────

/// **FINDING (bug / spec-violation).** `add_role` is `insert`, keyed on
/// `role.name`. A second role with the same name REPLACES the first and
/// instantly rewrites the effective grant of every actor already holding it:
///
/// * downward — silent mass **revocation** (an outage no caller can detect);
/// * upward — silent mass **escalation** (every holder gains the new
///   permissions retroactively).
///
/// `add_role` returns `()`, so the collision is invisible to the caller; the
/// signature cannot report it. Nothing journals it either — see
/// [`redefining_a_role_escalates_every_holder_with_an_empty_audit_trail`].
#[test]
fn add_role_silently_replaces_and_rewrites_every_holders_grant() {
    let _guard = serialized();
    let mut book = RoleBook::default();

    book.add_role(role("editor", &["memory.read", "memory.write"]));
    assert!(book.assign("alice", "editor"));
    assert!(book.assign("bob", "editor"));
    assert!(book.allows("alice", &perm("memory.write")));
    assert!(book.allows("bob", &perm("memory.write")));

    // Re-adding under the same name is accepted, unremarked, and REPLACES —
    // it does not merge. Both holders silently lose `memory.write`.
    book.add_role(role("editor", &["memory.read"]));
    assert!(book.allows("alice", &perm("memory.read")));
    assert!(
        !book.allows("alice", &perm("memory.write")),
        "DEFECT: re-adding a narrower role silently revoked a live grant"
    );
    assert!(
        !book.allows("bob", &perm("memory.write")),
        "…for every holder at once, with no signal to anyone"
    );
    assert_eq!(
        stored_role_names(&book).len(),
        1,
        "the first definition is gone, not shadowed"
    );

    // The same lever runs the other way: one call, and every existing holder
    // is an administrator. No re-assignment is needed.
    book.add_role(role("editor", &["memory.read", "policy.admin"]));
    assert!(
        book.allows("alice", &perm("policy.admin")),
        "DEFECT: redefinition retroactively escalates every holder"
    );
    assert!(book.allows("bob", &perm("policy.admin")));
    assert!(
        !book.allows("alice", &perm("memory.write")),
        "and simultaneously drops what the previous definition granted"
    );

    // Emptying a role is the closest thing to deletion, and it neither
    // removes the role nor the assignments — the grant just becomes nothing.
    book.add_role(role("editor", &[]));
    assert!(!book.allows("alice", &perm("memory.read")));
    assert_eq!(
        stored_role_names(&book),
        BTreeSet::from(["editor".to_string()])
    );
    assert_eq!(
        stored_actors(&book),
        BTreeSet::from(["alice".to_string(), "bob".to_string()]),
        "assignments to an emptied role are retained forever"
    );

    // Refilling it re-grants everyone, still with no re-assignment step.
    book.add_role(role("editor", &["memory.read"]));
    assert!(book.allows("alice", &perm("memory.read")));
    assert!(book.allows("bob", &perm("memory.read")));
}

/// The same defect through the product path, with the audit trail that is
/// supposed to catch it: `Deployment::add_role` escalates every `reader` to
/// `policy.admin` and journals **nothing**. `ccos_enterprise_admin`'s
/// `JUSTIFICATION_REQUIRED` list does not cover role mutation either, so
/// there is no surface on which this act could have demanded a reason.
#[test]
fn redefining_a_role_escalates_every_holder_with_an_empty_audit_trail() {
    let _guard = serialized();
    let mut d = two_tenant_deployment();
    let bob = actor("memorithm", "bob", AuthStrength::Token); // reader

    let denied = request("acme", "bob", "policy.set", "r-before");
    assert_eq!(
        d.admit(Call {
            actor: &bob,
            request: &denied,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::PermissionDenied),
        "a reader may not set policy"
    );
    let audit_before = d.audit().len();

    // One call. No justification, no actor, no target, no record.
    d.add_role("reader", &["memory.read", "policy.admin"]);
    assert_eq!(
        d.audit().len(),
        audit_before,
        "DEFECT: a mass privilege change produced zero audit records"
    );
    assert!(
        !ccos_enterprise_admin::JUSTIFICATION_REQUIRED.contains(&"role.grant"),
        "role mutation is not even in the justification-required list"
    );

    let now = request("acme", "bob", "policy.set", "r-after");
    assert_eq!(
        d.admit(Call {
            actor: &bob,
            request: &now,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
        }),
        Outcome::Forwarded,
        "DEFECT: the reader is an administrator now, and nothing recorded why"
    );
    assert_eq!(
        d.spent("acme"),
        1,
        "and the escalated call is billed as normal"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 5. Adversarial names
// ─────────────────────────────────────────────────────────────────────────

/// **FINDING (robustness).** `""` is a valid role name and a valid actor
/// name. Nothing rejects it, and the composed path authorizes a
/// `GatewayRequest` whose `actor` field is empty once `""` holds a role —
/// so a request that names no principal at all can reach a governed tool.
#[test]
fn the_empty_string_is_a_grantable_role_and_a_grantable_principal() {
    let _guard = serialized();
    let mut book = RoleBook::default();

    // Fail-closed while the empty role does not exist…
    assert!(!book.assign("alice", ""), "unknown role, even empty");
    assert!(!book.assign("", ""), "…for the empty actor too");

    // …but `Role::default()` has an empty name, so `add_role(Role::default())`
    // creates it, and from then on it grants like any other role.
    book.add_role(Role::default());
    assert!(book.assign("alice", ""), "DEFECT: '' is a grantable role");
    assert!(
        !book.allows("alice", &perm("anything")),
        "…granting nothing yet"
    );

    book.add_role(role("", &["policy.admin"]));
    assert!(
        book.allows("alice", &perm("policy.admin")),
        "DEFECT: the nameless role now confers administration"
    );

    // The empty *actor* is a principal in its own right.
    book.add_role(role("reader", &["memory.read"]));
    assert!(book.assign("", "reader"), "DEFECT: '' is a grantable actor");
    assert!(book.allows("", &perm("memory.read")));
    assert!(
        !book.allows(" ", &perm("memory.read")),
        "at least it is exact"
    );

    // …and the composed path honours it: an anonymous request line reaches a
    // governed tool. `classify` never inspects `GatewayRequest::actor`, and
    // `admit` looks the empty string straight up in the role book.
    let mut d = two_tenant_deployment();
    let caller = actor("memorithm", "nobody", AuthStrength::Token);
    let anon = request("acme", "", "memory.recall", "r-anon");
    assert_eq!(
        d.admit(Call {
            actor: &caller,
            request: &anon,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::PermissionDenied),
        "unassigned, the empty actor is refused"
    );
    assert!(d.assign("", "reader"));
    let anon = request("acme", "", "memory.recall", "r-anon-2");
    assert_eq!(
        d.admit(Call {
            actor: &caller,
            request: &anon,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
        }),
        Outcome::Forwarded,
        "DEFECT: a request naming no principal is authorized and billed"
    );
}

/// Role names are raw byte-for-byte keys: no trimming, no case folding, no
/// Unicode normalization, no length limit. Every look-alike below is a
/// *distinct* role, so the failure mode is fail-closed (a look-alike inherits
/// nothing) — but it is also an operator-confusion surface, and it is
/// **inconsistent with the gateway**, which lowercases tool names precisely
/// so "`RSI.x` cannot slip past a case-normalizing router downstream".
/// Two roles that render identically in any admin UI can carry different
/// permissions here.
#[test]
fn role_names_are_never_normalized_so_look_alikes_are_distinct_roles() {
    let _guard = serialized();
    let mut book = RoleBook::default();
    book.add_role(role("admin", &["policy.admin"]));
    assert!(book.assign("root", "admin"));

    // Case, padding, control bytes, NFC/NFD, homoglyphs, zero-width joiners,
    // bidi overrides — none of these resolve to the granted role.
    let look_alikes = [
        "Admin",
        "ADMIN",
        "admin ",
        " admin",
        "admin\n",
        "admin\u{0}",
        "adm\u{0131}n",  // dotless i (Turkish casefold trap)
        "\u{0430}dmin",  // Cyrillic а
        "admin\u{200d}", // zero-width joiner
        "\u{202e}admin", // right-to-left override
        "ad\u{fb01}min", // ﬁ ligature (NFKC-folds to "fi")
        "cafe\u{301}",   // NFD
        "café",          // NFC
        "ａｄｍｉｎ",    // fullwidth (NFKC-folds to "admin")
    ];
    for name in look_alikes {
        assert!(
            !book.assign("root", name),
            "{name:?} must not resolve to the existing 'admin' role"
        );
        assert!(
            !book.allows("root", &perm("nothing")),
            "a refused assign grants nothing"
        );
    }

    // Registered separately, they coexist as different roles with different
    // powers — indistinguishable to a human reading the role list.
    book.add_role(role("\u{0430}dmin", &["memory.read"])); // Cyrillic а
    book.add_role(role("ａｄｍｉｎ", &["memory.read"])); // fullwidth
    assert!(book.assign("mallory", "\u{0430}dmin"));
    assert!(book.assign("mallory", "ａｄｍｉｎ"));
    assert!(
        !book.allows("mallory", &perm("policy.admin")),
        "the look-alikes confer only their own permissions (fail-closed)"
    );
    assert_eq!(
        stored_role_names(&book).len(),
        3,
        "three roles whose names a human reads as one"
    );

    // NFC and NFD spellings of the same word are two roles.
    book.add_role(role("café", &["a"]));
    book.add_role(role("cafe\u{301}", &["b"]));
    assert!(book.assign("u", "café"));
    assert!(book.allows("u", &perm("a")));
    assert!(
        !book.allows("u", &perm("b")),
        "NFD twin is a separate role, not the same one"
    );

    // Permissions are exact too: no wildcard, prefix, or case tolerance.
    book.add_role(role("p", &["memory.read"]));
    assert!(book.assign("v", "p"));
    for probe in [
        "memory.",
        "memory.*",
        "memory",
        "Memory.read",
        "memory.read ",
        "memory.read\u{0}",
        "*",
        "",
    ] {
        assert!(
            !book.allows("v", &perm(probe)),
            "{probe:?} must not match the granted 'memory.read'"
        );
    }
}

/// **FINDING (exhaustion-vector).** Names are unbounded, and `assign` copies
/// the whole name per actor. One 1 MiB role name plus 64 assignments retains
/// ~66 MiB — a 64x amplification of a single stored string, from 65 calls.
#[test]
fn megabyte_names_are_accepted_and_every_assignment_copies_them_whole() {
    let _guard = serialized();
    const MIB: usize = 1024 * 1024;
    const HOLDERS: usize = 64;

    let huge = "z".repeat(MIB);
    let before = live_bytes();
    let mut book = RoleBook::default();
    book.add_role(role(&huge, &["memory.read"]));
    let after_role = live_bytes().saturating_sub(before);

    for i in 0..HOLDERS {
        assert!(
            book.assign(&format!("holder-{i:03}"), &huge),
            "no length cap"
        );
    }
    let after_assignments = live_bytes().saturating_sub(before);

    println!(
        "[amplification] one {MIB} B role name: {after_role} B stored, \
         {after_assignments} B after {HOLDERS} assignments \
         ({:.1}x — every assignment keeps its own copy)",
        after_assignments as f64 / after_role as f64
    );
    assert!(
        after_assignments > HOLDERS * MIB,
        "expected one full copy per assignment, got {after_assignments} B"
    );
    assert!(book.allows("holder-000", &perm("memory.read")));

    // A megabyte actor name is accepted just as readily.
    let huge_actor = "y".repeat(MIB);
    assert!(book.assign(&huge_actor, &huge));
    assert!(book.allows(&huge_actor, &perm("memory.read")));
    assert!(
        !book.allows(&huge_actor[..MIB - 1], &perm("memory.read")),
        "still exact: a truncated name is a different principal"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 6. Privilege bleed: the union, and only the union
// ─────────────────────────────────────────────────────────────────────────

/// An actor holding many roles gets exactly the union of their permission
/// sets — verified positively (every member) and negatively (a large corpus
/// of non-members, including near-misses of every granted name). This holds.
#[test]
fn many_roles_confer_exactly_the_union_and_nothing_adjacent() {
    let _guard = serialized();
    const ROLES: usize = 512;
    let mut book = RoleBook::default();

    // Overlapping sets on purpose: every role also grants a shared
    // permission, so the union is not merely a partition.
    for i in 0..ROLES {
        book.add_role(role(
            &format!("r{i:04}"),
            &[&format!("cap.{i:04}"), "cap.shared"],
        ));
        assert!(book.assign("omni", &format!("r{i:04}")));
    }

    for i in 0..ROLES {
        assert!(
            book.allows("omni", &perm(&format!("cap.{i:04}"))),
            "member cap.{i:04} missing from the union"
        );
    }
    assert!(book.allows("omni", &perm("cap.shared")));

    // Nothing beyond the union, including systematic near-misses.
    for i in 0..ROLES {
        for near in [
            format!("cap.{i:04} "),
            format!("cap.{i:04}\u{0}"),
            format!("CAP.{i:04}"),
            format!("cap.{i:05}"),
            format!("cap{i:04}"),
        ] {
            assert!(
                !book.allows("omni", &perm(&near)),
                "{near:?} is not in the union"
            );
        }
    }
    for outside in ["cap.9999", "cap", "cap.", "", "shared", "cap.shared."] {
        assert!(
            !book.allows("omni", &perm(outside)),
            "{outside:?} leaked in"
        );
    }

    // A second actor holding one of those roles gets that role's set only —
    // holding a role alongside a super-user does not widen it.
    assert!(book.assign("narrow", "r0007"));
    assert!(book.allows("narrow", &perm("cap.0007")));
    assert!(book.allows("narrow", &perm("cap.shared")));
    for i in 0..ROLES {
        if i != 7 {
            assert!(
                !book.allows("narrow", &perm(&format!("cap.{i:04}"))),
                "narrow bled cap.{i:04} from a co-holder"
            );
        }
    }
}

/// The truth about shrinking a role: re-adding it with fewer permissions DOES
/// shrink every holder's grant — immediately, silently, and only down to the
/// union of whatever other roles they hold. Documented here so the shrink
/// path is pinned as behaviour, not left as folklore.
#[test]
fn re_adding_a_narrower_role_shrinks_the_grant_to_the_remaining_union() {
    let _guard = serialized();
    let mut book = RoleBook::default();
    book.add_role(role("a", &["read", "write", "admin"]));
    book.add_role(role("b", &["read"]));
    assert!(book.assign("dual", "a"));
    assert!(book.assign("dual", "b"));
    assert!(book.assign("solo", "a"));

    for p in ["read", "write", "admin"] {
        assert!(book.allows("dual", &perm(p)));
        assert!(book.allows("solo", &perm(p)));
    }

    // Shrink `a` to nothing.
    book.add_role(role("a", &[]));
    // `dual` keeps exactly what `b` still grants…
    assert!(book.allows("dual", &perm("read")), "b still grants read");
    assert!(!book.allows("dual", &perm("write")));
    assert!(!book.allows("dual", &perm("admin")));
    // …and `solo` is left with nothing at all, still holding the role.
    for p in ["read", "write", "admin"] {
        assert!(!book.allows("solo", &perm(p)), "solo lost {p}");
    }
    assert!(
        stored_actors(&book).contains("solo"),
        "the assignment survives the permissions it conferred"
    );
    // Re-assigning changes nothing: the assignment was never the problem.
    assert!(book.assign("solo", "a"));
    assert!(!book.allows("solo", &perm("read")));
}

/// **FINDING (missing-behaviour).** There is no `unassign`, `revoke`,
/// `remove_role` or `remove_actor` anywhere in the RBAC API, and none in
/// `Deployment` either. A single actor's grant can never be withdrawn: the
/// only lever available to an operator is redefining the role, which hits
/// every other holder too. Offboarding one compromised agent therefore means
/// de-provisioning every colleague who shares its role.
#[test]
fn a_grant_can_never_be_withdrawn_from_a_single_actor() {
    let _guard = serialized();
    let mut book = RoleBook::default();
    book.add_role(role("oncall", &["policy.admin"]));
    assert!(book.assign("leaver", "oncall"));
    assert!(book.assign("stayer", "oncall"));

    // The only two things an operator can do, and what they cost:
    //
    // (a) re-assign — idempotent, never a removal.
    assert!(book.assign("leaver", "oncall"));
    assert!(book.allows("leaver", &perm("policy.admin")));

    // (b) redefine the role — collateral damage to every holder.
    book.add_role(role("oncall", &[]));
    assert!(
        !book.allows("leaver", &perm("policy.admin")),
        "the leaver is finally out…"
    );
    assert!(
        !book.allows("stayer", &perm("policy.admin")),
        "DEFECT: …and so is everyone else who shared the role"
    );

    // Restoring the colleague restores the departed actor too, because the
    // assignment was never removable in the first place.
    book.add_role(role("oncall", &["policy.admin"]));
    assert!(
        book.allows("leaver", &perm("policy.admin")),
        "DEFECT: a de-provisioned actor is re-granted by an unrelated repair"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 7. Unknown roles: fail-closed, now and later
// ─────────────────────────────────────────────────────────────────────────

/// `assign` to an unknown role returns `false`, stores nothing, and grants
/// nothing — including after the role is created later. The pending
/// assignment is not queued anywhere: it never existed. This holds, at one
/// call and at ten thousand.
#[test]
fn assigning_an_unknown_role_grants_nothing_now_or_later() {
    let _guard = serialized();
    let mut book = RoleBook::default();

    assert!(!book.assign("mallory", "superuser"), "unknown role refused");
    assert!(
        stored_actors(&book).is_empty(),
        "a refused assign must not even create an actor entry"
    );

    // Creating the role afterwards must not retro-grant it.
    book.add_role(role("superuser", &["policy.admin"]));
    assert!(
        !book.allows("mallory", &perm("policy.admin")),
        "a refused assignment is not replayed when the role appears"
    );
    assert!(
        stored_actors(&book).is_empty(),
        "still no entry: nothing was queued"
    );

    // Only an explicit, successful assign grants.
    assert!(book.assign("mallory", "superuser"));
    assert!(book.allows("mallory", &perm("policy.admin")));

    // At scale, a hostile caller guessing role names costs nothing and
    // leaves nothing behind — this is the one place the book is bounded.
    let before = live_bytes();
    let mut refused = 0usize;
    for i in 0..10_000 {
        if !book.assign("prober", &format!("guess-{i}")) {
            refused += 1;
        }
    }
    let retained = live_bytes().saturating_sub(before);
    assert_eq!(refused, 10_000, "every guess refused");
    assert!(
        retained < 64 * 1024,
        "10k refused assigns retained {retained} B — refusals must not accrete"
    );
    assert_eq!(
        stored_actors(&book),
        BTreeSet::from(["mallory".to_string()]),
        "the prober never became a principal"
    );
    assert!(!book.allows("prober", &perm("policy.admin")));

    // Same, through the product path.
    let mut d = two_tenant_deployment();
    assert!(
        !d.assign("mallory", "root"),
        "a role-shaped guess is refused"
    );
    d.add_role("root", &["policy.admin"]);
    let mallory = actor("memorithm", "mallory", AuthStrength::Strong);
    let req = request("acme", "mallory", "policy.set", "r-late");
    assert_eq!(
        d.admit(Call {
            actor: &mallory,
            request: &req,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::PermissionDenied),
        "creating the role later must not admit the earlier attempt"
    );
    assert_eq!(d.spent("acme"), 0, "and the refusal is free");
}

// ─────────────────────────────────────────────────────────────────────────
// 8. Composed path: whose permissions are actually being checked?
// ─────────────────────────────────────────────────────────────────────────

/// **FINDING (critical, spec-violation).** `Deployment::admit` checks the
/// permissions of `call.request.actor` — a caller-supplied string on the wire
/// — and never compares it with `call.actor.actor`, the authenticated
/// identity (`tests/ccos-enterprise-conformance/src/lib.rs:303`).
/// `AuthenticatedActor` is consulted **only** for `strength`; its `actor` and
/// `org` fields are never read by any gate.
///
/// Consequences, all demonstrated below:
///
/// * a reader impersonates a writer by putting their name in the request;
/// * an actor authenticated in a foreign org acts inside any tenant;
/// * the audit record stores the *claimed* actor (`src/lib.rs:274`), so the
///   journal attributes the act to the victim and the real caller is
///   unrecoverable — directly contradicting `docs/AGENT_IDENTITY_MODEL.md`
///   ("every journaled decision/action names its agent") and layer 1 of
///   `docs/ENTERPRISE_SECURITY_MODEL.md`.
///
/// The module docs of the composed crate state the rule for tenants — "the
/// request's tenant — not the actor's word — selects the state" — and then
/// take the actor entirely on the request's word.
#[test]
fn authorization_trusts_the_request_supplied_actor_string() {
    let _guard = serialized();
    let mut d = two_tenant_deployment();

    // bob is a reader. As himself, writing is refused.
    let bob = actor("memorithm", "bob", AuthStrength::Token);
    let honest = request("acme", "bob", "memory.ingest", "r-honest");
    assert_eq!(
        d.admit(Call {
            actor: &bob,
            request: &honest,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::PermissionDenied)
    );

    // The same authenticated bob, typing "alice" into the request.
    let forged = request("acme", "alice", "memory.ingest", "r-forged");
    assert_eq!(
        d.admit(Call {
            actor: &bob,
            request: &forged,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
        }),
        Outcome::Forwarded,
        "DEFECT: authorization used the request's actor string, not the \
         authenticated identity — bob wrote as alice"
    );

    // And the journal blames alice.
    let record = d
        .audit()
        .iter()
        .find(|r| r.request_id == "r-forged")
        .expect("the forged call was journaled");
    assert_eq!(
        record.actor, "alice",
        "DEFECT: the audit trail names the impersonated actor; the \
         authenticated caller appears nowhere in it"
    );
    assert!(
        d.audit()
            .iter()
            .all(|r| r.actor != "bob" || r.request_id == "r-honest"),
        "nothing anywhere ties the forged call back to bob"
    );

    // Identity is not even required to be non-empty or to belong to the org.
    let nobody = actor("", "", AuthStrength::Token);
    let as_root = request("acme", "root", "policy.set", "r-nobody");
    assert_eq!(
        d.admit(Call {
            actor: &nobody,
            request: &as_root,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
        }),
        Outcome::Forwarded,
        "DEFECT: an actor with no org and no name administered policy as root"
    );

    let foreign = actor("evil-corp", "mallory", AuthStrength::Token);
    let as_alice = request("acme", "alice", "memory.ingest", "r-foreign");
    assert_eq!(
        d.admit(Call {
            actor: &foreign,
            request: &as_alice,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
        }),
        Outcome::Forwarded,
        "DEFECT: org membership is never checked against the tenant"
    );

    // Strength is the one thing the authenticated identity is used for, and
    // it does hold: an anonymous caller is refused before anything else.
    let anon = actor("memorithm", "alice", AuthStrength::Anonymous);
    let req = request("acme", "alice", "memory.ingest", "r-anon");
    assert_eq!(
        d.admit(Call {
            actor: &anon,
            request: &req,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::Unauthenticated),
        "the only thing AuthenticatedActor is actually consulted for"
    );
}

/// **FINDING (spec-violation).** `RoleBook`'s API carries no `TenantId`, and
/// `Deployment` holds exactly one book for the whole install. Role names are
/// therefore a single global namespace: a grant made for one tenant applies
/// in every tenant, and one tenant's administrator redefining a common role
/// name (`reader`, `writer`, `admin`) silently rewrites the other tenant's
/// grants — the cross-tenant blast radius of defect 2.
///
/// `docs/TENANCY_MODEL.md` calls `TenantId` "the outermost data boundary" and
/// `docs/ENTERPRISE_SECURITY_MODEL.md` lists authorization as a layer of the
/// tenant-isolated stack; authorization state is the one thing not scoped.
#[test]
fn role_grants_are_deployment_global_not_tenant_scoped() {
    let _guard = serialized();
    let mut d = two_tenant_deployment();
    d.tenant_mut("globex")
        .expect("globex exists")
        .allow_model("claude-opus");

    // alice was assigned `writer` with no tenant in sight; the grant applies
    // in globex, a tenant nobody granted her anything in.
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let cross = request("globex", "alice", "memory.ingest", "r-cross");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &cross,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
        }),
        Outcome::Forwarded,
        "an acme grant is honoured inside globex: RBAC is not tenant-scoped"
    );

    // A brand-new tenant inherits the whole global role book on creation.
    d.add_tenant("initech", TenantState::new(100));
    d.tenant_mut("initech")
        .expect("initech exists")
        .allow_model("claude-opus");
    let fresh = request("initech", "alice", "memory.ingest", "r-fresh");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &fresh,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
        }),
        Outcome::Forwarded,
        "DEFECT: a tenant created seconds ago already has alice as a writer"
    );

    // …and globex's administrator, editing what they believe is their own
    // `writer` role, revokes acme's writers.
    d.add_role("writer", &["memory.read"]);
    let acme = request("acme", "alice", "memory.ingest", "r-collateral");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &acme,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::PermissionDenied),
        "DEFECT: one tenant's role edit rewrote another tenant's grants"
    );
}

/// Scale meets the composed path: 50 000 governed tools and 50 000 roles in
/// one deployment, then a single admission decision must still be exact. The
/// point is the negative — an actor holding 50 000 roles does not acquire the
/// one permission nobody granted it, however large the surrounding book.
#[test]
fn admission_stays_exact_with_fifty_thousand_roles_and_tools() {
    let _guard = serialized();
    const N: usize = 50_000;
    let mut d = two_tenant_deployment();

    let before = live_bytes();
    for i in 0..N {
        let p = format!("cap.{i:05}");
        d.add_role(&format!("role-{i:05}"), &[&p]);
        d.govern_tool(&format!("memory.tool{i:05}"), &p);
        assert!(d.assign("hoarder", &format!("role-{i:05}")));
    }
    // One permission is deliberately governed but never granted.
    d.govern_tool("memory.forbidden", "cap.never-granted");
    let retained = live_bytes().saturating_sub(before);
    println!("[scale] deployment with {N} roles + {N} governed tools: {retained} B");

    let hoarder = actor("memorithm", "hoarder", AuthStrength::Token);
    for i in [0usize, 1, N / 2, N - 1] {
        let req = request("acme", "hoarder", &format!("memory.tool{i:05}"), "r-ok");
        assert_eq!(
            d.admit(Call {
                actor: &hoarder,
                request: &req,
                model: "claude-opus",
                cost_tokens: 1,
                variant: None,
            }),
            Outcome::Forwarded,
            "granted tool {i} refused at scale"
        );
    }

    let denied = request("acme", "hoarder", "memory.forbidden", "r-no");
    assert_eq!(
        d.admit(Call {
            actor: &hoarder,
            request: &denied,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::PermissionDenied),
        "50k roles must not add up to the one permission nobody granted"
    );

    // An ungoverned neighbour is still refused as ungoverned, not authorized.
    let ungoverned = request("acme", "hoarder", "memory.tool99999", "r-unknown");
    assert_eq!(
        d.admit(Call {
            actor: &hoarder,
            request: &ungoverned,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
        })
        .refusal(),
        Some(&Refusal::ToolNotGoverned)
    );
    assert_eq!(
        d.spent("acme"),
        4,
        "only the four granted calls were billed"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 9. Beyond the default budget — kept out of the default run
// ─────────────────────────────────────────────────────────────────────────

/// The exhaustion vector has no ceiling other than the machine's: two million
/// roles on one actor behave exactly like five hundred thousand. Verified —
/// 995 809 703 B (~1 GB of process memory) retained from one admin loop, zero
/// refusals, 10.2 s in release. Ignored by default because of the gigabyte,
/// not because it is speculative.
///
/// Run it explicitly:
/// `cargo test -p ccos-enterprise-conformance --test stress_rbac_scale --release -- --ignored --nocapture`
#[test]
#[ignore = "multi-GB, minutes long: run explicitly with --ignored --release"]
fn rolebook_growth_has_no_ceiling_at_two_million() {
    let _guard = serialized();
    const N: usize = 2_000_000;
    let before = live_bytes();
    let mut book = RoleBook::default();
    for i in 0..N {
        book.add_role(role(&format!("r{i:07}"), &[&format!("p{i:07}")]));
        assert!(book.assign("mallory", &format!("r{i:07}")));
    }
    let retained = live_bytes().saturating_sub(before);
    println!("[exhaustion] {N} roles on one actor: {retained} B, still no refusal");
    assert!(book.allows("mallory", &perm(&format!("p{:07}", N - 1))));
    assert!(!book.allows("mallory", &perm("p9999999")));
}
