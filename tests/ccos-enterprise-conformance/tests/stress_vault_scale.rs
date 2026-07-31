//! # Hostile stress of the license vault: scale, durability, replay, dead seats
//!
//! `ccos_license_server::Vault` is the vendor's money ledger. It is the only
//! record that a seat was sold, the only enforcement point for the
//! single-seat rule, and the only thing between a leaked file and a keyring
//! of redeemable licenses. `tools/ccos-license-server/src/lib.rs` promises,
//! in its own module doc, that "a stolen vault holds nothing redeemable",
//! that the schema gate "fails closed", that a re-claim "can never extend a
//! license", and that the flip "must survive a crash *before* the token is
//! disclosed".
//!
//! This file attacks all four at 100 000-entry scale, plus every file-shaped
//! edge a corrupt disk, a hand-editing vendor or a hostile backup can reach.
//!
//! Everything asserted below is the product's **current, real** behaviour.
//! Where that behaviour is a defect the assertion pins the defect and the
//! comment names it, so a repair fails loudly here instead of silently
//! changing the commercial posture. Nothing here is weakened to pass.
//!
//! ## What held
//!
//! * **Anti-replay is real.** 10 000 leaked vault keys presented at the claim
//!   entry point are 10 000 `Refusal::UnknownCode`s, over the pure API and
//!   over `Counter::handle` alike, and the campaign leaves the ledger
//!   byte-identical. The stored machine fingerprints, licensees and labels
//!   are equally unredeemable. See
//!   [`a_leaked_vault_is_not_a_keyring_10k_keys_redeem_nothing`].
//! * **The claim state machine is exactly its spec, 100 000 operations
//!   deep.** 10 000 codes x 100 machines, mixing unclaimed/claimed/revoked
//!   with mid-stream revocation, agreed with an independent shadow model on
//!   every single operation: 8 548 seats sold, each to exactly one machine
//!   forever; 31 180 `SeatTaken`; 28 552 `Revoked` (which beats everything,
//!   including the seat's own owner); and across **31 720 same-machine
//!   re-issues at strictly increasing timestamps `exp_unix` never moved by
//!   one second**. See [`claim_state_machine_survives_100k_abusive_operations`].
//! * **Absurd day counts saturate.** `u64::MAX` days lands on `u64::MAX`, not
//!   in the past — in release as well as debug.
//! * **The write is genuinely atomic and 0600.** Mode never widens, and a
//!   100 000-entry / 80 426 140 B file round-trips losslessly through NUL
//!   bytes, RTL overrides, astral codepoints, 4 KiB names, absent optionals
//!   and `u64::MAX` — then re-serializes byte-identical. Durability cost at
//!   that scale: build 2.6 s / save+fsync 2.7 s / load+parse 0.97 s in debug;
//!   0.22 s / 0.73 s / 0.20 s in release.
//! * **Unknown status variants and mis-cased schema tags are refused**, not
//!   guessed. So are 22 other hostile files, whole.
//! * **No stack overflow anywhere**, including a 10 000-bracket recursion
//!   bomb, and no panic on any input this file could construct.
//!
//! ## What was repaired
//!
//! * **A live daemon no longer erases out-of-band vault edits.**
//!   `Counter::handle_claim` now calls `Counter::refresh_vault()`
//!   (`lib.rs:351`) before it consults the ledger: a `stat` of the vault file
//!   every claim, and a full `Vault::load` whenever `(mtime, len)` no longer
//!   matches what this process last read or wrote. A missing file is not an
//!   error. Before that, the counter held the whole map in memory and wrote it
//!   back on every sale, so a revocation applied with `ccos-license-admin`
//!   against a running daemon was not merely ignored — the next sale
//!   overwrote it. The behavioural guard for that repair lives in
//!   `stress_http_abuse.rs`; it is recorded here because it changed **every
//!   number this file measures**, and because it is the one thing that moved
//!   in the claim path. Every measurement below was re-taken against it.
//!
//!   It made the claim path **more** expensive, not less, and it did not go
//!   near findings 1 or 2 — those are still open, still pinned, and the only
//!   thing that changed about them is the arithmetic:
//!   - a refused request against a 100 000-entry / 23 400 059 B ledger with
//!     the file on disk now costs **102 055 126 B and 0.68 s** the first time
//!     and after every out-of-band edit (39 327 750 B of deep copy plus
//!     62 727 376 B of re-read), settling to the unchanged 39 327 750 B /
//!     56 ms once the fingerprint stops moving;
//!   - the first sale after start-up costs **~19 133 420 B** against a
//!     10 000-entry / 2 353 609 B ledger, versus **~12 845 771 B** in steady
//!     state — the 6 287 649 B difference is that one `Vault::load`.
//!
//!   Read-path figures here are exact: allocation is a property of the code
//!   path, identical in debug and release, which is why the assertions are on
//!   bytes rather than on time. Figures that include a `save` carry a `~`
//!   because `write_durable` names its temp file `<vault>.tmp.<pid>`, so the
//!   path length — and with it the byte count — moves by one or two between
//!   processes. No assertion depends on those last digits.
//!
//! ## What BROKE
//!
//! 1. **EXHAUSTION — every sale rewrites and fsyncs the whole ledger.**
//!    `Vault::save` (`lib.rs:172`) serializes the entire `BTreeMap` on every
//!    single claim, and `Counter::handle_claim` (`lib.rs:334`) calls it inside
//!    the request via `save_vault` (`lib.rs:316`). Marginal cost is a hard
//!    **234 B/entry**, so seat number N costs 234*N bytes of pretty-printing
//!    plus a full `fsync`: at 100 000 entries one sale writes **23.4 MB** and
//!    takes 0.6-0.9 s (debug) or 0.14 s (release). Measured end to end through
//!    the handler: **200 sales against a 100 000-entry ledger move
//!    4 693 589 800 B — 4.7 GB — through `fsync` to record 200 state flips.**
//!    Selling all 100 000 seats moves **~1.17 TB** to record 23.4 MB of truth:
//!    50 000x write amplification, and it is quadratic, so it gets worse. Each
//!    save also allocates 3.1-3.8x the file: `to_string_pretty` builds it
//!    whole, then `format!` copies it whole again just to append one newline.
//!    There is no cap on entries — the sibling `CounterRegistry` caps itself at
//!    `MAX_SERIES = 4096` precisely so "a label explosion can never exhaust
//!    memory"; the vault, which holds the money, caps at nothing.
//!    Re-measured after the `refresh_vault` repair, which sits in front of this
//!    and changed none of it: 40 sales against a 10 000-entry / 2 353 609 B
//!    ledger take 68.6 ms each and allocate **~12 845 771 B per sale in steady
//!    state — 5.5 whole copies of the ledger to flip one bit** — with the
//!    first sale after start-up costing ~19 133 420 B because it re-reads the
//!    file first.
//!    -> [`every_sale_rewrites_and_fsyncs_the_entire_ledger`],
//!    [`the_marginal_cost_of_one_sale_is_the_whole_ledger`]
//!
//! 2. **EXHAUSTION — an unauthenticated refused request deep-copies the whole
//!    ledger.** `Counter::handle_claim` takes `let before = self.vault.clone()`
//!    (`lib.rs:355`) **before** it knows whether the code exists. A request
//!    for a code that is not in the vault — the cheapest thing an attacker can
//!    send, and the only thing a brute-forcer ever sends — allocates a full
//!    copy of every key, licensee, label and fingerprint and then throws it
//!    away. Measured: **39 327 750 B allocated per 404** at 100 000 entries
//!    versus 394 350 B at 1 000 — a 99x amplification of ledger size into the
//!    cost of a request that reads nothing and writes nothing — costing
//!    56.5 ms of CPU in debug and **36.2 ms in release**. The allocation
//!    figures are byte-identical in both profiles, which is why this file
//!    asserts on them rather than on time.
//!    The `refresh_vault` repair landed one line above that clone and left it
//!    exactly where it was, while adding a second ledger-sized cost to the
//!    same unauthenticated path. Against a 100 000-entry ledger whose file is
//!    really on disk — the production shape — one refused request costs
//!    **102 055 126 B and 0.68 s** whenever the fingerprint check misses:
//!    the first 404 after start-up, and every 404 that follows an operator's
//!    upload. It settles back to 39 327 750 B / 56 ms once the file stops
//!    moving. So a brute-forcer scanning while the vendor edits the vault
//!    makes each of its own misses read the whole ledger *and* copy it.
//!    The global 0.5 req/s `TokenBucket` at `ccos-license-server.rs:104` is
//!    the only thing in front of it, and it was sized for "one request per
//!    sale", not for "each refusal costs a copy of the business".
//!    -> [`an_unknown_code_404_deep_copies_the_entire_ledger`]
//!
//! 3. **Any failed save wedges every future save, permanently.**
//!    `ccos_core::util::write_durable` opens `<vault>.tmp.<pid>` with
//!    `create_new(true)` and never removes it when anything downstream fails.
//!    So a rename that fails once — a full disk, a bad path, a crash between
//!    create and rename — leaves debris that makes the *next* save fail with
//!    `AlreadyExists`, and the one after that, forever: **every** claim
//!    answers `500 persistence failure` while `/healthz` keeps answering 200.
//!    A transient fault becomes a permanent outage that only a human deleting
//!    a file can end. The name is only pid-unique, so pid reuse makes it look
//!    random and two processes sharing a vault path collide by construction.
//!    -> [`a_stale_temp_file_wedges_every_future_save`],
//!    [`a_transient_save_failure_becomes_a_permanent_one`]
//!
//! ## What was BROKEN and is now REPAIRED
//!
//! Four of the ten. Every one was a way for a file that loaded cleanly to cost
//! a customer their seat or hand one away, and every one is now refused —
//! **both** at load, so a counter never starts holding a landmine, and in the
//! claim state machine, so a vault built in memory cannot burn a seat either.
//! The scenarios below are unchanged; the assertions are inverted.
//!
//! 5R. **A one-character typo silently converted an annual license into a
//!     perpetual one.** `Entry` had no `deny_unknown_fields`, so a vault
//!     holding `"expires_unix"` instead of `"exp_unix"` loaded without a
//!     murmur and the next re-claim signed a token with no expiry at all.
//!     Unknown fields are refused by name now, top-level ones included — a
//!     dropped `"max_seats"` is a seat cap nothing enforces. The other half
//!     took a different rule: `days` is deserialized through a named function,
//!     which is what makes serde report a **missing** field instead of
//!     defaulting it, because omitting a field is not an unknown field.
//!     `null` still means perpetual; saying nothing no longer does.
//!     -> [`a_typo_in_a_field_name_is_refused_rather_than_selling_a_perpetual_license`]
//!
//! 6R. **`days: 0` permanently destroyed a sold seat.** The claim succeeded,
//!     the code flipped to `Claimed`, the single seat burned, and the counter
//!     signed a token whose entire validity window was the claim instant —
//!     with no recovery path but vault surgery. It is refused now, the entry
//!     is left untouched, and the refusal is repeatable, so the vendor's fix
//!     lands on a seat that is still there.
//!     -> [`a_zero_day_entry_is_refused_without_burning_the_seat`]
//!
//! 7R. **`Claimed` + `machine: None` was an unreachable-recovery dead seat.**
//!     It answered `SeatTaken` to every machine *including the customer's*,
//!     forever. Both it and `machine: Some("")` are refused as
//!     `Unserviceable` rather than `SeatTaken`, and the difference is the
//!     repair: `SeatTaken` tells a paying customer somebody else has their
//!     seat, which is a lie and an unactionable one.
//!     -> [`a_claimed_entry_with_no_reachable_owner_is_refused_not_silently_dead`]
//!
//! 9R. **Duplicate keys collapsed silently, last one wins**, so appending one
//!     line un-revoked a revoked code. The entry map is deserialized through a
//!     visitor that refuses a repeated key, and keys that no `vault_key` could
//!     ever produce — empty, non-hex, uppercase, short — are refused with it.
//!     -> [`duplicate_keys_are_refused_rather_than_collapsed`]
//!
//! ## What is still BROKEN
//!
//! 4. **The schema gate is a self-declared string, not a proof.** A v1 file
//!    (keyed by the wire `code_hash`) with its `schema` field hand-edited to
//!    `v2` loads clean, and then **every paying customer gets 404 unknown
//!    code** while the server looks perfectly healthy — precisely the failure
//!    `Vault::load`'s own comment says the gate exists to prevent
//!    ("silently missing every lookup would refuse real customers while
//!    looking healthy"). `load_any_schema` additionally accepts schema tags
//!    that never existed, including the empty string.
//!    -> [`the_schema_gate_is_a_string_not_a_proof`]
//!
//! 8. **One malformed byte anywhere poisons the entire ledger.** There is no
//!    per-entry quarantine: a single `days: -1`, a stray BOM or a bad status
//!    in entry 50 000 of 100 000 makes `load` return `InvalidData` for the
//!    whole file, and the counter cannot serve *any* customer. Fail-closed,
//!    but the blast radius is the whole business — and the validation added
//!    for 5R/6R/7R/9R **widens** it, since more files are now bad. That is the
//!    right trade for a ledger (a landmine that loads is worse than a counter
//!    that refuses to start and says why) but it is a trade, and the
//!    quarantine question it sharpens is still open. `load` also
//!    `read_to_string`s the file with no size cap, and a depth bomb inside a
//!    field the product *does* read is still walked.
//!    -> [`hostile_vault_files_are_refused_whole_never_partially_trusted`]
//!
//! 10. **4 KiB in, megabytes out.** `MAX_BODY` caps a request at 4 KiB, but a
//!     1 MiB licensee in the vault is accepted, signed whole, and returned in
//!     a **1 398 346 B** claim response to a **182 B** request — a 7 683x
//!     request/response asymmetry, **~18 531 434 B allocated to serve it**, on
//!     a connection nothing has authenticated. (That figure was 16.4 MB before
//!     `refresh_vault`; the extra ~2.1 MB is the cold re-read of the 1 MiB
//!     ledger on the first claim. The asymmetry itself is untouched.)
//!     -> [`a_megabyte_licensee_is_signed_whole_and_returned_over_the_wire`]
//!
//! Run the whole file:
//! `cargo test -p ccos-enterprise-conformance --test stress_vault_scale`
//! The one `#[ignore]`d test names its own command.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::time::Instant;

use ccos_enterprise_governance::b64url;
use ccos_enterprise_governance::claim::{
    code_from_entropy, code_hash, is_sha256_hex, machine_fingerprint_of, vault_key, ClaimErr,
    ClaimOk, ClaimRequest, CLAIM_PATH, CLAIM_SCHEMA,
};
use ccos_enterprise_governance::vendor::sign_token_bound;
use ccos_enterprise_observability::CounterRegistry;
use ccos_license_server::{
    Counter, Entry, Refusal, Status, TokenBucket, Vault, VAULT_SCHEMA, VAULT_SCHEMA_V1,
};

// ── A thread-local accounting allocator ──────────────────────────────
//
// Wall-clock is machine-dependent and therefore useless as an assertion.
// Allocated bytes are not: they are a deterministic property of the code
// path, identical in debug and release, on any machine. The counter is
// thread-local so the harness's parallel test threads cannot pollute each
// other's measurements.

thread_local! {
    static ALLOCATED: Cell<u64> = const { Cell::new(0) };
}

struct Accounting;

fn note(n: usize) {
    // `Cell<u64>` has no destructor, so this thread-local is a plain
    // `#[thread_local]` static: no lazy init, no registration, no allocation,
    // hence no re-entry into the allocator. `try_with` covers TLS teardown.
    let _ = ALLOCATED.try_with(|c| c.set(c.get().wrapping_add(n as u64)));
}

unsafe impl GlobalAlloc for Accounting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        System.alloc_zeroed(layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(new_size.saturating_sub(layout.size()));
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ACCOUNTING: Accounting = Accounting;

/// Bytes this thread allocated while running `f`. Cumulative, not peak — it
/// answers "how much work did this request make the allocator do", which is
/// the exhaustion question.
fn allocated_by<T>(f: impl FnOnce() -> T) -> (T, u64) {
    let before = ALLOCATED.with(Cell::get);
    let out = f();
    let after = ALLOCATED.with(Cell::get);
    (out, after.wrapping_sub(before))
}

// ── Deterministic fixtures — no RNG, no wall clock, anywhere ─────────

/// Fixed claim instant. Every test that needs "later" adds to it explicitly.
const NOW: u64 = 1_700_000_000;
/// The counter's ed25519 signing seed for these tests.
const SEED: [u8; 32] = [0x5A; 32];
const DAY: u64 = 86_400;

/// 16 bytes of *deterministic* entropy for code `i` (splitmix64). The vendor's
/// entropy source is the only randomness in the real protocol; here there is
/// none at all, so every number this file prints is reproducible.
fn entropy(i: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut x = 0x9E37_79B9_7F4A_7C15u64 ^ u64::from(i).wrapping_mul(0xD1B5_4A32_D192_ED03);
    for chunk in out.chunks_mut(8) {
        x ^= x >> 30;
        x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x ^= x >> 27;
        x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
        x ^= x >> 31;
        chunk.copy_from_slice(&x.to_le_bytes());
    }
    out
}

/// Claim code `i` in canonical form.
fn code(i: u32) -> String {
    code_from_entropy(&entropy(i))
}

/// The **wire** hash of code `i` — what a client sends, what redeems a seat.
fn wire(i: u32) -> String {
    code_hash(&code(i))
}

/// The **vault key** of code `i` — what a leaked `vault.json` contains, and
/// what must never redeem anything.
fn key(i: u32) -> String {
    vault_key(&wire(i))
}

/// Machine fingerprint of host `m`.
fn fp(m: u32) -> String {
    machine_fingerprint_of(&format!("machine-{m:04}"))
}

fn unclaimed(licensee: &str, days: Option<u64>) -> Entry {
    Entry {
        licensee: licensee.to_string(),
        label: None,
        days,
        status: Status::Unclaimed,
        created_unix: NOW - 1_000,
        claimed_unix: None,
        exp_unix: None,
        machine: None,
    }
}

/// A deterministic LCG. Reproducible in debug and release, forever.
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        // Use the high bits: the low bits of an LCG have short periods.
        self.0 >> 17
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

/// Every field of `Entry`, compared by hand — `Entry` derives no `PartialEq`,
/// and "lossless" has to mean all eight fields, not the ones we remembered.
#[track_caller]
fn assert_entry_eq(a: &Entry, b: &Entry, what: &str) {
    assert_eq!(a.licensee, b.licensee, "{what}: licensee");
    assert_eq!(a.label, b.label, "{what}: label");
    assert_eq!(a.days, b.days, "{what}: days");
    assert_eq!(a.status, b.status, "{what}: status");
    assert_eq!(a.created_unix, b.created_unix, "{what}: created_unix");
    assert_eq!(a.claimed_unix, b.claimed_unix, "{what}: claimed_unix");
    assert_eq!(a.exp_unix, b.exp_unix, "{what}: exp_unix");
    assert_eq!(a.machine, b.machine, "{what}: machine");
}

/// A scratch directory unique to this process and tag, wiped on the way in.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ccos-vault-scale-{tag}-{pid}",
        pid = std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn counter_for(vault: Vault, path: &Path) -> Counter {
    Counter {
        vault,
        vault_path: path.to_path_buf(),
        seed: SEED,
        // Deliberately un-throttled: this file measures what one request
        // *costs*, not what the shipped 0.5 req/s bucket lets through.
        bucket: TokenBucket::new(1.0e9, 1.0e9),
        vault_seen: None,
    }
}

fn claim_body(code_hash: &str, machine: &str) -> String {
    serde_json::to_string(&ClaimRequest {
        schema: CLAIM_SCHEMA.to_string(),
        code_hash: code_hash.to_string(),
        machine: machine.to_string(),
    })
    .expect("request serializes")
}

/// Decode a `sign_token_bound` token and verify its ed25519 signature against
/// [`SEED`]'s public half — independently of the product's own verifier, so a
/// bug in that verifier cannot hide a bug here.
fn verified_payload(token: &str) -> serde_json::Value {
    use ed25519_dalek::{Signature, SigningKey, Verifier};
    let (payload_b64, sig_b64) = token.rsplit_once('.').expect("token is payload.sig");
    let sig_bytes = b64url::decode(sig_b64).expect("signature decodes");
    let sig = Signature::from_slice(&sig_bytes).expect("signature is 64 bytes");
    let vk = SigningKey::from_bytes(&SEED).verifying_key();
    vk.verify(payload_b64.as_bytes(), &sig)
        .expect("the counter's token verifies against its own seed");
    let json = b64url::decode(payload_b64).expect("payload decodes");
    serde_json::from_slice(&json).expect("payload is JSON")
}

/// Bytes `save` must pretty-print and fsync for this vault — the marginal
/// cost of one sale, computed without touching a disk.
fn serialized_len(v: &Vault) -> usize {
    serde_json::to_string_pretty(v)
        .expect("vault serializes")
        .len()
        + 1
}

/// A vault of `n` fixed-width synthetic entries. Keys are 64 hex characters,
/// exactly like real `vault_key`s, but skipping ~2n SHA-256 rounds: the size
/// and durability measurements care about shape, not preimages.
fn synthetic_vault(n: u32) -> Vault {
    let mut v = Vault::new();
    for i in 0..n {
        v.entries.insert(
            format!("{i:064x}"),
            Entry {
                licensee: format!("Customer {i:07}"),
                label: Some(format!("invoice-{i:07}")),
                days: Some(365),
                status: Status::Unclaimed,
                created_unix: NOW,
                claimed_unix: None,
                exp_unix: None,
                machine: None,
            },
        );
    }
    v
}

// ═════════════════════════════════════════════════════════════════════
// §1  Scale: the 100 000-entry round trip, and what durability costs
// ═════════════════════════════════════════════════════════════════════

/// Licensee strings chosen to break a serializer if one can be broken: quotes,
/// backslashes, every JSON control character, an embedded NUL, astral-plane
/// codepoints, an RTL override, a BOM in the middle, and a 4 KiB name.
fn hostile_licensee(i: u32) -> String {
    match i % 8 {
        0 => format!("quote\" backslash\\ slash/ #{i}"),
        1 => format!("newline\n carriage\r tab\t formfeed\u{c} #{i}"),
        2 => format!("nul\u{0} bell\u{7} escape\u{1b} #{i}"),
        3 => format!("emoji \u{1F680}\u{1F512} CJK \u{6F22}\u{5B57} #{i}"),
        4 => format!("rtl \u{202E}drowssap\u{202C} bom \u{FEFF} #{i}"),
        5 => format!("looks-like-json {{\"licensee\":\"admin\"}} #{i}"),
        6 => "A".repeat(4096),
        _ => format!("Customer {i}"),
    }
}

#[test]
fn vault_of_100k_entries_roundtrips_losslessly_and_reports_its_durability_cost() {
    const N: u32 = 100_000;
    let dir = scratch("roundtrip");
    let path = dir.join("vault.json");

    // Build: real vault keys (two SHA-256 rounds per code), hostile payloads,
    // and every combination of the optional fields that can reach disk.
    let t0 = Instant::now();
    let mut vault = Vault::new();
    for i in 0..N {
        // Every shape that can legitimately reach disk. `days: 0` used to be
        // in this corpus; it is now a file the counter refuses to load at all,
        // so it belongs in the test that proves the refusal
        // ([`a_zero_day_entry_is_refused_without_burning_the_seat`]) rather
        // than in a round-trip fixture whose whole point is that the file
        // loads.
        let days = match i % 5 {
            0 => None,               // perpetual
            1 => Some(1),            // the smallest sane value
            2 => Some(u64::MAX),     // absurd
            3 => Some(u64::MAX / 4), // absurd, differently
            _ => Some(365),
        };
        let status = match i % 3 {
            0 => Status::Unclaimed,
            1 => Status::Claimed,
            _ => Status::Revoked,
        };
        let claimed = status == Status::Claimed;
        vault.entries.insert(
            key(i),
            Entry {
                licensee: hostile_licensee(i),
                label: if i % 4 == 0 {
                    None
                } else {
                    Some(format!("invoice-{i}"))
                },
                days,
                status,
                created_unix: NOW + u64::from(i),
                claimed_unix: claimed.then_some(NOW + u64::from(i) + 7),
                exp_unix: if claimed {
                    days.map(|d| (NOW + u64::from(i)).saturating_add(d.saturating_mul(DAY)))
                } else {
                    None
                },
                // Every claimed entry gets an owner. The ownerless dead seat
                // of §7 used to be one in nine of this corpus; a file holding
                // one no longer loads, so that shape moved to the test that
                // proves the refusal.
                machine: claimed.then(|| fp(i % 100)),
            },
        );
    }
    let build = t0.elapsed();
    assert_eq!(vault.entries.len() as u32, N, "no key collisions in 100k");

    let t0 = Instant::now();
    vault.save(&path).expect("save 100k");
    let save = t0.elapsed();
    let bytes = std::fs::metadata(&path).expect("stat").len();

    let t0 = Instant::now();
    let back = Vault::load(&path).expect("the schema-gated load accepts what save wrote");
    let load = t0.elapsed();

    println!(
        "[§1] 100 000 entries: build {build:?}, save+fsync {save:?} ({bytes} B, \
         {per} B/entry), load+parse {load:?}",
        per = bytes / u64::from(N)
    );

    // Lossless, field by field, key by key — not "same length".
    assert_eq!(back.schema, VAULT_SCHEMA);
    assert_eq!(back.entries.len(), vault.entries.len());
    for (k, before) in &vault.entries {
        let after = back
            .entries
            .get(k)
            .unwrap_or_else(|| panic!("lost key {k}"));
        assert_entry_eq(before, after, k);
    }
    // ...and no key was invented.
    for k in back.entries.keys() {
        assert!(vault.entries.contains_key(k), "invented key {k}");
    }

    // Serialization is canonical: save(load(save(x))) is byte-identical, so a
    // backup differ never reports phantom churn. (BTreeMap ordering is what
    // buys this; a HashMap would not.)
    let again = dir.join("vault-again.json");
    back.save(&again).expect("re-save");
    assert_eq!(
        std::fs::read(&path).expect("read 1"),
        std::fs::read(&again).expect("read 2"),
        "save is not canonical — a round trip changed the bytes"
    );

    // The ledger holds customer names; the write must not widen its mode.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "vault.json is readable beyond its owner");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

// ═════════════════════════════════════════════════════════════════════
// §2  The claim state machine under 100 000 abusive operations
// ═════════════════════════════════════════════════════════════════════

/// What the *spec* says the vault must do, reimplemented independently from
/// `docs`/the module comment — not by reading `Vault::claim`. If the two ever
/// disagree the test names which one moved.
#[derive(Clone)]
struct Shadow {
    licensee: String,
    days: Option<u64>,
    status: Status,
    owner: Option<u32>,
    exp: Option<u64>,
    claimed_at: Option<u64>,
}

/// Compare an outcome against the spec's prediction, treating
/// `Unserviceable` as a class: the counter writes an operator-facing reason
/// into it, and the model has no business reproducing that text.
fn same_class(
    got: &Result<(String, Option<u64>), Refusal>,
    want: &Result<(String, Option<u64>), Refusal>,
) -> bool {
    match (got, want) {
        (Err(Refusal::Unserviceable(_)), Err(Refusal::Unserviceable(_))) => true,
        _ => got == want,
    }
}

impl Shadow {
    /// Whether the counter can honour this seat at all — the spec's copy of
    /// `Entry::validate`, restated in the model's own terms so the two are
    /// independent. One in thirteen of the seeded codes carries `days: 0`,
    /// which is unserviceable, and the model has to predict that before it can
    /// hold the counter to it.
    fn unserviceable(&self) -> bool {
        self.days == Some(0) && self.status != Status::Revoked
    }

    fn expect(&mut self, machine: u32, now: u64) -> Result<(String, Option<u64>), Refusal> {
        if self.unserviceable() {
            // The reason string is the counter's to write; the model only
            // claims the *class*, which is what `same_class` above compares.
            return Err(Refusal::Unserviceable(String::new()));
        }
        match self.status {
            Status::Revoked => Err(Refusal::Revoked),
            Status::Claimed => {
                if self.owner == Some(machine) {
                    Ok((self.licensee.clone(), self.exp))
                } else {
                    Err(Refusal::SeatTaken)
                }
            }
            Status::Unclaimed => {
                let exp = self
                    .days
                    .map(|d| now.saturating_add(d.saturating_mul(86_400)));
                self.status = Status::Claimed;
                self.owner = Some(machine);
                self.exp = exp;
                self.claimed_at = Some(now);
                Ok((self.licensee.clone(), exp))
            }
        }
    }
}

#[test]
fn claim_state_machine_survives_100k_abusive_operations() {
    const CODES: u32 = 10_000;
    const MACHINES: u32 = 100;
    const OPS: u32 = 100_000;

    let mut vault = Vault::new();
    let mut shadow: Vec<Shadow> = Vec::with_capacity(CODES as usize);
    let mut wires: Vec<String> = Vec::with_capacity(CODES as usize);
    let mut keys: Vec<String> = Vec::with_capacity(CODES as usize);

    for i in 0..CODES {
        let days = match i % 13 {
            0 => None,           // perpetual
            1 => Some(0),        // dead on arrival — §6
            2 => Some(u64::MAX), // absurd — must saturate
            _ => Some(30 + u64::from(i % 700)),
        };
        // One code in seven is already revoked before anyone touches it.
        let status = if i % 7 == 0 {
            Status::Revoked
        } else {
            Status::Unclaimed
        };
        let licensee = format!("Customer {i}");
        let w = wire(i);
        let k = vault_key(&w);
        vault.entries.insert(
            k.clone(),
            Entry {
                licensee: licensee.clone(),
                label: Some(format!("invoice-{i}")),
                days,
                status,
                created_unix: NOW - 500,
                claimed_unix: None,
                exp_unix: None,
                machine: None,
            },
        );
        shadow.push(Shadow {
            licensee,
            days,
            status,
            owner: None,
            exp: None,
            claimed_at: None,
        });
        wires.push(w);
        keys.push(k);
    }

    // Per-code invariant trackers, independent of both the vault and the
    // shadow: whatever the two agree on, these must also hold.
    let mut ever_issued_to: Vec<Option<u32>> = vec![None; CODES as usize];
    let mut first_exp: Vec<Option<Option<u64>>> = vec![None; CODES as usize];
    let mut first_claim_at: Vec<Option<u64>> = vec![None; CODES as usize];
    let mut reissues = 0u32;
    let mut seat_taken = 0u32;
    let mut revoked_refusals = 0u32;
    let mut first_claims = 0u32;
    let mut unserviceable = 0u32;

    let mut rng = Lcg::new(0xC0FF_EE00_1234_5678);
    let t0 = Instant::now();
    for op in 0..OPS {
        // Halfway through, the vendor revokes every third code — including
        // ones already claimed and in use. Revocation must beat the owner.
        if op == OPS / 2 {
            for i in (0..CODES).step_by(3) {
                vault
                    .entries
                    .get_mut(&keys[i as usize])
                    .expect("entry")
                    .status = Status::Revoked;
                shadow[i as usize].status = Status::Revoked;
            }
        }

        let i = rng.below(u64::from(CODES)) as u32;
        // Half the traffic re-presents a code from the machine that already
        // owns it — the lost-token self-service path, and the one place an
        // expiry could be extended. Driven from this file's own tracker, never
        // from the vault, so the assertions stay independent of it.
        let m = match ever_issued_to[i as usize] {
            Some(owner) if rng.below(2) == 0 => owner,
            _ => rng.below(u64::from(MACHINES)) as u32,
        };
        // A strictly increasing clock: every re-claim happens strictly later
        // than the first one, which is exactly when an extension bug shows up.
        let now = NOW + u64::from(op) * 173;

        let expected = shadow[i as usize].expect(m, now);
        let got = vault.claim(&wires[i as usize], &fp(m), now);
        assert!(
            same_class(&got, &expected),
            "op {op}: vault and spec disagree on code {i} / machine {m} at \
             t={now}: {got:?} vs {expected:?}"
        );

        match &got {
            Ok((licensee, exp)) => {
                assert_eq!(
                    licensee,
                    &format!("Customer {i}"),
                    "op {op}: wrong licensee"
                );

                // Single seat, forever: only one machine may ever be issued.
                match ever_issued_to[i as usize] {
                    None => {
                        ever_issued_to[i as usize] = Some(m);
                        first_exp[i as usize] = Some(*exp);
                        first_claim_at[i as usize] = Some(now);
                        first_claims += 1;
                    }
                    Some(owner) => {
                        assert_eq!(owner, m, "op {op}: code {i} issued to a SECOND machine");
                        reissues += 1;
                    }
                }

                // THE non-extension property: the expiry the counter hands out
                // is the one fixed at the first claim, bit for bit, however
                // much later the re-claim happens.
                assert_eq!(
                    Some(*exp),
                    first_exp[i as usize],
                    "op {op}: code {i} re-claim CHANGED the expiry (t={now}, first claim \
                     at t={:?}) — a re-claim must never extend a license",
                    first_claim_at[i as usize]
                );

                let e = &vault.entries[&keys[i as usize]];
                assert_eq!(e.status, Status::Claimed);
                assert_eq!(e.machine.as_deref(), Some(fp(m).as_str()));
                assert_eq!(e.exp_unix, *exp, "op {op}: entry expiry != issued expiry");
                assert_eq!(
                    e.claimed_unix, first_claim_at[i as usize],
                    "op {op}: claimed_unix moved on a re-claim"
                );
            }
            Err(Refusal::SeatTaken) => {
                seat_taken += 1;
                let e = &vault.entries[&keys[i as usize]];
                assert_eq!(e.status, Status::Claimed);
                assert_ne!(
                    e.machine.as_deref(),
                    Some(fp(m).as_str()),
                    "op {op}: SeatTaken from the seat's own owner"
                );
            }
            Err(Refusal::Revoked) => {
                revoked_refusals += 1;
                assert_eq!(vault.entries[&keys[i as usize]].status, Status::Revoked);
            }
            Err(Refusal::UnknownCode) => panic!("op {op}: a seeded code went missing"),
            // **§6, REPAIRED — and this is the assertion that proves it at
            // scale.** A `days: 0` entry used to be claimable: the flip
            // succeeded, the seat burned, and a token whose validity window
            // was the claim instant was signed and handed over. It is refused
            // now, and the refusal is *repeatable* — the entry is untouched,
            // so the vendor can still fix it and the customer still has a
            // seat to claim.
            Err(Refusal::Unserviceable(_)) => {
                unserviceable += 1;
                let e = &vault.entries[&keys[i as usize]];
                assert_eq!(e.days, Some(0), "op {op}: refused a serviceable entry");
                assert_ne!(
                    e.status,
                    Status::Claimed,
                    "op {op}: the refusal MOVED the entry — the seat was burnt \
                     after all"
                );
                assert_eq!(e.machine, None, "op {op}: a refused claim took the seat");
                assert_eq!(e.exp_unix, None);
                assert_eq!(e.claimed_unix, None);
            }
        }
    }
    let elapsed = t0.elapsed();

    // Every seeded code that was ever issued was issued exactly once.
    let issued = ever_issued_to.iter().filter(|o| o.is_some()).count();
    println!(
        "[§2] {OPS} claims / {CODES} codes / {MACHINES} machines in {elapsed:?}: \
         {first_claims} first claims, {reissues} same-machine re-issues, \
         {seat_taken} SeatTaken, {revoked_refusals} Revoked, \
         {unserviceable} Unserviceable, {issued} seats sold"
    );
    assert_eq!(issued as u32, first_claims);
    assert!(reissues > 10_000, "the re-claim path was barely exercised");
    assert!(
        seat_taken > 10_000,
        "the single-seat path was barely exercised"
    );
    assert!(
        revoked_refusals > 10_000,
        "the revoked path was barely exercised"
    );
    // Without this the §6 assertions above are vacuous: one in thirteen of the
    // seeded codes carries `days: 0`, so the new refusal must be reached
    // thousands of times or the arm was never taken.
    assert!(
        unserviceable > 1_000,
        "the unserviceable path was barely exercised: {unserviceable}"
    );

    // Final sweep: the vault agrees with the shadow on every code, and no
    // revoked entry was ever mutated by a claim attempt.
    for i in 0..CODES as usize {
        let e = &vault.entries[&keys[i]];
        let s = &shadow[i];
        assert_eq!(e.status, s.status, "code {i}: status drifted");
        assert_eq!(e.exp_unix, s.exp, "code {i}: expiry drifted");
        assert_eq!(
            e.machine.as_deref(),
            s.owner.map(fp).as_deref(),
            "code {i}: owner drifted"
        );
        if s.status == Status::Unclaimed {
            assert!(e.claimed_unix.is_none() && e.machine.is_none() && e.exp_unix.is_none());
        }
    }

    // The documented, accepted threat: a claim code is a bearer secret. An
    // attacker who intercepts the WIRE hash before the customer redeems it
    // wins the seat, and the customer is then locked out with a refusal the
    // counter cannot distinguish from a legitimate second machine. Pinned
    // here so nobody mistakes single-seat for authentication.
    // A fresh vault, so this says nothing about the 100k run above.
    let victim = 4_242u32;
    let mut fresh = Vault::new();
    fresh
        .entries
        .insert(key(victim), unclaimed("Victim Ltd", Some(365)));
    let thief = fp(999);
    assert!(
        fresh.claim(&wire(victim), &thief, NOW).is_ok(),
        "whoever presents the wire hash first wins the seat"
    );
    assert_eq!(
        fresh.claim(&wire(victim), &fp(1), NOW + 60),
        Err(Refusal::SeatTaken),
        "the paying customer is refused, and the counter cannot tell who is who"
    );
    assert_eq!(
        fresh.entries[&key(victim)].machine.as_deref(),
        Some(thief.as_str()),
        "the seat is bound to the interceptor, permanently"
    );
}

// ═════════════════════════════════════════════════════════════════════
// §3  Anti-replay: a leaked vault.json is not a keyring
// ═════════════════════════════════════════════════════════════════════

#[test]
fn a_leaked_vault_is_not_a_keyring_10k_keys_redeem_nothing() {
    const CODES: u32 = 10_000;
    let mut vault = Vault::new();
    for i in 0..CODES {
        let mut e = unclaimed(&format!("Customer {i}"), Some(365));
        e.label = Some(format!("invoice-{i}"));
        // Half the ledger is already claimed, so the thief also gets to see
        // real machine fingerprints and expiries.
        if i % 2 == 0 {
            e.status = Status::Claimed;
            e.machine = Some(fp(i % 50));
            e.claimed_unix = Some(NOW - 10);
            e.exp_unix = Some(NOW + 365 * DAY);
        }
        vault.entries.insert(key(i), e);
    }
    let stolen = serde_json::to_string(&vault).expect("the thief has the whole file");

    // Everything a leaked vault contains, presented at the entry point — code
    // by code, so each assertion is about the entry it names. (Iterating the
    // BTreeMap instead would pair hash-sorted positions with unrelated code
    // indices and quietly assert nothing.)
    let mut attempts = 0u32;
    for i in 0..CODES {
        let k = key(i);
        let w = wire(i);
        assert_ne!(k, w, "code {i}: the vault must never store the wire hash");
        assert!(vault.entries.contains_key(&k), "code {i} is in the ledger");
        assert!(is_sha256_hex(&k) && is_sha256_hex(&w), "both are hashes");
        let stored_machine = vault.entries[&k].machine.clone();

        // 1. the key itself — the whole point of the v2 schema
        assert_eq!(
            vault.claim(&k, &fp(777), NOW),
            Err(Refusal::UnknownCode),
            "code {i}: its own vault key was redeemable"
        );
        // 2. the stored machine fingerprint, in the code-hash slot
        if let Some(m) = &stored_machine {
            assert_eq!(vault.claim(m, &fp(777), NOW), Err(Refusal::UnknownCode));
            attempts += 1;
        }
        // 3. the key hashed once more, in case the thief guesses the ladder
        assert_eq!(
            vault.claim(&vault_key(&k), &fp(777), NOW),
            Err(Refusal::UnknownCode),
            "code {i}: vault_key(vault_key(..)) redeemed"
        );
        // 4. the key hashed as if it were a code
        assert_eq!(
            vault.claim(&code_hash(&k), &fp(777), NOW),
            Err(Refusal::UnknownCode),
            "code {i}: code_hash(vault key) redeemed"
        );
        attempts += 3;
    }

    // ...and the refusals above are refusals, not the ledger being empty: on
    // a throwaway copy, the wire hash of an unclaimed code still redeems.
    let mut control = vault.clone();
    for i in (1..CODES).step_by(2) {
        assert!(
            control.claim(&wire(i), &fp(777), NOW).is_ok(),
            "code {i} should have been claimable — the §3 refusals would be vacuous"
        );
    }

    // The whole replay campaign changed nothing: not one status flip.
    assert_eq!(
        serde_json::to_string(&vault).expect("serialize"),
        stolen,
        "a replay attempt mutated the ledger"
    );
    println!("[§3] {attempts} replays of leaked vault material: 0 redeemed, 0 state changes");

    // And over the real entry point, where the wire format is checked first.
    let dir = scratch("replay");
    let path = dir.join("vault.json");
    vault.save(&path).expect("save");
    let mut counter = counter_for(vault, &path);
    for i in 0..64u32 {
        let leaked = key(i);
        let (status, body) = counter.handle("POST", CLAIM_PATH, &claim_body(&leaked, &fp(7)), NOW);
        assert_eq!(status, 404, "leaked key {i} was not a 404: {body}");
        let err: ClaimErr = serde_json::from_str(&body).expect("announced refusal");
        assert!(err.error.contains("unknown"), "{}", err.error);
    }
    // The honest wire hash of an unclaimed code still works — the property is
    // "the vault is useless", not "nothing works".
    let (status, body) = counter.handle("POST", CLAIM_PATH, &claim_body(&wire(1), &fp(7)), NOW);
    assert_eq!(status, 200, "{body}");

    let _ = std::fs::remove_dir_all(&dir);
}

// ═════════════════════════════════════════════════════════════════════
// §4  The schema gate
// ═════════════════════════════════════════════════════════════════════

#[test]
fn schema_gate_refuses_v1_and_load_any_schema_reads_it() {
    let dir = scratch("schema");
    let path = dir.join("vault.json");

    let mut v1 = Vault::new();
    v1.schema = VAULT_SCHEMA_V1.to_string();
    // v1 keyed entries by the WIRE hash — that is the whole breaking change.
    v1.entries
        .insert(wire(1), unclaimed("Old Customer", Some(365)));
    v1.save(&path).expect("save");

    let err = Vault::load(&path).expect_err("v1 must fail closed");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains(VAULT_SCHEMA_V1), "{err}");
    assert!(
        err.to_string().contains("migrate"),
        "the refusal names the fix: {err}"
    );

    let read = Vault::load_any_schema(&path).expect("the migration path reads v1");
    assert_eq!(read.schema, VAULT_SCHEMA_V1);
    assert_eq!(read.entries.len(), 1);

    let _ = std::fs::remove_dir_all(&dir);
}

/// **DEFECT 4.** The gate compares a string the file supplies about itself.
/// Editing that one string turns a v1 vault into a "v2" vault that loads
/// clean and then refuses every paying customer — the exact failure mode
/// `Vault::load`'s own doc comment claims the gate prevents. And
/// `load_any_schema` will read literally any tag, including ones that have
/// never existed.
#[test]
fn the_schema_gate_is_a_string_not_a_proof() {
    let dir = scratch("mislabel");
    let path = dir.join("vault.json");

    // A genuine v1 ledger: 100 sold seats, keyed the v1 way.
    let mut v1 = Vault::new();
    for i in 0..100u32 {
        v1.entries
            .insert(wire(i), unclaimed(&format!("Customer {i}"), Some(365)));
    }
    // One field, hand-edited. Nothing else changes.
    v1.schema = VAULT_SCHEMA.to_string();
    v1.save(&path).expect("save");

    let loaded = Vault::load(&path).expect("the gate is satisfied by the string alone");
    assert_eq!(loaded.entries.len(), 100, "every seat is present on disk");

    let mut counter = counter_for(loaded, &path);
    // /healthz says the counter is fine.
    assert_eq!(counter.handle("GET", "/healthz", "", NOW).0, 200);
    // Every real customer is told their code does not exist.
    for i in 0..100u32 {
        let (status, _) = counter.handle("POST", CLAIM_PATH, &claim_body(&wire(i), &fp(1)), NOW);
        assert_eq!(
            status, 404,
            "code {i} redeemed against a mislabelled v1 vault — that would be worse"
        );
    }
    println!("[§4] one edited schema string: 100/100 paying customers refused, /healthz still 200");

    // load_any_schema is a hole of its own: any tag at all, including tags
    // that never shipped and the empty string.
    for tag in ["", "ccos.license.vault/v3", "not even a schema", "null"] {
        let p = dir.join("any.json");
        std::fs::write(
            &p,
            format!("{{\"schema\":{},\"entries\":{{}}}}\n", json_str(tag)),
        )
        .expect("write");
        let v = Vault::load_any_schema(&p).expect("load_any_schema accepts anything");
        assert_eq!(v.schema, tag);
        assert!(
            Vault::load(&p).is_err(),
            "at least the gated load refuses {tag:?}"
        );
    }
    // Case matters, which is the one good news here.
    let p = dir.join("case.json");
    std::fs::write(
        &p,
        "{\"schema\":\"CCOS.LICENSE.VAULT/V2\",\"entries\":{}}\n",
    )
    .expect("write");
    assert!(
        Vault::load(&p).is_err(),
        "the tag comparison is case-sensitive"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

fn json_str(s: &str) -> String {
    serde_json::to_string(s).expect("string serializes")
}

// ═════════════════════════════════════════════════════════════════════
// §5  Hostile vault files
// ═════════════════════════════════════════════════════════════════════

/// A well-formed entry body, so the battery below varies exactly one thing.
const GOOD_ENTRY: &str =
    r#"{"licensee":"Acme","days":365,"status":"unclaimed","created_unix":1700000000}"#;

fn vault_json(entries: &str) -> String {
    format!("{{\"schema\":\"{VAULT_SCHEMA}\",\"entries\":{{{entries}}}}}\n")
}

fn one_entry(k: &str, body: &str) -> String {
    vault_json(&format!("\"{k}\":{body}"))
}

#[test]
fn hostile_vault_files_are_refused_whole_never_partially_trusted() {
    let dir = scratch("hostile");
    let good_key = key(1);

    // Everything here must be refused with InvalidData — never half-loaded,
    // never guessed at, never a panic.
    let refused: Vec<(&str, String)> = vec![
        ("empty file", String::new()),
        ("open brace", "{".to_string()),
        ("truncated mid-string", "{\"schema\":\"ccos.lic".to_string()),
        ("json null", "null".to_string()),
        ("json array", "[]".to_string()),
        ("json number", "42".to_string()),
        (
            "missing entries",
            format!("{{\"schema\":\"{VAULT_SCHEMA}\"}}"),
        ),
        ("missing schema", "{\"entries\":{}}".to_string()),
        (
            "trailing garbage after the object",
            format!("{}garbage", vault_json("")),
        ),
        (
            "byte order mark before the object",
            format!("\u{FEFF}{}", vault_json("")),
        ),
        // One malformed entry poisons the whole ledger — DEFECT 8.
        (
            "negative days",
            one_entry(
                &good_key,
                r#"{"licensee":"A","days":-1,"status":"unclaimed","created_unix":1}"#,
            ),
        ),
        (
            "fractional days",
            one_entry(
                &good_key,
                r#"{"licensee":"A","days":365.5,"status":"unclaimed","created_unix":1}"#,
            ),
        ),
        (
            "days past u64::MAX",
            one_entry(
                &good_key,
                r#"{"licensee":"A","days":18446744073709551616,"status":"unclaimed","created_unix":1}"#,
            ),
        ),
        (
            "days as 1e999",
            one_entry(
                &good_key,
                r#"{"licensee":"A","days":1e999,"status":"unclaimed","created_unix":1}"#,
            ),
        ),
        (
            "missing licensee",
            one_entry(
                &good_key,
                r#"{"days":1,"status":"unclaimed","created_unix":1}"#,
            ),
        ),
        (
            "unknown status variant",
            one_entry(
                &good_key,
                r#"{"licensee":"A","days":1,"status":"expired","created_unix":1}"#,
            ),
        ),
        (
            "mis-cased status variant",
            one_entry(
                &good_key,
                r#"{"licensee":"A","days":1,"status":"Unclaimed","created_unix":1}"#,
            ),
        ),
        (
            "negative created_unix",
            one_entry(
                &good_key,
                r#"{"licensee":"A","days":1,"status":"unclaimed","created_unix":-1}"#,
            ),
        ),
        (
            "raw control byte inside a JSON string",
            one_entry(
                &good_key,
                "{\"licensee\":\"a\u{1}b\",\"days\":1,\"status\":\"unclaimed\",\"created_unix\":1}",
            ),
        ),
        (
            "entries is an array, not a map",
            format!("{{\"schema\":\"{VAULT_SCHEMA}\",\"entries\":[]}}"),
        ),
        // A recursion bomb as the document itself: the parser's depth guard
        // must fire long before the stack does.
        (
            "5000-deep top-level nesting",
            format!("{}{}", "[".repeat(5000), "]".repeat(5000)),
        ),
        (
            "5000-deep nesting where the schema string belongs",
            format!(
                "{{\"schema\":{}{},\"entries\":{{}}}}",
                "[".repeat(5000),
                "]".repeat(5000)
            ),
        ),
    ];

    for (what, text) in &refused {
        let p = dir.join("v.json");
        std::fs::write(&p, text).expect("write");
        let err = match Vault::load(&p) {
            Ok(_) => panic!("{what}: this hostile file LOADED — it must be refused"),
            Err(e) => e,
        };
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::InvalidData,
            "{what}: wrong error kind"
        );
        // load_any_schema is the same parser without the tag check: it must
        // refuse the same malformed bytes.
        assert!(
            Vault::load_any_schema(&p).is_err(),
            "{what}: load_any_schema was more trusting than load"
        );
    }
    println!("[§5] {} hostile files, all refused whole", refused.len());

    // ...but a bomb hidden in an *unknown* field is neither refused nor a
    // crash: serde_json skips ignored values iteratively, so the parser walks
    // the whole thing and throws it away. No stack overflow — which is the
    // good news — but `load` does unbounded work on content it has already
    // decided it does not care about, and there is no size cap on the file
    // either (`read_to_string` reads all of it into memory first).
    let bomb = one_entry(
        &good_key,
        &format!(
            "{{\"licensee\":\"A\",\"days\":1,\"status\":\"unclaimed\",\"created_unix\":1,\
             \"junk\":{}{}}}",
            "[".repeat(5_000),
            "]".repeat(5_000)
        ),
    );
    let p = dir.join("bomb.json");
    std::fs::write(&p, &bomb).expect("write");
    let t0 = Instant::now();
    // The bomb was in a field nobody reads, which used to mean serde walked
    // 10 000 brackets and discarded them without complaint. `deny_unknown_fields`
    // refuses the field itself, so the work is not merely wasted — it is not
    // done. Depth is still not *bounded* (a bomb inside a field the product
    // does read would still be walked), which is why this is a measurement and
    // not a bound.
    let err = Vault::load(&p).expect_err("an unknown field is refused, bomb and all");
    println!(
        "[§5] 10 000 brackets in a field nobody reads: refused in {:?} — {err}",
        t0.elapsed()
    );
    assert!(err.to_string().contains("junk"), "{err}");

    // A missing file is NotFound, not InvalidData — the counter never
    // conjures a vault into being.
    assert_eq!(
        Vault::load(&dir.join("nope.json"))
            .expect_err("missing")
            .kind(),
        std::io::ErrorKind::NotFound
    );

    // Truncation of a REAL file at every quartile: still refused, never a
    // partial ledger.
    let mut real = Vault::new();
    for i in 0..200u32 {
        real.entries
            .insert(key(i), unclaimed(&format!("Customer {i}"), Some(365)));
    }
    let full = dir.join("real.json");
    real.save(&full).expect("save");
    let bytes = std::fs::read(&full).expect("read");
    for cut in [1, bytes.len() / 4, bytes.len() / 2, bytes.len() - 2] {
        let p = dir.join("cut.json");
        std::fs::write(&p, &bytes[..cut]).expect("write");
        assert!(
            Vault::load(&p).is_err(),
            "a vault truncated at {cut}/{} loaded",
            bytes.len()
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// **§9, REPAIRED.** JSON allows duplicate object keys; `BTreeMap`
/// deserialization used to take the last one and say nothing, so a backup
/// merge, a `jq` append or a careless admin could **un-revoke a code by
/// appending one line** — with no error, no warning, and nothing left in the
/// file to show two entries ever existed.
///
/// The entry map is deserialized through a visitor that refuses a repeated
/// key. A ledger where the same seat appears twice is not a ledger with a
/// resolution rule; it is a ledger nobody can read.
#[test]
fn duplicate_keys_are_refused_rather_than_collapsed() {
    let dir = scratch("dupes");
    let p = dir.join("v.json");
    let k = key(1);

    let revoked = r#"{"licensee":"Revoked Corp","days":365,"status":"revoked","created_unix":1}"#;
    let live = r#"{"licensee":"Reinstated","days":365,"status":"unclaimed","created_unix":1}"#;

    // Both orders are refused: the defect was that *order* decided policy.
    for (first, second, tag) in [
        (revoked, live, "revoked then live"),
        (live, revoked, "live then revoked"),
    ] {
        std::fs::write(&p, vault_json(&format!("\"{k}\":{first},\"{k}\":{second}")))
            .expect("write");
        let err = Vault::load(&p).expect_err("a duplicate key must be refused");
        let msg = err.to_string();
        assert!(msg.contains("twice"), "{tag}: {msg}");
        assert!(
            msg.contains(&k),
            "{tag}: the operator is told which key: {msg}"
        );
    }

    // Case-variant hex keys are DIFFERENT entries, and the uppercase one is
    // dead weight: `vault_key` only ever produces lowercase. It is now refused
    // for that reason rather than sitting there unreachable forever.
    let upper = k.to_uppercase();
    std::fs::write(
        &p,
        vault_json(&format!("\"{k}\":{revoked},\"{upper}\":{live}")),
    )
    .expect("write");
    let err = Vault::load(&p).expect_err("an unreachable key is refused");
    assert!(err.to_string().contains("sha256 hex"), "{err}");

    // …and the lowercase original on its own still loads and still refuses
    // the claim, so the repair did not swallow the revocation with the twin.
    std::fs::write(&p, vault_json(&format!("\"{k}\":{revoked}"))).expect("write");
    let mut v = Vault::load(&p).expect("the real entry loads");
    assert_eq!(v.entries.len(), 1);
    assert_eq!(v.claim(&wire(1), &fp(1), NOW), Err(Refusal::Revoked));

    // Keys used never to be validated: empty and non-hex keys loaded fine and
    // sat there forever, unreachable by any claim. Each is refused now, by
    // name, because an unreachable entry in a ledger is an accounting error
    // whatever it cannot be reached by.
    for junk in ["", "not-a-hash", &"z".repeat(64), &k[..63]] {
        std::fs::write(&p, vault_json(&format!("\"{junk}\":{live}"))).expect("write");
        let err = Vault::load(&p)
            .err()
            .unwrap_or_else(|| panic!("key {junk:?} must be refused"));
        assert!(err.to_string().contains("sha256 hex"), "{junk:?}: {err}");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// **§5, REPAIRED.** A one-character typo in a field name used to silently
/// convert an annual license into a perpetual one. `Entry` had no
/// `deny_unknown_fields` and `exp_unix` is `#[serde(default)]`, so a vault
/// holding `"expires_unix"` loaded without a murmur, the field landed as
/// `None`, and the next re-claim signed a token with **no expiry at all**.
///
/// Two rules close it, and they are different rules:
///
/// * `#[serde(deny_unknown_fields)]` on `Entry` and `Vault` — a field name the
///   product does not know is a refusal, not a shrug. That also stops an
///   unknown *top-level* field that looks like policy (`"revoked_after"`,
///   `"max_seats"`) from being silently dropped.
/// * `days` is deserialized through a named function, which is what makes
///   serde report a **missing** field instead of defaulting it. `null` still
///   means perpetual; saying nothing at all no longer does. This is the half
///   `deny_unknown_fields` cannot reach, because omitting a field is not an
///   unknown field.
#[test]
fn a_typo_in_a_field_name_is_refused_rather_than_selling_a_perpetual_license() {
    let dir = scratch("typo");
    let p = dir.join("v.json");
    let k = key(1);
    let owner = fp(1);

    // Exactly what a correctly claimed 365-day seat looks like on disk...
    let correct = format!(
        r#"{{"licensee":"Acme","days":365,"status":"claimed","created_unix":1,
             "claimed_unix":{NOW},"exp_unix":{},"machine":"{owner}"}}"#,
        NOW + 365 * DAY
    );
    std::fs::write(&p, one_entry(&k, &correct)).expect("write");
    let mut v = Vault::load(&p).expect("load");
    assert_eq!(
        v.claim(&wire(1), &owner, NOW + 10),
        Ok(("Acme".to_string(), Some(NOW + 365 * DAY))),
        "the healthy case re-issues the stored expiry"
    );

    // ...and the same file with ONE character changed in a field name.
    let typo = correct.replace("\"exp_unix\"", "\"expires_unix\"");
    std::fs::write(&p, one_entry(&k, &typo)).expect("write");
    let err = Vault::load(&p).expect_err("the typo must be an error");
    assert!(
        err.to_string().contains("expires_unix"),
        "the operator is told which field: {err}"
    );
    println!("[§5] one typo in a field name: refused by name, not sold as perpetual");

    // The other side of the same hole: an entry that simply omits `days`.
    // `deny_unknown_fields` cannot see this one — nothing unknown is present —
    // so it takes the required-field rule.
    std::fs::write(
        &p,
        one_entry(
            &k,
            r#"{"licensee":"Acme","status":"unclaimed","created_unix":1}"#,
        ),
    )
    .expect("write");
    let err = Vault::load(&p).expect_err("an entry with no `days` must be an error");
    assert!(
        err.to_string().contains("days"),
        "a vault entry that forgot to say how long the license lasts must not \
         sell a perpetual one: {err}"
    );

    // …while an explicit null still does mean perpetual, which is the point of
    // requiring the field rather than banning the value.
    std::fs::write(
        &p,
        one_entry(
            &k,
            r#"{"licensee":"Acme","days":null,"status":"unclaimed","created_unix":1}"#,
        ),
    )
    .expect("write");
    let mut v = Vault::load(&p).expect("an explicit null loads");
    assert_eq!(v.entries[&k].days, None);
    assert_eq!(
        v.claim(&wire(1), &fp(1), NOW),
        Ok(("Acme".to_string(), None)),
        "a deliberately perpetual license is still sellable"
    );

    // An unknown top-level field, including one that looks like policy, is
    // refused too — dropping it silently is how a vault appears to carry a
    // seat cap that nothing enforces.
    std::fs::write(
        &p,
        format!(
            "{{\"schema\":\"{VAULT_SCHEMA}\",\"entries\":{{\"{k}\":{GOOD_ENTRY}}},\
             \"revoked_after\":\"{NOW}\",\"max_seats\":1}}\n"
        ),
    )
    .expect("write");
    let err = Vault::load(&p).expect_err("unknown top-level fields must be refused");
    assert!(
        err.to_string().contains("revoked_after") || err.to_string().contains("max_seats"),
        "{err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ═════════════════════════════════════════════════════════════════════
// §6  Arithmetic edges: absurd, zero, and perpetual day counts
// ═════════════════════════════════════════════════════════════════════

#[test]
fn absurd_day_counts_saturate_instead_of_wrapping_into_the_past() {
    // Every one of these must land at or after the claim instant. The one
    // that matters is `u64::MAX`: release-mode `+` would wrap it into 1970.
    for days in [
        u64::MAX,
        u64::MAX - 1,
        u64::MAX / 2,
        u64::MAX / 86_400,
        u64::MAX / 86_400 + 1,
        u64::MAX / 86_400 - 1,
        213_503_982_334_601, // just under the overflow threshold
        1_000_000_000_000,
    ] {
        let mut v = Vault::new();
        v.entries.insert(key(1), unclaimed("Acme", Some(days)));
        let (_, exp) = v.claim(&wire(1), &fp(1), NOW).expect("issues");
        let exp = exp.expect("a finite days always yields an expiry");
        assert!(
            exp >= NOW,
            "days={days} produced an expiry BEFORE the claim ({exp} < {NOW})"
        );
        assert_eq!(v.entries[&key(1)].exp_unix, Some(exp), "stored == issued");

        // And a token signed with it is still a real signed token.
        let payload = verified_payload(&sign_token_bound(&SEED, "Acme", Some(exp), Some(&fp(1))));
        assert_eq!(payload["exp"].as_u64(), Some(exp));
    }

    // The exact saturation point, pinned: 86_400 * d must saturate, then the
    // addition must saturate too.
    let mut v = Vault::new();
    v.entries.insert(key(2), unclaimed("Acme", Some(u64::MAX)));
    assert_eq!(v.claim(&wire(2), &fp(1), NOW).unwrap().1, Some(u64::MAX));

    // Perpetual stays perpetual — None is not 0.
    let mut v = Vault::new();
    v.entries.insert(key(3), unclaimed("Acme", None));
    assert_eq!(v.claim(&wire(3), &fp(1), NOW).unwrap().1, None);
    assert_eq!(v.entries[&key(3)].exp_unix, None);
}

/// **§6, REPAIRED.** `days: 0` used to permanently destroy a sold seat:
/// nothing validated it, so the claim succeeded, the code flipped to
/// `Claimed`, the single seat burned, and the counter signed a token whose
/// entire validity window was the claim instant. Every later re-claim
/// re-issued the same dead expiry, so the protocol had no recovery path —
/// only vault surgery.
///
/// The claim is refused now, and the two properties that make the refusal
/// worth having are asserted below: the entry is **untouched**, so the seat
/// is still there to be claimed once the vendor fixes it, and the refusal is
/// **repeatable** rather than a one-shot.
#[test]
fn a_zero_day_entry_is_refused_without_burning_the_seat() {
    let mut v = Vault::new();
    v.entries.insert(key(1), unclaimed("Acme Corp", Some(0)));

    let refusal = v.claim(&wire(1), &fp(1), NOW).expect_err("the claim FAILS");
    let Refusal::Unserviceable(why) = &refusal else {
        panic!("wrong refusal: {refusal:?}");
    };
    assert!(
        why.contains("days is 0"),
        "the operator is told which line: {why}"
    );
    assert!(why.contains("null"), "…and what to write instead: {why}");

    // The seat is intact. That is the whole point: a refusal costs a support
    // ticket, and the alternative cost the customer their license.
    let e = &v.entries[&key(1)];
    assert_eq!(e.status, Status::Unclaimed, "the seat was not burnt");
    assert_eq!(e.machine, None);
    assert_eq!(e.exp_unix, None);
    assert_eq!(e.claimed_unix, None);

    // Repeatable, from any machine, at any time — nothing was consumed.
    assert!(matches!(
        v.claim(&wire(1), &fp(2), NOW + 1),
        Err(Refusal::Unserviceable(_))
    ));
    assert!(matches!(
        v.claim(&wire(1), &fp(1), NOW + 365 * DAY),
        Err(Refusal::Unserviceable(_))
    ));
    assert_eq!(v.entries[&key(1)].status, Status::Unclaimed);

    // And the vendor's fix works on the seat that was preserved.
    v.entries.get_mut(&key(1)).expect("entry").days = Some(365);
    let (licensee, exp) = v.claim(&wire(1), &fp(1), NOW).expect("now it issues");
    assert_eq!(licensee, "Acme Corp");
    assert_eq!(exp, Some(NOW + 365 * DAY));
    println!("[§6] days:0 — refused, seat intact, vendor fix recovers it");

    // A file holding one cannot even be loaded, so the counter never starts
    // with a landmine in it.
    let dir = scratch("zero-days");
    let path = dir.join("vault.json");
    let mut bad = Vault::new();
    bad.entries.insert(key(3), unclaimed("Acme", Some(0)));
    std::fs::write(&path, serde_json::to_string_pretty(&bad).expect("json")).expect("write");
    let err = Vault::load(&path).expect_err("a vault holding a dead seat must not load");
    assert!(err.to_string().contains("days is 0"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);

    // days:1 is the smallest sane value, for contrast.
    let mut v = Vault::new();
    v.entries.insert(key(2), unclaimed("Acme", Some(1)));
    assert_eq!(v.claim(&wire(2), &fp(1), NOW).unwrap().1, Some(NOW + DAY));
}

// ═════════════════════════════════════════════════════════════════════
// §7  Unreachable states: dead seats the protocol cannot recover
// ═════════════════════════════════════════════════════════════════════

/// **§7, REPAIRED.** A `Claimed` entry with no owner used to answer
/// `SeatTaken` to **every** machine including the customer's, forever.
/// `machine` is `#[serde(default)]`, so a hand edit, a partial restore or a
/// migration that dropped a field produced one silently, and there was no way
/// back: the entry looked claimed, so nothing would ever re-issue it.
/// `Some("")` was the same trap over the wire, since no client can present the
/// empty owner.
///
/// Both are refused now — as `Unserviceable`, not `SeatTaken`, and the
/// difference is the whole repair. `SeatTaken` tells a paying customer someone
/// else has their seat, which is a lie and an unactionable one;
/// `Unserviceable` is a 500 that names the entry in the operator's log and
/// tells the customer nothing was consumed.
#[test]
fn a_claimed_entry_with_no_reachable_owner_is_refused_not_silently_dead() {
    let mut v = Vault::new();
    let mut orphan = unclaimed("Acme Corp", Some(365));
    orphan.status = Status::Claimed;
    orphan.claimed_unix = Some(NOW - 100);
    orphan.exp_unix = Some(NOW + 365 * DAY);
    orphan.machine = None; // the whole defect
    v.entries.insert(key(1), orphan);

    for m in 0..64u32 {
        let got = v.claim(&wire(1), &fp(m), NOW + u64::from(m));
        assert!(
            matches!(got, Err(Refusal::Unserviceable(_))),
            "machine {m}: {got:?} — an unreachable seat must not read as taken"
        );
    }
    // Not even the empty string, not even the entry's own licensee — and none
    // of them is told the seat belongs to somebody else.
    for m in ["", "Acme Corp"] {
        assert!(matches!(
            v.claim(&wire(1), m, NOW),
            Err(Refusal::Unserviceable(_))
        ));
    }
    println!("[§7] claimed + machine:None — refused as unserviceable, not as taken");

    // `machine: Some("")` is the same trap from the other side. The pure API
    // used to re-issue to the empty owner while `Counter::handle` rejected the
    // wire value, so the seat was dead in production and *looked* alive in a
    // unit test. It is now refused on both.
    let mut v = Vault::new();
    let mut empty_owner = unclaimed("Acme", Some(365));
    empty_owner.status = Status::Claimed;
    empty_owner.machine = Some(String::new());
    empty_owner.exp_unix = Some(NOW + DAY);
    v.entries.insert(key(2), empty_owner);
    assert!(
        matches!(v.claim(&wire(2), "", NOW), Err(Refusal::Unserviceable(_))),
        "the pure API must not bind the empty machine either"
    );
    assert!(!is_sha256_hex(""), "and the wire format still rejects it");

    let dir = scratch("deadseat");
    let path = dir.join("vault.json");
    v.save(&path).expect("save");
    let mut counter = counter_for(v, &path);
    let (status, _) = counter.handle("POST", CLAIM_PATH, &claim_body(&wire(2), ""), NOW);
    assert_eq!(status, 400, "no client can ever reach the empty owner");

    // A file holding either shape cannot be loaded at all, so a counter never
    // starts holding a seat it can only refuse.
    for (tag, mut bad) in [
        ("no-owner", {
            let mut e = unclaimed("Acme", Some(365));
            e.status = Status::Claimed;
            e.claimed_unix = Some(NOW);
            e.exp_unix = Some(NOW + DAY);
            e
        }),
        ("empty-owner", {
            let mut e = unclaimed("Acme", Some(365));
            e.status = Status::Claimed;
            e.claimed_unix = Some(NOW);
            e.exp_unix = Some(NOW + DAY);
            e.machine = Some(String::new());
            e
        }),
    ] {
        bad.licensee = format!("Acme {tag}");
        let mut v = Vault::new();
        v.entries.insert(key(4), bad);
        let p = dir.join(format!("{tag}.json"));
        std::fs::write(&p, serde_json::to_string_pretty(&v).expect("json")).expect("write");
        let err = Vault::load(&p).expect_err("a dead seat must not load");
        assert!(
            err.to_string().contains("machine") || err.to_string().contains("claimed"),
            "{tag}: {err}"
        );
    }

    // **STILL OPEN.** `Vault::claim` validates nothing about the machine
    // string it *stores* on a first claim — a megabyte of it is fine, lands in
    // the ledger and is persisted whole. `Counter::handle` requires
    // `is_sha256_hex` on the wire, so this is unreachable through the server;
    // the pure API remains the way in, and finding 10's asymmetry is the same
    // shape from the licensee side.
    let mut v = Vault::new();
    v.entries.insert(key(3), unclaimed("Acme", Some(365)));
    let huge = "m".repeat(1 << 20);
    assert!(v.claim(&wire(3), &huge, NOW).is_ok());
    assert_eq!(v.entries[&key(3)].machine.as_deref(), Some(huge.as_str()));
    let p2 = dir.join("huge.json");
    v.save(&p2).expect("save");
    assert!(
        std::fs::metadata(&p2).expect("stat").len() > (1 << 20),
        "the unvalidated machine string is persisted whole"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ═════════════════════════════════════════════════════════════════════
// §8  EXHAUSTION: what one sale costs the ledger
// ═════════════════════════════════════════════════════════════════════

/// **DEFECT 1, part one — the deterministic half. STILL OPEN.** `Vault::save`
/// serializes the entire map. The marginal cost per entry is a constant, so
/// the cost of recording sale number N is linear in N: the ledger is its own
/// amplifier. Byte counts are exact and machine-independent, so this is
/// asserted, not merely printed. Nothing in the `refresh_vault` repair reaches
/// this path — it is pure serialization arithmetic, and every number below is
/// the same as it was before.
#[test]
fn the_marginal_cost_of_one_sale_is_the_whole_ledger() {
    let sizes: Vec<(u32, usize)> = [1_000u32, 10_000, 100_000]
        .iter()
        .map(|&n| (n, serialized_len(&synthetic_vault(n))))
        .collect();

    let per_entry_small = (sizes[1].1 - sizes[0].1) / 9_000;
    let per_entry_large = (sizes[2].1 - sizes[1].1) / 90_000;
    for (n, bytes) in &sizes {
        println!("[§8] save() must write {bytes} B at {n} entries");
    }
    assert_eq!(
        per_entry_small, per_entry_large,
        "marginal bytes per entry must be a constant for this to be a clean O(N)"
    );

    // The defect, stated as an assertion: one sale at 100k entries costs ~100x
    // what it costs at 1k. There is no incremental write, no append log, no
    // per-entry file — the whole ledger is re-pretty-printed and re-fsynced.
    assert!(
        sizes[2].1 >= 95 * sizes[0].1,
        "if this ever fails, save() became sub-linear and this finding is fixed: \
         {} vs {}",
        sizes[2].1,
        sizes[0].1
    );

    // Total write amplification to sell N seats: sum of the file size at each
    // sale, i.e. ~N^2/2 * per_entry.
    let n: u64 = 100_000;
    let per = per_entry_large as u64;
    let total = per * n * (n + 1) / 2;
    println!(
        "[§8] selling {n} seats fsyncs ~{gb:.1} GB ({total} B) to record {mb:.1} MB of truth \
         — {ratio}x write amplification, at {per} B/entry",
        gb = total as f64 / 1e9,
        mb = (per * n) as f64 / 1e6,
        ratio = total / (per * n),
    );
    assert!(
        total > 1_000_000_000_000,
        "the amplification is the finding"
    );

    // And nothing bounds the map. The sibling counter registry caps itself at
    // MAX_SERIES precisely so "a label explosion can never exhaust memory";
    // the vault, which holds the money, has no equivalent.
    assert_eq!(CounterRegistry::MAX_SERIES, 4096);
    let v = synthetic_vault(100_000);
    assert!(
        v.entries.len() > CounterRegistry::MAX_SERIES * 24,
        "the vault accepts 24x the cap its sibling enforces, and would accept more"
    );
}

/// **DEFECT 1, part two — the wall clock. STILL OPEN.** Same finding,
/// measured against a real disk with real `fsync`s, through the real request
/// handler. `save_vault` (`lib.rs:316`) still calls `Vault::save`, which still
/// re-pretty-prints and re-`fsync`s the entire `BTreeMap` for every one-bit
/// state flip; nothing incremental was introduced, so this stays a pin rather
/// than a regression guard.
///
/// The numbers below were re-taken after `handle_claim` gained its
/// `refresh_vault()` call, which added a `stat` to every claim and a whole
/// `Vault::load` to any claim whose fingerprint check misses. The last block
/// separates the two so the per-sale cost is stated honestly: the repair made
/// the claim path *more* expensive, and the O(N) write it sits in front of is
/// untouched.
#[test]
fn every_sale_rewrites_and_fsyncs_the_entire_ledger() {
    let dir = scratch("amplify");

    // Growth curve of one save().
    for n in [1_000u32, 10_000, 100_000] {
        let v = synthetic_vault(n);
        let p = dir.join(format!("v{n}.json"));
        let mut best = std::time::Duration::from_secs(999);
        for _ in 0..3 {
            let t = Instant::now();
            v.save(&p).expect("save");
            best = best.min(t.elapsed());
        }
        let bytes = std::fs::metadata(&p).expect("stat").len();
        let (_, alloc) = allocated_by(|| v.save(&p).expect("save"));
        println!(
            "[§8] save at {n:>6} entries: {best:>10.3?}  {bytes:>9} B on disk  \
             {alloc:>10} B allocated ({x:.2}x the file)",
            x = alloc as f64 / bytes as f64
        );
        // `to_string_pretty` builds the whole file in memory, then `format!`
        // copies it whole to append one newline: two full-size buffers per
        // save, deterministically.
        assert!(
            alloc >= 2 * bytes,
            "save allocated {alloc} B for a {bytes} B file — the double buffer is gone?"
        );
        let _ = std::fs::remove_file(&p);
    }

    // Now through the handler, which is where it actually happens: 40
    // consecutive sales against a 10 000-entry ledger.
    const LEDGER: u32 = 10_000;
    const SALES: u32 = 40;
    let mut v = synthetic_vault(LEDGER);
    // Splice in real, claimable codes.
    for i in 0..SALES {
        v.entries
            .insert(key(i), unclaimed(&format!("Buyer {i}"), Some(365)));
    }
    let path = dir.join("counter.json");
    v.save(&path).expect("seed");
    let mut counter = counter_for(Vault::load(&path).expect("load"), &path);

    let t0 = Instant::now();
    let mut per_sale: Vec<u64> = Vec::with_capacity(SALES as usize);
    for i in 0..SALES {
        let body = claim_body(&wire(i), &fp(i));
        let ((status, _), alloc) = allocated_by(|| counter.handle("POST", CLAIM_PATH, &body, NOW));
        assert_eq!(status, 200);
        per_sale.push(alloc);
    }
    let elapsed = t0.elapsed();
    let total_alloc: u64 = per_sale.iter().sum();
    let file = std::fs::metadata(&path).expect("stat").len();
    println!(
        "[§8] {SALES} sales against a {LEDGER}-entry ledger: {elapsed:?} total, \
         {each:?} each, {alloc_each} B allocated per sale for a {file} B file \
         ({x:.1}x the file, per sale)",
        each = elapsed / SALES,
        alloc_each = total_alloc / u64::from(SALES),
        x = (total_alloc / u64::from(SALES)) as f64 / file as f64,
    );
    // Per sale the counter allocates several whole copies of the ledger: the
    // pre-claim clone, the pretty string, the newline copy.
    assert!(
        total_alloc / u64::from(SALES) >= 3 * file,
        "one sale allocated less than three copies of the ledger — has this been fixed?"
    );

    // What the `refresh_vault` repair costs, separated from the above. It runs
    // at the top of every claim: `vault_seen` starts `None`, so the FIRST sale
    // after start-up re-reads and re-parses the whole file before doing any of
    // the work already measured; `save_vault` then re-fingerprints what it
    // just wrote, so every later sale pays only the `stat`. Neither number is
    // an improvement — the point of this block is that the sale still costs
    // several whole copies of the ledger *underneath* the new read.
    let first = per_sale[0];
    let steady = per_sale[1..].iter().sum::<u64>() / (u64::from(SALES) - 1);
    assert!(
        first > steady,
        "the first claim after start-up did not re-read the ledger — was \
         refresh_vault removed? {first} vs {steady}"
    );
    println!(
        "[§8] refresh_vault: the first sale after start-up costs {first} B — {extra} B more \
         than the {steady} B steady state, i.e. one whole Vault::load of the {file} B file. \
         Steady state is that load's `stat` only, and the O(N) write underneath it is \
         unchanged.",
        extra = first - steady,
    );
    // The finding itself, restated on the steady-state number so the one-off
    // cold read cannot be mistaken for it: even with nothing to re-read, one
    // sale still allocates three whole ledgers to flip one bit.
    assert!(
        steady >= 3 * file,
        "in steady state one sale allocated {steady} B, less than three copies of a \
         {file} B ledger — save() would then have become incremental, and it has not"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The same measurement at the scale the finding is about: **4.7 GB of
/// fsynced writes to record 200 one-bit state flips**. ~2.5 min in debug,
/// ~27 s in release. Still open — `save_vault` still writes the whole map.
/// The `refresh_vault` repair adds a `stat` per sale and one 23.4 MB re-read
/// on the first, which is noise beside the 4.7 GB counted here (this figure
/// counts writes only, and the write path was not repaired).
/// `cargo test --release -p ccos-enterprise-conformance --test \
///  stress_vault_scale -- --ignored --nocapture sales_against_a_100k_ledger`
#[test]
#[ignore = "~2.5 min in debug (~27 s in release): 200 fsyncs of a 23 MB ledger"]
fn sales_against_a_100k_ledger_move_gigabytes_to_record_200_flips() {
    let dir = scratch("amplify-100k");
    const LEDGER: u32 = 100_000;
    const SALES: u32 = 200;
    let mut v = synthetic_vault(LEDGER);
    for i in 0..SALES {
        v.entries
            .insert(key(i), unclaimed(&format!("Buyer {i}"), Some(365)));
    }
    let path = dir.join("counter.json");
    v.save(&path).expect("seed");
    let mut counter = counter_for(v, &path);

    let t0 = Instant::now();
    for i in 0..SALES {
        let (status, _) = counter.handle("POST", CLAIM_PATH, &claim_body(&wire(i), &fp(i)), NOW);
        assert_eq!(status, 200);
    }
    let elapsed = t0.elapsed();
    let file = std::fs::metadata(&path).expect("stat").len();
    let written = file * u64::from(SALES);
    println!(
        "[§8] {SALES} sales against a {LEDGER}-entry ledger: {elapsed:?}, {each:?} per sale, \
         {written} B ({gb:.2} GB) written+fsynced to record {SALES} one-bit flips \
         — {amp}x amplification over the ~{useful} B that actually changed",
        each = elapsed / SALES,
        gb = written as f64 / 1e9,
        useful = u64::from(SALES) * 130,
        amp = written / (u64::from(SALES) * 130),
    );
    assert!(
        written > 4_000_000_000,
        "4 GB was the finding; if this shrank, save() became incremental"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// **DEFECT 2 — STILL OPEN, and the `refresh_vault` repair made it worse.**
/// `Counter::handle_claim` clones the entire vault *before* consulting it
/// (`lib.rs:355`). The cheapest possible request — an unknown code, which is
/// all a brute-forcer ever sends and all a scanner ever sends — therefore
/// costs a full deep copy of every key, licensee, label and fingerprint in
/// the ledger, thrown away microseconds later. That line was not touched by
/// the repair, so this test keeps pinning it.
///
/// What *did* change sits one line above it: `handle_claim` now calls
/// `refresh_vault()` (`lib.rs:351`) before it decides anything, so the same
/// unauthenticated request also `stat`s the vault file and — whenever
/// `(mtime, len)` no longer matches what this process last read or wrote —
/// re-reads and re-parses the whole file *as well as* cloning it. The second
/// half of this test measures that on the production shape (a vault file that
/// actually exists), because the honest cost of one refused request went up,
/// not down.
#[test]
fn an_unknown_code_404_deep_copies_the_entire_ledger() {
    let dir = scratch("clone");
    let unknown = claim_body(&"f".repeat(64), &fp(1));

    let mut measured: Vec<(u32, u64, std::time::Duration)> = Vec::new();
    for n in [1_000u32, 100_000] {
        let path = dir.join(format!("v{n}.json"));
        let mut counter = counter_for(synthetic_vault(n), &path);
        // Warm up so the first-call allocations do not skew the number.
        assert_eq!(counter.handle("POST", CLAIM_PATH, &unknown, NOW).0, 404);

        let t0 = Instant::now();
        let ((status, _), alloc) =
            allocated_by(|| counter.handle("POST", CLAIM_PATH, &unknown, NOW));
        let elapsed = t0.elapsed();
        assert_eq!(status, 404, "nothing was found, nothing was written");
        assert!(!path.exists(), "a 404 must not touch the disk");
        measured.push((n, alloc, elapsed));
        println!("[§8] one 404 against a {n:>6}-entry ledger: {alloc:>9} B allocated, {elapsed:?}");
    }

    let (small_n, small, _) = measured[0];
    let (large_n, large, large_t) = measured[1];
    let ratio = large / small.max(1);
    println!(
        "[§8] refused-request cost scales with LEDGER SIZE, not request size: \
         {ratio}x more allocation for {}x more entries ({large_t:?} of CPU per 404 at \
         {large_n} entries). The shipped TokenBucket::new(10.0, 0.5) is the only \
         thing in front of this.",
        large_n / small_n
    );
    // Deterministic: allocation is a property of the code path, not the host.
    assert!(
        ratio >= 50,
        "a 404 no longer copies the ledger — has lib.rs:355 been fixed? {small} -> {large}"
    );

    // ── The same refused request, with the vault file where production
    //    keeps it ─────────────────────────────────────────────────────────
    //
    // The measurements above run against a counter whose vault file does not
    // exist, which is exactly what lets them assert "a 404 must not touch the
    // disk": `refresh_vault` treats a missing file as "nothing to adopt" and
    // returns without reading anything. A deployed counter always has the
    // file, so the production cost is measured separately here — three
    // refused requests, identical bytes on the wire, against the same
    // 100 000-entry ledger:
    //
    //   * cold — `vault_seen` starts `None`, so the first refusal re-reads
    //     and re-parses the whole file *and then* deep-copies it;
    //   * warm — the fingerprint now matches, so the refresh is one `stat`
    //     and the deep copy is the whole cost, unchanged by the repair;
    //   * after an out-of-band edit — the operator uploads a vault
    //     (`docs/LICENSING_SERVER.md` tells them to), the fingerprint moves,
    //     and the very next brute-force miss pays the full re-read again.
    //
    // So a scanner that keeps guessing while a vendor edits the ledger makes
    // every single miss cost a file read *plus* a ledger copy, and neither is
    // work the request asked for.
    let seeded = dir.join("on-disk.json");
    let vault = synthetic_vault(100_000);
    vault.save(&seeded).expect("seed a real ledger on disk");
    let pristine = std::fs::read(&seeded).expect("read");
    let mut counter = counter_for(vault, &seeded);

    let t0 = Instant::now();
    let ((status, _), cold) = allocated_by(|| counter.handle("POST", CLAIM_PATH, &unknown, NOW));
    let cold_t = t0.elapsed();
    assert_eq!(status, 404, "cold refusal");
    let t0 = Instant::now();
    let ((status, _), warm) = allocated_by(|| counter.handle("POST", CLAIM_PATH, &unknown, NOW));
    let warm_t = t0.elapsed();
    assert_eq!(status, 404, "warm refusal");
    assert_eq!(
        std::fs::read(&seeded).expect("read"),
        pristine,
        "a 404 wrote to the ledger"
    );

    // The operator's upload: one entry more, so the length moves and the
    // fingerprint cannot miss it.
    let mut by_hand = Vault::load(&seeded).expect("the operator loads the ledger");
    by_hand.entries.insert(
        format!("{:064x}", u64::from(u32::MAX)),
        unclaimed("Late Arrival Ltd", Some(365)),
    );
    by_hand.save(&seeded).expect("the upload lands");
    let after_upload = std::fs::read(&seeded).expect("read");
    let t0 = Instant::now();
    let ((status, _), edited) = allocated_by(|| counter.handle("POST", CLAIM_PATH, &unknown, NOW));
    let edited_t = t0.elapsed();
    assert_eq!(status, 404, "refusal after an out-of-band edit");
    assert_eq!(
        std::fs::read(&seeded).expect("read"),
        after_upload,
        "a 404 overwrote the operator's upload"
    );

    println!(
        "[§8] one 404 against a 100 000-entry / {} B ledger with the file ON DISK: \
         cold {cold} B in {cold_t:?}, warm {warm} B in {warm_t:?}, after an out-of-band \
         edit {edited} B in {edited_t:?} — the {reread} B on top is refresh_vault \
         re-reading the file, the {warm} B underneath it is still the deep copy of \
         lib.rs:355, on a connection nothing has authenticated",
        pristine.len(),
        reread = cold.saturating_sub(warm),
    );
    // The repair is present: the cold refusal really does re-read the file.
    assert!(
        cold > warm,
        "the cold 404 did not re-read the ledger — was refresh_vault removed? \
         {cold} vs {warm}"
    );
    assert!(
        edited > warm,
        "an out-of-band edit was not adopted — {edited} vs {warm}"
    );
    // ...and the defect is present: the warm refusal, which does nothing but
    // `stat` and look up a key that is not there, still copies the ledger.
    assert!(
        warm >= large,
        "a 404 stopped deep-copying the ledger — lib.rs:355 would then be fixed, \
         and it is not: {warm} vs {large}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ═════════════════════════════════════════════════════════════════════
// §9  Durability: the atomic write, and how it wedges
// ═════════════════════════════════════════════════════════════════════

/// **DEFECT 3 — REPAIRED IN CORE, GUARDED HERE.**
///
/// `write_durable` used to create `<path>.tmp.<pid>` with `create_new(true)`.
/// A crash between create and rename left that file behind forever — nothing
/// cleaned it, and the name was only pid-unique. When a process with that pid
/// next served claims, every single one answered `500 persistence failure`
/// while `/healthz` kept answering 200: a total outage the health check could
/// not see, curable only by an operator deleting a file by hand.
///
/// Core now names the temp `<path>.tmp.<pid>.<attempt>` from a monotonic
/// counter, retrying up to 16 times, and unlinks it from a `Drop` guard on
/// every failure path. Two independent reasons the wedge cannot recur: the
/// name a crashed predecessor left is never reused, and a failure cleans up
/// after itself.
///
/// This test keeps the crash debris exactly as it was and asserts the opposite
/// outcome. It also asserts the guard's *restraint*: a file this call did not
/// create must never be unlinked, however inconvenient it is.
#[test]
fn a_stale_temp_file_no_longer_wedges_any_future_save() {
    let dir = scratch("wedge");
    let path = dir.join("vault.json");
    let mut v = Vault::new();
    v.entries.insert(key(1), unclaimed("Acme", Some(365)));
    v.save(&path).expect("the first save works");

    // The debris a crashed predecessor leaves behind — both the name the old
    // implementation used and the shape the new one uses, so neither can
    // collide by accident.
    let stale_old = dir.join(format!("vault.json.tmp.{}", std::process::id()));
    let stale_new = dir.join(format!("vault.json.tmp.{}.0", std::process::id()));
    std::fs::write(&stale_old, b"leftovers from a crash").expect("write");
    std::fs::write(&stale_new, b"leftovers from a crash").expect("write");

    v.save(&path)
        .expect("a stale temp file must not block a save");

    // Through the counter: claims are served, not refused, and the health
    // check and the service now agree — which was the whole point.
    let mut counter = counter_for(v, &path);
    for attempt in 0..5 {
        let (status, body) = counter.handle("POST", CLAIM_PATH, &claim_body(&wire(1), &fp(1)), NOW);
        // Only the first claim can succeed; the seat is single-use, so the
        // rest are refused on *business* grounds, never on persistence.
        if attempt == 0 {
            assert_eq!(status, 200, "attempt {attempt}: {body}");
        } else {
            assert_ne!(
                status, 500,
                "attempt {attempt} hit a persistence failure: {body}"
            );
        }
        assert!(
            !body.contains("nothing was issued"),
            "attempt {attempt}: a persistence failure resurfaced: {body}"
        );
        assert_eq!(counter.handle("GET", "/healthz", "", NOW).0, 200);
    }
    println!("[§9] two stale temp files: the first claim is served 200, none refused 500");

    // The guard is armed only on the file this call created, so a stranger's
    // debris survives untouched. Deleting it would be a different bug.
    assert!(
        stale_old.exists(),
        "the guard unlinked a file it did not create"
    );
    assert!(
        stale_new.exists(),
        "the guard unlinked a file it did not create"
    );

    // …and no debris of the successful saves is left beside them.
    let temps: Vec<String> = std::fs::read_dir(&dir)
        .expect("readdir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp."))
        .collect();
    assert_eq!(temps.len(), 2, "a successful save left debris: {temps:?}");

    // The on-disk ledger and the in-memory one agree.
    let on_disk = Vault::load(&path).expect("load");
    assert_eq!(on_disk.entries[&key(1)].status, Status::Claimed);
    assert_eq!(
        on_disk.entries[&key(1)].machine.as_deref(),
        Some(fp(1).as_str())
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// **DEFECT 3, the sharp edge — REPAIRED IN CORE, GUARDED HERE.**
///
/// `write_durable` did not clean up its own temp file when the rename failed.
/// So the *first* failure — whatever caused it, however transient —
/// manufactured the debris that guaranteed the second, third and every
/// subsequent failure. A full disk that cleared itself, or a vault path that
/// was briefly wrong, did not heal: it latched, for the life of the process.
///
/// The `Drop` guard now unlinks the temp on every early return, including
/// unwinding. This test keeps the identical transient-failure injection and
/// asserts recovery instead of latching: the failure is reported once, leaves
/// nothing behind, and the very next save succeeds once the real cause is
/// gone.
#[test]
fn a_transient_save_failure_no_longer_latches() {
    let dir = scratch("latch");
    // A path that cannot be renamed onto: rename(file, dir) is EISDIR. Stands
    // in for any one-off write failure — ENOSPC, EROFS, EACCES, a crash. It
    // fails *after* the temp file has been created, written and fsynced, which
    // is precisely the window the debris used to appear in.
    let path = dir.join("vault.json");
    std::fs::create_dir(&path).expect("the vault path is briefly a directory");

    let mut v = Vault::new();
    v.entries.insert(key(1), unclaimed("Acme", Some(365)));
    let first = v.save(&path).expect_err("the transient failure");
    assert_ne!(
        first.kind(),
        std::io::ErrorKind::AlreadyExists,
        "the FIRST failure is the real cause: {first}"
    );

    // THE REPAIR: the failed save cleaned up after itself. Nothing in the
    // directory carries a temp suffix, so there is no latch to inherit.
    let debris: Vec<String> = std::fs::read_dir(&dir)
        .expect("readdir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp."))
        .collect();
    assert!(
        debris.is_empty(),
        "the failed save left its temp file behind — that is the latch: {debris:?}"
    );

    // Repeat it: three more failures must not accumulate debris either, and
    // each must still report the real cause rather than `AlreadyExists`.
    for attempt in 0..3 {
        let again = v.save(&path).expect_err("the cause is still there");
        assert_ne!(
            again.kind(),
            std::io::ErrorKind::AlreadyExists,
            "attempt {attempt} reported debris instead of the cause: {again}"
        );
    }

    // The cause is now gone, and so is the failure.
    std::fs::remove_dir(&path).expect("the operator fixes the real problem");
    v.save(&path)
        .expect("a transient failure must not outlive its cause");
    let on_disk = Vault::load(&path).expect("load");
    assert_eq!(on_disk.entries.len(), 1, "and the ledger was written");
    println!("[§9] one transient EISDIR x4: no debris, and the next save succeeds");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A failed persist must not leak a token and must not leave the ledger in a
/// state the in-memory one disagrees with. The property is unchanged; the way
/// this test *forces* the failure had to change.
///
/// It used to plant a stale `vault.json.tmp.<pid>` and rely on the wedge above
/// to make the save fail. Core's repair means that no longer fails at all, so
/// the test was passing for a reason that had evaporated. Failure is now
/// injected with EISDIR at the rename — the deepest failure point, after the
/// temp has been created, written and fsynced, which is the one that used to
/// leave debris and is the only one worth testing the rollback against.
#[test]
fn a_failed_save_never_discloses_a_token_and_never_corrupts_the_file() {
    let dir = scratch("nodisclose");
    let path = dir.join("vault.json");
    let mut v = Vault::new();
    v.entries.insert(key(1), unclaimed("Acme", Some(365)));
    v.entries.insert(key(2), unclaimed("Beta", Some(365)));

    // A directory where the ledger belongs: every save fails at the rename.
    std::fs::create_dir(&path).expect("the vault path is a directory");

    let mut counter = counter_for(v, &path);
    let (status, body) = counter.handle("POST", CLAIM_PATH, &claim_body(&wire(1), &fp(1)), NOW);
    assert_eq!(status, 500, "{body}");
    assert!(
        !body.contains("token"),
        "a token leaked out of a failed persist: {body}"
    );
    assert!(serde_json::from_str::<ClaimOk>(&body).is_err());

    // The in-memory flip is rolled back, so memory and disk still agree: the
    // seat is sellable in both, and nobody was charged for a licence that was
    // never recorded.
    assert_eq!(
        counter.vault.entries[&key(1)].status,
        Status::Unclaimed,
        "the flip must be rolled back when the persist fails"
    );
    assert!(counter.vault.entries[&key(1)].machine.is_none());

    // Nothing was written anywhere: no ledger, and no temp debris to latch on.
    assert!(path.is_dir(), "the failed save replaced the target");
    let leftovers: Vec<String> = std::fs::read_dir(&dir)
        .expect("readdir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != "vault.json")
        .collect();
    assert!(
        leftovers.is_empty(),
        "a failed persist left files behind: {leftovers:?}"
    );

    // And once the cause is removed the same request succeeds, writing a
    // ledger that matches memory exactly — the rollback lost nothing.
    std::fs::remove_dir(&path).expect("the operator fixes the real problem");
    let (status, body) = counter.handle("POST", CLAIM_PATH, &claim_body(&wire(1), &fp(1)), NOW);
    assert_eq!(status, 200, "{body}");
    let on_disk = Vault::load(&path).expect("load");
    // `Entry` does not implement `PartialEq`, so compare the fields that carry
    // the claim: who owns the seat, and on which machine.
    assert_eq!(
        on_disk.entries.keys().collect::<Vec<_>>(),
        counter.vault.entries.keys().collect::<Vec<_>>()
    );
    for (k, disk) in &on_disk.entries {
        let mem = &counter.vault.entries[k];
        assert_eq!(disk.status, mem.status, "{k}: status drifted from memory");
        assert_eq!(disk.machine, mem.machine, "{k}: owner drifted from memory");
    }
    assert_eq!(on_disk.entries[&key(1)].status, Status::Claimed);
    assert_eq!(
        on_disk.entries[&key(2)].status,
        Status::Unclaimed,
        "the untouched seat is still sellable"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ═════════════════════════════════════════════════════════════════════
// §10  Size asymmetry: 4 KiB in, megabytes out
// ═════════════════════════════════════════════════════════════════════

/// **DEFECT 10 — STILL OPEN.** The request side is capped at
/// `MAX_BODY = 4 KiB`. The response side is capped at nothing: a licensee
/// string is copied verbatim into the signed payload, so a 1 MiB name — which
/// nothing rejects when the vendor types it — becomes a ~1.4 MB single-line
/// HTTP response, after being buffered twice by `save`. The allocation printed
/// below rose from 16.4 MB to ~18 531 434 B when `handle_claim` gained its
/// `refresh_vault()` call: this counter starts with `vault_seen: None`, so the
/// one claim it serves re-reads the 1 MiB ledger before signing. The
/// asymmetry the test is about is unchanged.
#[test]
fn a_megabyte_licensee_is_signed_whole_and_returned_over_the_wire() {
    let dir = scratch("megabyte");
    let path = dir.join("vault.json");

    let name = "L".repeat(1 << 20);
    let mut v = Vault::new();
    v.entries.insert(key(1), unclaimed(&name, Some(365)));
    v.save(&path)
        .expect("a 1 MiB licensee persists without complaint");
    let seeded = std::fs::metadata(&path).expect("stat").len();
    assert!(seeded > (1 << 20));

    let mut counter = counter_for(Vault::load(&path).expect("load"), &path);
    let request = claim_body(&wire(1), &fp(1));
    assert!(request.len() < 4096, "the request itself is tiny");

    let ((status, body), alloc) =
        allocated_by(|| counter.handle("POST", CLAIM_PATH, &request, NOW));
    assert_eq!(status, 200);
    let ok: ClaimOk = serde_json::from_str(&body).expect("a token came back");
    assert!(
        ok.token.len() > 1_300_000,
        "token is {} B — expected >1.3 MB",
        ok.token.len()
    );
    println!(
        "[§10] request {req} B -> response {resp} B ({ratio}x), {alloc} B allocated; \
         MAX_BODY caps the request at 4096 B and nothing caps the response",
        req = request.len(),
        resp = body.len(),
        ratio = body.len() / request.len(),
        alloc = alloc,
    );
    assert!(
        body.len() / request.len() > 7_000,
        "the asymmetry is the finding"
    );

    // It is a genuine signed token, not a truncated one — the licensee
    // survives byte for byte into the signed payload.
    let payload = verified_payload(&ok.token);
    assert_eq!(payload["licensee"].as_str(), Some(name.as_str()));
    assert_eq!(payload["exp"].as_u64(), Some(NOW + 365 * DAY));

    // A 1 MiB label (never signed, purely a vendor note) costs the same on
    // every subsequent save, forever.
    let mut v = Vault::new();
    let mut e = unclaimed("Acme", Some(365));
    e.label = Some("N".repeat(1 << 20));
    v.entries.insert(key(2), e);
    let p2 = dir.join("label.json");
    v.save(&p2).expect("save");
    assert!(std::fs::metadata(&p2).expect("stat").len() > (1 << 20));

    let _ = std::fs::remove_dir_all(&dir);
}

// ═════════════════════════════════════════════════════════════════════
// §11  A last sweep of the pure API's trust assumptions
// ═════════════════════════════════════════════════════════════════════

#[test]
fn the_pure_claim_api_validates_nothing_about_its_arguments() {
    let mut v = Vault::new();
    v.entries.insert(key(1), unclaimed("Acme", Some(365)));

    // `claim` hashes whatever it is given; only `Counter::handle` checks the
    // wire shape. Garbage is safely an unknown code — but only because
    // `vault_key` of garbage cannot collide with a real key, not because
    // anything validated it.
    for junk in [
        "",
        "not a hash",
        &"F".repeat(64), // uppercase hex: is_sha256_hex would refuse it
        &"\u{0}".repeat(64),
        &"\u{1F680}".repeat(64),
        &"a".repeat(1 << 16),
    ] {
        assert_eq!(
            v.claim(junk, &fp(1), NOW),
            Err(Refusal::UnknownCode),
            "unexpected acceptance of {:?}",
            &junk[..junk.len().min(24)]
        );
    }
    assert_eq!(
        v.entries[&key(1)].status,
        Status::Unclaimed,
        "still sellable"
    );

    // An empty vault refuses everything; a `Vault::new()` is not a wildcard.
    let mut empty = Vault::new();
    assert_eq!(empty.schema, VAULT_SCHEMA);
    assert_eq!(
        empty.claim(&wire(1), &fp(1), NOW),
        Err(Refusal::UnknownCode)
    );

    // now = 0 and now = u64::MAX are both accepted without arithmetic upset.
    let mut v = Vault::new();
    v.entries.insert(key(2), unclaimed("Acme", Some(365)));
    assert_eq!(v.claim(&wire(2), &fp(1), 0).unwrap().1, Some(365 * DAY));
    let mut v = Vault::new();
    v.entries.insert(key(3), unclaimed("Acme", Some(365)));
    assert_eq!(
        v.claim(&wire(3), &fp(1), u64::MAX).unwrap().1,
        Some(u64::MAX)
    );
}

/// The vendor's only documented recovery lever ("contact the vendor to
/// re-arm it") is flipping `status` back to `Unclaimed` by hand. It works —
/// and, importantly, it does not leak the previous owner into the new seat.
/// The owner comparison is a plain byte equality, so it folds no case and
/// trims no whitespace: near-miss fingerprints are refused, which is right.
#[test]
fn a_re_armed_code_forgets_its_previous_owner_and_the_owner_check_is_exact() {
    let mut v = Vault::new();
    v.entries.insert(key(1), unclaimed("Acme", Some(365)));
    assert!(v.claim(&wire(1), &fp(1), NOW).is_ok());

    // Near misses on the owner are all SeatTaken, not re-issues.
    let owner = fp(1);
    for near in [
        owner.to_uppercase(),
        format!(" {owner}"),
        format!("{owner} "),
        format!("{owner}\n"),
        owner[..63].to_string(),
        format!("{owner}0"),
    ] {
        assert_eq!(
            v.claim(&wire(1), &near, NOW + 1),
            Err(Refusal::SeatTaken),
            "a near-miss fingerprint was accepted as the owner"
        );
    }

    // The minimal hand edit — flip the status, leave the stale owner and
    // expiry in place — is now refused rather than sold. It produced a state
    // the claim machine cannot reach, and a state nothing downstream reasons
    // about correctly: an "unclaimed" seat that already names an owner.
    v.entries.get_mut(&key(1)).expect("entry").status = Status::Unclaimed;
    let got = v.claim(&wire(1), &fp(2), NOW + 10 * DAY);
    assert!(
        matches!(got, Err(Refusal::Unserviceable(_))),
        "a half re-arm must not sell the seat: {got:?}"
    );

    // The vendor's actual `rearm` clears all three fields, which is what makes
    // the entry serviceable again — the CLI's thoroughness is load-bearing,
    // and this is where that is asserted.
    {
        let e = v.entries.get_mut(&key(1)).expect("entry");
        e.status = Status::Unclaimed;
        e.claimed_unix = None;
        e.exp_unix = None;
        e.machine = None;
    }
    let (_, exp) = v
        .claim(&wire(1), &fp(2), NOW + 10 * DAY)
        .expect("re-armed and sold again");
    let e = &v.entries[&key(1)];
    assert_eq!(e.machine.as_deref(), Some(fp(2).as_str()), "new owner only");
    assert_eq!(
        exp,
        Some(NOW + 10 * DAY + 365 * DAY),
        "the expiry is recomputed from `days`, not inherited"
    );
    assert_eq!(e.claimed_unix, Some(NOW + 10 * DAY));
    assert_eq!(
        v.claim(&wire(1), &fp(1), NOW + 11 * DAY),
        Err(Refusal::SeatTaken),
        "the previous owner is now locked out, as it must be"
    );
}

#[test]
fn an_empty_and_a_one_entry_vault_still_round_trip() {
    let dir = scratch("tiny");
    let p = dir.join("v.json");

    let empty = Vault::new();
    empty.save(&p).expect("save");
    let back = Vault::load(&p).expect("load");
    assert!(back.entries.is_empty());
    assert_eq!(back.schema, VAULT_SCHEMA);

    let mut one = Vault::new();
    let mut e = unclaimed("Acme", None);
    e.label = None;
    one.entries.insert(key(1), e);
    one.save(&p).expect("save");
    let text = std::fs::read_to_string(&p).expect("read");
    // The skip_serializing_if fields really are absent, and `days` really is
    // not — that asymmetry is what §5's "missing days" case trips over.
    assert!(!text.contains("label"), "None label is omitted");
    assert!(!text.contains("machine"), "None machine is omitted");
    assert!(
        text.contains("\"days\": null"),
        "None days is written as null"
    );
    assert!(text.ends_with("}\n"), "the file ends with a newline");

    let back = Vault::load(&p).expect("load");
    assert_entry_eq(&one.entries[&key(1)], &back.entries[&key(1)], "one entry");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A `BTreeMap` keyed by hex strings: 100 000 entries retain a measurable,
/// unbounded amount of memory, and nothing anywhere refuses the 100 001st.
#[test]
fn the_ledger_is_unbounded_and_costs_what_it_costs_in_ram() {
    let mut measured = Vec::new();
    for n in [10_000u32, 100_000] {
        let (v, alloc) = allocated_by(|| synthetic_vault(n));
        assert_eq!(v.entries.len() as u32, n);
        measured.push((n, alloc));
        println!(
            "[§8] {n:>6} entries retained via {alloc} B of allocation ({per} B/entry)",
            per = alloc / u64::from(n)
        );
        drop(v);
    }
    let per_small = measured[0].1 / u64::from(measured[0].0);
    let per_large = measured[1].1 / u64::from(measured[1].0);
    // Linear, not quadratic — the map itself is honest. The finding is that
    // it has no ceiling, not that it grows badly.
    assert!(
        per_large <= per_small * 2,
        "per-entry cost grew from {per_small} to {per_large} B — worse than linear"
    );
}
