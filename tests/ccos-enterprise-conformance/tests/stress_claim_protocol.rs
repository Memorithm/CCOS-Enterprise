//! # Hostile fuzz of the license **claim protocol**
//!
//! `ccos_enterprise_governance::claim` is the shared half of the one-time
//! license claim: the vendor mints a 100-bit claim code, the customer types it
//! back, and the primitives here turn operator keystrokes into the two hashes
//! the protocol actually moves (`code_hash` on the wire, `vault_key` in the
//! vault). Everything downstream — the counter's single-seat flip, the signed
//! token, `ccos-license-admin revoke` — trusts `canonical_code` to be the
//! total, panic-free parser its doc comment promises:
//!
//! > `None` when the input is not a claim code (wrong length, symbol outside
//! > the alphabet).
//!
//! This file attacks that promise with a deterministic fuzzer (fixed seeds, no
//! wall clock in any assertion) plus an exhaustive Unicode sweep.
//!
//! ## VERDICT: the parser is total and sound again; four findings stay open.
//!
//! Two of the six findings below have been **repaired** in
//! `crates/ccos-enterprise-governance/src/claim.rs`. The tests that proved
//! them are kept verbatim in their inputs and inverted in their expectations,
//! so they now guard the repair instead of pinning the defect. The other four
//! are still the product's real, current behaviour.
//!
//! ### What was repaired
//!
//! * **CLAIM-1 (critical) — `canonical_code` used to PANIC on hostile input.**
//!   `claim.rs` slices the accumulated symbol buffer by *byte* index
//!   (`&body[0..5]`, `[5..10]`, `[10..15]`, `[15..20]`), and the alphabet
//!   filter used to let multi-byte characters through (CLAIM-2). When such a
//!   character straddled byte 5, 10 or 15 the slice was not on a `char`
//!   boundary and `canonical_code` panicked instead of returning `None`:
//!   `canonical_code("CCOS-AAAAа-AAAA-AAAAA-AAAAA")` (Cyrillic `а`, U+0430) →
//!   `byte index 5 is not a char boundary`. It was reachable in-tree from
//!   `tools/ccos-license-server/src/bin/ccos-license-admin.rs:297`, i.e. from
//!   `ccos-license-admin revoke <CODE>` — the vendor's incident-response path.
//!   An attacker-supplied "please revoke my code" string crashed the revoke
//!   instead of refusing it, and the leaked code stayed live. The guard now
//!   refuses non-ASCII outright, so nothing multi-byte ever reaches the
//!   slicing. Guarded by
//!   [`canonical_code_no_longer_panics_when_a_multibyte_symbol_straddles_a_group_boundary`],
//!   which keeps every input that used to abort the test binary — including
//!   the Cyrillic paste above — and asserts `None`.
//!
//! * **CLAIM-2 (high) — the alphabet filter used to validate a *truncated*
//!   cast.** The test was `ALPHABET.contains(&(c as u8))` alone. `char as u8`
//!   keeps only the low byte, so **138 976** non-ASCII code points were
//!   accepted as Crockford symbols — exactly those whose code point mod 256
//!   lands in the alphabet (verified exhaustively over all of Unicode, zero
//!   deviation from that model). `symbols.push(c)` then stored the *original*
//!   character, so `canonical_code` returned `Some` values that were not claim
//!   codes at all: `canonical_code("аAAAAAAAAAAAAAAAAAAA")` →
//!   `Some("CCOS-аAAA-AAAAA-AAAAA-AAAAA")` — 27 chars, a four-symbol group,
//!   and a symbol outside the alphabet the function exists to enforce. The
//!   guard is now `!c.is_ascii() || !ALPHABET.contains(&(c as u8))`, so all
//!   138 976 yield `None`. Guarded, still exhaustively over Unicode, by
//!   [`canonical_code_refuses_the_138976_non_ascii_code_points_the_truncating_cast_accepted`].
//!
//! ### What is still BROKEN
//!
//! * **CLAIM-3 (medium) — `code_from_entropy` silently discards 28 of the 128
//!   bits it is handed.** Bytes 13..16 and the low nibble of byte 12 never
//!   reach the code. The 100-bit width is documented; the *silent* truncation
//!   of a `&[u8; 16]` argument is not. A vendor that varies the tail of the
//!   buffer (a counter appended after a per-batch prefix, say) mints one
//!   thousand identical codes from one thousand distinct entropies. Pinned by
//!   [`code_from_entropy_silently_discards_28_of_the_128_entropy_bits`].
//!
//! * **CLAIM-4 (medium) — a bare payload beginning with `CC0S` is rejected.**
//!   `claim.rs:125` strips one leading `CC0S` *after* folding and *before* the
//!   length check, so the ~1-in-2^20 minted code whose first four payload
//!   symbols are `C C 0 S` is the only code that cannot be entered without its
//!   branding prefix. Pinned by
//!   [`canonical_code_rejects_a_bare_payload_that_begins_with_the_branding_prefix`].
//!
//! * **CLAIM-5 (low) — `"CCOS-"` repeated six times is a valid claim code**
//!   (`Some("CCOS-CC0SC-C0SCC-0SCC0-SCC0S")`): branding past the first
//!   occurrence is payload. Pinned by
//!   [`canonical_code_accepts_the_branding_prefix_repeated_six_times`].
//!
//! * **CLAIM-6 (low) — the trailing newline every paste carries is fatal.**
//!   ` `, `\t`, `_` and `-` are skipped anywhere; `\n` and `\r` are not, so
//!   `canonical_code("CCOS-…-AAAAA\n")` is `None`. Pinned by
//!   [`canonical_code_rejects_the_trailing_newline_that_every_paste_carries`].
//!
//! Everything asserted below is the product's **current, real** behaviour.
//! Where that behaviour is still a defect the assertion pins the defect and
//! the comment names it, so a repair fails loudly here instead of silently
//! changing the protocol. Where a defect was repaired the assertion pins the
//! *repair*, on the same inputs, so a regression fails just as loudly.

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Instant;

use ccos_enterprise_governance::claim::{
    canonical_code, code_from_entropy, code_hash, is_sha256_hex, machine_fingerprint_of, vault_key,
    CLAIM_SCHEMA,
};
use ccos_license_server::{Entry, Refusal as VaultRefusal, Status, Vault};

// ─────────────────────────────────────────────────────────────────────────
// Harness — deterministic everything.
// ─────────────────────────────────────────────────────────────────────────

/// The Crockford alphabet the module documents: no `I`, `L`, `O`, `U`.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The canonical display form: `CCOS-` + four groups of five.
const CANONICAL_LEN: usize = 28;

/// SplitMix64 — a bijection of its state, so distinct draws are guaranteed
/// distinct. Fixed seed at every call site; identical in debug and release.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    fn entropy(&mut self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.next_u64().to_le_bytes());
        out[8..].copy_from_slice(&self.next_u64().to_le_bytes());
        out
    }
}

/// The 100 bits of a `[u8; 16]` that `code_from_entropy` actually consumes:
/// bytes 0..12 whole, plus the *high* nibble of byte 12. Everything else is
/// discarded — see CLAIM-3.
fn consumed_bits(entropy: &[u8; 16]) -> [u8; 13] {
    let mut used = [0u8; 13];
    used[..12].copy_from_slice(&entropy[..12]);
    used[12] = entropy[12] & 0xF0;
    used
}

fn is_symbol(c: char) -> bool {
    c.is_ascii() && ALPHABET.contains(&(c as u8))
}

/// The shape the whole protocol assumes of a canonical code.
fn assert_canonical_shape(code: &str, provenance: &str) {
    assert_eq!(
        code.len(),
        CANONICAL_LEN,
        "{provenance}: {code:?} is not {CANONICAL_LEN} bytes"
    );
    assert_eq!(
        code.chars().count(),
        CANONICAL_LEN,
        "{provenance}: {code:?} is not {CANONICAL_LEN} characters"
    );
    assert!(
        code.starts_with("CCOS-"),
        "{provenance}: {code:?} lost the branding prefix"
    );
    let groups: Vec<&str> = code.split('-').collect();
    assert_eq!(groups.len(), 5, "{provenance}: {code:?} group count");
    assert_eq!(groups[0], "CCOS", "{provenance}: {code:?} prefix");
    for g in &groups[1..] {
        assert_eq!(g.len(), 5, "{provenance}: group {g:?} of {code:?}");
        for c in g.chars() {
            assert!(
                is_symbol(c),
                "{provenance}: symbol {c:?} of {code:?} is outside the Crockford alphabet"
            );
            assert!(
                !matches!(c, 'I' | 'L' | 'O' | 'U'),
                "{provenance}: ambiguous symbol {c:?} in {code:?}"
            );
        }
    }
}

/// `canonical_code` was not total (CLAIM-1): it aborted the process instead of
/// returning `None`. It is total now, but everything that feeds it hostile
/// input still goes through here, so a *regression* is data — a named,
/// localized failure — instead of a dead test binary.
#[derive(Debug, PartialEq, Eq)]
enum Parse {
    Panicked,
    Rejected,
    Accepted,
}

/// Serializes the panic-hook window so a parallel test's genuine failure is
/// not swallowed. Assertions always run *after* the hook is restored.
static HOOK: Mutex<()> = Mutex::new(());

fn probe_all(inputs: &[String]) -> Vec<Parse> {
    let _guard = HOOK.lock().unwrap_or_else(|e| e.into_inner());
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let out = inputs
        .iter()
        .map(
            |s| match std::panic::catch_unwind(|| canonical_code(s.as_str())) {
                Err(_) => Parse::Panicked,
                Ok(None) => Parse::Rejected,
                Ok(Some(_)) => Parse::Accepted,
            },
        )
        .collect();
    std::panic::set_hook(previous);
    out
}

fn probe(input: &str) -> Parse {
    probe_all(&[input.to_string()])
        .pop()
        .expect("one input in, one verdict out")
}

// ─────────────────────────────────────────────────────────────────────────
// 1. code_from_entropy — 100k codes: shape, alphabet, determinism, collisions
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn code_from_entropy_over_100k_entropies_is_well_formed_deterministic_and_collision_free() {
    const N: usize = 100_000;
    let mut rng = Rng(0x0C05_C1A1_0000_0001);
    let mut codes: HashSet<String> = HashSet::with_capacity(N);
    let mut consumed: HashSet<[u8; 13]> = HashSet::with_capacity(N);
    let mut symbol_histogram = [0usize; 32];

    for i in 0..N {
        let entropy = rng.entropy();
        let code = code_from_entropy(&entropy);

        // Format, length and alphabet, on every single sample.
        assert_canonical_shape(&code, "code_from_entropy");

        // Determinism: the vendor's entropy source is the only randomness.
        assert_eq!(
            code,
            code_from_entropy(&entropy),
            "code_from_entropy is not a function of its argument at sample {i}"
        );

        for c in code.chars().skip(5).filter(|c| *c != '-') {
            let idx = ALPHABET
                .iter()
                .position(|b| *b == c as u8)
                .expect("shape check already proved membership");
            symbol_histogram[idx] += 1;
        }

        // Distinct *consumed* bits in, distinct codes out — the property the
        // 100-bit code space is actually sold on.
        assert!(
            consumed.insert(consumed_bits(&entropy)),
            "the sample itself repeated its consumed bits at {i}; the collision \
             check would be vacuous"
        );
        assert!(
            codes.insert(code.clone()),
            "COLLISION at sample {i}: {code} was already minted"
        );
    }

    assert_eq!(codes.len(), N);
    assert_eq!(consumed.len(), N);
    // Every symbol of the alphabet is reachable (no dead symbol, no off-by-one
    // in the 5-bit extraction).
    for (idx, count) in symbol_histogram.iter().enumerate() {
        assert!(
            *count > 0,
            "symbol {:?} never appears in {N} codes",
            ALPHABET[idx] as char
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 2. CLAIM-3 — 28 of the 128 entropy bits are silently discarded
// ─────────────────────────────────────────────────────────────────────────

/// Exhaustive over every discarded bit: bytes 13, 14, 15 and the low nibble of
/// byte 12 have no effect whatsoever on the minted code.
///
/// The 100-bit width is documented ("100 of the 128 bits"); the hazard is that
/// the signature takes `&[u8; 16]` and says nothing about *which* 100, so a
/// caller whose entropy varies in the tail mints duplicates in silence.
#[test]
fn code_from_entropy_silently_discards_28_of_the_128_entropy_bits() {
    let baseline = code_from_entropy(&[0u8; 16]);

    // Bytes 13..16: every value of every byte, all 768 combinations.
    for byte in 13..16usize {
        for value in 0..=u8::MAX {
            let mut entropy = [0u8; 16];
            entropy[byte] = value;
            assert_eq!(
                code_from_entropy(&entropy),
                baseline,
                "entropy byte {byte} = {value} reached the code — CLAIM-3 repaired?"
            );
        }
    }
    // Byte 12: the low nibble is discarded, the high nibble is not.
    for low in 0..16u8 {
        let mut entropy = [0u8; 16];
        entropy[12] = low;
        assert_eq!(
            code_from_entropy(&entropy),
            baseline,
            "the low nibble of entropy byte 12 reached the code"
        );
    }
    for high in 1..16u8 {
        let mut entropy = [0u8; 16];
        entropy[12] = high << 4;
        assert_ne!(
            code_from_entropy(&entropy),
            baseline,
            "the high nibble of entropy byte 12 must reach the code"
        );
    }

    // The operational shape of the hazard: a mint loop that appends a
    // big-endian counter to the tail of the buffer produces ONE code for a
    // thousand distinct entropies.
    let mut minted = HashSet::new();
    for n in 0u32..1_000 {
        let mut entropy = [0u8; 16];
        entropy[12..].copy_from_slice(&n.to_be_bytes());
        minted.insert(code_from_entropy(&entropy));
    }
    assert_eq!(
        minted.len(),
        1,
        "CLAIM-3: 1000 distinct entropies collapsed to {} code(s) — pinned at 1",
        minted.len()
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 3. canonical_code — round-trip under hostile typography
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn canonical_code_round_trips_every_generated_code_through_hostile_typography() {
    const N: usize = 50_000;
    let mut rng = Rng(0xDEAD_BEEF_CAFE_0001);
    let mut bare_rejected = 0usize;

    for i in 0..N {
        let code = code_from_entropy(&rng.entropy());
        let payload: String = code.chars().skip(5).filter(|c| *c != '-').collect();
        assert_eq!(payload.len(), 20);

        // Identity — the canonical form is a fixed point.
        assert_eq!(
            canonical_code(&code).as_deref(),
            Some(code.as_str()),
            "sample {i}: canonical form is not a fixed point"
        );

        let sprinkled = {
            let mut s = String::new();
            for c in code.chars() {
                if rng.next_u64() & 1 == 0 {
                    s.push(c.to_ascii_lowercase());
                } else {
                    s.push(c);
                }
                if rng.below(5) == 0 {
                    s.push(['-', ' ', '_', '\t'][rng.below(4)]);
                }
            }
            s
        };
        let variants = [
            code.to_lowercase(),
            code.replace('-', ""),
            code.replace('-', " "),
            code.replace('-', "\t"),
            code.replace('-', "_"),
            code.replace('-', "  \t_ "),
            // Crockford confusions, folded back on the way in.
            code.replace('0', "O").replace('1', "l"),
            code.replace('0', "o").replace('1', "I").to_lowercase(),
            code.replace('0', "O").replace('1', "L").replace('-', ""),
            sprinkled,
        ];
        for variant in &variants {
            assert_eq!(
                canonical_code(variant).as_deref(),
                Some(code.as_str()),
                "sample {i}: variant {variant:?} did not canonicalize back"
            );
        }

        // The bare payload, with the branding prefix dropped, is accepted —
        // EXCEPT for the CLAIM-4 case, which this sweep keeps honest.
        match canonical_code(&payload) {
            Some(round) => assert_eq!(round, code, "sample {i}: bare payload mismatch"),
            None => {
                assert!(
                    payload.starts_with("CC0S"),
                    "sample {i}: bare payload {payload:?} rejected for a new reason"
                );
                bare_rejected += 1;
            }
        }

        // Canonicalization is load-bearing: hashing raw operator input sends
        // the counter a value it has never seen.
        assert_ne!(
            code_hash(&code),
            code_hash(&code.to_lowercase()),
            "sample {i}: code_hash folds case, so canonicalization is optional"
        );
    }
    // Expected 0 by probability (~0.02 hits over 20k draws); asserted so a
    // regression that starts rejecting ordinary payloads is loud.
    assert_eq!(bare_rejected, 0, "CLAIM-4 fired inside the random sweep");
}

// ─────────────────────────────────────────────────────────────────────────
// 4. canonical_code — hand-built hostile corpus
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn canonical_code_hostile_ascii_corpus() {
    let valid = "CCOS-AAAAA-AAAAA-AAAAA-AAAAA";
    let payload = "AAAAAAAAAAAAAAAAAAAA";

    // ── Refused, as documented ────────────────────────────────────────
    for bad in [
        "",
        " ",
        "-",
        "----------------------------",
        "CCOS-",
        "CCOS-SHORT",
        "CCOS-AAAAA-AAAAA-AAAAA-AAAA",   // 19 symbols
        "CCOS-AAAAA-AAAAA-AAAAA-AAAAAA", // 21 symbols
        "AAAAAAAAAAAAAAAAAAA",           // bare 19
        "AAAAAAAAAAAAAAAAAAAAA",         // bare 21
        "CCOS-UUUUU-UUUUU-UUUUU-UUUUU",  // U is outside the alphabet
        "CCOS-uuuuu-uuuuu-uuuuu-uuuuu",
        "CCOS+AAAAA+AAAAA+AAAAA+AAAAA", // '+' is not a separator
        "CCOS.AAAAA.AAAAA.AAAAA.AAAAA",
        "CCOS/AAAAA/AAAAA/AAAAA/AAAAA",
        "CCOS:AAAAA-AAAAA-AAAAA-AAAAA",
        "0xAAAAAAAAAAAAAAAAAAAA",
        "CCOS-AAAAA-AAAAA-AAAAA-AAA A", // ' ' is skipped → 19 symbols
    ] {
        assert_eq!(canonical_code(bad), None, "{bad:?} was accepted");
    }

    // Embedded NUL, anywhere, is not a separator and not a symbol.
    for at in 0..=valid.len() {
        let hostile = format!("{}\0{}", &valid[..at], &valid[at..]);
        assert_eq!(
            canonical_code(&hostile),
            None,
            "embedded NUL at {at} was accepted"
        );
    }

    // ── Accepted, and canonical ───────────────────────────────────────
    for good in [
        valid,
        payload,
        "ccos-aaaaa-aaaaa-aaaaa-aaaaa",
        "CC0S-AAAAA-AAAAA-AAAAA-AAAAA", // the folded prefix spelling
        "cc0saaaaaaaaaaaaaaaaaaaa",
        "\tCCOS AAAAA_AAAAA-AAAAA\tAAAAA ",
    ] {
        let got = canonical_code(good).unwrap_or_else(|| panic!("{good:?} was refused"));
        assert_eq!(got, valid, "{good:?}");
        assert_canonical_shape(&got, "hostile corpus");
    }

    // The branding prefix is only special at position 0 — mid-string `CC0S`
    // is payload, which is correct and worth pinning.
    let mid = format!("AAAAA-CC0S-{}", "A".repeat(11));
    assert_eq!(
        canonical_code(&mid).as_deref(),
        Some("CCOS-AAAAA-CC0SA-AAAAA-AAAAA")
    );
    // …and one prefix, not two: 24 symbols that do not *start* with CC0S are
    // refused even though they contain it.
    assert_eq!(canonical_code(&format!("A-CC0S-{}", "A".repeat(19))), None);

    // Double branding: the second `CCOS` becomes payload.
    assert_eq!(
        canonical_code(&format!("CCOS-CCOS-{}", "A".repeat(16))).as_deref(),
        Some("CCOS-CC0SA-AAAAA-AAAAA-AAAAA")
    );

    // Idempotence of every acceptance above.
    for good in [valid, "CCOS-AAAAA-CC0SA-AAAAA-AAAAA"] {
        assert_eq!(canonical_code(good).as_deref(), Some(good));
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 5. canonical_code — ASCII fuzz against the twenty-symbol contract
// ─────────────────────────────────────────────────────────────────────────

/// 120 000 hostile ASCII inputs. The contract under test, verbatim from the
/// doc comment plus the format the rest of the protocol assumes:
///
/// * `Some(c)` ⇒ `c` is exactly `CCOS-` + four groups of five alphabet
///   symbols, i.e. the input really was exactly 20 valid symbols (optionally
///   behind one `CC0S` prefix, hence 24);
/// * `Some(c)` ⇒ `canonical_code(c) == Some(c)` (idempotent);
/// * a `U`/`u` anywhere ⇒ `None` (not in the alphabet, and not folded);
/// * the function is a pure function of its argument.
///
/// For ASCII this always held. The parser's soundness used to fail only once
/// non-ASCII was in play (CLAIM-1/CLAIM-2) — both repaired, and guarded as
/// such by the next two tests.
#[test]
fn canonical_code_ascii_fuzz_upholds_the_twenty_symbol_contract() {
    const N: usize = 300_000;
    // Alphabet symbols, the four folded confusions, the four separators, and
    // ASCII that must never be a symbol.
    const HOSTILE: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZabcdefghjkmnpqrstvwxyzILOUilou-_ \t\n\r\0/;:.+*'\"\\|,()[]{}<>=?!@#$%^&~`";
    const BODY: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZILOUilou";
    let mut rng = Rng(0x5EED_0000_0BAD_F00D);
    let mut accepted = 0usize;

    let seed_code = code_from_entropy(&[0x5A; 16]);
    let seed_bytes: Vec<u8> = seed_code.bytes().collect();

    for i in 0..N {
        let input = match i % 3 {
            // Pure garbage.
            0 => {
                let len = rng.below(41);
                (0..len)
                    .map(|_| HOSTILE[rng.below(HOSTILE.len())] as char)
                    .collect::<String>()
            }
            // Mutations of a real code — the near-miss band where a parser
            // that guesses instead of refusing would show it.
            1 => {
                let mut bytes = seed_bytes.clone();
                for _ in 0..1 + rng.below(4) {
                    if bytes.is_empty() {
                        break;
                    }
                    let at = rng.below(bytes.len());
                    match rng.below(4) {
                        0 => {
                            bytes.remove(at);
                        }
                        1 => bytes.insert(at, HOSTILE[rng.below(HOSTILE.len())]),
                        2 => bytes[at] = HOSTILE[rng.below(HOSTILE.len())],
                        _ => bytes[at] = bytes[at].to_ascii_lowercase(),
                    }
                }
                String::from_utf8(bytes).expect("HOSTILE is ASCII")
            }
            // Length-targeted: 18..=26 symbols drawn from symbols + folds,
            // with separators sprinkled in.
            _ => {
                let symbols = 18 + rng.below(9);
                let mut s = String::new();
                for _ in 0..symbols {
                    s.push(BODY[rng.below(BODY.len())] as char);
                    if rng.below(6) == 0 {
                        s.push(['-', ' ', '_', '\t'][rng.below(4)]);
                    }
                }
                s
            }
        };

        assert!(input.is_ascii(), "the ASCII fuzz generated non-ASCII");
        let got = canonical_code(&input);
        assert_eq!(
            got,
            canonical_code(&input),
            "canonical_code is not a pure function on {input:?}"
        );

        if input.bytes().any(|b| b == b'U' || b == b'u') {
            assert_eq!(got, None, "{input:?} contains U but was accepted");
        }

        let Some(out) = got else { continue };
        accepted += 1;
        assert_canonical_shape(&out, "ascii fuzz");
        assert_eq!(
            canonical_code(&out).as_deref(),
            Some(out.as_str()),
            "{input:?} → {out:?} is not idempotent"
        );
        // The input really was 20 symbols (or 20 behind one branding prefix).
        let folded: String = input
            .chars()
            .filter(|c| !matches!(c, '-' | ' ' | '_' | '\t'))
            .map(|c| match c.to_ascii_uppercase() {
                'O' => '0',
                'I' | 'L' => '1',
                up => up,
            })
            .collect();
        assert!(
            folded.len() == 20 || folded.len() == 24,
            "{input:?} had {} symbols but produced {out:?}",
            folded.len()
        );
        if folded.len() == 24 {
            assert!(
                folded.starts_with("CC0S"),
                "{input:?} had 24 symbols without the branding prefix"
            );
        }
    }
    println!("ascii fuzz: {accepted} of {N} inputs were accepted");
    assert!(
        accepted >= 5_000,
        "only {accepted} of {N} fuzz inputs were accepted — the corpus stopped \
         reaching the acceptance path, so this test proves nothing"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 6. CLAIM-2 (REPAIRED) — the alphabet filter no longer validates a
//    truncated `char as u8`
// ─────────────────────────────────────────────────────────────────────────

/// Exhaustive over **every** non-ASCII scalar value in Unicode.
///
/// `claim.rs` used to ask `ALPHABET.contains(&(c as u8))` alone. That cast
/// keeps the low byte only, so the accepted set was exactly
/// `{ c : (c as u32) % 256 ∈ ALPHABET }` — 138 976 code points, each of which
/// was then pushed into the symbol buffer *as the original character*, so the
/// function returned values violating its own contract (and, past CLAIM-1,
/// panicked). The guard is now
/// `if !c.is_ascii() || !ALPHABET.contains(&(c as u8)) { return None }`.
///
/// The sweep is unchanged — same corpus, same framing (each character placed
/// first in a 20-byte buffer, where a leading multi-byte character cannot
/// straddle byte 5, so acceptance was measurable without tripping CLAIM-1) —
/// with the opposite expectation: **nothing** non-ASCII is accepted. The
/// low-byte model is still computed and still asserted to describe 138 976
/// code points, so the corpus cannot quietly stop exercising the vector this
/// test guards.
#[test]
fn canonical_code_refuses_the_138976_non_ascii_code_points_the_truncating_cast_accepted() {
    let mut accepted = 0usize;
    let mut first_accepted: Option<u32> = None;
    let mut once_accepted = 0usize;
    for cp in 0x80u32..=0x10_FFFF {
        let Some(c) = char::from_u32(cp) else {
            continue;
        };
        let input = format!("{c}{}", "A".repeat(20 - c.len_utf8()));
        assert_eq!(input.len(), 20);

        if canonical_code(&input).is_some() {
            accepted += 1;
            first_accepted.get_or_insert(cp);
        }
        if ALPHABET.contains(&(cp as u8)) {
            once_accepted += 1;
        }
    }
    assert_eq!(
        once_accepted, 138_976,
        "the low-byte model no longer describes 138 976 code points — this \
         sweep has stopped covering the vector it exists to guard"
    );
    assert_eq!(
        accepted,
        0,
        "CLAIM-2: the Crockford filter accepts non-ASCII code points again — \
         {accepted} of them, first U+{:04X}",
        first_accepted.unwrap_or(0)
    );

    // The concrete consequence, gone: this input used to yield a "canonical
    // code" 27 characters long, with a four-symbol group, carrying a character
    // the function exists to reject — `Some("CCOS-аAAA-AAAAA-AAAAA-AAAAA")`.
    // Cyrillic а (U+0430) → low byte 0x30 = ASCII '0'.
    let cyrillic = format!("\u{0430}{}", "A".repeat(18));
    assert_eq!(
        canonical_code(&cyrillic),
        None,
        "CLAIM-2: the Cyrillic homoglyph is a Crockford symbol again"
    );
    // And the malformed string the defect used to emit is not even accepted as
    // *input*, so a value stored while the defect was live cannot round-trip
    // back into the protocol.
    let once_emitted = "CCOS-\u{0430}AAA-AAAAA-AAAAA-AAAAA";
    assert_eq!(
        once_emitted.chars().count(),
        27,
        "the historical shape: 27 chars"
    );
    assert!(
        once_emitted.chars().any(|c| !is_symbol(c) && c != '-'),
        "the historical shape carried a non-alphabet symbol"
    );
    assert_eq!(
        canonical_code(once_emitted),
        None,
        "CLAIM-2: the malformed canonical form is accepted as input again"
    );

    // A representative sample of the lookalikes an operator can actually
    // produce: each used to be accepted exactly where the ASCII symbol it
    // imitates would be. Every one of them is refused now.
    for (c, low) in [
        ('\u{0430}', '0'),   // CYRILLIC SMALL A
        ('\u{0435}', '5'),   // CYRILLIC SMALL IE
        ('\u{0441}', 'A'),   // CYRILLIC SMALL ES
        ('\u{0130}', '0'),   // LATIN CAPITAL I WITH DOT ABOVE
        ('\u{2030}', '0'),   // PER MILLE SIGN (3 bytes)
        ('\u{1_0330}', '0'), // GOTHIC LETTER AHSA (4 bytes)
    ] {
        assert!(
            ALPHABET.contains(&(low as u8)),
            "test vector {c:?} maps to {low:?}"
        );
        let input = format!("{c}{}", "A".repeat(20 - c.len_utf8()));
        assert_eq!(
            canonical_code(&input),
            None,
            "lookalike {c:?} (U+{:04X}) was accepted as {low:?}",
            c as u32
        );
    }

    // The operational damage, closed: a homograph substitution used to be
    // *accepted* and *hashed*, so the customer's failure surfaced at the
    // counter as `UnknownCode` — indistinguishable from a revoked or
    // fabricated code — instead of at the parser as "that is not a claim
    // code". The ASCII spelling still parses and still hashes; the Cyrillic
    // one that renders nearly identically now produces no wire value at all,
    // so there is no second, equally-valid-looking hash to confuse with it.
    let ascii_code = canonical_code(&"0".repeat(20)).expect("all-zero payload is valid");
    assert_eq!(ascii_code, "CCOS-00000-00000-00000-00000");
    assert!(is_sha256_hex(&code_hash(&ascii_code)));
    assert!(is_sha256_hex(&vault_key(&code_hash(&ascii_code))));
    assert_eq!(
        canonical_code(&format!("\u{0430}{}", "0".repeat(18))),
        None,
        "CLAIM-2: the Cyrillic spelling of an all-zero payload is accepted again"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 7. CLAIM-1 (REPAIRED) — canonical_code returns None instead of panicking
// ─────────────────────────────────────────────────────────────────────────

/// `claim.rs` slices `body` at byte offsets 5, 10 and 15. While CLAIM-2 let
/// multi-byte characters into `body`, any character whose UTF-8 span
/// *strictly contained* one of those offsets made the slice land inside a
/// character, and `canonical_code` panicked — `byte index 5 is not a char
/// boundary` — instead of returning the `None` its doc comment promises. It
/// was reachable in-tree: `ccos-license-admin.rs:297` hands raw argv to
/// `canonical_code`, so `ccos-license-admin --vault v.json revoke '<string>'`
/// aborted the revoke on an attacker-supplied string instead of refusing it,
/// and the leaked code stayed live.
///
/// The guard now refuses non-ASCII before any symbol is buffered, so nothing
/// multi-byte ever reaches the slicing. The corpus here is unchanged —
/// exhaustive over insertion position for a 2-, 3- and 4-byte formerly
/// accepted character, in both the bare-payload and branded framings — and the
/// expectation is inverted: **no** position panics, and every position is
/// *rejected*, so the totality is not being bought by returning a malformed
/// `Some`. The once-fatal positions are still derived from the model
/// `pos < k < pos + width` for `k ∈ {5, 10, 15}` and asserted non-empty, so
/// the corpus cannot silently stop covering the straddling case.
#[test]
fn canonical_code_no_longer_panics_when_a_multibyte_symbol_straddles_a_group_boundary() {
    let boundaries = [5usize, 10, 15];
    for c in ['\u{0430}', '\u{0130}', '\u{2030}', '\u{1_0330}'] {
        let width = c.len_utf8();
        let last = 20 - width;

        // Bare payload: exactly 20 bytes of once-accepted symbols.
        let bare: Vec<String> = (0..=last)
            .map(|pos| format!("{}{c}{}", "A".repeat(pos), "A".repeat(last - pos)))
            .collect();
        // Branded: `CCOS-` + 20 bytes, i.e. 24 symbol bytes, one prefix stripped.
        let branded: Vec<String> = (0..=last)
            .map(|pos| format!("CCOS-{}{c}{}", "A".repeat(pos), "A".repeat(last - pos)))
            .collect();

        // The positions that aborted the process before the repair.
        let once_fatal: Vec<usize> = (0..=last)
            .filter(|pos| boundaries.iter().any(|k| *pos < *k && *k < pos + width))
            .collect();
        assert!(
            !once_fatal.is_empty(),
            "U+{:04X} ({width} bytes): the corpus no longer contains a position \
             whose character straddles a group boundary — this test would prove \
             nothing",
            c as u32
        );

        for (framing, corpus) in [("bare", &bare), ("branded", &branded)] {
            let verdicts = probe_all(corpus);
            let panicked: Vec<usize> = verdicts
                .iter()
                .enumerate()
                .filter(|(_, v)| **v == Parse::Panicked)
                .map(|(pos, _)| pos)
                .collect();
            assert!(
                panicked.is_empty(),
                "CLAIM-1 ({framing}, U+{:04X}, {width} bytes): canonical_code \
                 panicked again at {panicked:?} — it used to at {once_fatal:?}",
                c as u32
            );
            // Total *and* sound: every position is refused. Never a panic, and
            // never a malformed `Some` carrying a non-alphabet character.
            for (pos, verdict) in verdicts.iter().enumerate() {
                assert_eq!(
                    *verdict,
                    Parse::Rejected,
                    "{framing} U+{:04X} at {pos}: a non-ASCII symbol must be \
                     refused, not accepted and not fatal",
                    c as u32
                );
            }
        }
    }

    // The shape a human actually produces: a pasted code that lost one
    // character and gained one Cyrillic lookalike. The display form still
    // reads like a claim code, and this exact string used to abort the process
    // with `byte index 5 is not a char boundary`.
    assert_eq!(
        probe("CCOS-AAAA\u{0430}-AAAA-AAAAA-AAAAA"),
        Parse::Rejected,
        "CLAIM-1: the realistic pasted-code case must be refused — neither \
         fatal nor accepted"
    );
    // The same string reaching the admin CLI's classifier: not 64-hex, so
    // `ccos-license-admin revoke` still routes it into `canonical_code`, which
    // now refuses it and lets the revoke report a bad code instead of crashing.
    assert!(!is_sha256_hex("CCOS-AAAA\u{0430}-AAAA-AAAAA-AAAAA"));

    // ASCII input, however hostile, never panicked — the vector was exactly
    // the multi-byte one. Kept as the corpus that would catch a *new* one.
    let mut rng = Rng(0x0A11_C0DE_BADD_0001);
    const HOSTILE: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZILOUilou-_ \t\n\0";
    let ascii: Vec<String> = (0..60_000)
        .map(|_| {
            let len = rng.below(33);
            (0..len)
                .map(|_| HOSTILE[rng.below(HOSTILE.len())] as char)
                .collect()
        })
        .collect();
    let panics = probe_all(&ascii)
        .into_iter()
        .filter(|v| *v == Parse::Panicked)
        .count();
    assert_eq!(
        panics, 0,
        "an ASCII input panicked: a second CLAIM-1 vector"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 8. CLAIM-4 / CLAIM-5 / CLAIM-6 — prefix and separator handling
// ─────────────────────────────────────────────────────────────────────────

/// One minted code in ~2^20 has `C C 0 S` as its first four payload symbols.
/// `strip_prefix("CC0S")` runs before the length check and does not care
/// whether a prefix was actually present, so that code — and only that code —
/// cannot be entered in the bare form every other code accepts.
#[test]
fn canonical_code_rejects_a_bare_payload_that_begins_with_the_branding_prefix() {
    let payload = format!("CC0S{}", "A".repeat(16));
    assert_eq!(payload.len(), 20);
    assert!(payload.bytes().all(|b| ALPHABET.contains(&b)));

    // Twenty valid symbols, refused.
    assert_eq!(
        canonical_code(&payload),
        None,
        "CLAIM-4 repaired? A bare 20-symbol payload starting with CC0S is now accepted"
    );
    // The very same code, with its branding prefix, is fine — the asymmetry.
    assert_eq!(
        canonical_code(&format!("CCOS-{payload}")).as_deref(),
        Some("CCOS-CC0SA-AAAAA-AAAAA-AAAAA")
    );

    // And it is reachable: `code_from_entropy` can mint it. 'C' = 12,
    // '0' = 0, 'S' = 25 → the first four 5-bit groups are 12, 12, 0, 25,
    // i.e. the bit stream 01100 01100 00000 11001.
    let mut entropy = [0u8; 16];
    entropy[0] = 0b0110_0011; // 01100 011…
    entropy[1] = 0b0000_0001; // …00 00000 1…
    entropy[2] = 0b1001_0000; // …1001 0000
    let minted = code_from_entropy(&entropy);
    assert!(
        minted.starts_with("CCOS-CC0S"),
        "expected a CC0S payload, got {minted}"
    );
    let minted_payload: String = minted.chars().skip(5).filter(|c| *c != '-').collect();
    assert_eq!(
        canonical_code(&minted_payload),
        None,
        "CLAIM-4: a legitimately minted code is unenterable in bare form"
    );
    assert_eq!(canonical_code(&minted).as_deref(), Some(minted.as_str()));
}

/// The branding prefix is stripped once and positionally; the other five
/// copies are payload, so pure branding parses as a claim code.
#[test]
fn canonical_code_accepts_the_branding_prefix_repeated_six_times() {
    assert_eq!(
        canonical_code(&"CCOS-".repeat(6)).as_deref(),
        Some("CCOS-CC0SC-C0SCC-0SCC0-SCC0S"),
        "CLAIM-5: six copies of the branding prefix no longer parse as a code"
    );
    // Every other repetition count is refused (4·(n−1) ≠ 20).
    for n in [1usize, 2, 3, 4, 5, 7, 8, 12, 100, 1_000] {
        assert_eq!(
            canonical_code(&"CCOS-".repeat(n)),
            None,
            "CCOS- ×{n} was accepted"
        );
    }
    // It is a real, hashable code — nothing downstream can tell it apart.
    let branding = canonical_code(&"CCOS-".repeat(6)).expect("CLAIM-5");
    assert_canonical_shape(&branding, "CLAIM-5");
    assert!(is_sha256_hex(&code_hash(&branding)));
}

/// ` `, `\t`, `_` and `-` are skipped anywhere in the input; `\n` and `\r`
/// are not. The most common way a code arrives — `cat code.txt`, a copied
/// line, an email body — is therefore the one spelling that fails.
#[test]
fn canonical_code_rejects_the_trailing_newline_that_every_paste_carries() {
    let valid = "CCOS-AAAAA-AAAAA-AAAAA-AAAAA";
    assert_eq!(canonical_code(valid).as_deref(), Some(valid));
    for tail in ["\n", "\r\n", "\r", "\u{00A0}", "\u{200B}", "\u{FEFF}"] {
        assert_eq!(
            canonical_code(&format!("{valid}{tail}")),
            None,
            "CLAIM-6: {tail:?} is now tolerated"
        );
    }
    // The tolerated separators, for contrast.
    for tail in [" ", "\t", "_", "-", " \t__--  "] {
        assert_eq!(
            canonical_code(&format!("{valid}{tail}")).as_deref(),
            Some(valid),
            "{tail:?} should be skipped"
        );
    }
    // Note the asymmetry with `machine_fingerprint_of`, which *does* trim
    // ASCII and Unicode whitespace at both ends.
    assert_eq!(
        machine_fingerprint_of("abc\n"),
        machine_fingerprint_of("abc")
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 9. Domain separation of the three hashes
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn the_three_hash_domains_never_collide_over_ten_thousand_codes() {
    const N: usize = 10_000;
    let mut rng = Rng(0x0DD1_C0DE_0000_0007);
    // Five derivations per code, all in one set: any cross-domain collision,
    // or any two codes agreeing anywhere, shows up as a duplicate insert.
    let mut universe: HashSet<String> = HashSet::with_capacity(N * 5);

    for i in 0..N {
        let code = code_from_entropy(&rng.entropy());
        let wire = code_hash(&code);
        let key = vault_key(&wire);
        let fingerprint = machine_fingerprint_of(&code);
        // Deliberately wrong-domain applications: the counter must not be
        // reachable by feeding a value to the neighbouring primitive.
        let key_of_code = vault_key(&code);
        let fingerprint_of_wire = machine_fingerprint_of(&wire);

        for h in [
            &wire,
            &key,
            &fingerprint,
            &key_of_code,
            &fingerprint_of_wire,
        ] {
            assert!(is_sha256_hex(h), "sample {i}: {h} is not our hex shape");
            assert!(universe.insert(h.clone()), "sample {i}: {h} collided");
        }

        // The headline separation: the vault key is one hash past the wire
        // value, never equal to it, and never idempotent.
        assert_ne!(vault_key(&wire), wire, "sample {i}: vault_key(code_hash)");
        assert_ne!(vault_key(&key), key, "sample {i}: vault_key is idempotent");
        assert_ne!(key_of_code, wire, "sample {i}");
        assert_ne!(fingerprint, wire, "sample {i}");
        assert_ne!(fingerprint, key, "sample {i}");
    }
    assert_eq!(universe.len(), N * 5);

    // Structural, not statistical: the three domain tags differ at byte 5 of
    // the preimage, so no input to one can ever be an input to another.
    for probe in ["", "x", "ccos-machine-v1|x", "|", &"Z".repeat(4096)] {
        assert_ne!(code_hash(probe), vault_key(probe));
        assert_ne!(code_hash(probe), machine_fingerprint_of(probe));
        assert_ne!(vault_key(probe), machine_fingerprint_of(probe));
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 10. is_sha256_hex — exhaustive edges
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn is_sha256_hex_exhaustive_edges() {
    let real = code_hash("CCOS-AAAAA-AAAAA-AAAAA-AAAAA");
    assert!(is_sha256_hex(&real));
    assert!(is_sha256_hex(&vault_key(&real)));
    assert!(is_sha256_hex(&machine_fingerprint_of("m")));

    // Length: 0..=80 of a valid hex digit — only 64 passes.
    for n in 0..=80usize {
        assert_eq!(
            is_sha256_hex(&"a".repeat(n)),
            n == 64,
            "length {n} misjudged"
        );
    }

    // Every ASCII scalar, at three positions of an otherwise valid hash:
    // accepted iff it is a lowercase hex digit.
    for cp in 0u32..0x80 {
        let c = char::from_u32(cp).expect("ascii");
        let want = c.is_ascii_digit() || ('a'..='f').contains(&c);
        for at in [0usize, 32, 63] {
            let mut s: Vec<char> = real.chars().collect();
            s[at] = c;
            let s: String = s.into_iter().collect();
            assert_eq!(
                is_sha256_hex(&s),
                want,
                "U+{cp:04X} ({c:?}) at position {at}"
            );
        }
    }
    // Latin-1 and beyond: every one of them is multi-byte in UTF-8, so the
    // *length* gate rejects them before the digit gate ever runs. Both gates
    // agree here, but only by accident of encoding — worth pinning.
    for cp in 0x80u32..0x400 {
        let Some(c) = char::from_u32(cp) else {
            continue;
        };
        let mut s: Vec<char> = real.chars().collect();
        s[0] = c;
        let s: String = s.into_iter().collect();
        assert!(s.len() > 64);
        assert!(!is_sha256_hex(&s), "U+{cp:04X} was accepted");
    }

    // Uppercase hex — ours is always lowercase, so this is a wire mismatch,
    // not a courtesy.
    assert!(!is_sha256_hex(&real.to_uppercase()));
    assert!(!is_sha256_hex(&"A".repeat(64)));
    assert!(!is_sha256_hex(&"F".repeat(64)));
    let mut mixed: Vec<char> = real.chars().collect();
    let pos = mixed
        .iter()
        .position(|c| c.is_ascii_alphabetic())
        .expect("the vector contains a-f");
    mixed[pos] = mixed[pos].to_ascii_uppercase();
    let mixed: String = mixed.into_iter().collect();
    assert!(!is_sha256_hex(&mixed), "mixed case accepted: {mixed}");

    // 63 / 65 / whitespace / NUL / prefixes / unicode digits.
    assert!(!is_sha256_hex(&real[..63]));
    assert!(!is_sha256_hex(&format!("{real}0")));
    assert!(!is_sha256_hex(&format!(" {}", &real[..63])));
    assert!(!is_sha256_hex(&format!("{}\n", &real[..63])));
    assert!(!is_sha256_hex(&format!("{}\t", &real[..63])));
    assert!(!is_sha256_hex(&format!("{real} ")));
    assert!(!is_sha256_hex(&format!("\0{}", &real[..63])));
    assert!(!is_sha256_hex(&format!("0x{}", &real[..62])));
    assert!(!is_sha256_hex(""));
    assert!(!is_sha256_hex(&"٠".repeat(32))); // Arabic-Indic zero, 64 bytes
    assert!(!is_sha256_hex(&"٠".repeat(64)));
    assert!(!is_sha256_hex(&"０".repeat(21))); // fullwidth zero, 63 bytes
    assert!(!is_sha256_hex(&format!("{}0", "０".repeat(21)))); // 64 bytes
    assert!(!is_sha256_hex(&"\u{FF41}".repeat(21))); // fullwidth 'a'

    // Right length, wrong alphabet.
    assert!(!is_sha256_hex(&"g".repeat(64)));
    assert!(!is_sha256_hex(&"z".repeat(64)));
    assert!(!is_sha256_hex(&"-".repeat(64)));

    // And it accepts everything the primitives actually emit.
    let mut rng = Rng(0xFEED_FACE_0000_0011);
    for _ in 0..2_000 {
        let code = code_from_entropy(&rng.entropy());
        let wire = code_hash(&code);
        assert!(is_sha256_hex(&wire));
        assert!(is_sha256_hex(&vault_key(&wire)));
        assert!(is_sha256_hex(&machine_fingerprint_of(&code)));
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 11. Cross-implementation vectors (the PHP counter asserts these verbatim)
// ─────────────────────────────────────────────────────────────────────────

/// A drift in any of these three values is a protocol break: the Rust client
/// and the PHP counter stop agreeing on what a claim is, and every code in
/// every vault becomes unredeemable.
#[test]
fn cross_implementation_vectors_are_pinned() {
    let wire = code_hash("CCOS-AAAAA-AAAAA-AAAAA-AAAAA");
    assert_eq!(
        wire, "387c45ee5457f5e622d1b35c7c1afc302097a81880416bdab8352a2fa7345d79",
        "code_hash drifted"
    );
    let key = vault_key(&wire);
    assert_eq!(
        key, "836bf706f07466e2c098e17d2521650949555f5054bcb3d398fd93547b050c4b",
        "vault_key drifted"
    );
    assert_eq!(
        machine_fingerprint_of("vector-machine"),
        "6bb5b5a8623e94d18062c8ac5f37746f095bc93f9522307371c1bec7928a7c47",
        "machine_fingerprint_of drifted"
    );

    // The wire tag travels with them.
    assert_eq!(CLAIM_SCHEMA, "ccos.claim/v1");

    // The vectors are reached through canonicalization too, from every
    // spelling an operator can produce.
    for spelling in [
        "ccos-aaaaa-aaaaa-aaaaa-aaaaa",
        "CCOSAAAAAAAAAAAAAAAAAAAA",
        "AAAAAAAAAAAAAAAAAAAA",
        "cc0s aaaaa_aaaaa\taaaaa-aaaaa",
    ] {
        let canonical = canonical_code(spelling).expect("valid spelling");
        assert_eq!(code_hash(&canonical), wire, "{spelling:?}");
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 12. machine_fingerprint_of — whitespace folding and the empty identity
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn machine_fingerprint_folds_outer_whitespace_and_has_a_well_known_empty_identity() {
    // Documented: machine-id files end in a newline.
    let base = machine_fingerprint_of("abc123");
    for spelling in [
        "abc123\n",
        "abc123\r\n",
        " abc123 ",
        "\tabc123\t",
        "\u{00A0}abc123\u{00A0}", // NO-BREAK SPACE is Unicode White_Space
        "\u{3000}abc123\u{2009}",
        "\n\n abc123 \t\r\n",
    ] {
        assert_eq!(
            machine_fingerprint_of(spelling),
            base,
            "{spelling:?} should trim to the same identity"
        );
    }
    // Two hosts whose machine ids differ only in surrounding whitespace share
    // one seat. Interior whitespace is preserved, so the folding is bounded.
    assert_ne!(
        machine_fingerprint_of("ab c"),
        machine_fingerprint_of("abc")
    );
    assert_ne!(machine_fingerprint_of("abc"), machine_fingerprint_of("abd"));

    // The empty identity is a *stable, publicly computable* fingerprint. The
    // host path (`host_fingerprint`) refuses an empty machine-id and fails
    // closed, but `machine_fingerprint_of` does not, and the counter binds a
    // seat to any 64-hex string that arrives. Pinned so a repair is loud.
    let empty = machine_fingerprint_of("");
    for blank in ["", " ", "\t", "\n", "   \t\r\n ", "\u{00A0}\u{2003}"] {
        assert_eq!(
            machine_fingerprint_of(blank),
            empty,
            "{blank:?} is not the empty identity"
        );
    }
    assert!(is_sha256_hex(&empty));
    assert_eq!(
        empty, "7cfc1c72e12efbf964223c0c98910084f68fa5ca66d7b1df21e81f38dd15f61f",
        "the empty-identity fingerprint — sha256(\"ccos-machine-v1|\") — drifted"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 13. The protocol claim: a stolen vault is not replayable
// ─────────────────────────────────────────────────────────────────────────

/// The module's headline security property — "a stolen vault contains nothing
/// redeemable — neither the codes (behind two hashes) nor the wire hashes the
/// claim endpoint accepts (behind one)" — checked against the real counter.
#[test]
fn a_stolen_vault_yields_nothing_the_claim_endpoint_will_accept() {
    let code = code_from_entropy(&[0x11; 16]);
    let wire = code_hash(&code);
    let key = vault_key(&wire);
    let machine = machine_fingerprint_of("machine-one");
    let intruder = machine_fingerprint_of("machine-two");
    const NOW: u64 = 1_700_000_000;

    let seed_vault = || {
        let mut vault = Vault::new();
        vault.entries.insert(
            key.clone(),
            Entry {
                licensee: "acme".into(),
                label: None,
                days: Some(365),
                status: Status::Unclaimed,
                created_unix: NOW - 10,
                claimed_unix: None,
                exp_unix: None,
                machine: None,
            },
        );
        vault
    };

    // The wire hash redeems the seat; the expiry is fixed at claim.
    let mut vault = seed_vault();
    assert_eq!(
        vault.claim(&wire, &machine, NOW),
        Ok(("acme".to_string(), Some(NOW + 365 * 86_400)))
    );
    // Same machine → idempotent re-issue, never an extension.
    assert_eq!(
        vault.claim(&wire, &machine, NOW + 999_999),
        Ok(("acme".to_string(), Some(NOW + 365 * 86_400)))
    );
    // Any other machine → the single-seat refusal.
    assert_eq!(
        vault.claim(&wire, &intruder, NOW),
        Err(VaultRefusal::SeatTaken)
    );

    // Everything an intruder can read out of the vault file is refused at the
    // endpoint: the key itself, the key re-hashed, the code, and the key's
    // wire hash — none of them is the one preimage the endpoint wants.
    for stolen in [&key, &vault_key(&key), &code, &code_hash(&key)] {
        let mut fresh = seed_vault();
        assert_eq!(
            fresh.claim(stolen, &intruder, NOW),
            Err(VaultRefusal::UnknownCode),
            "{stolen} was redeemable straight out of the vault"
        );
    }
    // Revoked codes stay refused even for the bound machine.
    let mut fresh = seed_vault();
    if let Some(entry) = fresh.entries.get_mut(&key) {
        entry.status = Status::Revoked;
    }
    assert_eq!(
        fresh.claim(&wire, &machine, NOW),
        Err(VaultRefusal::Revoked)
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 14. Exhaustion
// ─────────────────────────────────────────────────────────────────────────

/// `canonical_code` buffers *every* accepted symbol before it checks the
/// length (`claim.rs:107-127`), so its working set is proportional to the
/// input, not to the 24 symbols a claim code can possibly have. The blast
/// radius is bounded by the caller — argv for `ccos-license-admin`, and the
/// counter never calls it at all (it takes hashes) — so this is a shape note,
/// not a remote vector. No timing is asserted; only that nothing aborts.
#[test]
fn oversized_inputs_are_refused_without_aborting() {
    for size in [1usize << 10, 1 << 16, 1 << 20] {
        // All-symbol: the worst case, buffered in full before the check.
        let started = Instant::now();
        assert_eq!(canonical_code(&"A".repeat(size)), None);
        let all_symbols = started.elapsed();

        // All-separator: skipped, never buffered.
        assert_eq!(canonical_code(&"-".repeat(size)), None);
        // Branding repeated: 4 symbols per 5 bytes.
        assert_eq!(canonical_code(&"CCOS-".repeat(size / 5)), None);
        // First byte invalid: the early return, no buffering at all.
        assert_eq!(canonical_code(&format!("U{}", "A".repeat(size))), None);
        // Non-ASCII bulk: refused at the first character now. CLAIM-2 used to
        // buffer the whole megabyte and leave the length check to refuse it.
        assert_eq!(canonical_code(&"\u{0430}".repeat(size / 2)), None);
        // NUL-filled.
        assert_eq!(canonical_code(&"\0".repeat(size)), None);

        println!("canonical_code({size} symbols) refused in {all_symbols:?}");
    }

    // The hashes take unbounded input without complaint.
    let huge = "A".repeat(1 << 20);
    assert!(is_sha256_hex(&code_hash(&huge)));
    assert!(is_sha256_hex(&vault_key(&huge)));
    assert!(is_sha256_hex(&machine_fingerprint_of(&huge)));
    // Trimming a megabyte of whitespace still lands on the empty identity.
    assert_eq!(
        machine_fingerprint_of(&" ".repeat(1 << 20)),
        machine_fingerprint_of("")
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 15. The long sweep (opt-in)
// ─────────────────────────────────────────────────────────────────────────

/// One million codes, for the collision property at a scale the default run
/// cannot afford.
///
/// `cargo test -p ccos-enterprise-conformance --test stress_claim_protocol
///  --release -- --ignored --nocapture`
#[test]
#[ignore = "long: 1M codes; see the doc comment for the command"]
fn one_million_codes_without_a_collision() {
    const N: usize = 1_000_000;
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    let mut codes: HashSet<String> = HashSet::with_capacity(N);
    for i in 0..N {
        let code = code_from_entropy(&rng.entropy());
        assert!(codes.insert(code.clone()), "COLLISION at {i}: {code}");
    }
    assert_eq!(codes.len(), N);
}
