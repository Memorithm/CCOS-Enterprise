//! # Hostile stress of the wire codec — `ccos_enterprise_governance::b64url`
//!
//! Three signed artifacts in this product are carried as base64url text and
//! nothing else: **license tokens** (`vendor::sign_token_bound` /
//! `sign_token_v1`), **release manifests** (`release::sign_manifest`) and
//! **offline revocation lists** (`vendor::sign_revocation_list_ed25519`). In
//! every one of them the signature is taken over the *ASCII of the encoded
//! segment*, never over the decoded bytes. That makes the codec a trust
//! boundary in the strictest sense: if one byte string had two accepted
//! encodings, an artifact could be re-spelled into a different wire form that
//! still verifies — a different `token_sha256`, a different blob digest, the
//! same signature. That is a signature-bypass primitive, not a cosmetic bug.
//!
//! The codec's own doc comment promises exactly the property that closes it:
//!
//! > every byte string has exactly ONE accepted encoding, so signed artifacts
//! > cannot be re-encoded into a different string that decodes identically
//! > (which would, for example, change a token's `token_sha256` without
//! > breaking its signature).
//!
//! This file tries to break that promise exhaustively (all 4 096 two-symbol
//! and all 262 144 three-symbol strings, all 256 one-byte and all 65 536
//! two-byte payloads, every ASCII byte, every Unicode scalar), then attacks
//! the two layers built on top of it with re-encoding, bit flips, truncation,
//! cross-scheme replay and trailing junk.
//!
//! ## VERDICT
//!
//! **The codec itself holds — it is exactly canonical.** There is provably
//! one accepted encoding per byte string and no impostor of any length is
//! accepted. Every malleability attack on the manifest and revocation-list
//! verifiers was refused. What broke is *around* it:
//!
//! * **B64-1 (high) — the codec's claim of parity with the license-token
//!   format is false, and the format it claims parity with is malleable.**
//!   `crates/ccos-enterprise-governance/src/lib.rs:28-30` says the local copy
//!   exists so "wire formats stay compatible … alphabet and semantics
//!   identical to the license token format". The alphabet is identical; the
//!   **semantics are not**. This crate's decoder enforces canonical padding
//!   bits (`lib.rs:84-92`); the decoder that actually parses the license
//!   tokens this crate *mints* — `ccos_core::license::b64url_decode`,
//!   `CCOS-Core/src/license.rs:258-288`, called by `Ed25519Verifier::verify`
//!   at `license.rs:353-365` — contains no padding check at all (its doc says
//!   only "`None` on any non-alphabet byte or a truncated group").
//!   Consequence: an ed25519 signature is 64 bytes, 64 % 3 == 1, so the
//!   signature segment is 86 symbols whose **final symbol carries 4 unused
//!   bits**. Every token minted by `vendor::sign_token_bound` therefore has
//!   **16 distinct wire spellings** carrying bit-identical signature bytes,
//!   all of which the core verifier accepts, and which produce **16 distinct
//!   `vendor::token_sha256` digests** — the exact value
//!   `RevocationEntry::token_sha256` revokes on. Revoking a token by digest
//!   is defeated by editing one character.
//!
//!   Measured against `ccos_core::license::Ed25519Verifier` directly (that
//!   crate is not a dependency of this test package, so the probe was run
//!   out-of-tree): of the 16 spellings of one machine-bound token, **16/16
//!   verify as the same valid license** (`licensee: "acme"`, same bound
//!   fingerprint), **1/16** is accepted by this crate's decoder, and the 16
//!   produce **16 distinct `token_sha256` values**. Trailing `"\n"`, `" "`,
//!   U+00A0, U+3000 and U+2028 were accepted by the core verifier as well
//!   (5/5), so the spelling count is not 16 but unbounded.
//!
//!   Source-level, not exercised here (the `license-pq` feature is not
//!   compiled into this workspace): the SLH-DSA verifier at
//!   `CCOS-Core/src/license.rs:490-520` decodes its signature segment with the
//!   *same* lax function (`license.rs:504`). An SLH-DSA-SHAKE-128s signature
//!   is 7 856 bytes and 7 856 % 3 == 2, so that segment ends in a three-symbol
//!   group with 2 free bits — 4 spellings per token rather than 16. The
//!   post-quantum format inherits the defect; it does not escape it.
//!
//!   Pinned by
//!   [`a_license_token_has_sixteen_wire_spellings_and_sixteen_distinct_digests`],
//!   which asserts every half of this that is reachable from inside this
//!   package: the 16 spellings denote bit-identical signature bytes, those
//!   bytes are a genuinely valid ed25519 signature, the digests are 16
//!   distinct values, and this crate's decoder refuses 15 of the 16 — the
//!   refusal being the divergence itself.
//!
//! * **B64-2 (medium) — the envelopes above the canonical codec are not
//!   canonical.** `release::verify_manifest_with` (`release.rs:78`) and
//!   `vendor::verify_revocation_list_with` (`vendor.rs:300-302`) call
//!   `str::trim`, which strips **Unicode** `White_Space` — U+00A0, U+2028,
//!   U+3000 and 20 others, not just ASCII blanks. So a signed artifact has
//!   unboundedly many accepted byte encodings after all; the canonicality the
//!   codec buys is given straight back one layer up. For revocation lists the
//!   1 MiB cap is applied to the **untrimmed** blob (`vendor.rs:295-299`), so
//!   a ~400-byte list has a legal ~1 MiB spelling: a ~2 600× inflation of
//!   anything that stores, hashes or ships the blob. Pinned by
//!   [`unicode_whitespace_makes_the_signed_envelopes_non_canonical`] and
//!   [`a_tiny_revocation_list_has_a_legal_one_mebibyte_spelling`].
//!
//! * **B64-3 (medium, exhaustion) — `verify_manifest_with` has no input bound
//!   and decodes before it length-checks.** `release.rs:89-91` runs
//!   `b64url::decode(sig_b64)` in full and *then* filters on `len() == 64`,
//!   and nothing anywhere bounds the manifest text (contrast `vendor.rs:295`,
//!   which at least caps revocation blobs at 1 MiB — while still decoding
//!   first, `vendor.rs:316-318`). `b64url::decode` reserves
//!   `bytes.len() * 3 / 4` up front (`lib.rs:75`), so a hostile mirror serving
//!   `ccos-release.AAAA.<N symbols>` to `ccos update` buys an attacker-chosen
//!   0.75·N allocation plus O(N) work for a reply the verifier was always
//!   going to reject. One `sig_b64.len() != 86` test before the decode closes
//!   it. Pinned by
//!   [`an_unbounded_manifest_signature_segment_is_fully_decoded_before_it_is_length_checked`].
//!
//! * **B64-4 (low) — the manifest is validated in one of its five fields, and
//!   is the only one of the three artifacts without `deny_unknown_fields`.**
//!   Once the signature checks out, `verify_manifest_with` inspects `sha256`
//!   (`release.rs:100-104`) and nothing else: `tier: "PRO"`, `url: ""` or
//!   `file:///etc/shadow`, `version: "../../etc"` and
//!   `released_unix: u64::MAX` all verify and are handed to `ccos update` as a
//!   legitimate release. And `ReleaseManifest` (`release.rs:33-47`) carries no
//!   `#[serde(deny_unknown_fields)]`, while `RevocationList` and
//!   `RevocationEntry` both do (`vendor.rs:166`, `vendor.rs:178`) — measured,
//!   not assumed: a signed manifest with `min_client` and `requires_reboot`
//!   verifies to a `ReleaseManifest` byte-identical to one without them, so a
//!   field added tomorrow to gate an install is silently *dropped* by today's
//!   verifier rather than refusing it. Every one of these needs the vendor
//!   key, so it is blast radius rather than bypass — but the artifact that
//!   triggers a download-and-install is the loosely validated one, and the
//!   artifact that only revokes is the strict one. Pinned by
//!   [`a_signed_manifest_is_validated_in_exactly_one_of_its_five_fields`].
//!
//! Everything asserted below is the product's **current, real** behaviour.
//! Where that behaviour is a defect the assertion pins the defect and the
//! comment names it, so a repair fails loudly here instead of silently
//! changing a wire format.
//!
//! Determinism: one fixed signing seed, one fixed-seed SplitMix64, no clock in
//! any assertion (`Instant` is used for progress reporting only).

use std::collections::HashSet;
use std::time::Instant;

use ccos_enterprise_governance::b64url;
use ccos_enterprise_governance::release::{self, ReleaseManifest, MANIFEST_TAG};
use ccos_enterprise_governance::vendor::{
    self, RevocationEntry, RevocationList, RevocationReason, MAX_REVOCATION_LIST_BYTES,
    REVOCATION_LIST_VERSION,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

// ── fixtures ──────────────────────────────────────────────────────────────

/// The 64 symbols the codec accepts, in value order (a local copy: the
/// constant is private to the crate under test, which is the point — this
/// file must be able to construct impostors the codec never would).
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// One throwaway signing seed for the whole file — never a real vendor key.
const SEED: [u8; 32] = [0x5Au8; 32];

/// A fixed instant, so nothing in this file reads a clock.
const NOW: u64 = 1_700_000_000;

fn public_key() -> [u8; 32] {
    SigningKey::from_bytes(&SEED).verifying_key().to_bytes()
}

/// The symbol for a 6-bit value.
fn sym(v: u8) -> char {
    ALPHABET[(v & 63) as usize] as char
}

/// The 6-bit value of a symbol, or `None` for anything outside the alphabet.
/// Uses `try_from` rather than `as u8`, so a non-ASCII scalar can never be
/// truncated into the alphabet (a bug the sibling claim-code parser has).
fn val(c: char) -> Option<u8> {
    let b = u8::try_from(u32::from(c)).ok()?;
    ALPHABET.iter().position(|&a| a == b).map(|i| i as u8)
}

/// Replace the final symbol of `s` with `v`.
fn with_last_symbol(s: &str, v: u8) -> String {
    let mut out: Vec<char> = s.chars().collect();
    *out.last_mut().expect("non-empty") = sym(v);
    out.into_iter().collect()
}

/// Deterministic PRNG (SplitMix64) — fixed seed, identical in debug and
/// release, so every "random" payload below is a constant of this file.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// How many symbols the codec emits for `n` bytes (the encoder's own shape).
fn encoded_len(n: usize) -> usize {
    n / 3 * 4
        + match n % 3 {
            0 => 0,
            r => r + 1,
        }
}

/// How many bytes an `n`-symbol string decodes to, or `None` when the length
/// itself is unrepresentable (`n % 4 == 1`, a lone trailing symbol).
fn decoded_len(n: usize) -> Option<usize> {
    match n % 4 {
        0 => Some(n / 4 * 3),
        1 => None,
        2 => Some(n / 4 * 3 + 1),
        3 => Some(n / 4 * 3 + 2),
        _ => unreachable!(),
    }
}

// ══════════════════════════════════════════════════════════════════════════
// 1. The codec: is there exactly ONE accepted encoding per byte string?
// ══════════════════════════════════════════════════════════════════════════

/// EXHAUSTIVE for one-byte payloads.
///
/// The uniqueness claim is proved, not sampled, and the proof has two halves:
///
/// * a one-byte output can *only* come from a two-symbol input — `decode`
///   emits 1, 2 or 3 bytes per 4-symbol chunk purely as a function of the
///   chunk's length, so the byte count is a function of the symbol count
///   alone (pinned exhaustively by
///   [`decoded_length_is_a_total_function_of_encoded_length`]);
/// * every one of the 64 × 64 = 4 096 two-symbol strings is tried here.
///
/// Together those two facts leave nowhere for a second encoding to hide.
#[test]
fn every_one_byte_payload_has_exactly_one_accepted_encoding() {
    let mut canonical: HashSet<String> = HashSet::new();
    for b in 0u8..=255 {
        let enc = b64url::encode(&[b]);
        assert_eq!(enc.len(), 2, "one byte must encode to exactly two symbols");
        assert_eq!(
            b64url::decode(&enc).as_deref(),
            Some(&[b][..]),
            "the canonical encoding of {b} must decode back"
        );
        assert!(canonical.insert(enc), "two payloads share one encoding");
    }
    assert_eq!(canonical.len(), 256, "the encoder is injective on one byte");

    // Now the whole two-symbol space, impostors included.
    let mut accepted = 0usize;
    let mut refused = 0usize;
    for hi in 0u8..64 {
        for lo in 0u8..64 {
            let s: String = [sym(hi), sym(lo)].iter().collect();
            // The 4 low bits of the second symbol are padding: they carry no
            // byte, so a non-zero value there is a second spelling of the
            // same byte and MUST be refused.
            let canonical_here = lo & 0x0F == 0;
            match b64url::decode(&s) {
                Some(bytes) => {
                    accepted += 1;
                    assert!(
                        canonical_here,
                        "{s:?} carries non-zero padding bits and was still accepted \
                         — a second spelling of byte {:?}",
                        bytes[0]
                    );
                    assert_eq!(bytes.len(), 1, "two symbols carry exactly one byte");
                    assert_eq!(bytes[0], (hi << 2) | (lo >> 4), "wrong bit assembly");
                    assert_eq!(
                        b64url::encode(&bytes),
                        s,
                        "accepted ⇒ it is the encoder's own output"
                    );
                    assert!(canonical.contains(&s));
                }
                None => {
                    refused += 1;
                    assert!(!canonical_here, "{s:?} is canonical yet was refused");
                }
            }
        }
    }
    assert_eq!(
        accepted, 256,
        "exactly one accepted spelling per byte value"
    );
    assert_eq!(refused, 3_840, "4096 − 256 impostors, all refused");
}

/// EXHAUSTIVE for two-byte payloads: all 65 536 values encode-and-decode, and
/// all 64³ = 262 144 three-symbol strings are classified. 262 144 − 65 536 =
/// 196 608 impostors (2 free padding bits) must be refused.
#[test]
fn every_two_byte_payload_has_exactly_one_accepted_encoding() {
    let started = Instant::now();
    let mut canonical: HashSet<String> = HashSet::with_capacity(65_536);
    for v in 0u32..=0xFFFF {
        let payload = [(v >> 8) as u8, v as u8];
        let enc = b64url::encode(&payload);
        assert_eq!(
            enc.len(),
            3,
            "two bytes must encode to exactly three symbols"
        );
        assert_eq!(b64url::decode(&enc).as_deref(), Some(&payload[..]));
        assert!(canonical.insert(enc), "two payloads share one encoding");
    }
    assert_eq!(canonical.len(), 65_536);

    let mut accepted = 0usize;
    let mut refused = 0usize;
    for a in 0u8..64 {
        for b in 0u8..64 {
            for c in 0u8..64 {
                let s: String = [sym(a), sym(b), sym(c)].iter().collect();
                let canonical_here = c & 0x03 == 0;
                match b64url::decode(&s) {
                    Some(bytes) => {
                        accepted += 1;
                        assert!(
                            canonical_here,
                            "{s:?} carries non-zero padding bits and was still accepted"
                        );
                        assert_eq!(bytes.len(), 2);
                        assert_eq!(bytes[0], (a << 2) | (b >> 4));
                        assert_eq!(bytes[1], (b << 4) | (c >> 2));
                        assert_eq!(b64url::encode(&bytes), s);
                        assert!(canonical.contains(&s));
                    }
                    None => {
                        refused += 1;
                        assert!(!canonical_here, "{s:?} is canonical yet was refused");
                    }
                }
            }
        }
    }
    assert_eq!(
        accepted, 65_536,
        "exactly one accepted spelling per 2-byte value"
    );
    assert_eq!(refused, 196_608, "262144 − 65536 impostors, all refused");
    eprintln!(
        "[b64url] exhaustive 2-byte / 3-symbol sweep: {:?}",
        started.elapsed()
    );
}

/// The premise the two proofs above lean on: how many bytes come out is a
/// function of how many symbols went in, and nothing else. Swept over every
/// length 0..=512 with an all-zero-bit payload (`A` = value 0, so padding is
/// always canonical and only the length can refuse).
#[test]
fn decoded_length_is_a_total_function_of_encoded_length() {
    for n in 0..=512usize {
        let s = "A".repeat(n);
        match (b64url::decode(&s), decoded_len(n)) {
            (Some(bytes), Some(expected)) => {
                assert_eq!(
                    bytes.len(),
                    expected,
                    "{n} symbols decoded to the wrong length"
                );
                assert!(bytes.iter().all(|&b| b == 0));
            }
            (None, None) => assert_eq!(n % 4, 1, "only a lone trailing symbol is length-refused"),
            (got, want) => panic!("length {n}: decode gave {got:?}, the shape says {want:?}"),
        }
    }
    // …and the encoder's inverse relation, which is what makes
    // `decode(encode(x)).len() == x.len()` hold for every x.
    for n in 0..=512usize {
        assert_eq!(
            decoded_len(encoded_len(n)),
            Some(n),
            "round-trip length for {n} bytes"
        );
    }
}

// ══════════════════════════════════════════════════════════════════════════
// 2. The codec: what does it refuse?
// ══════════════════════════════════════════════════════════════════════════

/// EXHAUSTIVE over every byte that can occupy a single position in a `&str`:
/// the alphabet is exactly 64 ASCII bytes, and `+`, `/`, `=`, every blank and
/// NUL are outside it. (The codec is `str`-based, so any *non*-ASCII scalar
/// occupies ≥ 2 bytes, all ≥ 0x80, none of them alphabet bytes — swept
/// separately in [`no_unicode_scalar_outside_the_alphabet_is_ever_accepted`].)
#[test]
fn the_alphabet_is_exactly_sixty_four_ascii_bytes() {
    let mut accepted = Vec::new();
    for b in 0u8..=127 {
        let s = format!("AAA{}", b as char);
        if b64url::decode(&s).is_some() {
            accepted.push(b);
        }
    }
    assert_eq!(
        accepted.len(),
        64,
        "the accepted alphabet is not 64 bytes wide"
    );
    let mut sorted = *ALPHABET;
    sorted.sort_unstable();
    assert_eq!(
        accepted[..],
        sorted[..],
        "the accepted set is not the alphabet"
    );

    // The named refusals the doc promises, spelled out.
    for bad in [
        '+', '/', '=', ' ', '\t', '\n', '\r', '\0', '.', ',', '*', '%',
    ] {
        assert!(
            b64url::decode(&format!("AAA{bad}")).is_none(),
            "{bad:?} must never be an alphabet symbol"
        );
    }
    // Standard-base64 text (`+`/`/`) is refused wholesale, not silently
    // re-mapped — the two alphabets are different wire formats.
    assert!(b64url::decode("a+b/").is_none());
    assert!(
        b64url::decode("AA==").is_none(),
        "padded base64 is not this format"
    );
    // The codec itself does NOT trim: whitespace is a decode error here, and
    // only the envelope one layer up tolerates it (see B64-2).
    for s in [
        "AAAA ", " AAAA", "AAAA\n", "\nAAAA", "AAAA\0", "\0AAAA", "AA AA",
    ] {
        assert!(b64url::decode(s).is_none(), "{s:?} must not decode");
    }
}

/// EXHAUSTIVE over all 1 112 064 Unicode scalar values: exactly 64 of them
/// are accepted as a symbol, and they are precisely the ASCII alphabet. This
/// is the sweep that would catch a truncating `char as u8` cast (the defect
/// the sibling claim-code parser has, where 138 976 non-ASCII scalars are
/// accepted as Crockford symbols).
#[test]
fn no_unicode_scalar_outside_the_alphabet_is_ever_accepted() {
    let started = Instant::now();
    let mut accepted = 0usize;
    for cp in 0u32..=0x10_FFFF {
        let Some(c) = char::from_u32(cp) else {
            continue; // surrogate range: not a scalar value
        };
        let s = format!("AAA{c}");
        if b64url::decode(&s).is_some() {
            accepted += 1;
            assert!(
                c.is_ascii() && ALPHABET.contains(&(c as u8)),
                "U+{cp:04X} ({c:?}) was accepted as a base64url symbol"
            );
            assert!(val(c).is_some());
        }
    }
    assert_eq!(accepted, 64, "exactly the ASCII alphabet, nothing else");
    eprintln!("[b64url] full Unicode sweep: {:?}", started.elapsed());
}

/// Lone trailing symbols and truncated groups. A truncated encoding may still
/// decode (base64url is prefix-compatible when the cut lands on a group
/// boundary *and* the exposed padding bits happen to be zero) — the property
/// that matters is that it can never decode to anything other than a genuine
/// **prefix** of the original payload. Truncation can drop bytes; it can
/// never inject one.
#[test]
fn lone_trailing_symbols_are_refused_and_truncation_can_never_inject_bytes() {
    for v in 0u8..64 {
        assert!(
            b64url::decode(&sym(v).to_string()).is_none(),
            "a single symbol carries no whole byte and must be refused"
        );
    }
    // Every length ≡ 1 (mod 4) is refused outright, whatever the symbols are.
    let mut rng = SplitMix64(0xB16B_00B5_1234_5678);
    for _ in 0..2_000 {
        let n = 1 + 4 * ((rng.next_u64() % 40) as usize);
        let s: String = (0..n).map(|_| sym((rng.next_u64() % 64) as u8)).collect();
        assert_eq!(s.len() % 4, 1);
        assert!(b64url::decode(&s).is_none(), "{s:?} ends in a lone symbol");
    }
    // Truncation of a real encoding.
    let payload: Vec<u8> = (0..96u8)
        .map(|i| i.wrapping_mul(37).wrapping_add(11))
        .collect();
    let enc = b64url::encode(&payload);
    let mut accepted_prefixes = 0usize;
    for cut in 0..enc.len() {
        match b64url::decode(&enc[..cut]) {
            Some(bytes) => {
                accepted_prefixes += 1;
                assert_ne!(cut % 4, 1);
                assert_eq!(
                    bytes.len(),
                    decoded_len(cut).expect("length is representable")
                );
                assert_eq!(
                    bytes[..],
                    payload[..bytes.len()],
                    "a truncated encoding decoded to something that is not a prefix"
                );
            }
            None => assert_ne!(
                cut % 4,
                0,
                "a prefix that lands on a whole group carries no padding bits \
                 and must decode"
            ),
        }
    }
    // Every 4-symbol boundary is a valid prefix; the ragged ones survive only
    // when the exposed bits are zero — deterministic for this fixed payload.
    assert!(
        accepted_prefixes >= enc.len() / 4,
        "whole groups must all decode"
    );
}

/// `decode` is a **total** function: 50 000 fixed-seed hostile strings — any
/// ASCII byte at any position, lengths 0..=200, plus multi-byte scalars spliced
/// in — and it never panics, never over-reads, and only ever returns `Some`
/// for a string it can re-encode to itself. (The sibling claim-code parser
/// fails exactly this property by slicing on non-`char` boundaries; the codec
/// does not, because it works on `as_bytes()` and only ever *reads*.)
#[test]
fn decode_is_total_and_never_returns_a_value_it_cannot_re_encode() {
    let mut rng = SplitMix64(0xDEFA_CED0_0BAD_F00D);
    let poison = [
        '+',
        '/',
        '=',
        ' ',
        '\n',
        '\t',
        '\0',
        '.',
        '\u{a0}',
        '\u{10FFFF}',
        'é',
        '中',
    ];
    let mut accepted = 0usize;
    for _ in 0..50_000 {
        let n = (rng.next_u64() % 201) as usize;
        let s: String = (0..n)
            .map(|_| {
                let r = rng.next_u64();
                match r % 8 {
                    // mostly alphabet, so a useful fraction of the corpus is
                    // structurally decodable rather than junk
                    0 => poison[(r >> 8) as usize % poison.len()],
                    1 => char::from_u32((r >> 8) as u32 % 128).unwrap_or('A'),
                    _ => sym(((r >> 8) % 64) as u8),
                }
            })
            .collect();
        if let Some(bytes) = b64url::decode(&s) {
            accepted += 1;
            assert!(s.is_ascii(), "a non-ASCII string decoded: {s:?}");
            assert_eq!(bytes.len(), decoded_len(s.len()).expect("representable"));
            assert_eq!(
                b64url::encode(&bytes),
                s,
                "decode accepted a string that is not its own encoding — a second spelling"
            );
        }
    }
    assert!(
        accepted > 500,
        "the corpus must actually exercise the happy path"
    );
}

/// 100 000 fixed-seed random payloads of length 0..=1024 round-trip byte for
/// byte, and `decode(encode(x)).len() == x.len()` holds on every one.
///
/// Injectivity comes free: `decode` is a function, so if two distinct
/// payloads shared an encoding it could not return both — and every payload
/// here decodes back to itself.
#[test]
fn one_hundred_thousand_random_payloads_round_trip_byte_for_byte() {
    let started = Instant::now();
    let mut rng = SplitMix64(0x0BAD_C0DE_DEAD_BEEF);
    let mut total_bytes = 0usize;
    let mut payload = Vec::with_capacity(1024);
    for i in 0..100_000u32 {
        let len = (rng.next_u64() % 1025) as usize; // 0..=1024
        payload.clear();
        while payload.len() < len {
            payload.extend_from_slice(&rng.next_u64().to_le_bytes());
        }
        payload.truncate(len);

        let enc = b64url::encode(&payload);
        assert_eq!(
            enc.len(),
            encoded_len(len),
            "case {i}: wrong encoded length"
        );
        assert!(
            enc.bytes().all(|c| ALPHABET.contains(&c)),
            "case {i}: encoder emitted a symbol outside its own alphabet"
        );
        let back = b64url::decode(&enc).unwrap_or_else(|| panic!("case {i}: own output refused"));
        assert_eq!(
            back.len(),
            payload.len(),
            "case {i}: length relation broken"
        );
        assert_eq!(back, payload, "case {i}: round-trip is not the identity");
        total_bytes += len;
    }
    assert!(
        total_bytes > 45_000_000,
        "the corpus should average ~512 bytes"
    );
    eprintln!(
        "[b64url] 100k round-trips ({total_bytes} bytes): {:?}",
        started.elapsed()
    );
}

/// A four-symbol group has no spare bits at all, so three-byte payloads are
/// rigid by construction: every one of the 64⁴ strings must be accepted and
/// map to a distinct triple. Sampled deterministically here; the full 2²⁴
/// sweep is [`exhaustive_three_byte_bijection`].
#[test]
fn four_symbol_groups_have_no_spare_bits() {
    let mut rng = SplitMix64(0xFEED_FACE_CAFE_0001);
    for _ in 0..20_000 {
        let v = rng.next_u64();
        let s: String = (0..4).map(|k| sym(((v >> (6 * k)) & 63) as u8)).collect();
        let bytes = b64url::decode(&s).expect("every 4-symbol group is canonical");
        assert_eq!(bytes.len(), 3);
        assert_eq!(
            b64url::encode(&bytes),
            s,
            "4-symbol groups are their own encoding"
        );
    }
}

/// The full 2²⁴ bijection between 4-symbol strings and 3-byte payloads.
#[test]
#[ignore = "2^24 sweep, minutes in debug. Run: cargo test -p ccos-enterprise-conformance \
            --release --test stress_b64url_malleability -- --ignored --nocapture"]
fn exhaustive_three_byte_bijection() {
    let started = Instant::now();
    let mut buf = [0u8; 3];
    for v in 0u32..=0x00FF_FFFF {
        buf[0] = (v >> 16) as u8;
        buf[1] = (v >> 8) as u8;
        buf[2] = v as u8;
        let enc = b64url::encode(&buf);
        assert_eq!(enc.len(), 4);
        assert_eq!(b64url::decode(&enc).as_deref(), Some(&buf[..]));
    }
    for v in 0u32..=0x00FF_FFFF {
        let s: String = (0..4)
            .map(|k| sym(((v >> (18 - 6 * k)) & 63) as u8))
            .collect();
        let bytes = b64url::decode(&s).expect("no 4-symbol string may be refused");
        assert_eq!(b64url::encode(&bytes), s);
    }
    eprintln!(
        "[b64url] exhaustive 2^24 bijection: {:?}",
        started.elapsed()
    );
}

// ══════════════════════════════════════════════════════════════════════════
// 3. The layer above: release manifests
// ══════════════════════════════════════════════════════════════════════════

/// A manifest whose serialised JSON length ≡ `residue` (mod 3), so that the
/// final base64url group has 0, 4 or 2 spare padding bits respectively —
/// i.e. so that a non-canonical re-spelling of the payload segment is even
/// *possible* to construct.
fn manifest_with_residue(residue: usize) -> ReleaseManifest {
    for pad in 0..3 {
        let m = ReleaseManifest {
            version: "0.5.0".into(),
            released_unix: NOW,
            sha256: "3b".repeat(32),
            url: format!("https://releases.example/ccos-0.5.0{}", "x".repeat(pad)),
            tier: "pro".into(),
        };
        let len = serde_json::to_vec(&m).expect("serialises").len();
        if len % 3 == residue {
            return m;
        }
    }
    unreachable!("one of three paddings must hit residue {residue}")
}

fn split_manifest(line: &str) -> (String, String) {
    let rest = line
        .strip_prefix(&format!("{MANIFEST_TAG}."))
        .expect("tagged");
    let (payload, sig) = rest.split_once('.').expect("tag.payload.signature");
    (payload.to_string(), sig.to_string())
}

/// The signed manifest round-trips, and the placeholder key fails closed.
#[test]
fn a_signed_manifest_round_trips_and_the_placeholder_key_verifies_nothing() {
    let pk = public_key();
    for residue in 0..3 {
        let m = manifest_with_residue(residue);
        let line = release::sign_manifest(&SEED, &m);
        assert!(line.starts_with(&format!("{MANIFEST_TAG}.")));
        assert_eq!(line.split('.').count(), 3);
        assert_eq!(
            release::verify_manifest_with(&pk, &line).expect("verifies"),
            m
        );
        // Fail-closed postures.
        assert!(
            release::verify_manifest_with(&[0u8; 32], &line).is_err(),
            "placeholder key"
        );
        assert!(
            release::verify_manifest_with(&[9u8; 32], &line).is_err(),
            "wrong key"
        );
    }
}

/// **The headline malleability attack, at the manifest layer.** Re-spell the
/// payload segment with non-zero padding bits: the byte string it decodes to
/// is unchanged, so a lax codec would let a re-spelled manifest verify — with
/// a different blob digest. Both defences must hold:
///
/// 1. the codec refuses the re-spelled segment outright; and
/// 2. the verifier refuses the line at the **signature** step, because the
///    signing input is the payload's *ASCII*, not its bytes — defence in
///    depth, so the manifest would survive even a lax decoder.
///
/// Residue 0 is included to prove the negative: when the payload length is a
/// multiple of 3 there are no spare bits and therefore no siblings at all.
#[test]
fn a_manifest_payload_re_spelled_with_non_canonical_padding_is_refused() {
    let pk = public_key();
    let mut tried = 0usize;
    for (residue, free_bits) in [(0usize, 0u32), (1, 4), (2, 2)] {
        let m = manifest_with_residue(residue);
        let line = release::sign_manifest(&SEED, &m);
        let (payload, sig) = split_manifest(&line);
        assert_eq!(payload.len() % 4, [0, 2, 3][residue]);

        let last = val(payload.chars().last().expect("non-empty")).expect("alphabet symbol");
        let mask = (1u8 << free_bits) - 1;
        assert_eq!(
            last & mask,
            0,
            "the signer emitted non-canonical padding of its own"
        );
        for d in 1..=mask {
            let respelled = with_last_symbol(&payload, last | d);
            assert_ne!(respelled, payload, "the attack must change the bytes");
            tried += 1;
            // (1) the codec closes it.
            assert!(
                b64url::decode(&respelled).is_none(),
                "{respelled:?} is a second spelling of the manifest payload and the \
                 codec accepted it"
            );
            // (2) and so does the signature, independently.
            let forged = format!("{MANIFEST_TAG}.{respelled}.{sig}");
            let err = release::verify_manifest_with(&pk, &forged).expect_err("must refuse");
            assert!(
                err.to_string().contains("bad manifest signature"),
                "expected the signature to catch the re-spelling first, got: {err}"
            );
        }
        if free_bits == 0 {
            assert_eq!(mask, 0, "residue 0 has no siblings to try");
        }
    }
    assert_eq!(tried, 15 + 3, "16 spellings for residue 1, 4 for residue 2");
}

/// The payload bit positions a sweep flips. `exhaustive` does every bit of
/// every byte; the default run does every bit of the first and last four
/// bytes plus one rotating bit of every byte in between — still touching
/// **every byte** of the payload, at a fifth of the ed25519 cost (one
/// verification is ~9 ms in the dev profile, and CI runs this file debug).
fn flip_positions(len: usize, exhaustive: bool) -> Vec<(usize, u8)> {
    let mut out = Vec::new();
    for i in 0..len {
        if exhaustive || i < 4 || i + 4 >= len {
            out.extend((0..8u8).map(|bit| (i, bit)));
        } else {
            out.push((i, (i % 8) as u8));
        }
    }
    out
}

/// Flip bits in a signed manifest's payload and signature; every forgery must
/// be refused. Returns how many forgeries were tried.
fn manifest_bit_flip_sweep(exhaustive: bool) -> usize {
    let pk = public_key();
    let m = manifest_with_residue(0);
    let line = release::sign_manifest(&SEED, &m);
    let (payload_b64, sig_b64) = split_manifest(&line);
    let payload = b64url::decode(&payload_b64).expect("own output");
    let sig = b64url::decode(&sig_b64).expect("own output");
    assert_eq!(sig.len(), 64, "ed25519 signatures are 64 bytes");

    let mut tried = 0usize;
    for (i, bit) in flip_positions(payload.len(), exhaustive) {
        let mut forged_payload = payload.clone();
        forged_payload[i] ^= 1 << bit;
        let forged = format!(
            "{MANIFEST_TAG}.{}.{sig_b64}",
            b64url::encode(&forged_payload)
        );
        assert!(
            release::verify_manifest_with(&pk, &forged).is_err(),
            "payload byte {i} bit {bit} flipped and the manifest still verified"
        );
        tried += 1;
    }
    // The signature is swept exhaustively in every mode: all 512 bits. This is
    // the segment nothing signs, so it is where malleability would live.
    for (i, bit) in flip_positions(sig.len(), true) {
        let mut forged_sig = sig.clone();
        forged_sig[i] ^= 1 << bit;
        let forged = format!(
            "{MANIFEST_TAG}.{payload_b64}.{}",
            b64url::encode(&forged_sig)
        );
        assert!(
            release::verify_manifest_with(&pk, &forged).is_err(),
            "signature byte {i} bit {bit} flipped and the manifest still verified"
        );
        tried += 1;
    }
    tried
}

/// Every single-bit flip in the manifest signature (all 512) and across every
/// byte of its payload is refused.
#[test]
fn every_single_bit_flip_in_a_signed_manifest_is_refused() {
    let started = Instant::now();
    let tried = manifest_bit_flip_sweep(false);
    assert!(tried > 512, "the payload must be swept too");
    eprintln!(
        "[manifest] {tried} single-bit forgeries refused in {:?}",
        started.elapsed()
    );
}

/// Truncation and appended junk at the manifest boundary.
///
/// **B64-2 is pinned here**: the verifier trims *Unicode* whitespace, so a
/// no-break space, a line separator or an ideographic space are all legal
/// padding on a signed artifact. The bytes on the wire differ; the verdict
/// does not.
#[test]
fn unicode_whitespace_makes_the_signed_envelopes_non_canonical() {
    let pk = public_key();
    let m = manifest_with_residue(0);
    let line = release::sign_manifest(&SEED, &m);

    // Truncation: every proper prefix is refused.
    for cut in 0..line.len() {
        assert!(
            release::verify_manifest_with(&pk, &line[..cut]).is_err(),
            "the first {cut} bytes of a manifest must not verify"
        );
    }
    // Extension with alphabet symbols is refused (the signature is now the
    // wrong length, then the wrong value).
    for extra in ["A", "AA", "AAA", "AAAA"] {
        assert!(release::verify_manifest_with(&pk, &format!("{line}{extra}")).is_err());
    }
    // A stray NUL is fatal — NUL is not `White_Space`.
    assert!(release::verify_manifest_with(&pk, &format!("{line}\0")).is_err());
    assert!(release::verify_manifest_with(&pk, &format!("\0{line}")).is_err());

    // …but every Unicode blank is silently accepted, on both ends. This is
    // B64-2: `release.rs:78` uses `str::trim`, i.e. `char::is_whitespace`,
    // i.e. the Unicode White_Space property — 25 scalars, not just ASCII.
    let blanks = [
        '\u{20}', '\u{09}', '\u{0a}', '\u{0d}', '\u{0b}', '\u{0c}', '\u{85}', '\u{a0}', '\u{1680}',
        '\u{2000}', '\u{2028}', '\u{2029}', '\u{202f}', '\u{205f}', '\u{3000}',
    ];
    let mut spellings: HashSet<String> = HashSet::new();
    spellings.insert(line.clone());
    for b in blanks {
        assert!(
            b.is_whitespace(),
            "U+{:04X} is not White_Space — fix the fixture",
            u32::from(b)
        );
        for candidate in [
            format!("{line}{b}"),
            format!("{b}{line}"),
            format!("{b}{line}{b}"),
        ] {
            assert_eq!(
                release::verify_manifest_with(&pk, &candidate).expect("trimmed and accepted"),
                m,
                "U+{:04X} padding changed the verdict",
                u32::from(b)
            );
            spellings.insert(candidate);
        }
    }
    // 46 distinct byte strings, one signature, one manifest. Any deployment
    // that pins or de-duplicates a release by the digest of the fetched file
    // is pinning something the attacker can vary at will.
    assert_eq!(spellings.len(), 1 + blanks.len() * 3);
    let digests: HashSet<String> = spellings
        .iter()
        .map(|s| vendor::token_sha256(s.as_bytes()))
        .collect();
    assert_eq!(
        digests.len(),
        spellings.len(),
        "each spelling hashes differently — that is the malleability"
    );
}

/// Domain separation across the three signed schemes. One keypair signs
/// license tokens, release manifests and revocation lists; a signature must
/// never transfer between them.
///
/// The `ccos-core` license verifier is not a dependency of this test package,
/// so the token side is asserted directly against ed25519: the manifest's
/// signature is checked over the exact byte string a bare `payload.sig` token
/// verifier would use, and must fail there while succeeding with the scheme
/// tag bound in.
#[test]
fn a_signature_never_transfers_between_the_three_signed_schemes() {
    let pk = public_key();
    let vk = VerifyingKey::from_bytes(&pk).expect("valid key");
    let m = manifest_with_residue(0);
    let manifest_line = release::sign_manifest(&SEED, &m);
    let token = vendor::sign_token_bound(&SEED, "acme", Some(NOW + 86_400), Some("fingerprint"));
    let revocation =
        vendor::sign_revocation_list_ed25519(&SEED, &revocation_list(0)).expect("signs");

    // Cross-feeding the two verifiers this crate owns.
    assert!(
        release::verify_manifest_with(&pk, &token).is_err(),
        "token as manifest"
    );
    assert!(
        release::verify_manifest_with(&pk, &format!("{MANIFEST_TAG}.{token}")).is_err(),
        "token wearing the manifest tag"
    );
    assert!(
        release::verify_manifest_with(&pk, &revocation).is_err(),
        "revocation as manifest"
    );
    assert!(
        vendor::verify_revocation_list_with(&pk, manifest_line.as_bytes(), NOW).is_err(),
        "manifest as revocation list"
    );
    assert!(
        vendor::verify_revocation_list_with(&pk, token.as_bytes(), NOW).is_err(),
        "token as revocation list"
    );
    assert!(
        vendor::verify_revocation_list_with(
            &pk,
            format!("ccosrev1.ed25519.{token}").as_bytes(),
            NOW
        )
        .is_err(),
        "token wearing the revocation envelope"
    );

    // The manifest, tag stripped, is byte-for-byte the shape a v0 license
    // token has (`payload.signature`). It must not verify as one.
    let (mp, ms) = split_manifest(&manifest_line);
    let msig = Signature::from_bytes(&to_sig(&ms));
    assert!(
        vk.verify(mp.as_bytes(), &msig).is_err(),
        "a manifest signature verified over the bare payload — domains are not separated"
    );
    assert!(
        vk.verify(format!("{MANIFEST_TAG}.{mp}").as_bytes(), &msig)
            .is_ok(),
        "…it must verify only with the scheme tag bound in"
    );

    // And the reverse direction: a v0 token's signature covers the bare
    // payload, so it cannot be lifted into the manifest domain.
    let (tp, ts) = token.split_once('.').expect("payload.signature");
    let tsig = Signature::from_bytes(&to_sig(ts));
    assert!(
        vk.verify(tp.as_bytes(), &tsig).is_ok(),
        "the token is well formed"
    );
    assert!(
        vk.verify(format!("{MANIFEST_TAG}.{tp}").as_bytes(), &tsig)
            .is_err(),
        "a token signature lifted into the manifest domain must fail"
    );
}

fn to_sig(b64: &str) -> [u8; 64] {
    b64url::decode(b64)
        .expect("signature segment decodes")
        .try_into()
        .expect("64 bytes")
}

/// Sign an arbitrary JSON body into a manifest envelope — the vendor's own
/// capability, so this is what a *signed* manifest is allowed to say.
fn sign_manifest_payload(json: &str) -> String {
    let input = format!("{MANIFEST_TAG}.{}", b64url::encode(json.as_bytes()));
    let sig = SigningKey::from_bytes(&SEED).sign(input.as_bytes());
    format!("{input}.{}", b64url::encode(&sig.to_bytes()))
}

/// What the manifest verifier actually validates, once the signature is good.
///
/// `verify_manifest_with` checks the shape of exactly one of the five fields
/// (`sha256`, `release.rs:100-104`). Everything else is taken verbatim, and
/// `ReleaseManifest` (`release.rs:33-47`) carries no
/// `#[serde(deny_unknown_fields)]` — unlike `RevocationList` and
/// `RevocationEntry`, which both do (`vendor.rs:166`, `vendor.rs:178`). This
/// test pins the current, real boundary of that validation.
///
/// It is not a signature bypass — everything here needs the vendor key — but
/// it is the blast radius of a signing pipeline that templates a field, and
/// the asymmetry with the revocation list is a defect of consistency: the
/// artifact that triggers a **download and install** is the loosely validated
/// one.
#[test]
fn a_signed_manifest_is_validated_in_exactly_one_of_its_five_fields() {
    let pk = public_key();
    let sha = "3b".repeat(32);

    // The one field that is checked: a bad sha256 is refused even signed.
    for bad in ["", "zz", &"A".repeat(64), &"3b".repeat(31)] {
        let line = sign_manifest_payload(&format!(
            r#"{{"version":"0.5.0","released_unix":1,"sha256":"{bad}","url":"u","tier":"pro"}}"#
        ));
        assert!(
            release::verify_manifest_with(&pk, &line).is_err(),
            "sha256 {bad:?} must be refused"
        );
    }

    // The four that are not. Each of these verifies and is handed straight to
    // the caller (`ccos update`) as a legitimate release description.
    for (field, body) in [
        (
            "empty version",
            format!(r#""version":"","released_unix":0,"sha256":"{sha}","url":"u","tier":"pro""#),
        ),
        (
            "non-numeric version",
            format!(
                r#""version":"../../etc","released_unix":0,"sha256":"{sha}","url":"u","tier":"pro""#
            ),
        ),
        (
            "unknown tier",
            format!(r#""version":"1.0","released_unix":0,"sha256":"{sha}","url":"u","tier":"PRO""#),
        ),
        (
            "empty tier",
            format!(r#""version":"1.0","released_unix":0,"sha256":"{sha}","url":"u","tier":"""#),
        ),
        (
            "file:// url",
            format!(
                r#""version":"1.0","released_unix":0,"sha256":"{sha}","url":"file:///etc/shadow","tier":"community""#
            ),
        ),
        (
            "empty url",
            format!(
                r#""version":"1.0","released_unix":0,"sha256":"{sha}","url":"","tier":"community""#
            ),
        ),
        (
            "far-future date",
            format!(
                r#""version":"1.0","released_unix":18446744073709551615,"sha256":"{sha}","url":"u","tier":"pro""#
            ),
        ),
    ] {
        let line = sign_manifest_payload(&format!("{{{body}}}"));
        let m = release::verify_manifest_with(&pk, &line)
            .unwrap_or_else(|e| panic!("{field} was expected to verify, got: {e}"));
        assert_eq!(m.sha256, sha);
    }

    // `tier: "PRO"` is not `"pro"`, so a caller doing the documented
    // `tier == "pro"` license gate treats it as community — i.e. the licence
    // requirement is dropped, not tightened. Pinned as current behaviour.
    let line = sign_manifest_payload(&format!(
        r#"{{"version":"1.0","released_unix":0,"sha256":"{sha}","url":"u","tier":"PRO"}}"#
    ));
    let m = release::verify_manifest_with(&pk, &line).expect("verifies");
    assert_ne!(
        m.tier, "pro",
        "the tier string is passed through uninspected"
    );

    // Unknown fields are silently dropped (no `deny_unknown_fields`), so many
    // distinct signed payloads verify to one identical `ReleaseManifest`.
    let plain = sign_manifest_payload(&format!(
        r#"{{"version":"1.0","released_unix":0,"sha256":"{sha}","url":"u","tier":"pro"}}"#
    ));
    let extended = sign_manifest_payload(&format!(
        r#"{{"version":"1.0","released_unix":0,"sha256":"{sha}","url":"u","tier":"pro","min_client":"9.9.9","requires_reboot":true}}"#
    ));
    assert_ne!(plain, extended, "two different signed lines");
    assert_eq!(
        release::verify_manifest_with(&pk, &plain).expect("verifies"),
        release::verify_manifest_with(&pk, &extended).expect("verifies"),
        "an unknown field in a signed manifest is dropped without a word — a \
         future `min_client`/`requires_reboot` gate is invisible to today's \
         verifier instead of refusing to install"
    );

    // The revocation list, by contrast, refuses the same trick outright.
    let signed = vendor::sign_revocation_list_ed25519(&SEED, &revocation_list(0)).expect("signs");
    let parts: Vec<&str> = signed.split('.').collect();
    let mut json: Vec<u8> = b64url::decode(parts[3]).expect("own output");
    let extra = br#""surprise":1,"#;
    json.splice(1..1, extra.iter().copied());
    let payload_b64 = b64url::encode(&json);
    let input = format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], payload_b64);
    let sig = SigningKey::from_bytes(&SEED).sign(input.as_bytes());
    let forged = format!("{input}.{}", b64url::encode(&sig.to_bytes()));
    let err = vendor::verify_revocation_list_with(&pk, forged.as_bytes(), NOW)
        .expect_err("deny_unknown_fields must bite");
    assert!(
        err.to_string().contains("unknown field"),
        "expected a deny_unknown_fields refusal, got: {err}"
    );
}

/// **B64-3.** `verify_manifest_with` bounds nothing and decodes the whole
/// signature segment before it checks that the segment is 64 bytes. The
/// refusal message proves the ordering: it is the *length* complaint, which
/// is only reachable after `b64url::decode` has run to completion and
/// allocated `len * 3 / 4` bytes.
#[test]
fn an_unbounded_manifest_signature_segment_is_fully_decoded_before_it_is_length_checked() {
    let pk = public_key();
    let started = Instant::now();
    // 4 MiB of alphabet — a mirror can serve any size it likes; nothing in
    // `release.rs` looks at the length of the input, ever.
    let huge = "A".repeat(4 << 20);
    let line = format!("{MANIFEST_TAG}.AAAA.{huge}");
    let err = release::verify_manifest_with(&pk, &line).expect_err("must refuse");
    assert!(
        err.to_string()
            .contains("signature is not 64 base64url bytes"),
        "expected the post-decode length complaint, got: {err}"
    );
    // Same shape one layer over: the revocation verifier at least caps the
    // blob (vendor.rs:295) — but only at 1 MiB, and still decodes first.
    let over = vec![b'A'; MAX_REVOCATION_LIST_BYTES + 1];
    let err = vendor::verify_revocation_list_with(&pk, &over, NOW).expect_err("must refuse");
    assert!(
        err.to_string().contains("exceeds 1 MiB limit"),
        "expected the size cap, got: {err}"
    );
    eprintln!(
        "[manifest] 4 MiB unbounded-input probe: {:?} (no length bound exists)",
        started.elapsed()
    );
}

// ══════════════════════════════════════════════════════════════════════════
// 4. The layer above: revocation lists
// ══════════════════════════════════════════════════════════════════════════

/// A well-formed revocation list, `pad` extra characters in the key id so the
/// serialised length can be steered onto a chosen residue (mod 3).
fn revocation_list(pad: usize) -> RevocationList {
    RevocationList {
        version: REVOCATION_LIST_VERSION,
        key_id: format!("vendor-2026{}", "x".repeat(pad)),
        generated_at: NOW - 10,
        expires_at: Some(NOW + 86_400),
        entries: vec![
            RevocationEntry {
                license_id: Some("lic-0001".into()),
                token_sha256: None,
                revoked_at: NOW - 20,
                reason: RevocationReason::Compromised,
            },
            RevocationEntry {
                license_id: None,
                token_sha256: Some(vendor::token_sha256(b"a stolen token")),
                revoked_at: NOW - 30,
                reason: RevocationReason::Refunded,
            },
        ],
    }
}

fn revocation_with_residue(residue: usize) -> RevocationList {
    for pad in 0..3 {
        let l = revocation_list(pad);
        if serde_json::to_vec(&l).expect("serialises").len() % 3 == residue {
            return l;
        }
    }
    unreachable!("one of three paddings must hit residue {residue}")
}

/// The same malleability battery against the revocation list: re-spelling,
/// kid tampering, wrong scheme, truncation and appended junk. (Bit flips are
/// [`every_single_bit_flip_in_a_signed_revocation_list_is_refused`].)
#[test]
fn a_revocation_list_refuses_re_spelling_and_a_swapped_key_id() {
    let started = Instant::now();
    let pk = public_key();

    // Round-trip, and the fail-closed placeholder.
    let list = revocation_with_residue(0);
    let signed = vendor::sign_revocation_list_ed25519(&SEED, &list).expect("signs");
    assert_eq!(
        vendor::verify_revocation_list_with(&pk, signed.as_bytes(), NOW).expect("verifies"),
        list
    );
    assert!(vendor::verify_revocation_list_with(&[0u8; 32], signed.as_bytes(), NOW).is_err());
    assert!(vendor::verify_revocation_list_with(&[9u8; 32], signed.as_bytes(), NOW).is_err());

    // Non-canonical re-spelling of the payload segment, for both residues
    // that have spare bits at all.
    let mut respellings = 0usize;
    for (residue, free_bits) in [(1usize, 4u8), (2, 2)] {
        let list = revocation_with_residue(residue);
        let signed = vendor::sign_revocation_list_ed25519(&SEED, &list).expect("signs");
        let parts: Vec<&str> = signed.split('.').collect();
        assert_eq!(parts.len(), 5, "ccosrev1.ed25519.kid.payload.signature");
        let payload = parts[3];
        let last = val(payload.chars().last().expect("non-empty")).expect("symbol");
        let mask = (1u8 << free_bits) - 1;
        assert_eq!(last & mask, 0, "the signer emitted non-canonical padding");
        for d in 1..=mask {
            let respelled = with_last_symbol(payload, last | d);
            respellings += 1;
            assert!(
                b64url::decode(&respelled).is_none(),
                "the codec accepted a second spelling of a revocation payload"
            );
            let forged = format!(
                "{}.{}.{}.{}.{}",
                parts[0], parts[1], parts[2], respelled, parts[4]
            );
            let err = vendor::verify_revocation_list_with(&pk, forged.as_bytes(), NOW)
                .expect_err("must refuse");
            assert!(
                err.to_string().contains("bad revocation-list signature"),
                "expected the signature to catch it first, got: {err}"
            );
        }
    }
    assert_eq!(respellings, 15 + 3);

    let parts: Vec<String> = signed.split('.').map(str::to_string).collect();
    // The key id is signed into the envelope AND cross-checked against the
    // payload — tampering with it is refused on both counts.
    let swapped = format!(
        "{}.{}.{}.{}.{}",
        parts[0], parts[1], "vendor-2027", parts[3], parts[4]
    );
    assert!(vendor::verify_revocation_list_with(&pk, swapped.as_bytes(), NOW).is_err());
    // Wrong scheme prefix / algorithm.
    for (p, a) in [
        ("ccosrev2", "ed25519"),
        ("ccosrev1", "ed448"),
        ("ccoslic1", "ed25519"),
    ] {
        let forged = format!("{}.{}.{}.{}.{}", p, a, parts[2], parts[3], parts[4]);
        assert!(vendor::verify_revocation_list_with(&pk, forged.as_bytes(), NOW).is_err());
    }
    // Truncation: every proper prefix.
    for cut in 0..signed.len() {
        assert!(
            vendor::verify_revocation_list_with(&pk, &signed.as_bytes()[..cut], NOW).is_err(),
            "the first {cut} bytes of a revocation list must not verify"
        );
    }
    // An extra segment (5 parts is exact, not "at least").
    assert!(
        vendor::verify_revocation_list_with(&pk, format!("{signed}.AAAA").as_bytes(), NOW).is_err()
    );
    // Non-UTF-8 is refused before anything else looks at it.
    assert!(vendor::verify_revocation_list_with(&pk, &[0xFF, 0xFE, 0xFD], NOW).is_err());
    eprintln!("[revocation] tamper battery: {:?}", started.elapsed());
}

/// Flip bits in a signed revocation list's payload and signature; every
/// forgery must be refused. Returns how many forgeries were tried.
fn revocation_bit_flip_sweep(exhaustive: bool) -> usize {
    let pk = public_key();
    let signed =
        vendor::sign_revocation_list_ed25519(&SEED, &revocation_with_residue(0)).expect("signs");
    let parts: Vec<String> = signed.split('.').map(str::to_string).collect();
    let payload = b64url::decode(&parts[3]).expect("own output");
    let sig = b64url::decode(&parts[4]).expect("own output");
    assert_eq!(sig.len(), 64);

    let mut tried = 0usize;
    for (i, bit) in flip_positions(payload.len(), exhaustive) {
        let mut forged_payload = payload.clone();
        forged_payload[i] ^= 1 << bit;
        let forged = format!(
            "{}.{}.{}.{}.{}",
            parts[0],
            parts[1],
            parts[2],
            b64url::encode(&forged_payload),
            parts[4]
        );
        assert!(
            vendor::verify_revocation_list_with(&pk, forged.as_bytes(), NOW).is_err(),
            "payload byte {i} bit {bit} flipped and the list still verified"
        );
        tried += 1;
    }
    for (i, bit) in flip_positions(sig.len(), true) {
        let mut forged_sig = sig.clone();
        forged_sig[i] ^= 1 << bit;
        let forged = format!(
            "{}.{}.{}.{}.{}",
            parts[0],
            parts[1],
            parts[2],
            parts[3],
            b64url::encode(&forged_sig)
        );
        assert!(
            vendor::verify_revocation_list_with(&pk, forged.as_bytes(), NOW).is_err(),
            "signature byte {i} bit {bit} flipped and the list still verified"
        );
        tried += 1;
    }
    tried
}

/// Every single-bit flip in the revocation list's signature (all 512) and
/// across every byte of its payload is refused.
#[test]
fn every_single_bit_flip_in_a_signed_revocation_list_is_refused() {
    let started = Instant::now();
    let tried = revocation_bit_flip_sweep(false);
    assert!(tried > 512, "the payload must be swept too");
    eprintln!(
        "[revocation] {tried} single-bit forgeries refused in {:?}",
        started.elapsed()
    );
}

/// The exhaustive twin of the two sweeps above: every bit of every payload
/// byte, not just every byte. Split out because one ed25519 verification
/// costs ~9 ms unoptimised and CI runs this file in the dev profile.
#[test]
#[ignore = "~45 s of ed25519 in debug. Run: cargo test -p ccos-enterprise-conformance \
            --test stress_b64url_malleability -- --ignored --nocapture"]
fn exhaustive_single_bit_flip_sweep_of_both_signed_artifacts() {
    let started = Instant::now();
    let tried = manifest_bit_flip_sweep(true) + revocation_bit_flip_sweep(true);
    eprintln!(
        "[both] {tried} exhaustive single-bit forgeries refused in {:?}",
        started.elapsed()
    );
}

/// **B64-2, revocation half.** `vendor.rs:295` caps the blob at 1 MiB, then
/// `vendor.rs:300-302` trims it — in that order. So a ~400-byte list has a
/// legal ~1 MiB spelling, and the cap protects nothing it was meant to: the
/// verifier still has to hold a megabyte of attacker-chosen padding, and a
/// digest taken over the fetched blob is meaningless.
#[test]
fn a_tiny_revocation_list_has_a_legal_one_mebibyte_spelling() {
    let pk = public_key();
    let list = revocation_list(0);
    let signed = vendor::sign_revocation_list_ed25519(&SEED, &list).expect("signs");
    assert!(signed.len() < 600, "the honest list is a few hundred bytes");

    // Exactly at the cap: accepted.
    let padded = format!(
        "{signed}{}",
        " ".repeat(MAX_REVOCATION_LIST_BYTES - signed.len())
    );
    assert_eq!(padded.len(), MAX_REVOCATION_LIST_BYTES);
    assert_eq!(
        vendor::verify_revocation_list_with(&pk, padded.as_bytes(), NOW).expect("accepted"),
        list,
        "a megabyte of blanks is a legal spelling of a 400-byte list"
    );
    let inflation = padded.len() as f64 / signed.len() as f64;
    assert!(inflation > 1_500.0, "inflation factor {inflation}");

    // One byte over: refused by the cap, not by the trim.
    let over = format!("{padded} ");
    assert!(vendor::verify_revocation_list_with(&pk, over.as_bytes(), NOW).is_err());

    // Non-ASCII blanks work too — the trim is Unicode-aware.
    let nbsp = format!("\u{a0}\u{3000}{signed}\u{2028}");
    assert_eq!(
        vendor::verify_revocation_list_with(&pk, nbsp.as_bytes(), NOW).expect("accepted"),
        list
    );
    // A NUL is not White_Space, so it is fatal — the one junk byte that is.
    assert!(
        vendor::verify_revocation_list_with(&pk, format!("{signed}\0").as_bytes(), NOW).is_err()
    );
}

// ══════════════════════════════════════════════════════════════════════════
// 5. B64-1 — the format the codec claims parity with is malleable
// ══════════════════════════════════════════════════════════════════════════

/// **B64-1 (high).** `lib.rs:28-30` justifies this crate's private copy of the
/// codec with "alphabet and semantics identical to the license token format so
/// wire formats stay compatible". The alphabet matches. The semantics do not:
///
/// | decoder | padding-bit check |
/// |---|---|
/// | `ccos_enterprise_governance::b64url::decode` (`lib.rs:84-92`) | **yes** |
/// | `ccos_core::license::b64url_decode` (`CCOS-Core/src/license.rs:258-288`) | **no** |
///
/// The second one is what parses the license tokens *this crate mints*
/// (`Ed25519Verifier::verify`, `license.rs:353-365`). An ed25519 signature is
/// 64 bytes and 64 % 3 == 1, so the signature segment ends in a two-symbol
/// group whose final symbol has 4 bits that carry no data. This test builds
/// all 16 spellings of one real token and shows, without leaving this crate:
///
/// * the 16 strings are pairwise distinct, and differ only in bits that carry
///   no signature data (asserted arithmetically against the alphabet);
/// * the signature bytes they all denote verify under ed25519 — so *any*
///   decoder that maps them to those bytes accepts all 16 tokens;
/// * their `vendor::token_sha256` digests are 16 distinct values — and
///   `RevocationEntry::token_sha256` revokes exactly that digest, so an
///   offline revocation by digest is defeated by editing one character;
/// * this crate's own decoder refuses 15 of the 16, which is the divergence.
///
/// The remaining link — that `ccos-core` really does accept all 16 — cannot
/// be asserted here (this package does not depend on `ccos-core`, and
/// `b64url_decode` is `pub(crate)` in any case). It was measured
/// out-of-tree against `Ed25519Verifier::with_public_key(&pk).verify(...)`:
/// **16/16 accepted**, each yielding `licensee: "acme"` with the same bound
/// machine fingerprint, while this crate's decoder accepted **1/16**. Adding
/// `ccos-core` to this package's dev-dependencies would let the assertion
/// move in here; that is a one-line `Cargo.toml` change this file is not
/// permitted to make.
#[test]
fn a_license_token_has_sixteen_wire_spellings_and_sixteen_distinct_digests() {
    let pk = public_key();
    let vk = VerifyingKey::from_bytes(&pk).expect("valid key");
    let token = vendor::sign_token_bound(&SEED, "acme", Some(NOW + 86_400), Some("fingerprint"));
    let (payload, sig_b64) = token.split_once('.').expect("payload.signature");

    // 64 bytes → 21 full groups + one two-symbol group = 86 symbols, and the
    // final symbol's low 4 bits are structurally free.
    assert_eq!(
        sig_b64.len(),
        86,
        "an ed25519 signature is 86 base64url symbols"
    );
    assert_eq!(sig_b64.len() % 4, 2, "…ending in a two-symbol group");
    let sig_bytes = to_sig(sig_b64);
    let last = val(sig_b64.chars().last().expect("non-empty")).expect("symbol");
    assert_eq!(last & 0x0F, 0, "the signer emits the canonical spelling");

    // Any decoder maps all 16 to the same byte: value = (prev << 2) | (last >> 4).
    let prev = val(sig_b64.chars().nth(84).expect("84th symbol")).expect("symbol");
    assert_eq!(
        sig_bytes[63],
        (prev << 2) | (last >> 4),
        "the final byte comes from the top 2 bits of the final symbol only"
    );

    let mut spellings = Vec::new();
    let mut accepted_by_this_crate = 0usize;
    for d in 0..16u8 {
        let respelled_sig = with_last_symbol(sig_b64, last | d);
        let spelling = format!("{payload}.{respelled_sig}");
        // Every spelling denotes the identical 64 signature bytes: the only
        // difference is in the 4 bits the codec calls padding.
        assert_eq!(
            (prev << 2) | ((last | d) >> 4),
            sig_bytes[63],
            "spelling {d} changes a signature byte — the model is wrong"
        );
        // This crate's decoder accepts exactly the canonical one…
        match b64url::decode(&respelled_sig) {
            Some(bytes) => {
                accepted_by_this_crate += 1;
                assert_eq!(d, 0, "a non-canonical spelling slipped past b64url::decode");
                assert_eq!(bytes, sig_bytes.to_vec());
            }
            None => assert_ne!(d, 0, "the canonical spelling was refused"),
        }
        spellings.push(spelling);
    }
    assert_eq!(
        accepted_by_this_crate, 1,
        "this crate's codec is canonical — it is `ccos_core`'s that is not"
    );

    // …and the signature those 16 spellings all denote is a *good* signature,
    // so a decoder without the padding check (CCOS-Core/src/license.rs:258)
    // accepts all 16 as the same, valid, machine-bound license.
    assert!(
        vk.verify(payload.as_bytes(), &Signature::from_bytes(&sig_bytes))
            .is_ok(),
        "the token must be genuinely valid for the finding to bite"
    );

    // The payload half is NOT malleable this way: the signature is taken over
    // the payload's ASCII, so re-spelling it breaks the signature. Only the
    // signature segment — which nothing signs — is free.
    let payload_last = val(payload.chars().last().expect("non-empty")).expect("symbol");
    if payload.len() % 4 == 2 {
        let respelled = with_last_symbol(payload, payload_last | 1);
        assert!(vk
            .verify(respelled.as_bytes(), &Signature::from_bytes(&sig_bytes))
            .is_err());
    }

    // The impact: 16 wire strings, 16 digests, one license.
    let unique: HashSet<&String> = spellings.iter().collect();
    assert_eq!(
        unique.len(),
        16,
        "the 16 spellings must be distinct strings"
    );
    let digests: HashSet<String> = spellings
        .iter()
        .map(|s| vendor::token_sha256(s.as_bytes()))
        .collect();
    assert_eq!(
        digests.len(),
        16,
        "16 distinct token_sha256 values for one license — a revocation list \
         keyed on RevocationEntry::token_sha256 catches at most one of them"
    );

    // And `trim()` in the verifiers multiplies each of those by every finite
    // string of Unicode blanks: the digest of a token is not a stable identity
    // for the token at all.
    let with_blank = format!("{}\u{a0}", spellings[0]);
    assert_ne!(
        vendor::token_sha256(with_blank.as_bytes()),
        vendor::token_sha256(spellings[0].as_bytes())
    );
}
