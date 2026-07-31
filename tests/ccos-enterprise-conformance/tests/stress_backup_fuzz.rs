//! # Hostile stress of the restore gate — 200 000 digests, the full schema
//! # matrix, and the backup that verifies nothing
//!
//! `crates/ccos-enterprise-backup/src/lib.rs:5` opens with the product's
//! integrity promise, repeated in `docs/BACKUP_AND_RESTORE.md`:
//!
//! > a backup that cannot verify its digest is not a backup
//!
//! and `docs/DISASTER_RECOVERY.md:8` builds the recovery procedure on it
//! ("Restore latest manifest passing all gates"). This file attacks that
//! promise with 200 000 generated digests (fixed seed, ten adversarial
//! families, every length 0..=130), a 9x9 schema cross-product taken to
//! `u32::MAX` and its neighbours, every segment count that matters, the JSON
//! wire form, and a 4 MiB digest.
//!
//! Everything asserted below is the product's **current, real** behaviour.
//! Where that behaviour is a defect the assertion pins the defect and the
//! comment names it, so a repair fails loudly here instead of silently
//! changing the security posture.
//!
//! ## What HELD (and why)
//!
//! * **The digest *shape* rule is exactly right, and nothing gets past it.**
//!   `restorable_by` (`crates/ccos-enterprise-backup/src/lib.rs:25-29`) tests
//!   `digest.len() == 64` over **bytes** and then requires every byte to be
//!   `is_ascii_hexdigit() && !is_ascii_uppercase()` — i.e. exactly `[0-9a-f]`.
//!   Across 200 000 generated digests spanning all 131 lengths in 0..=130 it
//!   agreed, case for case, with an independently written **character**-based
//!   oracle (`spec_lowercase_64_hex`): 20 000 accepted (all 20 000 distinct),
//!   180 000 refused, zero disagreements. A further 6 976 single-character
//!   substitutions — every hostile character at every one of the 64 positions
//!   — were refused without exception. Uppercase, mixed
//!   case, `g`-`z`, `0x`/`sha256:` prefixes, quotes, embedded NUL, every
//!   control byte, ASCII and Unicode whitespace, Arabic-Indic / Devanagari /
//!   Thai / full-width / mathematical-bold digits, Cyrillic homoglyphs and
//!   raw astral junk are all refused.
//! * **The byte-length check cannot be walked around with multi-byte text.**
//!   The nastiest shape — 62 ASCII hex + one 2-byte Arabic-Indic digit, which
//!   is **64 bytes but only 63 characters** — passes the `len() == 64` test
//!   and is then killed by the per-byte ASCII test. Same for 32 two-byte
//!   characters (64 bytes, 32 chars) and for 64 characters that are 65+ bytes.
//!   -> [`byte_and_character_length_confusions_are_all_refused`]
//! * **The refusal string never echoes attacker-controlled input.** A digest
//!   carrying a fake log line, ANSI escapes or NUL bytes produces the same
//!   fixed `"manifest digest is not lowercase 64-hex"`, and the tenant field
//!   is never quoted into any message. No log-injection surface here.
//! * **The gate is pure, order-independent and short-circuiting.** 2 000
//!   repeated calls on the same manifest return the same verdict; a clone
//!   verdicts identically; and a 4 MiB digest is refused without scanning it
//!   (`len() == 64` short-circuits), so an oversized digest is not a CPU
//!   amplifier.
//! * **The schema gate is exactly `schema_version <= build_schema`**, with no
//!   wrap-around or off-by-one at 0, 1, `u32::MAX-1` or `u32::MAX`: 81
//!   version pairs x 3 segment counts x 2 digest shapes, all as specified.
//! * **`serde` refuses out-of-range and mistyped wire values** (`segments`
//!   = 2^32, `-1`, `1.5`, a numeric `digest`, a missing field) rather than
//!   truncating them.
//! * **The two independent copies of the "is this a sha256?" rule agree.**
//!   `ccos_enterprise_governance::claim::is_sha256_hex` and the inline check
//!   in `restorable_by` are byte-for-byte the same rule in two crates; they
//!   returned identical answers on all 200 000 inputs. (That they are
//!   *duplicated* is the hazard — see BROKE 6.)
//!
//! ## What BROKE
//!
//! 1. **CRITICAL — the restore gate validates the *shape* of a digest and
//!    nothing else. No byte of content is ever hashed or compared, so a
//!    perfectly fabricated digest restores.** `restorable_by(&self,
//!    build_schema: u32)` (`crates/ccos-enterprise-backup/src/lib.rs:24`)
//!    receives no content, no reader, no segment list and no expected value —
//!    the signature makes verification *impossible*, not merely absent. A
//!    manifest whose digest is the real SHA-256 of the real segments, one
//!    whose digest is the real SHA-256 of **completely different** bytes, one
//!    whose digest is the hand-typed `deadbeef…`, one that is 64 zeros and one
//!    that is the SHA-256 of the empty input are all accepted, and all
//!    accepted *identically* — `Ok(())` is indistinguishable in every case.
//!    The doc's "a backup that cannot verify its digest is not a backup" is
//!    therefore not implemented: nothing in the workspace can verify a digest.
//!    -> [`fabricated_digest_restores_because_no_byte_of_content_is_ever_hashed`]
//!
//! 2. **The gate never consults `manifest.tenant` — there is no tenant
//!    binding on a restore in a multi-tenant product.** The verdict is
//!    bit-identical for tenant `"acme"`, `"globex"`, `""`, `"\0"`,
//!    `"../../etc/shadow"`, a 1 MiB name and a name carrying newlines. Nothing
//!    in the type or the gate ties a manifest to the tenant restoring it, and
//!    `restorable_by` takes no actor, no `TenantId` and no `Deployment`, so
//!    none of the six layers of `docs/ENTERPRISE_SECURITY_MODEL.md` is on the
//!    restore path at all. `backup.restore` is not even in the gateway
//!    catalogue, so restore cannot be governed, audited or budgeted the way
//!    every other capability is.
//!    -> [`restore_gate_never_consults_the_tenant_and_is_outside_the_governed_path`]
//!
//! 3. **`created_unix` is attacker-controlled, unvalidated, and load-bearing
//!    for disaster recovery.** `docs/DISASTER_RECOVERY.md:8` says "restore
//!    latest manifest passing all gates". "Latest" is read straight off the
//!    manifest, and `u64::MAX` is accepted — a value nothing legitimate can
//!    ever exceed (`u64::MAX.checked_add(1) == None`). Combined with BROKE 1
//!    and 2, a single planted manifest with a fabricated digest and
//!    `created_unix = u64::MAX` is selected by the documented procedure over
//!    every genuine backup, permanently.
//!    -> [`dr_latest_manifest_selection_prefers_a_planted_future_manifest`]
//!
//! 4. **EXHAUSTION VECTOR — `segments` has a floor but no ceiling and no
//!    relationship to anything.** `segments == 0` is refused; `segments ==
//!    u32::MAX` (4 294 967 295) is accepted, from an unsigned manifest, with a
//!    digest that was demonstrably computed over three segments. The gate is
//!    the only thing standing between an unauthenticated manifest and the
//!    restore driver, so any per-segment allocation downstream is handed
//!    4.29e9 work items by a 200-byte JSON file.
//!    -> [`segments_matrix_has_a_floor_but_no_ceiling_and_no_cross_check`]
//!
//! 5. **The manifest is unsigned, and its wire form accepts unknown fields.**
//!    There is no signature, MAC or key id anywhere in `BackupManifest`
//!    (`crates/ccos-enterprise-backup/src/lib.rs:11-19`), and JSON carrying a
//!    `"signature"` field parses happily into a manifest that will never look
//!    at it (no `deny_unknown_fields`) — an operator can be shown a signed-
//!    looking document that restores unverified. Duplicate `digest` keys *are*
//!    refused by the derived deserializer (that HELD), but a generic
//!    `serde_json::Value` reader — what a signer or auditor built on untyped
//!    JSON would use — silently keeps the **last** one. Fail-closed today,
//!    a parser-differential the moment signing is added.
//!    -> [`json_wire_form_is_unsigned_and_lenient_but_refuses_duplicate_digest_keys`]
//!
//! 6. **The sha256-shape rule is duplicated, not shared.** It exists twice,
//!    verbatim: `crates/ccos-enterprise-backup/src/lib.rs:25-29` and
//!    `crates/ccos-enterprise-governance/src/claim.rs:188-192`. They agree
//!    today; nothing makes them agree tomorrow.
//!    -> [`the_hex_rule_is_duplicated_across_two_crates_and_agrees_only_by_luck`]
//!
//! 7. **Minor — no schema floor and first-failure-only reporting.** A
//!    `schema_version` of 0 is restorable by a build at `u32::MAX`: there is
//!    no deprecation window, so a pre-versioning snapshot is forever
//!    restorable. And the gate reports only the *first* failure (digest, then
//!    segments, then schema), so an operator triaging a future-schema backup
//!    with a malformed digest is told only about the digest.
//!    -> [`schema_has_no_floor_and_only_the_first_failure_is_reported`]
//!
//! Runtime: 0.9 s in debug, 0.15 s in release. Nothing is `#[ignore]`d.

use std::collections::{BTreeMap, BTreeSet};

use ccos_enterprise_auth::AuthStrength;
use ccos_enterprise_backup::BackupManifest;
use ccos_enterprise_conformance::{actor, request, two_tenant_deployment, Call, Refusal};
use ccos_enterprise_governance::claim::is_sha256_hex;
use ccos_enterprise_governance::vendor::token_sha256;

// ── Deterministic machinery ──────────────────────────────────────────────

/// SplitMix64. Fixed seed, no wall clock, no thread-local state: the corpus
/// below is byte-identical on every machine, in debug and in release.
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

    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[self.below(xs.len())]
    }
}

/// The **specification**, written independently of the implementation: a
/// digest is acceptable iff it is exactly 64 *characters* and every character
/// is `0`-`9` or `a`-`f`.
///
/// Deliberately character-based where `restorable_by` is byte-based
/// (`crates/ccos-enterprise-backup/src/lib.rs:25-29`), so the 200 000-case
/// differential below is a real cross-check and not a copy of the code under
/// test: any byte/char confusion in either direction shows up as a mismatch.
fn spec_lowercase_64_hex(s: &str) -> bool {
    let mut n = 0usize;
    for c in s.chars() {
        n += 1;
        if n > 64 {
            return false;
        }
        if !matches!(c, '0'..='9' | 'a'..='f') {
            return false;
        }
    }
    n == 64
}

/// A manifest that is valid in every field except the one under attack.
fn manifest(digest: &str, segments: u32, schema_version: u32) -> BackupManifest {
    BackupManifest {
        tenant: "acme".into(),
        created_unix: 1_700_000_000,
        digest: digest.to_string(),
        segments,
        schema_version,
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex_digest(rng: &mut Rng, len: usize) -> String {
    (0..len).map(|_| HEX[rng.below(16)] as char).collect()
}

/// ASCII that is *not* lowercase hex — including the hex-adjacent traps.
const NON_HEX_ASCII: &[char] = &[
    'g', 'h', 'i', 'j', 'o', 'q', 's', 'u', 'w', 'y', 'z', 'G', 'S', 'Z', 'x', 'X', 'O', 'l', 'I',
    '+', '/', '=', '-', '_', '.', ',', ':', ';', '\'', '"', '\\', '*', '#', '%', '$', '@', '!',
    '?', '(', ')', '[', ']', '{', '}', '<', '>', '~', '`', '^', '&', '|',
];

/// Uppercase hex — the single most likely "legitimate" digest to arrive from
/// another tool, and refused outright.
const UPPER_HEX: &[char] = &['A', 'B', 'C', 'D', 'E', 'F', '0', '1', '9'];

/// Control bytes, NUL first.
const CONTROL: &[char] = &[
    '\0', '\u{1}', '\u{7}', '\u{8}', '\t', '\n', '\u{b}', '\u{c}', '\r', '\u{1b}', '\u{1f}',
    '\u{7f}',
];

/// ASCII and Unicode whitespace / invisibles.
const SPACEY: &[char] = &[
    ' ', '\t', '\n', '\r', '\u{a0}', '\u{2000}', '\u{2028}', '\u{202f}', '\u{3000}', '\u{200b}',
    '\u{feff}',
];

/// "Digits" that are not ASCII digits: Arabic-Indic, extended Arabic-Indic,
/// Devanagari, Thai, full-width, mathematical bold/monospace, superscripts,
/// subscripts, enclosed and Roman numerals.
const UNICODE_DIGITS: &[char] = &[
    '\u{660}',   // ٠ Arabic-Indic zero
    '\u{661}',   // ١
    '\u{669}',   // ٩
    '\u{6f0}',   // ۰ extended Arabic-Indic zero
    '\u{966}',   // ० Devanagari zero
    '\u{e50}',   // ๐ Thai zero
    '\u{ff10}',  // ０ full-width zero
    '\u{ff11}',  // １
    '\u{ff19}',  // ９
    '\u{ff41}',  // ａ full-width latin a
    '\u{ff46}',  // ｆ full-width latin f
    '\u{1d7ce}', // 𝟎 mathematical bold digit zero
    '\u{1d7f6}', // 𝟶 mathematical monospace digit zero
    '\u{b9}',    // ¹
    '\u{b2}',    // ²
    '\u{2070}',  // ⁰
    '\u{2080}',  // ₀
    '\u{24ea}',  // ⓪
    '\u{2460}',  // ①
    '\u{2170}',  // ⅰ
];

/// Homoglyphs for hex characters — Cyrillic and full-width look-alikes.
const HOMOGLYPHS: &[char] = &[
    '\u{430}',   // а Cyrillic a
    '\u{435}',   // е Cyrillic e
    '\u{441}',   // с Cyrillic c
    '\u{432}',   // в
    '\u{4bb}',   // һ
    '\u{ff42}',  // ｂ
    '\u{ff43}',  // ｃ
    '\u{ff44}',  // ｄ
    '\u{1d41a}', // 𝐚 mathematical bold a
];

const PREFIXES: &[&str] = &[
    "0x",
    "0X",
    "sha256:",
    "sha256-",
    "SHA256:",
    "\"",
    "'",
    "\\x",
    "#",
    "@",
    "urn:sha256:",
];

const SUFFIXES: &[&str] = &["\"", "'", ";", ",", ")", "\n", "\0", " ", "=", "..."];

// ── 1. The 200 000-digest differential fuzz ──────────────────────────────

/// Ten adversarial families, 20 000 cases each, generated from a fixed seed.
///
/// The oracle is [`spec_lowercase_64_hex`]; the assertion is a strict
/// equivalence, so this test fails both when something illegitimate is
/// accepted **and** when something legitimate is refused. It also cross-checks
/// the other copy of the rule (`claim::is_sha256_hex`) on every input, and
/// re-runs every case against a second gate configuration to prove the digest
/// verdict is independent of `segments` and `schema_version`.
#[test]
fn two_hundred_thousand_digests_only_lowercase_64_hex_is_ever_accepted() {
    const CASES: usize = 200_000;
    const FAMILIES: usize = 10;
    const FAMILY_NAMES: [&str; FAMILIES] = [
        "valid-lowercase-64-hex",
        "hex-of-every-length-0..=130",
        "mixed-and-upper-case",
        "whitespace-padded",
        "control-and-embedded-NUL",
        "prefixed-and-suffixed",
        "unicode-digits",
        "homoglyphs-and-non-hex-ascii",
        "raw-random-unicode",
        "byte-vs-char-length-confusion",
    ];

    let mut rng = Rng::new(0x0BAC_C0DE_5EED_1234);
    let mut accepted = 0usize;
    let mut refused = 0usize;
    let mut spec_valid = 0usize;
    let mut distinct_accepted: BTreeSet<String> = BTreeSet::new();
    let mut per_family_accepted = [0usize; FAMILIES];
    let mut lengths_seen: BTreeSet<usize> = BTreeSet::new();

    // One manifest, mutated in place: the corpus is the subject, not the
    // allocator.
    let mut m = manifest("", 1, 1);

    for i in 0..CASES {
        let family = i % FAMILIES;
        let digest = generate(&mut rng, family, i);
        lengths_seen.insert(digest.chars().count());

        let expected = spec_lowercase_64_hex(&digest);
        if expected {
            spec_valid += 1;
        }

        // The other copy of the same rule, in another crate.
        assert_eq!(
            is_sha256_hex(&digest),
            expected,
            "governance::claim::is_sha256_hex disagrees with the spec on {digest:?} \
             (family {})",
            FAMILY_NAMES[family]
        );

        m.digest = digest;
        m.segments = 1;
        m.schema_version = 1;
        let verdict = m.restorable_by(1);

        assert_eq!(
            verdict.is_ok(),
            expected,
            "restore gate disagrees with the spec on {:?} (family {}, {} chars, {} bytes)",
            m.digest,
            FAMILY_NAMES[family],
            m.digest.chars().count(),
            m.digest.len()
        );

        if let Err(why) = &verdict {
            assert_eq!(
                why, "manifest digest is not lowercase 64-hex",
                "a refused digest must be refused *for its shape*, and the message \
                 must not vary with the input"
            );
        }

        // The digest verdict must not depend on any other field: same input,
        // the widest legal segment count and the oldest possible schema
        // against the newest possible build.
        m.segments = u32::MAX;
        m.schema_version = 0;
        assert_eq!(
            m.restorable_by(u32::MAX).is_ok(),
            expected,
            "digest verdict changed with segments/schema for {:?}",
            m.digest
        );

        if expected {
            accepted += 1;
            per_family_accepted[family] += 1;
            distinct_accepted.insert(std::mem::take(&mut m.digest));
        } else {
            refused += 1;
        }
    }

    // Coverage: this test must never be able to pass vacuously.
    assert_eq!(accepted + refused, CASES);
    assert_eq!(accepted, spec_valid);
    assert_eq!(
        per_family_accepted[0], 20_000,
        "family 0 is 20 000 well-formed digests and every one must restore"
    );
    assert!(
        accepted >= 20_000,
        "at least the valid family must be accepted, got {accepted}"
    );
    assert!(
        refused >= 170_000,
        "the hostile families must all be refused, got {refused}"
    );
    assert!(
        distinct_accepted.len() >= 19_900,
        "the accepted corpus must be genuinely varied, got {} distinct",
        distinct_accepted.len()
    );
    for (family, name) in FAMILY_NAMES.iter().enumerate().skip(1) {
        assert_eq!(
            per_family_accepted[family], 0,
            "hostile family {name} must contribute zero accepted digests"
        );
    }
    // Every length in 0..=130 was exercised (family 1 sweeps them).
    for len in 0..=130usize {
        assert!(lengths_seen.contains(&len), "length {len} never generated");
    }

    println!(
        "backup digest fuzz: {CASES} cases, {accepted} accepted ({} distinct), {refused} refused, \
         {} distinct lengths",
        distinct_accepted.len(),
        lengths_seen.len()
    );
}

/// The corpus generator. `i` is folded in so the sweeps are exhaustive rather
/// than merely probable.
fn generate(rng: &mut Rng, family: usize, i: usize) -> String {
    match family {
        // Well-formed: the only family that may ever be accepted.
        0 => hex_digest(rng, 64),

        // All-hex, every length 0..=130 in turn (64 excluded — it belongs to
        // family 0 and would make the family counters lie).
        1 => {
            let mut len = (i / 10) % 131;
            if len == 64 {
                len = 65;
            }
            hex_digest(rng, len)
        }

        // Mixed / upper case, at least one uppercase guaranteed.
        2 => {
            let mut s: Vec<char> = hex_digest(rng, 64).chars().collect();
            let flips = 1 + rng.below(8);
            for _ in 0..flips {
                let at = rng.below(64);
                s[at] = rng.pick(UPPER_HEX).to_ascii_uppercase();
            }
            // Guarantee at least one A-F/uppercase letter survives.
            s[rng.below(64)] = rng.pick(&['A', 'B', 'C', 'D', 'E', 'F']);
            s.into_iter().collect()
        }

        // Whitespace padded / interleaved, including forms whose total length
        // is still exactly 64.
        3 => {
            let ws = rng.pick(SPACEY);
            match rng.below(5) {
                0 => format!("{ws}{}", hex_digest(rng, 64)),
                1 => format!("{}{ws}", hex_digest(rng, 64)),
                2 => format!("{ws}{}{ws}", hex_digest(rng, 64)),
                3 => format!("{ws}{}", hex_digest(rng, 63)), // 64 chars total
                _ => {
                    let mut s: Vec<char> = hex_digest(rng, 64).chars().collect();
                    s[rng.below(64)] = ws;
                    s.into_iter().collect()
                }
            }
        }

        // Control bytes and embedded NUL, at a random position.
        4 => {
            let mut s: Vec<char> = hex_digest(rng, 64).chars().collect();
            let c = rng.pick(CONTROL);
            match rng.below(3) {
                0 => s[0] = c,
                1 => s[63] = c,
                _ => s[rng.below(64)] = c,
            }
            s.into_iter().collect()
        }

        // "0x"-prefixed and friends.
        5 => {
            let p = rng.pick(PREFIXES);
            let s = rng.pick(SUFFIXES);
            match rng.below(4) {
                0 => format!("{p}{}", hex_digest(rng, 64)),
                // Keeps the total at 64 characters — the interesting one.
                1 => format!("{p}{}", hex_digest(rng, 64 - p.chars().count())),
                2 => format!("{}{s}", hex_digest(rng, 64)),
                _ => format!("{p}{}{s}", hex_digest(rng, 62)),
            }
        }

        // Unicode digits substituted into an otherwise perfect digest.
        6 => {
            let mut s: Vec<char> = hex_digest(rng, 64).chars().collect();
            let n = 1 + rng.below(3);
            for _ in 0..n {
                let at = rng.below(64);
                s[at] = rng.pick(UNICODE_DIGITS);
            }
            s.into_iter().collect()
        }

        // Homoglyphs and non-hex ASCII.
        7 => {
            let mut s: Vec<char> = hex_digest(rng, 64).chars().collect();
            let at = rng.below(64);
            s[at] = if rng.below(2) == 0 {
                rng.pick(HOMOGLYPHS)
            } else {
                rng.pick(NON_HEX_ASCII)
            };
            s.into_iter().collect()
        }

        // Raw random text of random length, from the whole scalar range.
        8 => {
            let len = rng.below(131);
            (0..len)
                .map(|_| {
                    let v = rng.below(0x11_0000);
                    char::from_u32(v as u32).unwrap_or('\u{fffd}')
                })
                .collect()
        }

        // Byte-length vs character-length confusion: strings whose *byte*
        // length is exactly 64 but whose character length is not, and vice
        // versa. This is the family that would find a `chars().count() == 64`
        // regression, or a `len() == 64`-only regression.
        _ => {
            let wide = rng.pick(&['\u{660}', '\u{ff10}', '\u{1d7ce}', '\u{a0}', '\u{4bb}']);
            let w = wide.len_utf8();
            match rng.below(4) {
                // 64 bytes, fewer than 64 chars.
                0 => {
                    let ascii = 64 - w;
                    format!("{}{wide}", hex_digest(rng, ascii))
                }
                // 64 chars, more than 64 bytes.
                1 => format!("{}{wide}", hex_digest(rng, 63)),
                // Exactly 64 bytes made only of wide characters where the
                // width divides 64.
                2 => {
                    let c = if 64 % w == 0 { wide } else { '\u{660}' };
                    let n = 64 / c.len_utf8();
                    std::iter::repeat_n(c, n).collect()
                }
                // 63 bytes / 63 chars — the near miss.
                _ => hex_digest(rng, 63),
            }
        }
    }
}

// ── 2. Systematic sweeps ─────────────────────────────────────────────────

/// Every length from 0 to 130, all-lowercase-hex: exactly one is restorable.
#[test]
fn digest_length_sweep_zero_to_one_hundred_thirty() {
    let mut rng = Rng::new(0xA111_E467);
    let mut accepted_lengths = Vec::new();
    for len in 0..=130usize {
        let digest = hex_digest(&mut rng, len);
        assert_eq!(digest.chars().count(), len);
        let m = manifest(&digest, 1, 1);
        if m.restorable_by(1).is_ok() {
            accepted_lengths.push(len);
        }
    }
    assert_eq!(
        accepted_lengths,
        vec![64],
        "only a 64-character digest may restore"
    );
}

/// For every one of the 64 positions, substitute every hostile character: the
/// gate must refuse all 64 x N of them. A "check only the first/last k bytes"
/// regression dies here.
#[test]
fn every_position_rejects_every_hostile_character() {
    let mut rng = Rng::new(0x5B57_1717);
    let base: Vec<char> = hex_digest(&mut rng, 64).chars().collect();
    assert!(manifest(&base.iter().collect::<String>(), 1, 1)
        .restorable_by(1)
        .is_ok());

    let hostile: Vec<char> = NON_HEX_ASCII
        .iter()
        .chain(UPPER_HEX.iter().filter(|c| c.is_ascii_uppercase()))
        .chain(CONTROL.iter())
        .chain(SPACEY.iter())
        .chain(UNICODE_DIGITS.iter())
        .chain(HOMOGLYPHS.iter())
        .copied()
        .collect();

    let mut checked = 0usize;
    for pos in 0..64 {
        for &c in &hostile {
            let mut s = base.clone();
            s[pos] = c;
            let digest: String = s.into_iter().collect();
            assert!(
                manifest(&digest, 1, 1).restorable_by(1).is_err(),
                "position {pos} accepted {c:?} (U+{:04X})",
                c as u32
            );
            checked += 1;
        }
    }
    assert!(checked >= 64 * 90, "coverage: only {checked} substitutions");
    println!("position sweep: {checked} single-character substitutions, all refused");
}

/// The shapes that exist to defeat a length check written in the wrong unit.
///
/// `restorable_by` measures **bytes** (`String::len`); the spec is in
/// **characters**. They coincide only because every accepted byte is ASCII —
/// which the second half of the check enforces. Both halves are load-bearing,
/// and this test says so case by case.
#[test]
fn byte_and_character_length_confusions_are_all_refused() {
    // 64 BYTES, 63 characters: passes `len() == 64`, killed by the ASCII test.
    let sixty_four_bytes_63_chars = format!("{}\u{660}", "a".repeat(62));
    assert_eq!(sixty_four_bytes_63_chars.len(), 64);
    assert_eq!(sixty_four_bytes_63_chars.chars().count(), 63);
    assert!(
        manifest(&sixty_four_bytes_63_chars, 1, 1)
            .restorable_by(1)
            .is_err(),
        "a 64-BYTE, 63-character digest must not restore"
    );

    // 64 BYTES, 32 characters (all two-byte).
    let all_wide: String = std::iter::repeat_n('\u{660}', 32).collect();
    assert_eq!(all_wide.len(), 64);
    assert_eq!(all_wide.chars().count(), 32);
    assert!(manifest(&all_wide, 1, 1).restorable_by(1).is_err());

    // 64 BYTES, 16 characters (all four-byte astral).
    let astral: String = std::iter::repeat_n('\u{1d7ce}', 16).collect();
    assert_eq!(astral.len(), 64);
    assert!(manifest(&astral, 1, 1).restorable_by(1).is_err());

    // 64 CHARACTERS, 66 bytes: fails the byte length test.
    let sixty_four_chars_66_bytes = format!("{}\u{ff10}", "a".repeat(63));
    assert_eq!(sixty_four_chars_66_bytes.chars().count(), 64);
    assert_eq!(sixty_four_chars_66_bytes.len(), 66);
    assert!(manifest(&sixty_four_chars_66_bytes, 1, 1)
        .restorable_by(1)
        .is_err());

    // A NUL in the middle of an otherwise perfect digest — and note the byte
    // length is still exactly 64.
    let nul_inside = format!("{}\0{}", "a".repeat(32), "b".repeat(31));
    assert_eq!(nul_inside.len(), 64);
    assert!(manifest(&nul_inside, 1, 1).restorable_by(1).is_err());

    // A NUL-terminated digest, C-style: 65 bytes.
    let nul_terminated = format!("{}\0", "a".repeat(64));
    assert!(manifest(&nul_terminated, 1, 1).restorable_by(1).is_err());

    // "0x"-prefixed at exactly 64 characters, the shape a hex dumper emits.
    let zero_x = format!("0x{}", "a".repeat(62));
    assert_eq!(zero_x.len(), 64);
    assert!(
        manifest(&zero_x, 1, 1).restorable_by(1).is_err(),
        "'0x' + 62 hex is 64 characters and must still be refused"
    );

    // Whitespace-padded to exactly 64 characters, both ends.
    for pad in [" ", "\t", "\n", "\r", "\u{a0}", "\u{feff}"] {
        let padded = format!("{pad}{}", "a".repeat(63));
        assert!(
            manifest(&padded, 1, 1).restorable_by(1).is_err(),
            "leading {pad:?} must be refused"
        );
        let padded = format!("{}{pad}", "a".repeat(63));
        assert!(
            manifest(&padded, 1, 1).restorable_by(1).is_err(),
            "trailing {pad:?} must be refused"
        );
        // And the untrimmed 66-character form.
        let padded = format!("{pad}{}{pad}", "a".repeat(64));
        assert!(manifest(&padded, 1, 1).restorable_by(1).is_err());
    }

    // Uppercase is refused even though it is a perfectly valid SHA-256 hex
    // rendering — strict, and worth pinning: a digest pasted from `sha256sum`
    // on a case-normalising platform will not restore.
    let upper = "AB".repeat(32);
    assert!(manifest(&upper, 1, 1).restorable_by(1).is_err());
    assert!(manifest(&upper.to_lowercase(), 1, 1)
        .restorable_by(1)
        .is_ok());
}

// ── 3. The schema and segment matrices ───────────────────────────────────

/// 9 snapshot versions x 9 build versions x 3 segment counts x 2 digest
/// shapes = 486 verdicts, asserted against the rule
/// `ok <=> digest_ok && segments != 0 && schema_version <= build_schema`.
///
/// The interesting corners are all present: 0 against 0, `u32::MAX` against
/// `u32::MAX` (equal — accepted), `u32::MAX` against `u32::MAX - 1` (newer —
/// refused) and 0 against `u32::MAX` (ancient — accepted, see BROKE 7).
#[test]
fn schema_matrix_across_zero_one_and_u32_max_with_neighbours() {
    const VERSIONS: [u32; 9] = [
        0,
        1,
        2,
        3,
        0x7FFF_FFFF,
        0x8000_0000,
        u32::MAX - 2,
        u32::MAX - 1,
        u32::MAX,
    ];
    const SEGMENTS: [u32; 3] = [0, 1, u32::MAX];

    let good = "ab".repeat(32);
    let bad = "AB".repeat(32);
    let mut newer_refusals = 0usize;
    let mut equal_or_older_accepts = 0usize;
    let mut checked = 0usize;

    for &snapshot in &VERSIONS {
        for &build in &VERSIONS {
            for &segments in &SEGMENTS {
                for digest in [good.as_str(), bad.as_str()] {
                    let m = manifest(digest, segments, snapshot);
                    let verdict = m.restorable_by(build);
                    let digest_ok = digest == good;
                    let expected = digest_ok && segments != 0 && snapshot <= build;
                    assert_eq!(
                        verdict.is_ok(),
                        expected,
                        "snapshot v{snapshot} / build v{build} / {segments} segments / \
                         digest_ok={digest_ok}"
                    );
                    checked += 1;

                    if digest_ok && segments != 0 {
                        if snapshot > build {
                            newer_refusals += 1;
                            let why = verdict.unwrap_err();
                            assert!(
                                why.contains(&snapshot.to_string())
                                    && why.contains(&build.to_string()),
                                "the refusal must name both versions, got {why:?}"
                            );
                        } else {
                            equal_or_older_accepts += 1;
                        }
                    }
                }
            }
        }
    }

    assert_eq!(checked, 9 * 9 * 3 * 2);
    assert_eq!(
        newer_refusals,
        36 * 2,
        "every newer pair, both segment counts"
    );
    assert_eq!(equal_or_older_accepts, 45 * 2);

    // The two extremes, spelled out.
    assert!(manifest(&good, 1, u32::MAX).restorable_by(u32::MAX).is_ok());
    assert!(manifest(&good, 1, u32::MAX)
        .restorable_by(u32::MAX - 1)
        .is_err());
    assert!(manifest(&good, 1, 0).restorable_by(0).is_ok());
    assert!(manifest(&good, 1, 1).restorable_by(0).is_err());

    println!(
        "schema matrix: {checked} verdicts, {newer_refusals} newer-than-build refusals, \
         {equal_or_older_accepts} equal-or-older accepts"
    );
}

/// **BROKE 4 — exhaustion vector.** `segments` is gated at the bottom only.
///
/// Zero is refused ("an empty backup restores nothing"), but `u32::MAX` is
/// accepted, and nothing ties the count to the digest: the manifest below
/// carries a digest that was genuinely computed over **three** segment
/// digests and claims 4 294 967 295 segments. `restorable_by` is the only
/// gate a restore driver gets, so whatever allocates per segment downstream is
/// handed 4.29e9 work items by an unsigned 200-byte document.
#[test]
fn segments_matrix_has_a_floor_but_no_ceiling_and_no_cross_check() {
    // A real digest over three real segment digests, exactly as
    // docs/BACKUP_AND_RESTORE.md specifies ("sha256 over concatenated
    // segment digests").
    let seg: Vec<String> = (0..3)
        .map(|i| token_sha256(format!("acme/segment-{i}").as_bytes()))
        .collect();
    let real = token_sha256(seg.concat().as_bytes());
    assert!(is_sha256_hex(&real));

    assert!(
        manifest(&real, 0, 1).restorable_by(1).is_err(),
        "an empty backup must be refused"
    );
    assert_eq!(
        manifest(&real, 0, 1).restorable_by(1).unwrap_err(),
        "manifest has no segments"
    );

    for segments in [1u32, 2, 3, 1_000_000, u32::MAX - 1, u32::MAX] {
        assert!(
            manifest(&real, segments, 1).restorable_by(1).is_ok(),
            "{segments} segments accepted"
        );
    }

    // The digest was computed over THREE segments. The manifest may claim
    // any other number and the gate cannot tell — there is no cross-check,
    // because there is nothing to cross-check against (BROKE 1).
    let liar = manifest(&real, u32::MAX, 1);
    assert_eq!(liar.segments, u32::MAX);
    assert!(
        liar.restorable_by(1).is_ok(),
        "EXHAUSTION VECTOR: 4 294 967 295 claimed segments behind a 3-segment digest"
    );
}

/// **BROKE 7.** No schema floor, and only the first failure is reported.
#[test]
fn schema_has_no_floor_and_only_the_first_failure_is_reported() {
    let good = "ab".repeat(32);

    // A snapshot from schema 0 — a pre-versioning artefact — is restorable by
    // a build 4 billion versions later. There is no deprecation window and no
    // minimum-supported-schema constant anywhere in the crate.
    assert!(manifest(&good, 1, 0).restorable_by(u32::MAX).is_ok());

    // Three defects at once: only the digest is reported. An operator
    // triaging "why will this backup not restore" is never told it is also
    // empty and also from the future.
    let all_wrong = manifest("nope", 0, u32::MAX);
    assert_eq!(
        all_wrong.restorable_by(0).unwrap_err(),
        "manifest digest is not lowercase 64-hex"
    );
    // Fix the digest, and the *second* problem surfaces — one per attempt.
    let two_wrong = manifest(&good, 0, u32::MAX);
    assert_eq!(
        two_wrong.restorable_by(0).unwrap_err(),
        "manifest has no segments"
    );
    let one_wrong = manifest(&good, 1, u32::MAX);
    assert!(one_wrong
        .restorable_by(0)
        .unwrap_err()
        .starts_with("snapshot schema v4294967295 is newer"));
}

// ── 4. THE CRITICAL FINDING ──────────────────────────────────────────────

/// **BROKE 1 — spec violation, high severity.**
///
/// `crates/ccos-enterprise-backup/src/lib.rs:5` states *"a backup that cannot
/// verify its digest is not a backup"*; `docs/BACKUP_AND_RESTORE.md:6` defines
/// the digest ("sha256 over concatenated segment digests") and `:8` promises
/// "Restore verifies the manifest BEFORE any byte is applied".
/// `restorable_by` never verifies a digest. It cannot: its whole signature is
///
/// ```text
/// pub fn restorable_by(&self, build_schema: u32) -> Result<(), String>
/// ```
///
/// — no content, no reader, no segment digests, no expected value. The only
/// thing it inspects is whether `self.digest` *looks like* a SHA-256, which
/// is a property of 16^64 strings, exactly one of which is the right one.
///
/// This test proves the absence of verification the only way absence can be
/// proven: by showing that five manifests which a verifying implementation
/// would have to separate are accepted **identically**.
#[test]
fn fabricated_digest_restores_because_no_byte_of_content_is_ever_hashed() {
    // Pin the signature. If someone ever gives the gate access to content,
    // this line stops compiling and this finding must be revisited — which is
    // exactly the review we want to force.
    let gate: fn(&BackupManifest, u32) -> Result<(), String> = BackupManifest::restorable_by;

    // The genuine article: three real segments, their real digests, and the
    // real SHA-256 over the concatenation — the digest the document specifies.
    let real_segments: Vec<&[u8]> = vec![
        b"acme/segment-0: the actual snapshot bytes",
        b"acme/segment-1: more actual snapshot bytes",
        b"acme/segment-2: the tail",
    ];
    let segment_digests: Vec<String> = real_segments.iter().map(|s| token_sha256(s)).collect();
    let honest = token_sha256(segment_digests.concat().as_bytes());

    // The digest of *completely different* content — a backup of somebody
    // else's data, or of nothing at all like these segments.
    let other = token_sha256(b"globex/segment-0: an entirely different backup");
    assert_ne!(honest, other);

    // A digest that is not the SHA-256 of anything anyone hashed: hand-typed.
    let fabricated = "deadbeef".repeat(8);
    assert_eq!(fabricated.len(), 64);
    // Sanity: it really is fabricated, not accidentally correct.
    assert_ne!(fabricated, honest);
    assert_ne!(fabricated, other);

    // The two degenerate constants an attacker reaches for first.
    let all_zero = "0".repeat(64);
    let sha256_of_nothing = token_sha256(b"");
    assert_eq!(
        sha256_of_nothing, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "SHA-256 of the empty input, as a fixed vector"
    );

    let candidates = [
        ("honest digest over the real segments", honest.as_str()),
        ("real digest over DIFFERENT content", other.as_str()),
        (
            "hand-typed deadbeef, hashed from nothing",
            fabricated.as_str(),
        ),
        ("sixty-four zeros", all_zero.as_str()),
        ("SHA-256 of the empty input", sha256_of_nothing.as_str()),
    ];

    for (label, digest) in candidates {
        let m = manifest(digest, 3, 1);
        assert_eq!(
            gate(&m, 1),
            Ok(()),
            "{label}: the restore gate accepts it — it has no way not to"
        );
    }

    // Indistinguishable: the honest and the fabricated manifests produce the
    // *same value*, so no caller downstream can tell them apart either.
    let honest_manifest = manifest(&honest, 3, 1);
    let forged_manifest = manifest(&fabricated, 3, 1);
    assert_eq!(
        honest_manifest.restorable_by(1),
        forged_manifest.restorable_by(1),
        "the gate returns the same Ok(()) for a real and a forged digest"
    );

    // And the forgery is trivial to produce: any 64 characters drawn from
    // [0-9a-f] restore. 20 000 random ones, none of them the digest of
    // anything, every one accepted.
    let mut rng = Rng::new(0xF0_46_ED);
    let mut forged_accepted = 0usize;
    for _ in 0..20_000 {
        let d = hex_digest(&mut rng, 64);
        assert_ne!(
            d, honest,
            "astronomically improbable, and would void the test"
        );
        if manifest(&d, 3, 1).restorable_by(1).is_ok() {
            forged_accepted += 1;
        }
    }
    assert_eq!(
        forged_accepted, 20_000,
        "SPEC VIOLATION: every one of 20 000 fabricated digests is 'restorable'"
    );

    // Concretely: this is the whole attack, as a file. 200-odd bytes of JSON
    // an attacker drops beside the real backups. It parses, it passes every
    // gate the product has, and it claims 4 294 967 295 segments of a tenant
    // it does not own.
    let planted_file = format!(
        r#"{{"tenant":"acme","created_unix":18446744073709551615,
            "digest":"{fabricated}","segments":4294967295,"schema_version":0}}"#
    );
    assert!(planted_file.len() < 300, "a very small file");
    let planted: BackupManifest = serde_json::from_str(&planted_file).expect("parses");
    assert_eq!(
        planted.restorable_by(3),
        Ok(()),
        "SPEC VIOLATION: an attacker-authored JSON file is 'restorable'"
    );

    println!(
        "restore gate accepted 20 000/20 000 fabricated digests plus {} \
         hand-picked forgeries; nothing in the workspace hashes a byte of backup content",
        candidates.len() - 1
    );
}

// ── 5. Tenant binding, governance reach, and the DR procedure ────────────

/// **BROKE 2.** The gate ignores `manifest.tenant` entirely, and restore is
/// not reachable through the governed admission path at all.
#[test]
fn restore_gate_never_consults_the_tenant_and_is_outside_the_governed_path() {
    let good = "ab".repeat(32);
    let baseline = manifest(&good, 4, 1).restorable_by(1);
    assert_eq!(baseline, Ok(()));

    let hostile_tenants: Vec<String> = vec![
        "acme".into(),
        "globex".into(),
        "".into(),
        " ".into(),
        "\0".into(),
        "acme\0globex".into(),
        "../../etc/shadow".into(),
        "acme/../globex".into(),
        "ACME".into(),
        "acme\nrestore approved".into(),
        "tenant-that-does-not-exist".into(),
        "\u{202e}emca".into(),
        "a".repeat(1 << 20), // 1 MiB
    ];

    for tenant in &hostile_tenants {
        let m = BackupManifest {
            tenant: tenant.clone(),
            created_unix: 1_700_000_000,
            digest: good.clone(),
            segments: 4,
            schema_version: 1,
        };
        assert_eq!(
            m.restorable_by(1),
            baseline,
            "the verdict changed with the tenant field — it must not have, and \
             that is the finding: there is no tenant binding"
        );
    }

    // A manifest naming a tenant that does not exist in the deployment is
    // just as restorable as one naming a real tenant. `restorable_by` takes
    // no Deployment, no TenantId and no AuthenticatedActor, so none of the
    // six layers of docs/ENTERPRISE_SECURITY_MODEL.md can be consulted.
    let foreign = BackupManifest {
        tenant: "globex".into(),
        created_unix: 1_700_000_000,
        digest: good.clone(),
        segments: 4,
        schema_version: 1,
    };
    assert!(
        foreign.restorable_by(1).is_ok(),
        "globex's manifest restores under any build, including acme's"
    );

    // Nor can restore be governed as a tool: `backup.` is not in the gateway
    // catalogue, so there is no `backup.restore` capability to attach a
    // permission, an audit record or a budget to.
    let mut d = two_tenant_deployment();
    let root = actor("memorithm", "root", AuthStrength::Strong);
    for tool in ["backup.restore", "backup.list", "restore.apply"] {
        let req = request("acme", "root", tool, "restore-1");
        let outcome = d.admit(Call {
            actor: &root,
            request: &req,
            model: "claude-opus",
            cost_tokens: 0,
            variant: None,
        });
        match outcome.refusal() {
            Some(Refusal::OutsideBoundary(why)) => {
                assert!(why.contains("not in the Enterprise catalogue"), "{why}");
            }
            other => panic!("expected a boundary refusal for {tool}, got {other:?}"),
        }
    }
    // The gateway is not the problem — it is doing exactly the right thing.
    // The problem is that restore therefore happens somewhere the gateway
    // never sees, guarded only by a 64-character string test.
    assert_eq!(
        d.audit().len(),
        3,
        "the *attempts* are journaled; a real restore would not be"
    );
    assert_eq!(d.spent("acme"), 0);
}

/// **BROKE 3.** The documented disaster-recovery procedure, executed
/// literally, selects a planted manifest over every genuine one.
///
/// `docs/DISASTER_RECOVERY.md:8`: "Restore latest manifest passing all gates
/// (BACKUP_AND_RESTORE.md)." `created_unix` is the only notion of "latest",
/// it is carried inside the unsigned manifest, and it is never validated —
/// so the attacker picks it, and `u64::MAX` cannot be outbid.
#[test]
fn dr_latest_manifest_selection_prefers_a_planted_future_manifest() {
    const BUILD_SCHEMA: u32 = 3;

    /// The DR procedure, verbatim: newest first, take the first that passes
    /// every gate. Deterministic — the tie-break is the tenant name, and
    /// nothing here reads a clock.
    fn restore_latest(pool: &[BackupManifest], build: u32) -> Option<&BackupManifest> {
        let mut by_recency: Vec<&BackupManifest> = pool.iter().collect();
        by_recency.sort_by(|a, b| {
            b.created_unix
                .cmp(&a.created_unix)
                .then_with(|| a.digest.cmp(&b.digest))
        });
        by_recency
            .into_iter()
            .find(|m| m.restorable_by(build).is_ok())
    }

    // Three genuine nightly backups, digests really computed over their
    // really-hashed segments.
    let genuine: Vec<BackupManifest> = (0..3)
        .map(|night: u64| {
            let segs: Vec<String> = (0..8)
                .map(|s| token_sha256(format!("acme/night-{night}/segment-{s}").as_bytes()))
                .collect();
            BackupManifest {
                tenant: "acme".into(),
                created_unix: 1_700_000_000 + night * 86_400,
                digest: token_sha256(segs.concat().as_bytes()),
                segments: 8,
                schema_version: 3,
            }
        })
        .collect();

    // Sanity: without an attacker the procedure picks the newest genuine one.
    let newest_genuine = restore_latest(&genuine, BUILD_SCHEMA).expect("a genuine backup restores");
    assert_eq!(newest_genuine.created_unix, 1_700_000_000 + 2 * 86_400);

    // The plant: a fabricated digest, the victim's tenant name, and a
    // creation time nothing can ever exceed.
    let planted = BackupManifest {
        tenant: "acme".into(),
        created_unix: u64::MAX,
        digest: "beefcafe".repeat(8),
        segments: 1,
        schema_version: 0,
    };
    assert!(
        is_sha256_hex(&planted.digest),
        "well-formed, and meaningless"
    );
    assert!(
        planted.restorable_by(BUILD_SCHEMA).is_ok(),
        "the plant passes every gate the product has"
    );
    assert!(
        u64::MAX.checked_add(1).is_none(),
        "no honest backup can ever be 'later' than the plant"
    );

    let mut pool = genuine.clone();
    pool.push(planted.clone());
    let chosen = restore_latest(&pool, BUILD_SCHEMA).expect("something restores");
    assert_eq!(
        chosen.created_unix,
        u64::MAX,
        "the documented procedure restores the plant, not the backup"
    );
    assert_eq!(chosen.digest, planted.digest);
    assert_eq!(
        chosen.segments, 1,
        "and it restores 1 segment where 8 exist"
    );

    // The genuine manifests are not corrupt, not stale and not refused — they
    // are simply never reached. Nothing announces that.
    for g in &genuine {
        assert!(g.restorable_by(BUILD_SCHEMA).is_ok());
    }

    // created_unix is unvalidated in both directions: epoch zero and the far
    // future are equally restorable, and a backup "created" before the
    // product existed is not a gate failure either.
    for created in [0u64, 1, 1_000, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
        let m = BackupManifest {
            created_unix: created,
            ..planted.clone()
        };
        assert!(
            m.restorable_by(BUILD_SCHEMA).is_ok(),
            "created_unix={created} is accepted — there is no freshness gate"
        );
    }
}

// ── 6. Wire form, message hygiene, purity, exhaustion ────────────────────

/// **BROKE 5 (partly) — and one thing that HELD.**
///
/// The manifest is unsigned and accepts unknown fields, but the *derived*
/// deserializer does refuse a duplicate `digest` key, which is the strict
/// behaviour. The asymmetry is worth pinning: a generic `serde_json::Value`
/// reader — the shape any signing or auditing tool built on untyped JSON
/// would have — silently keeps the **last** value, while the restore path
/// refuses the document outright. Today that is fail-closed. The day a
/// signature is added over the `Value` form, the two readers disagreeing
/// about what "the digest" is becomes exploitable.
#[test]
fn json_wire_form_is_unsigned_and_lenient_but_refuses_duplicate_digest_keys() {
    let good = "ab".repeat(32);
    let forged = "cd".repeat(32);

    // Round-trip is stable and the verdict survives it.
    let m = manifest(&good, 7, 2);
    let json = serde_json::to_string(&m).expect("serializes");
    let back: BackupManifest = serde_json::from_str(&json).expect("deserializes");
    assert_eq!(back.digest, m.digest);
    assert_eq!(back.restorable_by(2), m.restorable_by(2));

    // Unknown fields are accepted: nothing rejects a manifest carrying a
    // "signature" field the restore path will never look at.
    let with_extras = format!(
        r#"{{"tenant":"acme","created_unix":1,"digest":"{good}","segments":1,
            "schema_version":1,"signature":"not-checked","key_id":"nor-this"}}"#
    );
    let parsed: BackupManifest = serde_json::from_str(&with_extras).expect("extras accepted");
    assert!(parsed.restorable_by(1).is_ok());

    // DUPLICATE KEY. The derived deserializer refuses it — this HELD.
    let duplicated = format!(
        r#"{{"tenant":"acme","created_unix":1,"digest":"{good}","segments":1,
            "schema_version":1,"digest":"{forged}"}}"#
    );
    let err = serde_json::from_str::<BackupManifest>(&duplicated)
        .expect_err("a manifest with two digests must not deserialize");
    assert!(
        err.to_string().contains("duplicate field `digest`"),
        "unexpected error: {err}"
    );

    // ...but the untyped reader takes the LAST one, without a word. Two
    // readers, one document, two different digests.
    let untyped: serde_json::Value =
        serde_json::from_str(&duplicated).expect("Value accepts duplicates");
    assert_eq!(
        untyped["digest"],
        serde_json::Value::String(forged.clone()),
        "serde_json::Value silently keeps the second digest"
    );
    assert_ne!(untyped["digest"], serde_json::Value::String(good.clone()));

    // What serde does hold: numeric range and type discipline.
    let rejected = [
        // segments = 2^32
        r#"{"tenant":"a","created_unix":1,"digest":"x","segments":4294967296,"schema_version":1}"#,
        // negative segments
        r#"{"tenant":"a","created_unix":1,"digest":"x","segments":-1,"schema_version":1}"#,
        // fractional segments
        r#"{"tenant":"a","created_unix":1,"digest":"x","segments":1.5,"schema_version":1}"#,
        // negative time
        r#"{"tenant":"a","created_unix":-1,"digest":"x","segments":1,"schema_version":1}"#,
        // schema beyond u32
        r#"{"tenant":"a","created_unix":1,"digest":"x","segments":1,"schema_version":4294967296}"#,
        // digest is not a string
        r#"{"tenant":"a","created_unix":1,"digest":123,"segments":1,"schema_version":1}"#,
        // missing field: there is no serde default, so a truncated manifest
        // cannot become a zero-initialised one
        r#"{"tenant":"a","created_unix":1,"segments":1,"schema_version":1}"#,
    ];
    for doc in rejected {
        assert!(
            serde_json::from_str::<BackupManifest>(doc).is_err(),
            "wire form must reject {doc}"
        );
    }

    // A 1 MiB digest parses fine and is refused by shape, not by size.
    let huge = format!(
        r#"{{"tenant":"a","created_unix":1,"digest":"{}","segments":1,"schema_version":1}}"#,
        "a".repeat(1 << 20)
    );
    let parsed: BackupManifest = serde_json::from_str(&huge).expect("parses");
    assert_eq!(parsed.digest.len(), 1 << 20);
    assert!(parsed.restorable_by(1).is_err());
}

/// The refusal strings never quote attacker-controlled input, so a manifest
/// cannot forge log lines through the restore path. This HELD.
#[test]
fn refusal_messages_never_echo_the_digest_or_the_tenant() {
    let payloads = [
        "\n2026-01-01T00:00:00Z INFO restore verified by root\n",
        "\u{1b}[2J\u{1b}[1;31mVERIFIED\u{1b}[0m",
        "\0\0\0\0",
        "%s%n%s%n",
        "</audit><audit outcome=\"ok\">",
        "'; DROP TABLE manifests; --",
        &"A".repeat(4096),
    ];

    for payload in payloads {
        let m = BackupManifest {
            tenant: payload.to_string(),
            created_unix: 1,
            digest: payload.to_string(),
            segments: 1,
            schema_version: 1,
        };
        let why = m.restorable_by(1).unwrap_err();
        assert_eq!(
            why, "manifest digest is not lowercase 64-hex",
            "the digest refusal must be a constant"
        );
        // Nothing distinctive from the payload may appear in the message.
        // (Checked token-wise: an empty-after-trimming payload would make a
        // naive `contains` check vacuously true.)
        for token in payload
            .split(|c: char| c.is_whitespace() || c.is_control())
            .filter(|t| t.len() >= 3)
        {
            assert!(
                !why.contains(token),
                "refusal echoed attacker token {token:?}: {why:?}"
            );
        }
        assert!(!why.contains('\u{1b}') && !why.contains('\0'));
    }

    // The schema refusal does interpolate — but only two integers, both of
    // them the deployment's own numbers. (It does disclose the build's schema
    // version to whoever supplied the manifest; noted, not a defect.)
    let m = BackupManifest {
        tenant: "\n\u{1b}[31mroot".into(),
        created_unix: 1,
        digest: "ab".repeat(32),
        segments: 1,
        schema_version: 9,
    };
    let why = m.restorable_by(4).unwrap_err();
    assert_eq!(why, "snapshot schema v9 is newer than this build (v4)");
    assert!(!why.contains('\u{1b}'));
    assert!(!why.contains("root"));
}

/// The gate is a pure function of the manifest: no state, no memoisation, no
/// interior mutability, no first-call/second-call difference. This HELD.
#[test]
fn the_gate_is_pure_and_its_verdict_is_stable_under_repetition_and_cloning() {
    let cases = [
        (manifest(&"ab".repeat(32), 1, 1), 1u32, true),
        (manifest(&"AB".repeat(32), 1, 1), 1, false),
        (manifest(&"ab".repeat(32), 0, 1), 1, false),
        (manifest(&"ab".repeat(32), 1, 2), 1, false),
    ];
    for (m, build, expected) in &cases {
        let first = m.restorable_by(*build);
        for _ in 0..2_000 {
            assert_eq!(
                m.restorable_by(*build),
                first,
                "verdict drifted between calls"
            );
        }
        assert_eq!(first.is_ok(), *expected);
        assert_eq!(
            m.clone().restorable_by(*build),
            first,
            "a clone verdicts identically"
        );
    }
}

/// An oversized digest is refused without being scanned: `len() == 64`
/// short-circuits the per-byte test (`crates/ccos-enterprise-backup/src/lib.rs:25`).
///
/// 20 000 calls against a 4 MiB digest. If the length check ever moves after
/// the byte scan this becomes 80 GB of work and the suite hangs — a
/// deterministic failure, without asserting on a clock.
#[test]
fn an_oversized_digest_is_refused_without_being_scanned() {
    let huge = "a".repeat(4 << 20);
    let m = manifest(&huge, 1, 1);
    for _ in 0..20_000 {
        assert!(m.restorable_by(1).is_err());
    }

    // The same at the two lengths that bracket the accepted one, so an
    // off-by-one in the bound is caught too.
    for len in [0usize, 1, 63, 64, 65, 128, 1024, 65_536] {
        let d = "a".repeat(len);
        assert_eq!(
            manifest(&d, 1, 1).restorable_by(1).is_ok(),
            len == 64,
            "length {len}"
        );
    }
}

/// **BROKE 6.** Two crates carry the same rule, character for character, with
/// no shared definition: `crates/ccos-enterprise-backup/src/lib.rs:25-29` and
/// `crates/ccos-enterprise-governance/src/claim.rs:188-192`. They agree today.
/// This test is what will notice when they stop.
#[test]
fn the_hex_rule_is_duplicated_across_two_crates_and_agrees_only_by_luck() {
    let mut rng = Rng::new(0xD0_0B_1E);
    let mut disagreements = 0usize;
    let mut checked = 0usize;

    // A dense corpus around the boundary of the rule.
    let mut corpus: Vec<String> = Vec::new();
    for len in 60..=68usize {
        corpus.push(hex_digest(&mut rng, len));
    }
    for c in NON_HEX_ASCII
        .iter()
        .chain(UPPER_HEX.iter())
        .chain(CONTROL.iter())
        .chain(SPACEY.iter())
        .chain(UNICODE_DIGITS.iter())
        .chain(HOMOGLYPHS.iter())
    {
        let mut s: Vec<char> = hex_digest(&mut rng, 64).chars().collect();
        s[rng.below(64)] = *c;
        corpus.push(s.into_iter().collect());
        corpus.push(format!("{c}{}", hex_digest(&mut rng, 63)));
        corpus.push(format!("{}{c}", hex_digest(&mut rng, 63)));
    }
    for _ in 0..5_000 {
        corpus.push(hex_digest(&mut rng, 64));
        let len = rng.below(131);
        corpus.push(hex_digest(&mut rng, len));
    }

    for d in &corpus {
        let by_backup = manifest(d, 1, 1).restorable_by(1).is_ok();
        let by_governance = is_sha256_hex(d);
        let by_spec = spec_lowercase_64_hex(d);
        if by_backup != by_governance || by_backup != by_spec {
            disagreements += 1;
        }
        checked += 1;
    }

    assert_eq!(
        disagreements, 0,
        "the two copies of the sha256-shape rule have drifted"
    );
    assert!(checked > 10_000, "coverage: {checked}");

    // The duplication itself, made explicit: a governance-issued hash (a real
    // one, produced by the licensing stack) is a valid backup digest, and a
    // backup digest is a valid claim hash. Neither crate knows the other
    // exists.
    let from_governance = token_sha256(b"a license token, not a backup at all");
    assert!(is_sha256_hex(&from_governance));
    assert!(
        manifest(&from_governance, 1, 1).restorable_by(1).is_ok(),
        "a license-token hash is an acceptable backup digest — shape is all there is"
    );
}

/// A last sweep over the composed product: the restore gate's verdict is
/// unaffected by everything a deployment knows. Same digest, same answer,
/// whatever the tenant's budget, roles, models or Q-Pages say — because the
/// gate cannot see any of it.
#[test]
fn no_deployment_state_can_influence_a_restore_verdict() {
    let good = "ab".repeat(32);
    let mut d = two_tenant_deployment();

    // Burn acme's whole budget and refuse a few calls, so the deployment is
    // in a thoroughly non-pristine state.
    let alice = actor("memorithm", "alice", AuthStrength::Strong);
    for i in 0..12 {
        let req = request("acme", "alice", "memory.ingest", &format!("r-{i}"));
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 100,
            variant: None,
        });
    }
    assert_eq!(d.spent("acme"), 1_000, "budget exhausted");

    let mut verdicts: BTreeMap<&str, bool> = BTreeMap::new();
    for tenant in ["acme", "globex", "nonexistent"] {
        let m = BackupManifest {
            tenant: tenant.into(),
            created_unix: 1,
            digest: good.clone(),
            segments: 2,
            schema_version: 1,
        };
        verdicts.insert(tenant, m.restorable_by(1).is_ok());
    }
    assert_eq!(verdicts.values().filter(|v| **v).count(), 3);

    // And no restore attempt appears anywhere in the journal or the metrics:
    // there is no audit record and no counter for restore, because the
    // backup crate has no way to reach either.
    assert!(
        d.audit().iter().all(|r| !r.tool.contains("restore")),
        "nothing about restore is journaled"
    );
    assert!(
        d.metrics()
            .iter()
            .all(|(k, _)| !k.contains("backup") && !k.contains("restore")),
        "no restore metric exists"
    );
}
