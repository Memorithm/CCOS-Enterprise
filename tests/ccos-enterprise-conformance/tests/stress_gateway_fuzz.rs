//! # Hostile fuzz of the gateway boundary
//!
//! `ccos_enterprise_gateway::classify` is the product's security frontier: it
//! is the one gate `docs/ENTERPRISE_SECURITY_MODEL.md` promises no tenant can
//! widen, evaluated (per `ccos_enterprise_conformance`'s module docs) *before*
//! every tenant-configurable gate precisely so "no tenant's roles, allowlists
//! or budgets may ever widen it".
//!
//! This file attacks that claim with a deterministic fuzzer (fixed seed, no
//! wall-clock in any assertion) plus a hand-built adversarial corpus:
//! homoglyphs, NFKC/NFKD look-alikes, Turkish case folding, bidi overrides,
//! zero-width joiners, NUL bytes, 1 MiB names and prefix-boundary games.
//!
//! ## The invariant under test
//!
//! > No input may ever produce `Disposition::Forward` for a tool that is,
//! > after any plausible downstream normalization, a forbidden capability.
//!
//! ## VERDICT: the invariant HOLDS. This file is now its regression guard.
//!
//! It did not always. Every assertion below that once pinned a bypass now
//! pins its closure, with the same inputs and the opposite expectation, so a
//! reintroduction fails here loudly instead of silently reopening the
//! security posture.
//!
//! ## What was repaired
//!
//! **The prefix-laundering class (critical).** `classify` used to test
//! `FORBIDDEN_PREFIXES` only against the **start** of the name and then admit
//! anything starting with an `ALLOWED_PREFIXES` entry, so prefixing a
//! forbidden capability with an exposed namespace turned a boundary violation
//! into a `Forward`:
//!
//! | input                         | classify WAS | classify NOW      |
//! |-------------------------------|--------------|-------------------|
//! | `ccos.shell.exec`             | `Forward`    | outside boundary  |
//! | `memory.repository.modify`    | `Forward`    | outside boundary  |
//! | `ccos.rsi.propose`            | `Forward`    | outside boundary  |
//! | `memory.recall/../shell.exec` | `Forward`    | not canonical     |
//! | `policy.set;shell.exec`       | `Forward`    | not canonical     |
//! | `ccos.\u{200d}shell.exec`     | `Forward`    | not canonical     |
//!
//! The cost was not theoretical: [`the_composed_path_can_no_longer_forward_or_bill_a_wrapped_shell_exec`]
//! used to show those names traversing the *whole* admission pipeline —
//! identity, tenant, boundary, RBAC, model, budget — as a read-only actor,
//! being **billed** to the tenant, and landing in the journal as ordinary
//! successes with no boundary counter moving.
//! `tests/boundary_contract.rs::no_privilege_reaches_past_the_boundary` only
//! ever proved the *bare* spellings were stopped.
//!
//! Two independent changes closed it, and both are guarded here:
//!
//! 1. **Forbidden matching is segment-wise.** Every suffix beginning at a
//!    segment boundary is tested, so `ccos.shell.exec` matches on its
//!    `shell.exec` suffix. `class_strip` — the gateway's *own documented*
//!    downstream translation, see [`class_strip`] — can no longer reach a
//!    forbidden capability from anything the boundary forwards.
//! 2. **A name must be canonical before any matching happens**: non-empty,
//!    at most 256 bytes, every dot-separated segment non-empty and made only
//!    of `[A-Za-z0-9_]`. That refuses path and command separators, all
//!    non-ASCII (homoglyphs, CJK, emoji, zero-width, RTL, combining marks),
//!    control bytes, whitespace, NUL and leading/trailing/double dots.
//!
//! **Oversized names are refused by length, not scanned (high).** The 256-byte
//! ceiling is checked first, so a 1 MiB or 8 MiB name costs `len()`, not a
//! megabyte-scale lowercase-and-scan, and never reaches a refusal message.
//!
//! **Refusal messages are sanitized (low → closed).** They used to embed the
//! caller's bytes verbatim — `format!("tool '{}' is not in the Enterprise
//! catalogue", req.tool)` — so a 1 MiB name produced a >1 MiB message and a
//! bidi override rendered the attacked name backwards in a terminal. The name
//! now passes through `sanitize()`: at most 64 chars, every non-graphic char
//! replaced by U+FFFD, ellipsis if truncated.
//!
//! **The audit journal no longer retains what the attacker sent (high).** It
//! was an uncapped `Vec` holding every rejected tool name untruncated, so a
//! flood turned N bytes of request into ~N bytes of permanently retained heap,
//! linear in request count, with nothing counting it. Moving the composed path
//! into `ccos_enterprise_runtime` closed both halves: every wire-supplied
//! identifier is clamped to `MAX_IDENTIFIER_BYTES` before it is journaled, and
//! the journal itself is a bounded buffer (`DEFAULT_AUDIT_CAPACITY`, settable
//! with `Deployment::with_audit_capacity`) that drops the oldest record and
//! counts the loss in `Deployment::audit_dropped`. Pinned by
//! [`a_refused_request_retains_a_bounded_number_of_attacker_bytes`], which
//! floods exactly as it used to and now measures the bound instead of the
//! growth. Dropping is a deliberate, announced loss — it bounds memory, it is
//! not by itself an audit story.
//!
//! ## What is still open
//!
//! - **Refusal taxonomy collapses on the composed path (medium, spec
//!   violation).** The gateway distinguishes violation / omission /
//!   malformed-name; `ccos_enterprise_runtime`'s `Deployment::decide` folds
//!   all three into `Refusal::OutsideBoundary` and one counter. Pinned by
//!   [`the_composed_path_collapses_three_refusals_into_one_boundary_label`].
//! - **`gateway.refused.*` still cannot count boundary probes (medium).**
//!   Canonicality is checked before the boundary, so appending `\0` to
//!   `shell.exec` relabels the probe as malformed. Pinned by
//!   [`canonicality_check_precedes_the_boundary_check`].
//! - **The boundary lowercases and the authorizer does not (low).**
//!   `MEMORY.RECALL` clears the boundary and misses `governed_tools`; that
//!   fails closed, but by accident. Pinned by
//!   [`boundary_is_case_insensitive_but_authorization_is_not`].
//!
//! Everything asserted below is the product's **current, real** behaviour.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use ccos_enterprise_auth::AuthStrength;
use ccos_enterprise_conformance::{
    actor, request, two_tenant_deployment, AuditRecord, Call, Deployment, Outcome, Refusal,
    TenantState, DEFAULT_AUDIT_CAPACITY, MAX_IDENTIFIER_BYTES,
};
use ccos_enterprise_gateway::{
    classify, Disposition, GatewayRequest, ALLOWED_PREFIXES, ALLOWED_TOOLS, FORBIDDEN_PREFIXES,
    FORBIDDEN_TOOLS,
};

// ─────────────────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────────────────

fn req(tool: &str) -> GatewayRequest {
    request("acme", "hermes", tool, "r-fuzz")
}

fn forwards(tool: &str) -> bool {
    classify(&req(tool)) == Disposition::Forward
}

fn why(tool: &str) -> String {
    match classify(&req(tool)) {
        Disposition::Forward => panic!("{tool:?} was forwarded, expected a refusal"),
        Disposition::Reject(w) => w,
    }
}

/// The three refusal families the gateway documents as distinguishable, plus
/// `Forward`. Shared by every table-driven test below.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Verdict {
    /// Traverses the boundary.
    Forward,
    /// *outside the Enterprise boundary* — a forbidden capability.
    Violation,
    /// *not in the Enterprise catalogue* — merely unlisted.
    Omission,
    /// *tool name is empty or not canonical* — refused before any matching.
    NonCanonical,
}

fn verdict(tool: &str) -> Verdict {
    match classify(&req(tool)) {
        Disposition::Forward => Verdict::Forward,
        Disposition::Reject(w) if w.contains("outside the Enterprise boundary") => {
            Verdict::Violation
        }
        Disposition::Reject(w) if w.contains("not in the Enterprise catalogue") => {
            Verdict::Omission
        }
        Disposition::Reject(_) => Verdict::NonCanonical,
    }
}

/// The ground truth the boundary exists to enforce, restated independently of
/// `classify` so the test cannot inherit `classify`'s own blind spots.
fn is_forbidden_capability(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    FORBIDDEN_PREFIXES.iter().any(|p| lowered.starts_with(p))
        || FORBIDDEN_TOOLS.contains(&lowered.as_str())
}

fn starts_with_exposed_prefix(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    ALLOWED_PREFIXES.iter().any(|p| lowered.starts_with(p))
}

// ─────────────────────────────────────────────────────────────────────────
// Plausible downstream normalizations
//
// Each is something a real MCP router, path resolver, log pipeline or Unicode
// -aware dispatcher does routinely. None is exotic; the pipeline at the end
// is simply "all of them", which is what a name meets after crossing two or
// three services.
// ─────────────────────────────────────────────────────────────────────────

/// Default-ignorable / invisible code points a sanitizer typically drops.
/// None of these are `char::is_control` or `char::is_whitespace`, which is
/// exactly why the old canonicality check let every one of them through; the
/// repaired check is an ASCII allow-list, so they are all refused now.
const INVISIBLE: &[char] = &[
    '\u{00ad}', // SOFT HYPHEN
    '\u{200b}', // ZERO WIDTH SPACE
    '\u{200c}', // ZERO WIDTH NON-JOINER
    '\u{200d}', // ZERO WIDTH JOINER
    '\u{200e}', // LEFT-TO-RIGHT MARK
    '\u{200f}', // RIGHT-TO-LEFT MARK
    '\u{061c}', // ARABIC LETTER MARK
    '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', // bidi embed/override
    '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', // bidi isolates
    '\u{feff}', // ZERO WIDTH NO-BREAK SPACE / BOM
    '\u{034f}', // COMBINING GRAPHEME JOINER
];

fn strip_invisible(s: &str) -> String {
    s.chars().filter(|c| !INVISIBLE.contains(c)).collect()
}

/// The NFKC-style compatibility folds that matter for this catalogue, applied
/// without pulling in a normalization crate: fullwidth ASCII, the long s, the
/// one-dot leader, the Kelvin sign, and both Turkish dotted/dotless i.
fn compat_fold(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            // Fullwidth forms U+FF01..U+FF5E → ASCII U+0021..U+007E.
            '\u{ff01}'..='\u{ff5e}' => {
                out.push(char::from_u32(c as u32 - 0xff01 + 0x21).expect("in ASCII range"))
            }
            '\u{017f}' => out.push('s'), // LATIN SMALL LETTER LONG S
            '\u{212a}' => out.push('k'), // KELVIN SIGN
            '\u{212b}' => out.push('a'), // ANGSTROM SIGN
            '\u{2024}' => out.push('.'), // ONE DOT LEADER
            '\u{0130}' => out.push('i'), // LATIN CAPITAL I WITH DOT ABOVE
            '\u{0131}' => out.push('i'), // LATIN SMALL DOTLESS I
            '\u{0307}' => {}             // COMBINING DOT ABOVE (NFD residue of U+0130)
            _ => out.push(c),
        }
    }
    out
}

/// Confusable-skeleton folding (UTS #39, hand-rolled for the letters that
/// spell this catalogue's forbidden names).
fn homoglyph_fold(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            // Cyrillic
            '\u{0455}' => 's', // ѕ DZE
            '\u{0430}' => 'a',
            '\u{0435}' => 'e',
            '\u{043e}' => 'o',
            '\u{0440}' => 'p',
            '\u{0441}' => 'c',
            '\u{0445}' => 'x',
            '\u{0456}' => 'i',
            '\u{0501}' => 'd',
            // Greek
            '\u{03bf}' => 'o',
            '\u{03b1}' => 'a',
            '\u{03c1}' => 'p',
            '\u{03f2}' => 'c',
            // Latin look-alikes
            '\u{0131}' => 'i',
            '\u{1d1c}' => 'u',
            _ => c,
        })
        .collect()
}

/// What a path-aware router does with `a/../b`.
fn path_resolve(s: &str) -> String {
    let mut stack: Vec<&str> = Vec::new();
    for seg in s.split('/') {
        match seg {
            "." | "" => {}
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }
    stack.join("/")
}

/// What anything that treats the name as a list/command takes.
fn separator_tail(s: &str) -> String {
    s.rsplit([';', '|', '&', ',', '\\', '/'])
        .next()
        .unwrap_or(s)
        .to_string()
}

/// The gateway's **own documented translation**, applied downstream.
///
/// `ALLOWED_PREFIXES`' doc comment: "Names are *capability classes* … Core
/// itself exposes bare `recall`/`ingest` over MCP, so the gateway is
/// deliberately a translation boundary", and "`ccos.` is kept as an accepted
/// alias for the catalogue this crate shipped with". Translating
/// `memory.recall` → `recall` and `ccos.recall` → `recall` is therefore not a
/// speculative downstream behaviour, it is the stated design — and applied to
/// `memory.shell.exec` it used to yield `shell.exec`. This is the exact fold
/// segment-wise forbidden matching now covers: every prefix `class_strip` can
/// remove ends in `.`, so every string it can produce is a segment suffix the
/// repaired `classify` already tested.
fn class_strip(s: &str) -> String {
    let mut cur = s.to_string();
    loop {
        let lowered = cur.to_ascii_lowercase();
        let Some(p) = ALLOWED_PREFIXES
            .iter()
            .find(|p| lowered.starts_with(**p) && cur.len() > p.len())
        else {
            return cur;
        };
        cur = cur[p.len()..].to_string();
    }
}

fn trim_punct(s: &str) -> String {
    s.trim_matches(|c| c == '.' || c == '/' || c == ' ')
        .to_string()
}

type Normalizer = (&'static str, fn(&str) -> String);

fn normalizers() -> Vec<Normalizer> {
    vec![
        ("identity", |s: &str| s.to_string()),
        ("ascii_lower", |s: &str| s.to_ascii_lowercase()),
        ("unicode_lower", |s: &str| s.to_lowercase()),
        ("strip_invisible", strip_invisible),
        ("compat_fold", compat_fold),
        ("homoglyph_fold", homoglyph_fold),
        ("path_resolve", path_resolve),
        ("separator_tail", separator_tail),
        ("class_strip", class_strip),
        ("trim_punct", trim_punct),
    ]
}

/// "All of the above", i.e. what a name looks like after two or three hops.
fn full_pipeline(s: &str) -> String {
    let s = strip_invisible(s);
    let s = compat_fold(&s);
    let s = homoglyph_fold(&s);
    let s = s.to_lowercase();
    let s = s.to_ascii_lowercase();
    let s = path_resolve(&s);
    let s = separator_tail(&s);
    let s = class_strip(&s);
    trim_punct(&s)
}

/// The single check the whole file is built around: does this name reach a
/// forbidden capability under some plausible downstream normalization?
/// Returns the name of the normalizer that got there.
fn normalizes_to_forbidden(name: &str) -> Option<&'static str> {
    for (label, f) in normalizers() {
        if is_forbidden_capability(&f(name)) {
            return Some(label);
        }
    }
    if is_forbidden_capability(&full_pipeline(name)) {
        return Some("full_pipeline");
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────
// Deterministic PRNG + corpus generator (fixed seed, identical in debug and
// release — no HashMap iteration, no wall clock, no `rand`).
// ─────────────────────────────────────────────────────────────────────────

struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[self.below(xs.len())]
    }
}

/// Character classes the fuzzer draws from, spanning every family the task
/// names: ASCII, CJK, emoji, RTL marks, ZWJ, combining marks, NUL/controls,
/// whitespace, fullwidth, Cyrillic/Greek homoglyphs.
fn char_pool(rng: &mut SplitMix64, class: usize) -> char {
    match class {
        0 => rng.pick(&[
            'a', 'b', 'c', 'd', 'e', 'h', 'i', 'l', 'm', 'o', 'p', 'r', 's', 't', 'u', 'x', 'y',
            'z',
        ]),
        1 => rng.pick(&[
            '.', '/', '-', '_', ':', ';', '|', '&', ',', '\\', '*', '@', '%',
        ]),
        2 => char::from_u32(0x21 + rng.below(0x5e) as u32).expect("ASCII printable"),
        3 => rng.pick(&['A', 'E', 'H', 'I', 'L', 'M', 'O', 'R', 'S', 'X']),
        // CJK
        4 => char::from_u32(0x4e00 + rng.below(0x1000) as u32).expect("CJK"),
        // Emoji
        5 => char::from_u32(0x1f300 + rng.below(0x400) as u32).expect("emoji"),
        // Bidi controls / RTL marks / zero-width joiners
        6 => rng.pick(INVISIBLE),
        // Combining marks
        7 => char::from_u32(0x0300 + rng.below(0x70) as u32).expect("combining"),
        // NUL and C0/C1 controls
        8 => char::from_u32(rng.below(0x20) as u32).expect("C0 control"),
        // Whitespace of several widths
        9 => rng.pick(&[
            ' ', '\t', '\n', '\r', '\u{0b}', '\u{0c}', '\u{85}', '\u{a0}', '\u{1680}', '\u{2000}',
            '\u{2028}', '\u{2029}', '\u{3000}',
        ]),
        // Fullwidth ASCII
        10 => char::from_u32(0xff01 + rng.below(0x5e) as u32).expect("fullwidth"),
        // Cyrillic + Greek homoglyphs and other confusables
        11 => rng.pick(&[
            '\u{0455}', '\u{0430}', '\u{0435}', '\u{043e}', '\u{0440}', '\u{0441}', '\u{0445}',
            '\u{0456}', '\u{03bf}', '\u{03b1}', '\u{03c1}', '\u{017f}', '\u{212a}', '\u{0130}',
            '\u{0131}', '\u{2024}',
        ]),
        _ => 'q',
    }
}

/// Fragments an attacker would splice in: every forbidden entry, every
/// exposed prefix, and the boundary-probing decorations named in the brief.
const FRAGMENTS: &[&str] = &[
    "shell.",
    "shell.exec",
    "shell.spawn",
    "rsi.",
    "rsi.status",
    "rsi.propose",
    "forge.",
    "forge.run",
    "slha.",
    "slha.explain",
    "octa.",
    "octa.recall",
    "patch.",
    "patch.apply",
    "self.",
    "self.rewrite",
    "code.execute",
    "repository.modify",
    "memory.",
    "memory.recall",
    "context.",
    "policy.",
    "policy.set",
    "audit.",
    "audit.query",
    "ccos.",
    "system.health",
    "..",
    "../",
    "/../",
    ".",
    "//",
    "%2e%2e",
    "\u{0}",
    "SHELL.EXEC",
    "Shell.Exec",
];

fn generate(rng: &mut SplitMix64) -> String {
    let mut s = String::new();
    // Half the corpus is seeded with a real fragment so the fuzzer spends its
    // budget near the boundary rather than in random noise.
    if rng.below(2) == 0 {
        s.push_str(rng.pick(FRAGMENTS));
    }
    let len = rng.below(28);
    for _ in 0..len {
        // Bias toward tool-shaped characters, but keep every exotic class live.
        let class = if rng.below(4) == 0 {
            rng.below(12)
        } else {
            rng.below(3)
        };
        s.push(char_pool(rng, class));
    }
    if rng.below(3) == 0 {
        s.push_str(rng.pick(FRAGMENTS));
    }
    if rng.below(8) == 0 {
        // Occasionally splice a fragment into the middle.
        let at = rng.below(s.len() + 1);
        let at = (0..=at).rev().find(|i| s.is_char_boundary(*i)).unwrap_or(0);
        s.insert_str(at, rng.pick(FRAGMENTS));
    }
    s
}

/// Stable fingerprint (FNV-1a) so the corpus is provably identical in debug
/// and release, and any generator drift is caught rather than silently
/// changing what the pinned counts below mean.
fn fnv1a(acc: u64, bytes: &[u8]) -> u64 {
    let mut h = acc;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

const SEED: u64 = 0x0ea7_beef_1234_5678;
const CORPUS: usize = 120_000;

// ─────────────────────────────────────────────────────────────────────────
// 1. The fuzz sweep
// ─────────────────────────────────────────────────────────────────────────

/// 120 000 generated names through `classify`. Three claims:
///
/// 1. it never panics (any panic aborts the test with the offending input);
/// 2. it is a pure function of the tool name — same corpus, same verdicts,
///    fingerprint pinned so debug and release agree;
/// 3. **no** `Forward` it emits reaches a forbidden capability under any
///    plausible downstream normalization.
///
/// Claim 3 used to read the other way round: the fuzzer found 322 bypasses at
/// this seed, one in every 25 forwarded names, and the assertion pinned that
/// count so a repair would surface here. The repair landed — segment-wise
/// forbidden matching plus a canonical-name rule — and the count is now
/// pinned at **zero**. The histogram below is re-derived from the repaired
/// gateway, not edited by hand; it moved wholesale from `forwarded` into
/// `noncanonical_rejects` and `boundary_rejects`.
#[test]
fn fuzz_120k_names_never_panics_and_is_deterministic() {
    let mut rng = SplitMix64(SEED);
    let mut fingerprint = 0xcbf2_9ce4_8422_2325u64;
    let mut forwarded = 0usize;
    let mut violations = 0usize;
    let mut boundary_rejects = 0usize;
    let mut catalogue_rejects = 0usize;
    let mut noncanonical_rejects = 0usize;

    for _ in 0..CORPUS {
        let name = generate(&mut rng);
        // A panic here fails the test and names the input via the harness'
        // backtrace; `classify` has no fallible slicing, so this is a real
        // (and satisfied) claim rather than a formality.
        let disposition = classify(&req(&name));
        fingerprint = fnv1a(fingerprint, name.as_bytes());
        match &disposition {
            Disposition::Forward => {
                fingerprint = fnv1a(fingerprint, b"F");
                forwarded += 1;
                if normalizes_to_forbidden(&name).is_some() {
                    violations += 1;
                }
            }
            Disposition::Reject(w) => {
                fingerprint = fnv1a(fingerprint, b"R");
                if w.contains("outside the Enterprise boundary") {
                    boundary_rejects += 1;
                } else if w.contains("not in the Enterprise catalogue") {
                    catalogue_rejects += 1;
                } else {
                    noncanonical_rejects += 1;
                }
            }
        }
        // `classify` must be pure: a second call on the same name agrees.
        assert_eq!(
            classify(&req(&name)),
            disposition,
            "classify is not a pure function of the tool name: {name:?}"
        );
    }

    assert_eq!(
        forwarded + boundary_rejects + catalogue_rejects + noncanonical_rejects,
        CORPUS,
        "every input got exactly one disposition"
    );
    assert!(boundary_rejects > 0 && catalogue_rejects > 0 && noncanonical_rejects > 0);
    // The boundary is not an outage: the corpus still reaches `Forward`, so
    // the zero-bypass claim below is about a live gate, not a closed door.
    assert!(forwarded > 0, "the repaired boundary still forwards");

    // Pinned: identical in debug and release, and any change to the generator
    // invalidates the counts below loudly instead of quietly.
    assert_eq!(
        fingerprint, 0xcd0a_ca04_b975_3aa2,
        "corpus/verdict fingerprint drifted — regenerate the pinned counts"
    );
    // Re-derived from the repaired gateway by running it, not by editing the
    // old numbers. Before the repair this was
    // `(7_764, 17_965, 42_809, 51_462)`; the canonical-name rule moved the
    // bulk of the corpus into `noncanonical_rejects`, and segment-wise
    // matching moved the laundered spellings out of `forwarded`.
    assert_eq!(
        (
            forwarded,
            boundary_rejects,
            catalogue_rejects,
            noncanonical_rejects
        ),
        (612, 1_887, 1_890, 115_611),
        "pinned disposition histogram at SEED {SEED:#x}"
    );

    // ── REGRESSION GUARD (critical) ──────────────────────────────────────
    // The invariant is "no Forward ever reaches a forbidden capability under
    // plausible downstream normalization". A clean gateway scores 0, and it
    // now does. This assertion used to pin 322; if it ever goes non-zero the
    // prefix-laundering class has been reopened.
    assert_eq!(
        violations, 0,
        "the gateway forwarded {violations} of {forwarded} names that reach a \
         forbidden capability downstream — the prefix-laundering class is open again"
    );
}

/// Root cause, now closed: every bypass the fuzzer used to find was a
/// forbidden capability wearing an `ALLOWED_PREFIXES` hat, because `classify`
/// anchored the forbidden check at byte 0 only. This test still generates the
/// full corpus, still isolates the names shaped like that attack, and asserts
/// that **not one of them traverses**.
///
/// It is deliberately not a vacuous "found nothing": the attack-shape count
/// is pinned too, so if the generator ever stops producing laundering
/// candidates the test fails rather than passing for the wrong reason. The
/// `by_normalizer` histogram — once "the shape of the hole" — is now the
/// shape of the attack surface the repair has to keep covering.
#[test]
fn no_fuzz_input_still_launders_a_forbidden_capability_behind_an_exposed_prefix() {
    let mut rng = SplitMix64(SEED);
    let mut attempts_by_normalizer: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut attempts: BTreeSet<String> = BTreeSet::new();
    let mut bypasses: BTreeSet<String> = BTreeSet::new();

    for _ in 0..CORPUS {
        let name = generate(&mut rng);
        let Some(via) = normalizes_to_forbidden(&name) else {
            continue;
        };
        // The exact shape that used to launder: an exposed namespace in front
        // of something that reaches a forbidden capability downstream, and
        // therefore *not* a bare forbidden name `classify` would have caught
        // even before the repair.
        if !starts_with_exposed_prefix(&name) || is_forbidden_capability(&name) {
            continue;
        }
        *attempts_by_normalizer.entry(via).or_default() += 1;
        if attempts.len() < 64 {
            attempts.insert(name.clone());
        }
        if forwards(&name) {
            bypasses.insert(name);
        }
    }

    // Non-vacuity: the fuzzer must still be producing the attack.
    assert!(
        !attempts.is_empty(),
        "the fuzzer must still generate exposed-prefix-wrapped forbidden names"
    );
    // Four *independent* downstream normalizations each reach a forbidden
    // capability from one of these names, so "our router does not resolve
    // `..`" was never a defence. Pinned exactly: this is the shape of the
    // attack surface, and every route on it must stay refused.
    //
    // The counts are larger than the 322 bypasses this test used to pin
    // because they now count every attack-shaped *name the fuzzer generates*
    // — 484 of them — rather than only the ones that got through. Before the
    // repair the split of the same routes among forwarded names was
    // `class_strip 88 / full_pipeline 11 / path_resolve 1 / separator_tail 222`.
    assert_eq!(
        attempts_by_normalizer,
        BTreeMap::from([
            ("class_strip", 107),
            ("full_pipeline", 16),
            ("path_resolve", 1),
            ("separator_tail", 360),
        ]),
        "pinned normalization routes into the forbidden catalogue"
    );

    // ── REGRESSION GUARD (critical) ──────────────────────────────────────
    // This set used to hold 322 witnesses — `audit.forge.run`,
    // `audit.patch.apply`, `audit.Shell.Exec`. The fuzzer needed no
    // cleverness whatsoever. It must now stay empty.
    assert!(
        bypasses.is_empty(),
        "{} laundered names traversed the boundary: {:?}",
        bypasses.len(),
        bypasses.iter().take(16).collect::<Vec<_>>()
    );

    // And the named historical witnesses, refused with the boundary label —
    // segment-wise matching sees `forge.run` inside `audit.forge.run`.
    for witness in ["audit.forge.run", "audit.patch.apply", "audit.Shell.Exec"] {
        assert_eq!(
            verdict(witness),
            Verdict::Violation,
            "{witness:?}: {}",
            why(witness)
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 2. Targeted bypasses — the headline defect, now the headline guard
// ─────────────────────────────────────────────────────────────────────────

/// REPAIRED (was critical), `crates/ccos-enterprise-gateway/src/lib.rs`:
///
/// ```text
/// let forbidden = FORBIDDEN_PREFIXES.iter().any(|p| lowered.starts_with(p))
///     || FORBIDDEN_TOOLS.contains(&lowered.as_str());
/// ```
///
/// `starts_with` anchored the forbidden check at byte 0; `ALLOWED_PREFIXES`
/// then admitted on the same anchor, so any forbidden capability prefixed
/// with an exposed namespace was forwarded. All 121 wrapper x forbidden
/// spellings below were `Forward`.
///
/// They are now all refused, by two different halves of the repair, and this
/// test pins **which half catches which family** so a partial revert cannot
/// hide behind an aggregate count:
///
/// - the five dotted wrappers (`ccos.`, `memory.`, `context.`, `policy.`,
///   `audit.`) produce canonical names, caught by segment-wise forbidden
///   matching → *outside the Enterprise boundary*;
/// - the six separator-bearing or non-ASCII wrappers never get that far →
///   *tool name is empty or not canonical*.
#[test]
fn an_exposed_prefix_can_no_longer_launder_a_forbidden_capability() {
    let forbidden_entries = [
        "shell.exec",
        "shell.spawn",
        "rsi.status",
        "rsi.propose",
        "forge.run",
        "slha.explain",
        "octa.recall",
        "patch.apply",
        "self.rewrite",
        "code.execute",
        "repository.modify",
    ];
    // Wrappers built only from names the gateway itself calls exposed, each
    // paired with the refusal family that must catch it.
    let wrappers = [
        ("ccos.", Verdict::Violation),    // the documented compat alias
        ("memory.", Verdict::Violation),  // exposed class
        ("context.", Verdict::Violation), //
        ("policy.", Verdict::Violation),  //
        ("audit.", Verdict::Violation),   //
        ("memory.recall/../", Verdict::NonCanonical), // path traversal
        ("memory.recall/", Verdict::NonCanonical), // path join
        ("policy.set;", Verdict::NonCanonical), // list/command separator
        ("ccos.\u{200d}", Verdict::NonCanonical), // alias + zero-width joiner
        ("ccos.\u{feff}", Verdict::NonCanonical), // alias + BOM
        ("audit.query/\u{202e}", Verdict::NonCanonical), // path join + RTL override
    ];

    let mut laundered = Vec::new();
    let mut refused = 0usize;
    for (w, expected) in wrappers {
        for f in forbidden_entries {
            let name = format!("{w}{f}");
            // Ground truth: this names a capability the product must never carry.
            assert!(
                normalizes_to_forbidden(&name).is_some(),
                "test corpus error: {name:?} is not a laundered forbidden capability"
            );
            let got = verdict(&name);
            if got == Verdict::Forward {
                laundered.push(name);
                continue;
            }
            assert_eq!(got, expected, "{name:?} caught by the wrong half: {got:?}");
            refused += 1;
        }
    }

    // 11 wrappers x 11 forbidden entries: the boundary now stops all of them.
    assert!(
        laundered.is_empty(),
        "these laundered spellings still traverse: {laundered:?}"
    );
    assert_eq!(
        refused,
        wrappers.len() * forbidden_entries.len(),
        "all 121 laundered spellings are refused, each by its expected half"
    );
    // Spot-check the two the brief names explicitly, so the failure message
    // is unambiguous if this ever regresses.
    assert_eq!(
        verdict("memory.recall/../shell.exec"),
        Verdict::NonCanonical
    );
    assert_eq!(verdict("ccos.shell.exec"), Verdict::Violation);
}

/// REPAIRED (was critical), composed path: the same names used to traverse
/// **the entire admission pipeline** and be billed to the tenant.
///
/// `ccos_enterprise_conformance`'s module docs claim the boundary "is
/// unreachable-around" and that no tenant-configurable gate can widen it.
/// `Deployment::govern_tool` was exactly such a knob: governing
/// `memory.recall/../shell.exec` under the everyday `memory.read` permission
/// handed a plain **reader** a forwarded, billed call to a capability charter
/// §4.2 forbids the profile from carrying at all — three calls, 21 tokens,
/// three journal entries reading as ordinary successes and not one boundary
/// counter moving.
///
/// The boundary is evaluated before authorization, so the repair reaches the
/// composed path unchanged: the same operator action now refuses all three,
/// bills nothing and moves the boundary counter every time.
#[test]
fn the_composed_path_can_no_longer_forward_or_bill_a_wrapped_shell_exec() {
    let mut d = two_tenant_deployment();
    // Nothing privileged happens here: an operator adds two tools under the
    // *lowest* permission in the deployment. It is no longer enough.
    d.govern_tool("memory.recall/../shell.exec", "memory.read")
        .govern_tool("ccos.shell.exec", "memory.read")
        .govern_tool("ccos.rsi.propose", "memory.read");

    // bob is the read-only role from the fixture.
    let bob = actor("memorithm", "bob", AuthStrength::Token);
    for (i, tool) in [
        "memory.recall/../shell.exec",
        "ccos.shell.exec",
        "ccos.rsi.propose",
    ]
    .iter()
    .enumerate()
    {
        let r = request("acme", "bob", tool, &format!("r-{i}"));
        let outcome = d.admit(Call {
            actor: &bob,
            request: &r,
            model: "claude-opus",
            cost_tokens: 7,
            variant: None,
        });
        assert!(
            matches!(outcome.refusal(), Some(Refusal::OutsideBoundary(_))),
            "{tool:?} must be stopped at the boundary even when governed: {outcome:?}"
        );
    }

    // …and none of it costs the tenant budget, i.e. no call went live.
    assert_eq!(
        d.spent("acme"),
        Some(0),
        "nothing was forwarded, nothing billed"
    );

    // The audit trail records three refusals, not three ordinary successes.
    let journal = d.audit_of("acme");
    assert_eq!(journal.len(), 3);
    assert!(journal.iter().all(|r| !r.outcome.is_forwarded()));
    let metrics: BTreeMap<String, u64> = d.metrics().into_iter().collect();
    assert_eq!(metrics.get("gateway.forwarded"), None);
    assert_eq!(
        metrics.get("gateway.refused.outside_boundary"),
        Some(&3),
        "three forbidden capabilities, three boundary counter increments — \
         the events are visible to review now"
    );

    // The *bare* spelling is still stopped, which is all
    // `boundary_contract.rs::no_privilege_reaches_past_the_boundary` proves;
    // the wrapped spellings above are what this file adds.
    d.govern_tool("shell.exec", "memory.read");
    let r = request("acme", "bob", "shell.exec", "r-bare");
    let outcome = d.admit(Call {
        actor: &bob,
        request: &r,
        model: "claude-opus",
        cost_tokens: 7,
        variant: None,
    });
    assert!(matches!(
        outcome.refusal(),
        Some(Refusal::OutsideBoundary(_))
    ));
    assert_eq!(d.spent("acme"), Some(0), "the refusal was not billed");
}

/// REPAIRED (was high): the exposed prefixes used to forward a *bare
/// namespace* with no tool component at all, and arbitrarily deep degenerate
/// sub-namespaces — `memory.` alone, `ccos.` alone and `memory.......` all
/// traversed, because `starts_with("memory.")` is satisfied by `memory.`
/// itself. The canonical-name rule forbids an empty segment, so a trailing or
/// doubled dot is now refused before any matching.
#[test]
fn bare_and_degenerate_namespaces_no_longer_traverse() {
    for tool in [
        "memory.",
        "context.",
        "policy.",
        "audit.",
        "ccos.",
        "memory..",
        "memory.....",
        "ccos.ccos.ccos.ccos.",
        "memory./",
        "memory.\u{feff}",
    ] {
        assert_eq!(
            verdict(tool),
            Verdict::NonCanonical,
            "{tool:?} names no tool and must not be classifiable: {}",
            why(tool)
        );
    }
    // The nearest miss was always correctly refused; it stays refused, as an
    // omission rather than a malformed name, because it *is* a well-formed
    // name that simply is not in the catalogue.
    for tool in ["memory", "ccos", "audit", "system", "system.healthz"] {
        assert_eq!(verdict(tool), Verdict::Omission, "{tool:?}");
    }
    // …and the real thing still forwards, so this is a boundary fix and not
    // an outage of the namespace.
    for tool in ["memory.recall", "ccos.recall", "audit.query", "policy.set"] {
        assert!(forwards(tool), "{tool:?}");
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 3. Homoglyph / normalization / case-folding attacks
// ─────────────────────────────────────────────────────────────────────────

/// What always HELD: every homoglyph and compatibility spelling of a
/// forbidden name is refused. `classify` failed closed because deny-by-default
/// caught what the forbidden list missed.
///
/// What was WRONG (medium, detection) and is now repaired: each one was
/// reported as *"not in the Enterprise catalogue"* — an **omission** — when it
/// was in fact a deliberate boundary attack, so an operator reading the audit
/// trail saw "someone typo'd", not "someone tried `shell.exec`". The
/// canonical-name rule is an ASCII allow-list, so every one of these is now
/// refused as a **malformed name**, before any matching. That is still not the
/// *boundary* label, but it is no longer the label for an honest typo either:
/// `memry.recall` is an omission, `\u{0455}hell.exec` is not.
///
/// Also repaired (low, log spoofing): the refusal used to echo the attacker's
/// raw bytes, bidi overrides included, straight into whatever reads the audit
/// trail. Non-canonical refusals no longer name the tool at all, and the two
/// refusals that do name it pass it through `sanitize()`.
#[test]
fn homoglyph_and_compatibility_spellings_are_refused_as_non_canonical() {
    let attacks = [
        ("\u{0455}hell.exec", "Cyrillic ѕ (U+0455)"),
        ("\u{ff53}hell.exec", "fullwidth ｓ (U+FF53)"),
        ("\u{ff33}HELL.EXEC", "fullwidth Ｓ + ASCII caps"),
        ("\u{017f}hell.exec", "long s ſ (U+017F), NFKC → s"),
        ("shell\u{2024}exec", "one-dot leader ․ (U+2024), NFKC → ."),
        ("shell\u{ff0e}exec", "fullwidth full stop"),
        (
            "s\u{200b}hell.exec",
            "zero-width space inside the namespace",
        ),
        ("s\u{200d}hell.exec", "zero-width joiner"),
        ("s\u{00ad}hell.exec", "soft hyphen"),
        ("\u{200e}shell.exec", "leading LRM"),
        ("\u{202e}shell.exec", "leading RTL override"),
        ("\u{feff}shell.exec", "leading BOM"),
        ("c\u{043e}de.execute", "Cyrillic о in code.execute"),
        (
            "re\u{0440}ository.modify",
            "Cyrillic р in repository.modify",
        ),
        ("\u{0455}elf.rewrite", "Cyrillic ѕ in self.rewrite"),
        ("r\u{0455}i.status", "Cyrillic ѕ in rsi.status"),
    ];

    for (tool, note) in attacks {
        // Ground truth: this *is* a forbidden capability downstream.
        assert!(
            normalizes_to_forbidden(tool).is_some(),
            "test corpus error ({note}): {tool:?}"
        );
        // HELD: fail closed.
        let reason = why(tool);
        // REPAIRED: no longer mislabelled as a catalogue omission.
        assert_eq!(
            reason, "tool name is empty or not canonical",
            "{note}: a non-ASCII spelling must be refused as malformed, got {reason:?}"
        );
        // REPAIRED: the message never carries the attacker's bytes back out.
        for c in tool.chars().filter(|c| !c.is_ascii_graphic()) {
            assert!(
                !reason.contains(c),
                "{note}: refusal message echoes {c:?} from the attacked name"
            );
        }
    }

    // The bidi-override spoof specifically: the message used to contain
    // U+202E verbatim, so a terminal rendered the attacked name backwards.
    let spoof = "\u{202e}shell.exec";
    assert!(
        !why(spoof).contains('\u{202e}'),
        "the rejection message must not embed unescaped bidi overrides"
    );
    assert!(why(spoof).is_ascii(), "{:?}", why(spoof));

    // The two refusals that *do* name the tool only ever see canonical ASCII,
    // and `sanitize()` still caps what they echo at 64 chars plus an ellipsis.
    let long = format!("zz.{}", "y".repeat(200));
    assert_eq!(
        long.len(),
        203,
        "a canonical name under the 256-byte ceiling"
    );
    let reason = why(&long);
    assert_eq!(verdict(&long), Verdict::Omission);
    assert!(
        reason.contains('\u{2026}') && reason.chars().count() < 120,
        "a 203-char name must be truncated in the message, got {} chars: {reason:?}",
        reason.chars().count()
    );
    assert!(
        !reason.contains(&"y".repeat(80)),
        "the message must not replay the whole name: {reason:?}"
    );
}

/// The ASCII-vs-Unicode case-folding gap, measured rather than assumed —
/// and now closed by construction rather than by luck.
///
/// `classify` documents its lowering as the defence against "a case-
/// normalizing router downstream", but uses `to_ascii_lowercase`. The gap was
/// real — Turkish dotless ı, dotted İ and the Kelvin sign all survived it —
/// and cost classification quality: every such name was reported as a
/// catalogue omission. It no longer matters, because a name containing any
/// non-ASCII character is refused as malformed before the lowering is even
/// reached. The Rust facts below still hold and still document *why* an
/// ASCII-only rule is the right shape for this gate.
#[test]
fn the_unicode_case_folding_gap_is_closed_by_refusing_non_ascii_names() {
    // A locale-aware or Unicode-aware downstream maps these onto forbidden
    // names; `to_ascii_lowercase` does not — which is why they must never be
    // classified at all.
    assert_eq!(
        '\u{0131}'.to_uppercase().to_string(),
        "I",
        "ı uppercases to I"
    );
    assert_eq!(
        '\u{0130}'.to_lowercase().to_string(),
        "i\u{0307}",
        "İ lowercases to i + combining dot, never to plain i"
    );

    for tool in [
        "rs\u{0131}.status", // dotless ı — Turkish-locale downstream folds to rsi.
        "RS\u{0130}.status", // dotted İ — Unicode lowercase folds to rsi̇.
        "she\u{212a}.exec",  // Kelvin sign, NFKC → k (not in a forbidden name, but
                             // proves the fold is unimplemented)
    ] {
        assert_eq!(
            why(tool),
            "tool name is empty or not canonical",
            "{tool:?} must be refused for shape, not measured against the catalogue"
        );
    }
    // The ASCII half of the promise does hold, exactly and for every entry.
    for entry in FORBIDDEN_PREFIXES.iter().chain(FORBIDDEN_TOOLS.iter()) {
        for spelling in [
            entry.to_uppercase(),
            entry.to_lowercase(),
            entry
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if i % 2 == 0 {
                        c.to_ascii_uppercase()
                    } else {
                        c.to_ascii_lowercase()
                    }
                })
                .collect::<String>(),
        ] {
            let name = if FORBIDDEN_PREFIXES.contains(entry) {
                format!("{spelling}x")
            } else {
                spelling.clone()
            };
            assert!(
                why(&name).contains("outside the Enterprise boundary"),
                "{name:?} must be a boundary violation whatever its ASCII case"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 4. Prefix-boundary and canonicality attacks
// ─────────────────────────────────────────────────────────────────────────

/// The prefix-boundary matrix from the brief, each row asserting the real
/// disposition and the real *reason*.
///
/// What always HELD: `.`-anchoring is exact — `shell` is not `shell.` — and
/// every whitespace/control decoration fails closed before any matching.
///
/// What changed, and why each row moved:
///
/// - the seven `Forward` rows at the bottom are gone. Five separator- or
///   invisible-bearing spellings are now `NonCanonical`; `ccos.shell.exec`,
///   `ccos.code.execute` and `memory.repository.modify` are `Violation`,
///   because forbidden matching runs at every segment boundary;
/// - `.shell.exec`, `x/shell.exec`, `code.execute.`, `repository.modify/`
///   and `shell.` moved from `Omission`/`Violation` to `NonCanonical`: an
///   empty segment or a `/` is not a name the boundary will read;
/// - `shell.exec\u{feff}` and `shell.exec\u{200d}` moved from `Violation` to
///   `NonCanonical`. The invisible code points used to be neither
///   `is_control` nor `is_whitespace` and so survived the old check; the
///   ASCII allow-list refuses them.
///
/// The `Forward` rows are now real catalogue names, and the guard on them is
/// inverted: a forwarded name must **not** reach a forbidden capability under
/// any modelled downstream normalization.
#[test]
fn prefix_boundary_matrix() {
    use Verdict::*;

    let cases: &[(&str, Verdict)] = &[
        ("shell", Omission),      // no dot: not the namespace
        ("shell.", NonCanonical), // trailing dot: empty final segment
        ("shell..", NonCanonical),
        ("shell.exec", Violation),
        ("SHELL.EXEC", Violation),
        ("sHeLl.ExEc", Violation),
        (".shell.exec", NonCanonical), // leading dot: empty first segment
        ("x/shell.exec", NonCanonical), // `/` is not a canonical byte
        ("shell.exec\u{0}", NonCanonical), // NUL is a control byte
        ("shell.exec ", NonCanonical), // trailing space
        (" shell.exec", NonCanonical),
        ("shell.exec\t", NonCanonical),
        ("shell.exec\n", NonCanonical),
        ("shell.exec\u{a0}", NonCanonical),   // NBSP
        ("shell.exec\u{3000}", NonCanonical), // ideographic space
        ("shell.exec\u{2028}", NonCanonical), // line separator
        ("", NonCanonical),
        ("   ", NonCanonical),
        ("\u{0}", NonCanonical),
        // …and the invisible, non-`is_control`, non-`is_whitespace` code
        // points that used to survive the old canonicality check are refused
        // by the ASCII allow-list now:
        ("shell.exec\u{feff}", NonCanonical),
        ("shell.exec\u{200d}", NonCanonical),
        // Exact-match forbidden tools no longer lose their label to a
        // decoration by being silently reclassified as a mere omission.
        ("code.execute", Violation),
        ("code.execute.", NonCanonical),
        ("code.execute\u{feff}", NonCanonical),
        ("repository.modify/", NonCanonical),
        // And every formerly laundered form is refused — by shape…
        ("memory.recall/../shell.exec", NonCanonical),
        ("memory.recall/shell.exec", NonCanonical),
        ("policy.set;shell.exec", NonCanonical),
        ("ccos.\u{200d}shell.exec", NonCanonical),
        // …or by the boundary itself, matched at a segment boundary.
        ("ccos.shell.exec", Violation),
        ("ccos.code.execute", Violation),
        ("memory.repository.modify", Violation),
        ("audit.query.shell.spawn", Violation),
        ("memory.recall.self.rewrite", Violation),
        // The catalogue still traverses — the repair is not an outage.
        ("memory.recall", Forward),
        ("ccos.recall", Forward),
        ("ccos.qpage.read", Forward),
        ("policy.set", Forward),
        ("audit.query", Forward),
        ("system.health", Forward),
        ("MEMORY.RECALL", Forward),
    ];

    for (tool, expected) in cases {
        if *expected == Forward {
            // The inverted guard: nothing the boundary forwards may reach a
            // forbidden capability under any downstream normalization we model.
            assert_eq!(
                normalizes_to_forbidden(tool),
                None,
                "matrix error: {tool:?} is forwarded and still reaches a forbidden capability"
            );
        }
        assert_eq!(&verdict(tool), expected, "{tool:?}");
    }
}

/// STILL OPEN (medium): every canonicality rejection happens *before* any
/// matching, so a forbidden name with a control byte is refused as "not
/// canonical" rather than as a boundary violation. That is fail-closed and
/// fine for containment — but it means `gateway.refused.*` cannot be used to
/// count boundary probes, since the cheapest evasion (append `\0`) changes
/// the label. The repair did not change this, and it is pinned deliberately:
/// the order is correct, the *observability* consequence is the open finding.
#[test]
fn canonicality_check_precedes_the_boundary_check() {
    for entry in FORBIDDEN_PREFIXES {
        let attacked = format!("{entry}exec\u{0}");
        assert_eq!(
            why(&attacked),
            "tool name is empty or not canonical",
            "{attacked:?} is refused for shape, never reported as a boundary probe"
        );
    }
    // The undecorated name is what gets the boundary label.
    assert!(why("shell.exec").contains("outside the Enterprise boundary"));
}

// ─────────────────────────────────────────────────────────────────────────
// 5. Refusal taxonomy in the composed path
// ─────────────────────────────────────────────────────────────────────────

/// STILL OPEN (medium, spec violation) —
/// `crates/ccos-enterprise-runtime/src/lib.rs`:
///
/// ```text
/// if let Disposition::Reject(why) = classify(call.request) {
///     return refuse(Refusal::OutsideBoundary(why));
/// }
/// ```
///
/// Unchanged by the move out of the test harness and into a shipped crate:
/// the composition is now owned, but this collapse moved with it verbatim.
///
/// The gateway crate goes to deliberate trouble to distinguish a boundary
/// *violation* from a catalogue *omission* (its own docs: "an operator
/// reading the audit trail should be able to tell the two apart"), and
/// `tests/boundary_contract.rs::unlisted_tools_are_refused_as_omissions_not_violations`
/// pins that distinction. The composed path then collapses all three gateway
/// refusals — violation, omission and malformed-name — into the single
/// `Refusal::OutsideBoundary` variant and the single
/// `gateway.refused.outside_boundary` counter. A typo and an attempted
/// `shell.exec` are indistinguishable in the journal's structured fields and
/// in every metric; only the free-text string still differs. Untouched by the
/// gateway repair, and still an open finding.
#[test]
fn the_composed_path_collapses_three_refusals_into_one_boundary_label() {
    let mut d = two_tenant_deployment();
    let bob = actor("memorithm", "bob", AuthStrength::Token);

    let probes = [
        ("memry.recall", "a typo — an omission"),
        ("shell.exec", "a boundary attack — a violation"),
        ("memory.recall\u{0}", "a malformed name"),
    ];
    for (i, (tool, note)) in probes.iter().enumerate() {
        let r = request("acme", "bob", tool, &format!("r-{i}"));
        let outcome = d.admit(Call {
            actor: &bob,
            request: &r,
            model: "claude-opus",
            cost_tokens: 5,
            variant: None,
        });
        assert!(
            matches!(outcome.refusal(), Some(Refusal::OutsideBoundary(_))),
            "{note}: {tool:?} → {outcome:?}"
        );
    }

    let metrics: BTreeMap<String, u64> = d.metrics().into_iter().collect();
    assert_eq!(
        metrics.get("gateway.refused.outside_boundary"),
        Some(&3),
        "DEFECT pinned: all three land on the same counter, so an operator \
         cannot alert on boundary probes without alerting on typos"
    );
    assert_eq!(metrics.get("gateway.refused.tool_not_governed"), None);
    // Nothing was billed — that part of the contract holds.
    assert_eq!(d.spent("acme"), Some(0));

    // The information does survive in the message, which is the only reason
    // this is a taxonomy defect and not a total loss.
    let reasons: Vec<&Refusal> = d
        .audit_of("acme")
        .iter()
        .filter_map(|r| r.outcome.refusal())
        .collect();
    let texts: Vec<&str> = reasons
        .iter()
        .map(|r| match r {
            Refusal::OutsideBoundary(w) => w.as_str(),
            _ => unreachable!("all three are boundary refusals"),
        })
        .collect();
    assert!(texts[0].contains("not in the Enterprise catalogue"));
    assert!(texts[1].contains("outside the Enterprise boundary"));
    assert!(texts[2].contains("not canonical"));
}

/// STILL OPEN (low). What HELD: the gateway's case-insensitivity is *not*
/// carried into the governance map, and that asymmetry fails closed.
/// `MEMORY.RECALL` clears the boundary but misses `governed_tools`, so it is
/// refused. Worth pinning: it means a deployment cannot be tricked into
/// authorizing a case variant, but it also means the boundary and the
/// authorizer key on different strings, and only luck (a `BTreeMap` miss)
/// makes that safe. The canonical-name rule permits `[A-Za-z0-9_]`, so
/// uppercase names are still classifiable and the asymmetry survives.
#[test]
fn boundary_is_case_insensitive_but_authorization_is_not() {
    let mut d = two_tenant_deployment();
    let bob = actor("memorithm", "bob", AuthStrength::Token);

    assert!(forwards("MEMORY.RECALL"), "the boundary lowercases");
    let r = request("acme", "bob", "MEMORY.RECALL", "r-case");
    let outcome = d.admit(Call {
        actor: &bob,
        request: &r,
        model: "claude-opus",
        cost_tokens: 5,
        variant: None,
    });
    assert_eq!(
        outcome.refusal(),
        Some(&Refusal::ToolNotGoverned),
        "authorization does not lowercase — fail-closed, but by accident"
    );
    assert_eq!(d.spent("acme"), Some(0));
}

// ─────────────────────────────────────────────────────────────────────────
// 6. Size, time and memory
// ─────────────────────────────────────────────────────────────────────────

/// REPAIRED (was high): a 1 MiB tool name used to be **forwarded**. It was at
/// least linear rather than quadratic — one `to_ascii_lowercase` allocation
/// plus a `chars()` scan — but the gateway allocated and scanned a megabyte
/// per request, and then embedded the whole thing in a refusal message and an
/// audit record.
///
/// A 256-byte ceiling is now checked before anything else, so an oversized
/// name costs `len()` and never reaches the lowercase, the scan, the matching
/// or the message. This test pins the ceiling *exactly* — 256 bytes forwards,
/// 257 does not — and keeps one-sided timing ceilings measured back to back
/// on the same machine, so they cannot flake into a false failure the way an
/// equality on a duration would.
#[test]
fn an_oversized_name_is_refused_by_length_not_scanned() {
    const MIB: usize = 1 << 20;
    let small = format!("memory.{}", "a".repeat(64 * 1024 - 7));
    let large = format!("memory.{}", "a".repeat(MIB - 7));
    assert_eq!(small.len(), 64 * 1024);
    assert_eq!(large.len(), MIB);

    // The ceiling, to the byte. Both names are otherwise perfectly canonical
    // and in the exposed catalogue, so only the length decides.
    let at_limit = format!("memory.{}", "a".repeat(256 - 7));
    let over_limit = format!("memory.{}", "a".repeat(257 - 7));
    assert_eq!(at_limit.len(), 256);
    assert_eq!(over_limit.len(), 257);
    assert_eq!(verdict(&at_limit), Verdict::Forward, "256 bytes is allowed");
    assert_eq!(
        verdict(&over_limit),
        Verdict::NonCanonical,
        "257 bytes is refused by length"
    );

    let bench = |name: &str, expected: Disposition| -> u128 {
        let r = req(name);
        let mut best = u128::MAX;
        for _ in 0..64 {
            let t0 = Instant::now();
            let d = classify(&r);
            let ns = t0.elapsed().as_nanos();
            assert_eq!(d, expected);
            best = best.min(ns);
        }
        best.max(1)
    };

    let rejected = Disposition::Reject("tool name is empty or not canonical".into());
    let t_at_limit = bench(&at_limit, Disposition::Forward);
    let t_small = bench(&small, rejected.clone());
    let t_large = bench(&large, rejected);

    // 16x the bytes must not cost 16x the time: the length check is O(1), so
    // the two refusals are indistinguishable in cost. Both are the minimum of
    // 64 back-to-back samples, so this is a one-sided ceiling on the best
    // case and cannot flake the way an equality on a duration would.
    let ratio = t_large as f64 / t_small as f64;
    assert!(
        ratio < 16.0,
        "16x input cost {ratio:.1}x the time — the length check is being \
         preceded by a scan (small {t_small} ns, large {t_large} ns)"
    );
    // The actual point of the repair, stated absolutely. `classify` used to
    // allocate a lowercased megabyte and scan it; no allocation-plus-scan of
    // 1 MiB fits in 50 µs on any machine this suite runs on, so coming in
    // under that is proof the length check ran first. Measured around 60 ns
    // in debug, against ~3.5 µs for the 256-byte name that does traverse.
    assert!(
        t_large < 50_000,
        "1 MiB refusal took {t_large} ns (a 256-byte forwarded name takes \
         {t_at_limit} ns) — the megabyte is being scanned again"
    );

    // Bigger, weirder, still no panic — and every one of them is now refused
    // rather than forwarded.
    for name in [
        format!("memory.{}", "\u{1f600}".repeat(64 * 1024)), // 256 KiB of emoji
        format!("ccos.{}", "\u{4e2d}".repeat(64 * 1024)),    // CJK
        format!("{}shell.exec", "memory.recall/../".repeat(4096)),
        "\u{200d}".repeat(200_000),
        "\u{0}".repeat(MIB),
    ] {
        assert_eq!(
            verdict(&name),
            Verdict::NonCanonical,
            "an oversized hostile name must be refused, not classified"
        );
    }
    assert!(
        !forwards(&large),
        "a 1 MiB tool name no longer traverses the boundary"
    );
}

/// REPAIRED (was high, exhaustion), in three separate places. The original
/// finding had three halves and every one of them is now closed; this test
/// keeps the same hostile inputs and asserts the opposite of what it used to.
///
/// 1. **The refusal message used to carry the name back out.** Every rejected
///    request stored the attacker's entire tool name **twice** — once in
///    `AuditRecord::tool`, once inside the `Refusal::OutsideBoundary` message
///    `classify` built with `format!("tool '{}' is not in the Enterprise
///    catalogue", req.tool)`. N bytes of request became >2N bytes of
///    permanently retained heap. Names over 256 bytes are now refused before
///    any message is formatted, and the two messages that do name a tool
///    truncate it to 64 chars via `sanitize()`.
/// 2. **The journal used to store the untruncated name.** This test asserted
///    `record.tool.len() == 1 MiB` as an open finding. `Deployment::journal`
///    now clamps every wire-supplied identifier to `MAX_IDENTIFIER_BYTES`
///    (128), so a 1 MiB name retains 128 bytes: amplification fell from ~1.0x
///    to ~0.0001x, and the assertion below is the same measurement with the
///    opposite expectation.
/// 3. **The journal had no cap.** It was a `Vec` that only grew, so a flood
///    converted N bytes of request into ~N bytes of retained heap, linear in
///    request count, with no counter or quota reacting — the shape that let an
///    unauthenticated caller retain 1.15 GiB across five million refused
///    calls. The journal is now a bounded buffer
///    (`DEFAULT_AUDIT_CAPACITY`, overridable via
///    `Deployment::with_audit_capacity`) that drops the oldest record and
///    counts the loss in `Deployment::audit_dropped`. The flood below no
///    longer measures unbounded growth; it measures the **bound** and the
///    **drop count**, which is the honest failure mode announced in
///    `ccos_enterprise_runtime`'s module docs.
#[test]
fn a_refused_request_retains_a_bounded_number_of_attacker_bytes() {
    const MIB: usize = 1 << 20;
    let mut d = two_tenant_deployment();
    let bob = actor("memorithm", "bob", AuthStrength::Token);

    let huge = "z".repeat(MIB);
    let r = request("acme", "bob", &huge, "r-huge");
    let outcome = d.admit(Call {
        actor: &bob,
        request: &r,
        model: "claude-opus",
        cost_tokens: 1,
        variant: None,
    });

    let Some(Refusal::OutsideBoundary(message)) = outcome.refusal() else {
        panic!("expected a boundary-labelled refusal, got {outcome:?}");
    };
    // REPAIRED (1): the message is a constant, not a copy of the 1 MiB name.
    assert_eq!(
        message, "tool name is empty or not canonical",
        "the refusal message must not embed the attacker's name"
    );
    assert!(
        message.len() < 256,
        "refusal messages are bounded ({} bytes)",
        message.len()
    );
    let trail: Vec<&AuditRecord> = d.audit().collect();
    let record = trail[0];
    // ── REGRESSION GUARD (high) ──────────────────────────────────────────
    // REPAIRED (2): this used to assert `== MIB`, with the comment "the
    // journal still stores the untruncated name". Same 1 MiB input, opposite
    // expectation: the record keeps only what identifies the attempt.
    assert_eq!(
        record.tool.len(),
        MAX_IDENTIFIER_BYTES,
        "the journal must clamp a wire-supplied name, not store all {MIB} bytes"
    );
    assert!(
        record.tool.chars().all(|c| c == 'z'),
        "the retained prefix is the attacker's own bytes, just bounded: {:?}",
        record.tool
    );
    let retained = record.tool.len()
        + match &record.outcome {
            Outcome::Refused(Refusal::OutsideBoundary(w)) => w.len(),
            other => panic!("{other:?}"),
        };
    assert!(
        retained < MAX_IDENTIFIER_BYTES + 256,
        "amplification factor {:.6}x per refused request — a 1 MiB name must \
         not retain more than a clamped identifier plus a constant message",
        retained as f64 / MIB as f64
    );

    // ── REGRESSION GUARD (high) ──────────────────────────────────────────
    // REPAIRED (3): growth used to be linear in request count and this block
    // asserted it ("STILL OPEN: no journal cap"). Same flood, opposite claim:
    // 24 x 128 KiB of hostile request — 3 MiB on the wire — now retains a few
    // kilobytes, because each record is clamped.
    let mut d = two_tenant_deployment();
    let chunk = "q".repeat(128 * 1024);
    for i in 0..24 {
        let r = request("acme", "bob", &chunk, &format!("r-{i}"));
        d.admit(Call {
            actor: &bob,
            request: &r,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
        });
    }
    let total: usize = d
        .audit()
        .map(|r| {
            r.tool.len()
                + match &r.outcome {
                    Outcome::Refused(Refusal::OutsideBoundary(w)) => w.len(),
                    _ => 0,
                }
        })
        .sum();
    assert_eq!(
        d.audit().count(),
        24,
        "24 records fit inside the default cap"
    );
    assert_eq!(d.audit_dropped(), 0, "so nothing was dropped");
    assert!(
        total <= 24 * (MAX_IDENTIFIER_BYTES + 256),
        "24 refused 128 KiB requests retained {total} bytes — the journal is \
         storing untruncated names again"
    );
    assert!(
        total < 128 * 1024,
        "REPAIRED: 3 MiB of hostile request must retain less than one of its \
         own requests, got {total} bytes"
    );

    // ── REGRESSION GUARD (high) ──────────────────────────────────────────
    // And the record *count* is bounded too, which is what turns "linear in
    // request count" into "flat". A deliberately tiny capacity makes the drop
    // arithmetic exact and the test cheap; the default is
    // `DEFAULT_AUDIT_CAPACITY` and the mechanism is the same one.
    assert_eq!(DEFAULT_AUDIT_CAPACITY, 100_000, "the announced default cap");
    let mut d = two_tenant_deployment().with_audit_capacity(16);
    for i in 0..500 {
        let r = request("acme", "bob", &chunk, &format!("r-{i}"));
        d.admit(Call {
            actor: &bob,
            request: &r,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
        });
    }
    assert_eq!(
        d.audit().count(),
        16,
        "500 refused floods must not grow the journal past its capacity"
    );
    assert_eq!(
        d.audit_dropped(),
        484,
        "and the deployment says exactly how many records it lost, so an \
         operator knows the buffer is not the audit story"
    );
    let flooded: usize = d.audit().map(|r| r.tool.len()).sum();
    assert!(
        flooded <= 16 * MAX_IDENTIFIER_BYTES,
        "64 MiB of hostile request retained {flooded} bytes — the bound is off"
    );
    // The retained window is the newest, and still ordered by decision.
    let seqs: Vec<u64> = d.audit().map(|r| r.sequence).collect();
    assert_eq!(seqs, (484..500).collect::<Vec<_>>());

    // And none of it was billed, so the budget gate never notices (HELD).
    assert_eq!(d.spent("acme"), Some(0));
    // Nor does the metric registry: refusal labels are low-cardinality (HELD).
    // `audit.dropped` is a fixed series name, not one per dropped record.
    assert!(
        d.metrics().len() <= 8,
        "metric cardinality stays bounded under name flooding: {:?}",
        d.metrics()
    );
}

/// What HELD: the tool name never leaks into a metric series name, so the
/// 120k-name corpus cannot blow past `CounterRegistry::MAX_SERIES`. This is
/// the exhaustion vector that was *always* closed, and it is worth a
/// regression pin because `Deployment::admit` builds a series name with
/// `format!`.
#[test]
fn hostile_tool_names_cannot_explode_metric_cardinality() {
    let mut d = two_tenant_deployment();
    let bob = actor("memorithm", "bob", AuthStrength::Token);
    let mut rng = SplitMix64(SEED ^ 0xa5a5_a5a5);
    for i in 0..3_000 {
        let name = generate(&mut rng);
        let r = request("acme", "bob", &name, &format!("r-{i}"));
        d.admit(Call {
            actor: &bob,
            request: &r,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
        });
    }
    let metrics = d.metrics();
    assert!(
        metrics.len() <= 8,
        "3000 hostile names produced {} series: {metrics:?}",
        metrics.len()
    );
    assert!(metrics.iter().all(|(k, _)| k.starts_with("gateway.")));
    assert!(metrics.iter().all(|(k, _)| k.is_ascii() && k.len() < 64));
}

// ─────────────────────────────────────────────────────────────────────────
// 7. Heavy sweep — kept out of the default run
// ─────────────────────────────────────────────────────────────────────────

/// One million generated names plus an 8 MiB name.
///
/// This used to assert `violations > 0` — "the bypass reproduces at 1M
/// scale". It now asserts the opposite at the same scale, and the 8 MiB names
/// are refused by length instead of forwarded.
///
/// Run with:
/// `cargo test -p ccos-enterprise-conformance --test stress_gateway_fuzz \
///  --release -- --ignored --nocapture`
#[test]
#[ignore = "1M names + 8 MiB inputs; see the doc comment for the command"]
fn heavy_million_name_sweep() {
    let mut rng = SplitMix64(SEED ^ 0xdead_beef);
    let mut violations: Vec<String> = Vec::new();
    let mut attempts = 0usize;
    for _ in 0..1_000_000 {
        let name = generate(&mut rng);
        if normalizes_to_forbidden(&name).is_some() && !is_forbidden_capability(&name) {
            attempts += 1;
        }
        if classify(&req(&name)) == Disposition::Forward && normalizes_to_forbidden(&name).is_some()
        {
            violations.push(name);
        }
    }
    assert!(attempts > 0, "the fuzzer must still generate the attack");
    assert!(
        violations.is_empty(),
        "the bypass reproduced at 1M scale: {:?}",
        violations.iter().take(16).collect::<Vec<_>>()
    );

    for bytes in [1 << 21, 1 << 22, 1 << 23] {
        let name = format!("memory.{}", "a".repeat(bytes - 7));
        let t0 = Instant::now();
        assert_eq!(
            verdict(&name),
            Verdict::NonCanonical,
            "{bytes} bytes must be refused by length"
        );
        println!("{bytes} bytes → {:?}", t0.elapsed());
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 8. Hostile identifiers on the composed path
// ─────────────────────────────────────────────────────────────────────────

/// REGRESSION GUARD (was critical), composed path. Everything above attacks
/// the *tool* name; the composed path takes three more strings straight off
/// the wire — tenant, actor and request_id — and until the composition became
/// a shipped crate, nothing bounded them and nothing bound them to the
/// credential. `Deployment::admit` read only `AuthenticatedActor`'s
/// **strength**, then keyed RBAC on `request.actor` (a plain client string)
/// and resolved the tenant from `request.tenant`, so any token-strength
/// principal could present another actor's name and another tenant's id and
/// act with their permissions against their budget. `OrgId` was carried on
/// every credential and read by nothing.
///
/// The rest of this file relies on that hole being shut — every composed-path
/// test above pairs `bob`'s credential with `bob`'s request — without ever
/// saying so. This test says so, with the same generator pointed at the three
/// identifier fields instead of the tool name, and pins four claims:
///
/// 1. the request must name the actor its credential proves, so `bob` asking
///    to be `alice` (who *can* write) is `ActorMismatch`, not a forwarded
///    write;
/// 2. the credential's org must own the tenant, so a `memorithm` principal
///    cannot reach `initech`'s tenant;
/// 3. an empty or over-long identifier is `MalformedRequest(field)` *before*
///    any tenant state is consulted — the ceiling is `MAX_IDENTIFIER_BYTES`
///    and it is pinned to the byte;
/// 4. none of it is ever billed, `admit` never panics, and the refusal tags
///    stay constants rather than becoming a metric series per hostile string.
#[test]
fn hostile_identifiers_never_traverse_the_composed_path() {
    let mut d = two_tenant_deployment();
    // A tenant in a *different* organization, so claim 2 is reachable at all.
    // `add_tenant` now names the owning org and reports whether it provisioned
    // anything: re-provisioning a live tenant used to silently zero its ledger.
    let mut hooli = TenantState::new(1_000);
    hooli.allow_model("claude-opus");
    assert!(d.add_tenant("initech", "hooli", hooli), "a fresh tenant");
    assert!(
        !d.add_tenant("initech", "hooli", TenantState::new(1)),
        "a live tenant is not silently replaced"
    );
    // alice can write; bob cannot. That asymmetry is what impersonation buys.
    let bob = actor("memorithm", "bob", AuthStrength::Token);

    // Non-vacuity: the legitimate call this test's hostile variants are built
    // from really is admitted, so a blanket refusal cannot pass by accident.
    let good = request("acme", "bob", "memory.recall", "r-baseline");
    assert_eq!(
        d.admit(Call {
            actor: &bob,
            request: &good,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
        }),
        Outcome::Forwarded
    );
    assert_eq!(d.spent("acme"), Some(1));

    // ── The named witnesses ──────────────────────────────────────────────
    // Every probe below uses `memory.ingest`, which bob is *not* permitted:
    // authorization is evaluated after all three identifier gates, so nothing
    // here can be billed however the generator collides with a real id, and
    // any of these reaching `PermissionDenied` proves the earlier gate ran.
    let probe = |d: &mut Deployment, tenant: &str, name: &str, id: &str| -> Outcome {
        let r = request(tenant, name, "memory.ingest", id);
        d.admit(Call {
            actor: &bob,
            request: &r,
            model: "claude-opus",
            cost_tokens: 500,
            variant: None,
        })
    };

    // (1) The impersonation. Under the predecessor this was a forwarded,
    // billed write: RBAC keyed on `request.actor`, and alice is a writer.
    assert_eq!(
        probe(&mut d, "acme", "alice", "r-impersonate").refusal(),
        Some(&Refusal::ActorMismatch),
        "a credential proving bob must not authorize a request naming alice"
    );
    // (2) The cross-org reach, likewise genuine authentication in the wrong org.
    assert_eq!(
        probe(&mut d, "hooli", "bob", "r-cross-org").refusal(),
        Some(&Refusal::TenantNotOwnedByOrg),
        "memorithm's principal must not reach initech's tenant"
    );
    // (3) The shape gate, pinned to the byte on each of the three fields.
    let at_limit = "z".repeat(MAX_IDENTIFIER_BYTES);
    let over_limit = "z".repeat(MAX_IDENTIFIER_BYTES + 1);
    for (field, tenant, name, id) in [
        ("tenant", "", "bob", "r-empty"),
        ("actor", "acme", "", "r-empty"),
        ("request_id", "acme", "bob", ""),
        ("tenant", over_limit.as_str(), "bob", "r-over"),
        ("actor", "acme", over_limit.as_str(), "r-over"),
        ("request_id", "acme", "bob", over_limit.as_str()),
    ] {
        assert_eq!(
            probe(&mut d, tenant, name, id).refusal(),
            Some(&Refusal::MalformedRequest(field.to_string())),
            "an empty or oversized {field} is refused for shape, by name"
        );
    }
    // …and exactly at the ceiling the shape gate is satisfied, so the *next*
    // gate decides. 128 bytes is a legal identifier, 129 is not.
    assert_eq!(
        probe(&mut d, at_limit.as_str(), "bob", "r-at-limit").refusal(),
        Some(&Refusal::UnknownTenant),
        "{MAX_IDENTIFIER_BYTES} bytes is a well-formed tenant id, merely unknown"
    );
    assert_eq!(
        probe(&mut d, "acme", "bob", at_limit.as_str()).refusal(),
        Some(&Refusal::PermissionDenied),
        "a {MAX_IDENTIFIER_BYTES}-byte request_id reaches authorization"
    );

    // The impersonation is journaled, at zero cost, under the name that was
    // *claimed* — an operator can see who was impersonated, and the ledger
    // still reconciles because a refusal is never billed.
    let impersonation = d
        .audit_of("acme")
        .into_iter()
        .find(|r| r.request_id == "r-impersonate")
        .expect("the attempt is journaled, not dropped");
    assert_eq!(impersonation.actor, "alice", "the claimed name is recorded");
    assert_eq!(impersonation.cost, 0, "a refusal is never billed");

    // ── The sweep ────────────────────────────────────────────────────────
    // The same generator, aimed at each identifier field in turn.
    let mut rng = SplitMix64(SEED ^ 0x1dea_5eed);
    let mut tags: BTreeMap<&'static str, usize> = BTreeMap::new();
    for i in 0..2_000 {
        let s = generate(&mut rng);
        for (field, r) in [
            (
                "tenant",
                request(&s, "bob", "memory.ingest", &format!("t-{i}")),
            ),
            (
                "actor",
                request("acme", &s, "memory.ingest", &format!("a-{i}")),
            ),
            ("request_id", request("acme", "bob", "memory.ingest", &s)),
        ] {
            // A panic here fails the test and names the input.
            let outcome = d.admit(Call {
                actor: &bob,
                request: &r,
                model: "claude-opus",
                cost_tokens: 500,
                variant: None,
            });
            let Some(refusal) = outcome.refusal() else {
                panic!("hostile {field} {s:?} traversed the composed path");
            };
            *tags
                .entry(match refusal {
                    Refusal::MalformedRequest(_) => "malformed_request",
                    Refusal::ActorMismatch => "actor_mismatch",
                    Refusal::UnknownTenant => "unknown_tenant",
                    Refusal::PermissionDenied => "permission_denied",
                    other => panic!("unexpected refusal for a hostile {field}: {other:?}"),
                })
                .or_default() += 1;
        }
    }
    // Non-vacuity per gate: the sweep must actually exercise each of them,
    // or "nothing traversed" would be a claim about a generator that stopped
    // generating. `permission_denied` is the tail: a hostile string that is a
    // well-formed request_id gets all the way to authorization.
    for gate in [
        "malformed_request",
        "actor_mismatch",
        "unknown_tenant",
        "permission_denied",
    ] {
        assert!(
            tags.get(gate).copied().unwrap_or(0) > 0,
            "{gate} unexercised"
        );
    }

    // 6 000 hostile calls at 500 tokens each against a 1 000-token budget:
    // only the one baseline call was ever charged.
    assert_eq!(
        d.spent("acme"),
        Some(1),
        "not one hostile identifier reached the meter"
    );
    assert_eq!(d.spent("hooli"), Some(0));
    assert_eq!(d.spent("nowhere"), None, "and an absent tenant says so");

    // Refusal tags are constants, so 6 000 distinct hostile identifiers do not
    // become 6 000 metric series.
    let metrics = d.metrics();
    assert!(
        metrics.len() <= 12,
        "hostile identifiers produced {} series: {metrics:?}",
        metrics.len()
    );
    assert!(metrics.iter().all(|(k, _)| k.is_ascii() && k.len() < 64));
    let by_name: BTreeMap<String, u64> = metrics.into_iter().collect();
    let count = |k: &str| by_name.get(k).copied().unwrap_or(0);
    assert_eq!(
        by_name.get("gateway.forwarded"),
        Some(&1),
        "the baseline only"
    );
    assert_eq!(count("gateway.refused.tenant_not_owned"), 1);
    assert!(count("gateway.refused.actor_mismatch") > 0);
    assert!(count("gateway.refused.malformed_request") > 0);
}

/// Sanity, and the outage guard for the repair: the exposed catalogue still
/// works. A boundary that refused everything would make every assertion above
/// vacuous, and the canonical-name rule plus segment-wise forbidden matching
/// are exactly the kind of change that could over-refuse.
#[test]
fn the_exposed_catalogue_is_not_collaterally_broken() {
    for tool in ALLOWED_TOOLS {
        assert!(forwards(tool), "{tool}");
    }
    for prefix in ALLOWED_PREFIXES {
        assert!(forwards(&format!("{prefix}recall")), "{prefix}recall");
    }
    // Real, multi-segment catalogue spellings — the shapes an installed
    // deployment actually sends, including the `ccos.` compatibility alias
    // and mixed case, which the canonical-name rule must keep accepting.
    for tool in [
        "memory.recall",
        "memory.ingest",
        "memory.search",
        "context.get",
        "context.window.read",
        "policy.set",
        "policy.budget.read",
        "audit.query",
        "audit.record.export",
        "ccos.recall",
        "ccos.qpage.read",
        "ccos.memory.recall",
        "system.health",
        "memory.recall_v2",
        "memory.recall2",
        "MEMORY.Recall",
    ] {
        assert!(forwards(tool), "{tool:?}: {}", why(tool));
    }
    for entry in FORBIDDEN_PREFIXES {
        assert!(!forwards(&format!("{entry}anything")), "{entry}");
    }
    for entry in FORBIDDEN_TOOLS {
        assert!(!forwards(entry), "{entry}");
    }
}
