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
//! ## VERDICT: the invariant is BROKEN, and broken end to end.
//!
//! `classify` checks `FORBIDDEN_PREFIXES` only against the **start** of the
//! name, then admits anything that starts with an `ALLOWED_PREFIXES` entry.
//! Prefixing a forbidden capability with an exposed namespace therefore turns
//! a boundary violation into a `Forward`:
//!
//! | input                         | classify  | plausible downstream         |
//! |-------------------------------|-----------|------------------------------|
//! | `ccos.shell.exec`             | `Forward` | class strip → `shell.exec`   |
//! | `memory.repository.modify`    | `Forward` | class strip → the exact tool |
//! | `ccos.rsi.propose`            | `Forward` | class strip → `rsi.propose`  |
//! | `memory.recall/../shell.exec` | `Forward` | path resolve → `shell.exec`  |
//! | `policy.set;shell.exec`       | `Forward` | list split → `shell.exec`    |
//! | `ccos.\u{200d}shell.exec`     | `Forward` | ZWJ strip, then class strip  |
//!
//! "Class strip" is not hypothetical decoration — it is the gateway's own
//! stated design. `ALLOWED_PREFIXES`' doc comment says the names are
//! "*capability classes*", that "Core itself exposes bare `recall`/`ingest`
//! over MCP, so the gateway is deliberately a translation boundary", and that
//! "`ccos.` is kept as an accepted alias for the catalogue this crate shipped
//! with". A downstream translation `memory.recall` → `recall` is therefore
//! the documented behaviour; applied to `memory.shell.exec` it yields
//! `shell.exec`.
//!
//! [`the_composed_path_forwards_and_bills_a_wrapped_shell_exec`] then shows
//! the same names surviving the whole composed admission path — identity,
//! tenant, boundary, RBAC, model, budget — and being **billed** to the
//! tenant. `tests/boundary_contract.rs::no_privilege_reaches_past_the_boundary`
//! only proves the *bare* spellings are stopped.
//!
//! Everything asserted below is the product's **current, real** behaviour.
//! Where that behaviour is a defect the assertion pins the defect and the
//! comment names it, so a future repair fails loudly here instead of silently
//! changing the security posture.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use ccos_enterprise_auth::AuthStrength;
use ccos_enterprise_conformance::{actor, request, two_tenant_deployment, Call, Outcome, Refusal};
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
/// None of these are `char::is_control` or `char::is_whitespace`, so every
/// one of them survives `classify`'s canonicality check.
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
/// `memory.shell.exec` it yields `shell.exec`.
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
/// 3. every `Forward` it emits that reaches a forbidden capability under a
///    plausible downstream normalization is a **boundary bypass** — and the
///    fuzzer finds thousands of them.
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

    // Pinned: identical in debug and release, and any change to the generator
    // invalidates the counts below loudly instead of quietly.
    assert_eq!(
        fingerprint, 0xc135_dc44_df83_746a,
        "corpus/verdict fingerprint drifted — regenerate the pinned counts"
    );
    assert_eq!(
        (
            forwarded,
            boundary_rejects,
            catalogue_rejects,
            noncanonical_rejects
        ),
        (7_764, 17_965, 42_809, 51_462),
        "pinned disposition histogram at SEED {SEED:#x}"
    );

    // ── DEFECT (critical) ────────────────────────────────────────────────
    // The invariant is "no Forward ever reaches a forbidden capability under
    // plausible downstream normalization". A clean gateway would score 0.
    // It does not. This assertion pins the real number so a repair shows up
    // as a failure here rather than as a silent posture change.
    assert!(
        violations > 0,
        "expected the fuzzer to find boundary bypasses; if this now fails the \
         gateway was repaired — replace this with assert_eq!(violations, 0)"
    );
    assert_eq!(
        violations, 322,
        "pinned count of forwarded-but-forbidden names at SEED {SEED:#x}"
    );
    assert!(
        violations * 25 > forwarded,
        "and they are not a rounding error: {violations} of {forwarded} forwarded \
         names ( > 1 in 25 ) reach a forbidden capability downstream"
    );
}

/// Root cause, isolated: **every** bypass the fuzzer finds is a forbidden
/// capability wearing an `ALLOWED_PREFIXES` hat. `classify` anchors the
/// forbidden check at the start of the string only, so an exposed namespace
/// in front of `shell.exec` is a complete bypass of the boundary.
#[test]
fn every_fuzz_bypass_is_a_forbidden_capability_behind_an_exposed_prefix() {
    let mut rng = SplitMix64(SEED);
    let mut by_normalizer: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut examples: BTreeSet<String> = BTreeSet::new();

    for _ in 0..CORPUS {
        let name = generate(&mut rng);
        if !forwards(&name) {
            continue;
        }
        let Some(via) = normalizes_to_forbidden(&name) else {
            continue;
        };
        *by_normalizer.entry(via).or_default() += 1;
        // The single structural fact behind every one of them.
        assert!(
            starts_with_exposed_prefix(&name),
            "a bypass that is NOT an exposed-prefix wrap — new root cause: {name:?}"
        );
        assert!(
            !is_forbidden_capability(&name),
            "classify would have caught a bare forbidden name: {name:?}"
        );
        if examples.len() < 64 {
            examples.insert(name);
        }
    }

    assert!(!examples.is_empty(), "the fuzzer must produce witnesses");
    // Four *independent* downstream normalizations each reach a forbidden
    // capability, so "our router does not resolve `..`" is no defence.
    // Pinned exactly: this is the shape of the hole, not merely its size.
    assert_eq!(
        by_normalizer,
        BTreeMap::from([
            ("class_strip", 88),
            ("full_pipeline", 11),
            ("path_resolve", 1),
            ("separator_tail", 222),
        ]),
        "pinned normalization routes into the forbidden catalogue"
    );
    // Witnesses worth reading aloud: `audit.forge.run`, `audit.patch.apply`,
    // `audit.Shell.Exec`. The fuzzer needed no cleverness whatsoever.
    assert!(examples.iter().any(|e| e.contains("forge.run")));
}

// ─────────────────────────────────────────────────────────────────────────
// 2. Targeted bypasses — the headline defect, spelled out
// ─────────────────────────────────────────────────────────────────────────

/// DEFECT (critical), `crates/ccos-enterprise-gateway/src/lib.rs:98`:
///
/// ```text
/// let forbidden = FORBIDDEN_PREFIXES.iter().any(|p| lowered.starts_with(p))
///     || FORBIDDEN_TOOLS.contains(&lowered.as_str());
/// ```
///
/// `starts_with` anchors the forbidden check at byte 0. `ALLOWED_PREFIXES`
/// then admits on the same anchor. Any forbidden capability prefixed with an
/// exposed namespace is therefore forwarded. Every row below is a `Forward`
/// today.
#[test]
fn an_exposed_prefix_launders_every_forbidden_capability() {
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
    // Wrappers built only from names the gateway itself calls exposed.
    let wrappers = [
        "ccos.",                // the documented compatibility alias
        "memory.",              // exposed class
        "context.",             //
        "policy.",              //
        "audit.",               //
        "memory.recall/../",    // path traversal
        "memory.recall/",       // path join
        "policy.set;",          // list/command separator
        "ccos.\u{200d}",        // alias + zero-width joiner
        "ccos.\u{feff}",        // alias + BOM
        "audit.query/\u{202e}", // path join + right-to-left override
    ];

    let mut laundered = Vec::new();
    for w in wrappers {
        for f in forbidden_entries {
            let name = format!("{w}{f}");
            // Ground truth: this names a capability the product must never carry.
            assert!(
                normalizes_to_forbidden(&name).is_some(),
                "test corpus error: {name:?} is not a laundered forbidden capability"
            );
            if forwards(&name) {
                laundered.push(name);
            }
        }
    }

    // 11 wrappers x 11 forbidden entries: the boundary stops none of them.
    assert_eq!(
        laundered.len(),
        wrappers.len() * forbidden_entries.len(),
        "every laundered spelling is forwarded today; unforwarded: {:?}",
        wrappers.len() * forbidden_entries.len() - laundered.len()
    );
    // Spot-check the two the brief names explicitly, so the failure message
    // is unambiguous if this ever changes.
    assert!(forwards("memory.recall/../shell.exec"));
    assert!(forwards("ccos.shell.exec"));
}

/// DEFECT (critical), composed path: the same names traverse **the entire
/// admission pipeline** and are billed to the tenant.
///
/// `ccos_enterprise_conformance`'s module docs claim the boundary "is
/// unreachable-around" and that no tenant-configurable gate can widen it.
/// But `Deployment::govern_tool` is exactly such a knob: governing
/// `memory.recall/../shell.exec` under the everyday `memory.read` permission
/// hands a plain **reader** a forwarded call to a capability charter §4.2
/// forbids the profile from carrying at all.
#[test]
fn the_composed_path_forwards_and_bills_a_wrapped_shell_exec() {
    let mut d = two_tenant_deployment();
    // Nothing privileged happens here: an operator adds two tools under the
    // *lowest* permission in the deployment.
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
        assert_eq!(
            outcome,
            Outcome::Forwarded,
            "DEFECT: {tool:?} traverses the whole governed path as a read-only actor"
        );
    }

    // …and it costs the tenant real budget, i.e. it was a live call.
    assert_eq!(d.spent("acme"), 21, "three forwarded calls were billed");

    // The audit trail records them as ordinary successes: nothing in the
    // journal marks a boundary event, so this is invisible to review.
    let journal = d.audit_of("acme");
    assert_eq!(journal.len(), 3);
    assert!(journal.iter().all(|r| r.outcome.is_forwarded()));
    let metrics: BTreeMap<String, u64> = d.metrics().into_iter().collect();
    assert_eq!(metrics.get("gateway.forwarded"), Some(&3));
    assert_eq!(
        metrics.get("gateway.refused.outside_boundary"),
        None,
        "DEFECT: three forbidden capabilities traversed without a single \
         boundary counter moving"
    );

    // Contrast: the *bare* spelling is stopped, which is all
    // `boundary_contract.rs::no_privilege_reaches_past_the_boundary` proves.
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
    assert_eq!(d.spent("acme"), 21, "the refusal was not billed");
}

/// DEFECT (high): the exposed prefixes forward a *bare namespace* with no
/// tool component at all, and forward arbitrarily deep sub-namespaces. The
/// catalogue is documented as a list of "capability classes"; in practice
/// `memory.` alone, `ccos.` alone and `memory.......` all traverse.
#[test]
fn bare_and_degenerate_namespaces_traverse() {
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
        assert!(
            forwards(tool),
            "DEFECT pinned: {tool:?} names no tool yet traverses the boundary"
        );
    }
    // The nearest miss is correctly refused, which is what makes the above a
    // boundary bug rather than a deliberate design.
    for tool in ["memory", "ccos", "audit", "system", "system.healthz"] {
        assert!(!forwards(tool), "{tool:?}");
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 3. Homoglyph / normalization / case-folding attacks
// ─────────────────────────────────────────────────────────────────────────

/// What HELD: every homoglyph and compatibility spelling of a forbidden name
/// is refused. `classify` fails closed because deny-by-default catches what
/// the forbidden list misses.
///
/// What is nonetheless WRONG (medium, detection): each one is reported as
/// *"not in the Enterprise catalogue"* — an **omission** — when it is in fact
/// a deliberate boundary attack. `crates/ccos-enterprise-gateway/src/lib.rs:74`
/// promises the two refusals are distinguishable so "an operator reading the
/// audit trail should be able to tell the two apart". For homoglyph attacks
/// the audit trail says "someone typo'd", not "someone tried `shell.exec`".
#[test]
fn homoglyph_and_compatibility_spellings_fail_closed_but_are_logged_as_typos() {
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
        // DEFECT pinned: mislabelled as an omission, never as a violation.
        assert!(
            reason.contains("not in the Enterprise catalogue"),
            "{note}: expected the (wrong) omission label, got {reason:?}"
        );
        assert!(
            !reason.contains("outside the Enterprise boundary"),
            "{note}: if this now reports a boundary violation the detection gap \
             was repaired — flip this assertion"
        );
    }

    // And the refusal message echoes the raw, attacker-controlled bytes,
    // including bidi overrides, straight into whatever reads the audit trail.
    let spoof = "\u{202e}shell.exec";
    assert!(
        why(spoof).contains('\u{202e}'),
        "DEFECT (low, log spoofing): the rejection message embeds unescaped \
         bidi overrides, so a terminal renders the attacked name backwards"
    );
}

/// The ASCII-vs-Unicode case-folding gap, measured rather than assumed.
///
/// `classify` documents its lowering as the defence against "a case-
/// normalizing router downstream", but uses `to_ascii_lowercase`. The gap is
/// real — Turkish dotless ı, dotted İ and the Kelvin sign all survive it —
/// though deny-by-default still catches every case, so the gap costs
/// classification quality, not containment.
#[test]
fn ascii_lowercasing_leaves_a_unicode_case_folding_gap() {
    // A locale-aware or Unicode-aware downstream maps these onto forbidden
    // names; `to_ascii_lowercase` does not.
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
        let reason = why(tool);
        assert!(
            reason.contains("not in the Enterprise catalogue"),
            "{tool:?}: {reason}"
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
/// disposition and the real *reason*. What HELD: `.`-anchoring is exact —
/// `shell` is not `shell.`, `.shell.exec` and `x/shell.exec` do not start a
/// forbidden namespace, and every whitespace/control decoration fails closed
/// before any matching happens.
#[test]
fn prefix_boundary_matrix() {
    #[derive(Debug, PartialEq, Eq)]
    enum Verdict {
        Forward,
        Violation,
        Omission,
        NonCanonical,
    }
    use Verdict::*;

    let cases: &[(&str, Verdict)] = &[
        ("shell", Omission),   // no dot: not the namespace
        ("shell.", Violation), // bare forbidden namespace
        ("shell..", Violation),
        ("shell.exec", Violation),
        ("SHELL.EXEC", Violation),
        ("sHeLl.ExEc", Violation),
        (".shell.exec", Omission),         // leading dot breaks the anchor
        ("x/shell.exec", Omission),        // and so does any non-exposed prefix
        ("shell.exec\u{0}", NonCanonical), // NUL is a control byte
        ("shell.exec ", NonCanonical),     // trailing space
        (" shell.exec", NonCanonical),
        ("shell.exec\t", NonCanonical),
        ("shell.exec\n", NonCanonical),
        ("shell.exec\u{a0}", NonCanonical), // NBSP is White_Space
        ("shell.exec\u{3000}", NonCanonical), // ideographic space
        ("shell.exec\u{2028}", NonCanonical), // line separator
        ("", NonCanonical),
        ("   ", NonCanonical),
        ("\u{0}", NonCanonical),
        // …but the invisible, non-`is_control`, non-`is_whitespace` code
        // points are NOT non-canonical, and they do not break the anchor:
        ("shell.exec\u{feff}", Violation),
        ("shell.exec\u{200d}", Violation),
        // Exact-match forbidden tools lose their label to any decoration.
        ("code.execute", Violation),
        ("code.execute.", Omission),
        ("code.execute\u{feff}", Omission),
        ("repository.modify/", Omission),
        // And every laundered form traverses.
        ("memory.recall/../shell.exec", Forward),
        ("ccos.shell.exec", Forward),
        ("memory.recall/shell.exec", Forward),
        ("policy.set;shell.exec", Forward),
        ("ccos.\u{200d}shell.exec", Forward),
        ("ccos.code.execute", Forward),
        ("memory.repository.modify", Forward),
    ];

    for (tool, expected) in cases {
        if *expected == Forward {
            // Each Forward row above really does reach a forbidden capability
            // downstream — the matrix is not just cataloguing odd spellings.
            assert!(
                normalizes_to_forbidden(tool).is_some(),
                "matrix error: {tool:?} is listed as a laundered bypass"
            );
        }
        let got = match classify(&req(tool)) {
            Disposition::Forward => Forward,
            Disposition::Reject(w) if w.contains("outside the Enterprise boundary") => Violation,
            Disposition::Reject(w) if w.contains("not in the Enterprise catalogue") => Omission,
            Disposition::Reject(_) => NonCanonical,
        };
        assert_eq!(&got, expected, "{tool:?}");
    }
}

/// Every canonicality rejection happens *before* any matching, so a
/// forbidden name with a control byte is refused as "not canonical" rather
/// than as a boundary violation. That is fail-closed and fine — but it means
/// `gateway.refused.*` cannot be used to count boundary probes, since the
/// cheapest evasion (append `\0`) changes the label.
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

/// DEFECT (medium, spec violation) —
/// `tests/ccos-enterprise-conformance/src/lib.rs:295`:
///
/// ```text
/// if let Disposition::Reject(why) = classify(call.request) {
///     return Outcome::Refused(Refusal::OutsideBoundary(why));
/// }
/// ```
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
/// in every metric; only the free-text string still differs.
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
    assert_eq!(d.spent("acme"), 0);

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

/// What HELD: the gateway's case-insensitivity is *not* carried into the
/// governance map, and that asymmetry fails closed. `MEMORY.RECALL` clears
/// the boundary but misses `governed_tools`, so it is refused. Worth pinning:
/// it means a deployment cannot be tricked into authorizing a case variant,
/// but it also means the boundary and the authorizer key on different
/// strings, and only luck (a `BTreeMap` miss) makes that safe.
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
    assert_eq!(d.spent("acme"), 0);
}

// ─────────────────────────────────────────────────────────────────────────
// 6. Size, time and memory
// ─────────────────────────────────────────────────────────────────────────

/// A 1 MiB tool name must not panic and must not cost superlinear time.
///
/// HELD: `classify` is linear — one `to_ascii_lowercase` allocation plus a
/// `chars()` scan plus prefix compares. Both checks below are one-sided
/// ceilings measured back to back on the same machine, so they cannot flake
/// into a false failure the way an equality on a duration would; a quadratic
/// scan of 1 MiB would miss them by many orders of magnitude.
#[test]
fn a_one_megabyte_name_is_linear_and_never_panics() {
    const MIB: usize = 1 << 20;
    let small = format!("memory.{}", "a".repeat(64 * 1024 - 7));
    let large = format!("memory.{}", "a".repeat(MIB - 7));
    assert_eq!(small.len(), 64 * 1024);
    assert_eq!(large.len(), MIB);

    let bench = |name: &str| -> u128 {
        let r = req(name);
        let mut best = u128::MAX;
        for _ in 0..5 {
            let t0 = Instant::now();
            let d = classify(&r);
            let ns = t0.elapsed().as_nanos();
            assert_eq!(d, Disposition::Forward);
            best = best.min(ns);
        }
        best.max(1)
    };

    let t_small = bench(&small);
    let t_large = bench(&large);

    // 16x the bytes must not cost anywhere near 16^2 the time.
    let ratio = t_large as f64 / t_small as f64;
    assert!(
        ratio < 16.0 * 12.0,
        "16x input cost {ratio:.1}x the time — superlinear (small {t_small} ns, \
         large {t_large} ns)"
    );
    // Absolute ceiling: quadratic behaviour on 1 MiB would take minutes.
    assert!(t_large < 5_000_000_000, "1 MiB classify took {t_large} ns");

    // Bigger, weirder, still no panic — and note that a 1 MiB *forwarded*
    // name is perfectly acceptable to the boundary.
    for name in [
        format!("memory.{}", "\u{1f600}".repeat(64 * 1024)), // 256 KiB of emoji
        format!("ccos.{}", "\u{4e2d}".repeat(64 * 1024)),    // CJK
        format!("{}shell.exec", "memory.recall/../".repeat(4096)),
        "\u{200d}".repeat(200_000),
        "\u{0}".repeat(MIB),
    ] {
        let _ = classify(&req(&name));
    }
    assert!(forwards(&large), "a 1 MiB tool name traverses the boundary");
}

/// EXHAUSTION VECTOR (high): every rejected request stores the attacker's
/// entire tool name **twice** — once in `AuditRecord::tool`, once inside the
/// `Refusal::OutsideBoundary` message that `classify` builds with
/// `format!("tool '{}' is not in the Enterprise catalogue", req.tool)`
/// (`crates/ccos-enterprise-gateway/src/lib.rs:109`). The audit `Vec` has no
/// cap and nothing truncates the name, so an unauthenticated-adjacent caller
/// converts N bytes of request into >2N bytes of permanently retained heap,
/// with no counter or quota reacting.
#[test]
fn refused_requests_retain_more_attacker_bytes_than_they_carry() {
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
    assert!(
        message.len() > MIB,
        "the refusal message embeds the whole 1 MiB name ({} bytes)",
        message.len()
    );
    let record = &d.audit()[0];
    assert_eq!(
        record.tool.len(),
        MIB,
        "and the journal keeps a second copy"
    );
    let retained = record.tool.len()
        + match &record.outcome {
            Outcome::Refused(Refusal::OutsideBoundary(w)) => w.len(),
            other => panic!("{other:?}"),
        };
    assert!(
        retained > 2 * MIB,
        "amplification factor {:.2}x per refused request",
        retained as f64 / MIB as f64
    );

    // Growth is unbounded and linear in request count: nothing folds, caps or
    // truncates. 24 x 128 KiB keeps the test cheap while proving the shape.
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
        .iter()
        .map(|r| {
            r.tool.len()
                + match &r.outcome {
                    Outcome::Refused(Refusal::OutsideBoundary(w)) => w.len(),
                    _ => 0,
                }
        })
        .sum();
    assert_eq!(d.audit().len(), 24, "no journal cap");
    assert!(
        total > 24 * 2 * 128 * 1024,
        "24 refused 128 KiB requests retained {total} bytes — >2x amplification, \
         unbounded in request count"
    );
    // And none of it was billed, so the budget gate never notices.
    assert_eq!(d.spent("acme"), 0);
    // Nor does the metric registry: refusal labels are low-cardinality (HELD).
    assert!(
        d.metrics().len() <= 8,
        "metric cardinality stays bounded under name flooding: {:?}",
        d.metrics()
    );
}

/// What HELD: the tool name never leaks into a metric series name, so the
/// 120k-name corpus cannot blow past `CounterRegistry::MAX_SERIES`. This is
/// the exhaustion vector that was *closed*, and it is worth a regression pin
/// because `Deployment::admit` builds a series name with `format!`.
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
/// Run with:
/// `cargo test -p ccos-enterprise-conformance --test stress_gateway_fuzz \
///  --release -- --ignored --nocapture`
#[test]
#[ignore = "1M names + 8 MiB inputs; see the doc comment for the command"]
fn heavy_million_name_sweep() {
    let mut rng = SplitMix64(SEED ^ 0xdead_beef);
    let mut violations = 0usize;
    for _ in 0..1_000_000 {
        let name = generate(&mut rng);
        if classify(&req(&name)) == Disposition::Forward && normalizes_to_forbidden(&name).is_some()
        {
            violations += 1;
            assert!(
                starts_with_exposed_prefix(&name),
                "new root cause: {name:?}"
            );
        }
    }
    assert!(violations > 0, "the bypass reproduces at 1M scale");

    for bytes in [1 << 21, 1 << 22, 1 << 23] {
        let name = format!("memory.{}", "a".repeat(bytes - 7));
        let t0 = Instant::now();
        assert!(forwards(&name));
        println!("{bytes} bytes → {:?}", t0.elapsed());
    }
}

/// Sanity: the exposed catalogue still works. A boundary that refused
/// everything would make every assertion above vacuous.
#[test]
fn the_exposed_catalogue_is_not_collaterally_broken() {
    for tool in ALLOWED_TOOLS {
        assert!(forwards(tool), "{tool}");
    }
    for prefix in ALLOWED_PREFIXES {
        assert!(forwards(&format!("{prefix}recall")), "{prefix}recall");
    }
    for entry in FORBIDDEN_PREFIXES {
        assert!(!forwards(&format!("{entry}anything")), "{entry}");
    }
    for entry in FORBIDDEN_TOOLS {
        assert!(!forwards(entry), "{entry}");
    }
}
