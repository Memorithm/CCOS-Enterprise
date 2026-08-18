//! # Hostile fuzz of the administrative gate
//!
//! Layer 6 of `docs/ENTERPRISE_SECURITY_MODEL.md` — "administrative acts
//! validated and journaled with justification (`ccos-enterprise-admin`)" — is,
//! in the shipping product, one `const` list of five strings and one twelve
//! line function. `docs/TENANCY_MODEL.md` leans on it ("tenant lifecycle
//! (create/suspend/delete) is an administrative action requiring
//! justification") and `docs/HUMAN_APPROVAL_POLICIES.md` widens it further
//! ("approval-gated by default: tenant deletion/suspension, quota overrides,
//! policy disabling, license revocation, model-allowlist changes, any
//! Enterprise-side schema migration"; "unrecorded approval = denial").
//!
//! This file attacks that gate with the full cross-product of
//! *every* `JUSTIFICATION_REQUIRED` action + a large corpus of non-sensitive
//! and adversarially-spelled actions × eight justification shapes × six
//! actor/target shapes (empty, ASCII blank, Unicode blank, normal, Unicode,
//! 1 MiB), plus hand-built case, padding, homoglyph and zero-width attacks and
//! the JSON wire form the type derives.
//!
//! ## What held
//!
//! * `validate` **never panics** on any of the ~16 000 hostile inputs, 1 MiB
//!   fields and NUL bytes included. It has no indexing, no `unwrap`, no
//!   arithmetic; `String` is always valid UTF-8, so there is no lone-surrogate
//!   input to reach it with.
//! * A justification made of **ASCII *or* Unicode whitespace is correctly
//!   refused**. `str::trim` uses the Unicode `White_Space` property, so
//!   U+00A0, U+2007, U+3000, U+1680, U+202F, U+205F and U+0085 are all caught.
//!   That half of the question in the brief comes out clean.
//! * `validate` is pure, order-independent and identical in debug and release.
//! * The error message interpolates `a.action`, but only on a path where the
//!   action is byte-identical to one of five literals — so it is **not** an
//!   attacker-controlled format sink.
//!
//! ## What BROKE, and what is now REPAIRED
//!
//! A and B are closed; the tests that found them are now the guards on the
//! repair, each keeping its original attack corpus and asserting the opposite
//! outcome. C through H are open and still pinned.
//!
//! | # | defect | state | test |
//! |---|--------|-------|------|
//! | A | `JUSTIFICATION_REQUIRED` was matched byte-exactly, so `TENANT.DELETE`, `Tenant.Delete`, `tenant.delete ` (padded), `license.revoKe` (U+212A KELVIN SIGN) and full-width/Cyrillic homoglyphs all **bypassed the justification requirement entirely** | **repaired**: the gate canonicalizes (trim + full Unicode lowercase) before matching, and refuses outright any name it cannot canonicalize — the fail-closed answer for the homoglyph family, which no folding can resolve | [`no_case_variant_of_a_sensitive_action_escapes_the_gate`], [`padded_and_homoglyph_spellings_are_refused`] |
//! | B | `trim()` is a *whitespace* test, not a *visibility* test: a justification of one U+200B (or U+FEFF, U+2060, U+00AD, U+2800, NUL…) counted as "written" | **repaired**: the gate now asks whether the string draws anything, not whether it survives a trim | [`no_justification_that_draws_nothing_is_accepted`] |
//! | C | any single non-whitespace byte — `"."` — satisfies "a written justification" | [`a_single_dot_is_a_written_justification`] |
//! | D | `actor`/`action`/`target` are checked with `is_empty()`, **not** trimmed, so a sensitive act can be attributed to an actor of pure whitespace or of one zero-width character | [`blank_actor_and_target_are_accepted_because_only_the_justification_is_trimmed`] |
//! | E | no field has any length bound; a 1 MiB (or 128 MiB) justification validates `Ok` | [`one_mebibyte_fields_are_accepted_without_bound`], [`admin_journal_growth_is_unbounded`] |
//! | F | two categories `docs/HUMAN_APPROVAL_POLICIES.md` declares approval-gated — model-allowlist changes and schema migration — are **absent** from `JUSTIFICATION_REQUIRED` | [`the_approval_policy_lists_categories_the_gate_does_not_cover`] |
//! | G | nothing in the composed product ever calls `validate`: `Call` has no justification field, `AuditRecord` has no justification field, and `policy.set` — the deployment's one administrative tool — is forwarded and journaled with no "why" | [`the_composed_path_administers_with_no_justification_at_all`] |
//! | H | the workspace revokes licences on three surfaces demanding three different reasons — a mandatory typed `RevocationReason`, an `Option<String>` satisfied by `"."`, and nothing at all | [`the_three_revocation_surfaces_demand_three_different_reasons`] |
//!
//! Defect A was never a theoretical worry about a hypothetical caller: the
//! sibling gate in the *same product*, `ccos_enterprise_gateway::classify`,
//! already lowercased and rejected non-canonical names precisely because
//! "matching is case-insensitive so `RSI.x` cannot slip past a case-normalizing
//! router downstream" (its own doc comment). The admin gate did neither, and
//! the asymmetry was the argument that it was a defect rather than a design
//! choice. [`both_gates_now_defend_against_the_same_spellings`] guards the
//! symmetry — and notes that the two gates reach it by separate code, so it is
//! an equivalence maintained by tests rather than by types.
//!
//! [`the_json_wire_form_inherits_the_repairs_and_the_remaining_gaps`] runs the
//! same attacks through the `Deserialize` impl the type derives — the path an
//! admin HTTP or MCP API actually takes — and shows A and B closed there too,
//! with D and E still reachable.
//!
//! Every assertion below states the product's **current, real** behaviour.
//! Where that behaviour is the defect, the assertion pins the defect so a
//! future repair fails loudly here instead of silently changing the posture.

use std::collections::BTreeSet;
use std::panic::{catch_unwind, AssertUnwindSafe};

use ccos_enterprise_admin::{is_canonical_action, validate, AdminAction, JUSTIFICATION_REQUIRED};
use ccos_enterprise_auth::AuthStrength;
use ccos_enterprise_conformance::{actor, request, two_tenant_deployment, Call, Refusal};
use ccos_enterprise_gateway::{classify, Disposition};

// ─────────────────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────────────────

const MIB: usize = 1_048_576;

/// A fixed, non-zero timestamp. Nothing in this file reads the wall clock.
const T0: u64 = 1_767_225_600;

fn act(who: &str, what: &str, target: &str, why: Option<&str>) -> AdminAction {
    AdminAction {
        actor: who.to_string(),
        action: what.to_string(),
        target: target.to_string(),
        unix_time: T0,
        justification: why.map(str::to_string),
    }
}

fn accepted(who: &str, what: &str, target: &str, why: Option<&str>) -> bool {
    validate(&act(who, what, target, why)).is_ok()
}

/// At least `bytes` bytes' worth of `c`. Built once per shape and cloned, so
/// the cross-product's 1 MiB fields cost one allocation apiece, not one per
/// validation.
fn repeat_to(c: char, bytes: usize) -> String {
    let unit = c.to_string();
    unit.repeat(bytes.div_ceil(unit.len()))
}

/// The exact rule the gate implements today: byte-for-byte membership.
fn required_exactly(action: &str) -> bool {
    JUSTIFICATION_REQUIRED.contains(&action)
}

/// Any plausible downstream canonicalization of an admin action name: strip
/// the padding a wire format leaves behind and fold case — exactly what
/// `ccos_enterprise_gateway::classify` already does to tool names, and what
/// any SQL `lower()`, HTTP router or config loader does by default.
fn canonical_action(action: &str) -> String {
    action.trim().to_lowercase()
}

fn required_after_canonicalization(action: &str) -> bool {
    JUSTIFICATION_REQUIRED.contains(&canonical_action(action).as_str())
}

/// Characters that render as nothing but are **not** `White_Space`, so
/// `str::trim` leaves them in place. Verified against `char::is_whitespace`
/// by [`no_justification_that_draws_nothing_is_accepted`] — if a future
/// Unicode table update moves one of these, that test says so.
const ZERO_WIDTH: &[char] = &[
    '\u{00AD}', // SOFT HYPHEN
    '\u{061C}', // ARABIC LETTER MARK
    '\u{180E}', // MONGOLIAN VOWEL SEPARATOR
    '\u{200B}', // ZERO WIDTH SPACE
    '\u{200C}', // ZERO WIDTH NON-JOINER
    '\u{200D}', // ZERO WIDTH JOINER
    '\u{200E}', // LEFT-TO-RIGHT MARK
    '\u{200F}', // RIGHT-TO-LEFT MARK
    '\u{202A}', // LEFT-TO-RIGHT EMBEDDING
    '\u{202B}', // RIGHT-TO-LEFT EMBEDDING
    '\u{202C}', // POP DIRECTIONAL FORMATTING
    '\u{202D}', // LEFT-TO-RIGHT OVERRIDE
    '\u{202E}', // RIGHT-TO-LEFT OVERRIDE
    '\u{2060}', // WORD JOINER
    '\u{2061}', // FUNCTION APPLICATION
    '\u{2800}', // BRAILLE PATTERN BLANK
    '\u{3164}', // HANGUL FILLER
    '\u{FEFF}', // ZERO WIDTH NO-BREAK SPACE / BOM
    '\u{FFA0}', // HALFWIDTH HANGUL FILLER
];

/// The property the *product* promises, stated without reference to how the
/// gate happens to be implemented: a justification an operator can read.
/// A string that draws nothing — whitespace, control bytes or zero-width
/// formatting characters — is, to the human being who has to audit the act,
/// indistinguishable from `None`.
fn renders_blank(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_whitespace() || c.is_control() || ZERO_WIDTH.contains(&c))
}

fn is_a_written_reason(justification: Option<&str>) -> bool {
    justification.is_some_and(|j| !renders_blank(j))
}

// ── Spelling attacks ─────────────────────────────────────────────────────

fn shout(s: &str) -> String {
    s.to_uppercase()
}

fn title_segments(s: &str) -> String {
    s.split('.')
        .map(|seg| {
            let mut it = seg.chars();
            match it.next() {
                Some(first) => format!("{}{}", first.to_ascii_uppercase(), it.as_str()),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn alternating(s: &str) -> String {
    s.chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

/// U+212A KELVIN SIGN lowercases (Unicode simple mapping) to `k`, so
/// `license.revoKe` spelled with it is *not* byte-equal to `license.revoke`
/// but `to_lowercase()` makes it so.
fn kelvin(s: &str) -> String {
    s.replace('k', "\u{212A}")
}

/// U+0435 CYRILLIC SMALL LETTER IE is visually identical to `e` in every
/// common monospace font — an auditor reading the journal cannot tell the two
/// actions apart.
fn cyrillic_e(s: &str) -> String {
    s.replace('e', "\u{0435}")
}

/// Full-width Latin letters NFKC-normalize back to their ASCII forms, so any
/// consumer that normalizes before dispatch sees the sensitive action.
fn fullwidth(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_lowercase() {
                char::from_u32(0xFF41 + (c as u32 - 'a' as u32)).expect("valid full-width letter")
            } else {
                c
            }
        })
        .collect()
}

// ── The action corpus ────────────────────────────────────────────────────

/// Ordinary administrative verbs that carry no justification requirement.
const NON_SENSITIVE_ACTIONS: &[&str] = &[
    "tenant.create",
    "tenant.rename",
    "tenant.list",
    "tenant.resume",
    "tenant.export",
    "org.create",
    "org.rename",
    "user.add",
    "user.remove",
    "user.disable",
    "user.reset_password",
    "role.create",
    "role.delete",
    "role.assign",
    "role.revoke",
    "key.rotate",
    "key.revoke",
    "session.terminate",
    "backup.create",
    "backup.restore",
    "backup.verify",
    "schema.migrate",
    "model.allowlist.add",
    "model.allowlist.remove",
    "model.switch",
    "quota.set",
    "quota.increase",
    "quota.reset",
    "policy.enable",
    "policy.set",
    "policy.update",
    "license.issue",
    "license.rearm",
    "audit.export",
    "audit.purge",
    "audit.retention.set",
    "feature.toggle",
    "qpage.activate",
    "qpage.deactivate",
    "",
];

/// Spellings a hostile (or merely sloppy) caller produces for the five
/// sensitive actions. None of them is byte-equal to a listed entry.
fn near_miss_actions() -> Vec<String> {
    let mut out = Vec::new();
    for s in JUSTIFICATION_REQUIRED {
        out.push(shout(s));
        out.push(title_segments(s));
        out.push(alternating(s));
        out.push(format!(" {s}"));
        out.push(format!("{s} "));
        out.push(format!("{s}\n"));
        out.push(format!("{s}\t"));
        out.push(format!("{s}\u{0}"));
        out.push(format!("{s}\u{200b}"));
        out.push(format!("\u{feff}{s}"));
        out.push(cyrillic_e(s));
        out.push(fullwidth(s));
        if s.contains('k') {
            out.push(kelvin(s));
        }
        // Genuinely different actions that merely share letters — these must
        // *not* be caught by any canonicalization, and are here to prove the
        // attack model has no false positives.
        out.push(format!("{s}d"));
        out.push(format!("x{s}"));
    }
    out
}

// ── Field shapes ─────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Field {
    Empty,
    AsciiBlank,
    UnicodeBlank,
    Normal,
    Unicode,
    Mib,
}

const FIELD_SHAPES: &[Field] = &[
    Field::Empty,
    Field::AsciiBlank,
    Field::UnicodeBlank,
    Field::Normal,
    Field::Unicode,
    Field::Mib,
];

fn field_value(shape: Field) -> String {
    match shape {
        Field::Empty => String::new(),
        Field::AsciiBlank => "  \t\r\n ".to_string(),
        // NBSP, FIGURE SPACE, IDEOGRAPHIC SPACE, OGHAM, NNBSP, MMSP, NEL.
        Field::UnicodeBlank => "\u{a0}\u{2007}\u{3000}\u{1680}\u{202f}\u{205f}\u{85}".to_string(),
        Field::Normal => "root".to_string(),
        Field::Unicode => {
            "ZEKRITI Tarek \u{202e}nimda\u{202c} \u{1f512} \u{4e2d}\u{6587}".to_string()
        }
        Field::Mib => repeat_to('A', MIB),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Just {
    Absent,
    Empty,
    AsciiBlank,
    UnicodeBlank,
    ZeroWidth,
    Dot,
    Mib,
    BigBlank,
}

const JUST_SHAPES: &[Just] = &[
    Just::Absent,
    Just::Empty,
    Just::AsciiBlank,
    Just::UnicodeBlank,
    Just::ZeroWidth,
    Just::Dot,
    Just::Mib,
    Just::BigBlank,
];

/// A large all-whitespace justification is the one shape whose cost is linear
/// in its own length *inside* `validate` (`trim` has to walk every byte before
/// concluding the buffer is blank), so the cross-product uses 16 KiB of it and
/// [`one_mebibyte_fields_are_accepted_without_bound`] carries the full 1 MiB
/// case. Nothing about the verdict changes with length — that is asserted
/// there and in [`no_justification_that_draws_nothing_is_accepted`].
const BIG_BLANK: usize = 16 * 1024;

fn just_value(shape: Just) -> Option<String> {
    match shape {
        Just::Absent => None,
        Just::Empty => Some(String::new()),
        Just::AsciiBlank => Some("   \t\r\n\u{b}\u{c} ".to_string()),
        Just::UnicodeBlank => {
            Some("\u{a0}\u{2007}\u{3000}\u{1680}\u{202f}\u{205f}\u{85}".to_string())
        }
        Just::ZeroWidth => Some("\u{200b}\u{feff}\u{2060}\u{ad}\u{2800}".to_string()),
        Just::Dot => Some(".".to_string()),
        Just::Mib => Some(repeat_to('r', MIB)),
        Just::BigBlank => Some(repeat_to('\u{a0}', BIG_BLANK)),
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 1. The cross-product fuzz
// ─────────────────────────────────────────────────────────────────────────

/// Every sensitive action + a large corpus of non-sensitive and adversarially
/// spelled ones, against every justification shape and every actor/target
/// shape. ~16 000 validations, each one asserted against three independent
/// properties.
#[test]
fn validate_never_panics_over_the_full_hostile_cross_product() {
    let mut actions: Vec<String> = JUSTIFICATION_REQUIRED
        .iter()
        .map(|s| s.to_string())
        .collect();
    actions.extend(NON_SENSITIVE_ACTIONS.iter().map(|s| s.to_string()));
    actions.extend(near_miss_actions());

    // Built once, cloned per combination.
    let fields: Vec<(Field, String)> = FIELD_SHAPES.iter().map(|s| (*s, field_value(*s))).collect();
    let justs: Vec<(Just, Option<String>)> =
        JUST_SHAPES.iter().map(|s| (*s, just_value(*s))).collect();

    let mut checked = 0usize;
    let mut accepted_count = 0usize;
    // Spellings *outside* the list that a canonicalizing consumer would route
    // to a sensitive action, yet which validated with no readable reason.
    let mut spelling_bypasses: BTreeSet<String> = BTreeSet::new();
    // Justification shapes that satisfied a *listed* action while rendering as
    // nothing to a human reader.
    let mut blank_reason_bypasses: BTreeSet<Just> = BTreeSet::new();

    for (j_shape, justification) in &justs {
        for (a_shape, actor_value) in &fields {
            for (t_shape, target_value) in &fields {
                // Built once per (justification, actor, target) triple; only
                // the (small) action string changes in the inner loop, so the
                // 1 MiB shapes are allocated 288 times, not 16 000 times.
                let mut a = AdminAction {
                    actor: actor_value.clone(),
                    action: String::new(),
                    target: target_value.clone(),
                    unix_time: T0,
                    justification: justification.clone(),
                };

                for action in &actions {
                    a.action.clear();
                    a.action.push_str(action);

                    // P0 — never panics, on any input, ever.
                    let result = catch_unwind(AssertUnwindSafe(|| validate(&a)))
                        .unwrap_or_else(|_| panic!("validate PANICKED on {a:?}"));
                    checked += 1;

                    let fields_present =
                        !a.actor.is_empty() && !a.action.is_empty() && !a.target.is_empty();
                    let comparable = is_canonical_action(&canonical_action(action));
                    let written = is_a_written_reason(a.justification.as_deref());

                    // P1 — the repaired contract, restated: acceptance is
                    // exactly "three non-empty fields, an action name the gate
                    // can compare with the policy list, and — whenever the
                    // canonicalized name is on that list — a justification
                    // that renders something a human can read".
                    let expected = fields_present
                        && comparable
                        && (!required_after_canonicalization(action) || written);
                    assert_eq!(
                        result.is_ok(),
                        expected,
                        "unexpected verdict for action={action:?} \
                         actor={a_shape:?} target={t_shape:?} just={j_shape:?}: {result:?}"
                    );

                    // P2 — the brief's invariant: a *required* justification is
                    // never satisfied by a blank one. Holds, for every ASCII
                    // and Unicode whitespace shape — and now for the
                    // zero-width shapes too.
                    if required_after_canonicalization(action) && comparable && !written {
                        assert!(
                            result.is_err(),
                            "BLANK JUSTIFICATION SATISFIED A REQUIREMENT: \
                             {action:?} / {j_shape:?}"
                        );
                    }

                    // P3 — determinism: the same input always decides the same
                    // way, in debug and in release.
                    assert_eq!(
                        validate(&a).is_ok(),
                        result.is_ok(),
                        "validate is not deterministic for {action:?}"
                    );

                    if result.is_ok() {
                        accepted_count += 1;
                        // P4 — the security property, stated independently of
                        // the implementation: *no* accepted act whose name a
                        // consumer would resolve to a sensitive one may lack a
                        // reason a human can read. Violations are collected,
                        // not asserted away — they are DEFECT A and DEFECT B,
                        // and the fuzz finds both on its own.
                        if required_after_canonicalization(action)
                            && !is_a_written_reason(a.justification.as_deref())
                        {
                            if required_exactly(action) {
                                blank_reason_bypasses.insert(*j_shape);
                            } else {
                                spelling_bypasses.insert(action.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    assert_eq!(
        checked,
        actions.len() * JUST_SHAPES.len() * FIELD_SHAPES.len() * FIELD_SHAPES.len()
    );
    assert!(
        accepted_count > 0,
        "the fuzz never exercised the accept path"
    );

    // ── DEFECT A, found by fuzzing ───────────────────────────────────────
    // A non-empty set here is the finding: these action spellings performed a
    // sensitive administrative act with no reason attached at all. Pinned as
    // REPAIRED: the set is now empty. Every spelling either canonicalizes onto
    // the listed name and inherits the requirement, or is refused outright as
    // a name the gate cannot compare. Both outcomes keep it out of this set.
    assert!(
        spelling_bypasses.is_empty(),
        "these spellings of a listed sensitive action still validate with no \
         justification: {spelling_bypasses:?}"
    );

    // Soundness of the attack model, restated for the repaired gate: the
    // corpus really did contain a re-spelling of every listed action, so the
    // empty result above is a repair rather than a test that stopped looking.
    for sensitive in JUSTIFICATION_REQUIRED {
        assert!(
            actions
                .iter()
                .any(|a| canonical_action(a) == *sensitive && a != sensitive),
            "the corpus contains no re-spelling of {sensitive}, so the empty \
             bypass set above proves nothing"
        );
    }

    // ── DEFECT B, also found by fuzzing, now REPAIRED ────────────────────
    // The fuzz reached this on its own, without being told about zero-width
    // characters: a listed action was accepted when the "justification" was a
    // run of `White_Space = No` invisibles, because `trim()` asks whether a
    // string is *whitespace*, not whether it is *readable*, and those are
    // different questions. The gate now asks the second one.
    assert!(
        blank_reason_bypasses.is_empty(),
        "these justification shapes still satisfied a listed sensitive action \
         while rendering as nothing: {blank_reason_bypasses:?}"
    );
    // …and the corpus really did contain the shape that used to slip through,
    // so the empty set is a repair and not a narrowed search.
    assert!(
        JUST_SHAPES.contains(&Just::ZeroWidth),
        "the corpus no longer probes the zero-width shape"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 2. DEFECT A — the case attack
// ─────────────────────────────────────────────────────────────────────────

/// **The question in the brief, answered: no.** `"TENANT.DELETE"` and
/// `"Tenant.Delete"` are *not* caught by `JUSTIFICATION_REQUIRED`, because
/// `validate` matches with `slice::contains` — byte-exact equality.
///
/// Any admin API that accepts mixed case (an HTTP handler, a CLI, a YAML
/// runbook, a SQL row whose column is `citext`, an MCP tool argument) and then
/// dispatches on a case-folded name therefore performs tenant deletion,
/// tenant suspension, quota override, policy disabling and licence revocation
/// **with no justification at all** — the exact hole
/// `docs/HUMAN_APPROVAL_POLICIES.md` calls "unrecorded approval = denial".
#[test]
fn no_case_variant_of_a_sensitive_action_escapes_the_gate() {
    for sensitive in JUSTIFICATION_REQUIRED {
        // The gate works, for the one spelling it knows.
        assert!(
            !accepted("root", sensitive, "acme", None),
            "{sensitive} must be refused without a justification"
        );
        assert!(!accepted("root", sensitive, "acme", Some("")));
        assert!(!accepted("root", sensitive, "acme", Some("   \t\r\n")));

        for variant in [
            shout(sensitive),
            title_segments(sensitive),
            alternating(sensitive),
        ] {
            assert_ne!(
                &variant, sensitive,
                "the variant must differ, or the test is vacuous"
            );
            assert_eq!(
                variant.to_lowercase(),
                *sensitive,
                "…but only in case: {variant:?} folds to {sensitive}"
            );

            // REPAIRED: the variant canonicalizes onto the listed name, so
            // it inherits the requirement instead of escaping it.
            assert!(
                !accepted("root", &variant, "acme", None),
                "{variant:?} escaped the justification requirement"
            );
            assert!(
                !accepted("root", &variant, "acme", Some("")),
                "{variant:?} + empty justification was accepted"
            );
            // …and it is accepted once a real reason is written.
            assert!(accepted("root", &variant, "acme", Some("contract ended")));
        }
    }

    // U+212A KELVIN SIGN: not ASCII, folds to `k` under `str::to_lowercase`.
    // `license.revoKe` spelled with it is a different byte string, and so is
    // exempt from the requirement — while any Unicode-lowercasing consumer
    // resolves it straight back to `license.revoke`.
    let kelvined = kelvin("license.revoke");
    assert_ne!(kelvined, "license.revoke");
    assert_eq!(kelvined.to_lowercase(), "license.revoke");
    assert!(
        !accepted("root", &kelvined, "lic-0001", None),
        "the Kelvin spelling escaped the requirement"
    );
    // Worth noting why the repair catches it: `to_ascii_lowercase` — which is
    // what the gateway crate uses on tool names — does NOT collapse U+212A, so
    // copying the gateway's defence verbatim would have left this one open.
    // The gate uses full Unicode `to_lowercase`, which does.
    assert_ne!(kelvined.to_ascii_lowercase(), "license.revoke");
}

/// Padding and homoglyphs: the same bypass, reached without touching case.
#[test]
fn padded_and_homoglyph_spellings_are_refused() {
    // Whitespace padding — what every JSON/CSV/form-encoded wire leaves behind.
    for pad in [
        " tenant.delete",
        "tenant.delete ",
        "\ttenant.delete",
        "tenant.delete\n",
        "tenant.delete\r\n",
        "\u{a0}tenant.delete",
        "tenant.delete\u{3000}",
    ] {
        assert_eq!(pad.trim(), "tenant.delete", "the pad must be pure padding");
        assert!(
            !accepted("root", pad, "acme", None),
            "padding escaped the requirement for {pad:?}"
        );
    }

    // A NUL or a zero-width character welded onto the end: invisible in every
    // console, and enough to leave the list.
    // These cannot be folded onto the listed name, so they are refused as
    // non-canonical instead — the same outcome for the caller, and the only
    // fail-closed one available: a name the gate cannot compare must not be
    // assumed harmless.
    for smuggled in [
        "tenant.delete\u{0}",
        "tenant.delete\u{200b}",
        "\u{feff}tenant.delete",
        "tenant.delete\u{ad}",
    ] {
        assert!(
            !accepted("root", smuggled, "acme", None),
            "smuggled invisible escaped the gate for {smuggled:?}"
        );
        assert!(
            !accepted("root", smuggled, "acme", Some("a real reason")),
            "a name the gate cannot compare must be refused even when justified: {smuggled:?}"
        );
    }

    // Homoglyphs: `tеnant.dеlеtе` with U+0435 CYRILLIC SMALL LETTER IE is
    // pixel-identical to the real thing in the audit trail, and exempt.
    let cyr = cyrillic_e("tenant.delete");
    assert_ne!(cyr, "tenant.delete");
    assert_eq!(cyr.chars().count(), "tenant.delete".chars().count());
    assert!(
        !accepted("root", &cyr, "acme", None),
        "the Cyrillic homoglyph escaped the gate"
    );
    assert!(
        !is_canonical_action(&cyr),
        "and it is refused as non-canonical"
    );

    // Full-width: NFKC-normalizes back to `tenant.delete`, so any consumer
    // that normalizes (Postgres `normalize()`, ICU, most identity systems)
    // reunites the two after the gate has already waved it through.
    let wide = fullwidth("tenant.delete");
    assert_ne!(wide, "tenant.delete");
    assert!(
        !accepted("root", &wide, "acme", None),
        "the full-width spelling escaped the gate"
    );

    // Soundness: genuinely different actions stay exempt for the right
    // reason, and the repair does not over-reach into refusing them.
    for benign in ["tenant.deleted", "xtenant.delete", "tenant.del"] {
        assert!(
            !required_after_canonicalization(benign),
            "{benign} is not the same act"
        );
        assert!(
            accepted("root", benign, "acme", None),
            "{benign} was refused"
        );
    }
    // `tenant..delete` has an empty segment, so it is not a canonical name and
    // is refused — a stricter answer than before, and the right one: an empty
    // segment is exactly the shape a naive join or a trailing dot produces.
    assert!(!accepted("root", "tenant..delete", "acme", None));
}

/// The asymmetry that makes DEFECT A a *defect* rather than a design choice:
/// the sibling gate in the same product already defends against exactly these
/// spellings, and says in its own doc comment why.
#[test]
fn both_gates_now_defend_against_the_same_spellings() {
    let rejected = |tool: &str| {
        matches!(
            classify(&request("acme", "root", tool, "r-1")),
            Disposition::Reject(_)
        )
    };

    // The gateway lowercases before matching…
    assert!(rejected("SHELL.exec"), "the gateway folds case");
    assert!(rejected("Rsi.status"));
    // …and refuses any name carrying whitespace or a control byte at all.
    assert!(rejected(" memory.recall"));
    assert!(rejected("memory.recall "));
    assert!(rejected("memory.\u{0}recall"));
    assert_eq!(
        classify(&request("acme", "root", "memory.recall", "r-2")),
        Disposition::Forward
    );

    // REPAIRED: the admin gate now does both. The same three transformations
    // the gateway treats as attacks are refused here too — the asymmetry this
    // test was written to pin is gone, and the test now guards its absence.
    assert!(!accepted("root", "TENANT.DELETE", "acme", None));
    assert!(!accepted("root", " tenant.delete", "acme", None));
    assert!(!accepted("root", "tenant.\u{0}delete", "acme", None));
    // The two gates reach the same verdict by different routes, which is worth
    // stating: the gateway rejects a non-canonical *tool*, the admin gate
    // rejects a non-canonical *action*. Neither delegates to the other, so
    // this equivalence is a coincidence maintained by tests, not by types.
    // With a real reason, the two shapes part company — and the distinction
    // is the point. A spelling that canonicalizes onto the listed action is a
    // *valid* way to name it, so it is admitted once justified; a spelling the
    // gate cannot canonicalize is refused whatever the caller writes.
    assert!(accepted(
        "root",
        "TENANT.DELETE",
        "acme",
        Some("a real reason")
    ));
    assert!(accepted(
        "root",
        " tenant.delete",
        "acme",
        Some("a real reason")
    ));
    assert!(!accepted(
        "root",
        "tenant.\u{0}delete",
        "acme",
        Some("a real reason")
    ));
}

// ─────────────────────────────────────────────────────────────────────────
// 3. DEFECT B — trim() is a whitespace test, not a visibility test
// ─────────────────────────────────────────────────────────────────────────

/// **The second question in the brief, answered: yes for U+00A0 / U+2007 /
/// U+3000, no for the zero-width family.**
///
/// `str::trim` keys on the Unicode `White_Space` property, so every "space"
/// character — including the non-ASCII ones named in the brief — is correctly
/// stripped and the justification is correctly refused. That is the good news
/// and it is asserted below so a future switch to `is_ascii_whitespace` (a
/// plausible "optimization") fails loudly.
///
/// The bad news is the complement: U+200B, U+FEFF, U+2060, U+00AD, U+2800,
/// U+3164 and the bidi controls are `White_Space = No`. They render as
/// nothing, and `"\u{200b}"` is therefore a **written justification** as far
/// as `ccos-enterprise-admin` is concerned. So is a lone NUL byte.
#[test]
fn no_justification_that_draws_nothing_is_accepted() {
    // (name, char, is White_Space → caught by trim)
    let table: &[(&str, char, bool)] = &[
        ("U+0020 SPACE", '\u{20}', true),
        ("U+0009 TAB", '\u{9}', true),
        ("U+000A LF", '\u{a}', true),
        ("U+000B VT", '\u{b}', true),
        ("U+000C FF", '\u{c}', true),
        ("U+000D CR", '\u{d}', true),
        ("U+0085 NEL", '\u{85}', true),
        ("U+00A0 NO-BREAK SPACE", '\u{a0}', true),
        ("U+1680 OGHAM SPACE MARK", '\u{1680}', true),
        ("U+2000 EN QUAD", '\u{2000}', true),
        ("U+2007 FIGURE SPACE", '\u{2007}', true),
        ("U+2008 PUNCTUATION SPACE", '\u{2008}', true),
        ("U+200A HAIR SPACE", '\u{200a}', true),
        ("U+202F NARROW NO-BREAK SPACE", '\u{202f}', true),
        ("U+205F MEDIUM MATHEMATICAL SPACE", '\u{205f}', true),
        ("U+3000 IDEOGRAPHIC SPACE", '\u{3000}', true),
        // ── what used to be the hole: NOT `White_Space`, and now refused
        //    anyway, because the gate tests visibility rather than whitespace
        ("U+0000 NUL", '\u{0}', false),
        ("U+0007 BEL", '\u{7}', false),
        ("U+001B ESC", '\u{1b}', false),
        ("U+00AD SOFT HYPHEN", '\u{ad}', false),
        ("U+180E MONGOLIAN VOWEL SEPARATOR", '\u{180e}', false),
        ("U+200B ZERO WIDTH SPACE", '\u{200b}', false),
        ("U+200C ZERO WIDTH NON-JOINER", '\u{200c}', false),
        ("U+200D ZERO WIDTH JOINER", '\u{200d}', false),
        ("U+202E RIGHT-TO-LEFT OVERRIDE", '\u{202e}', false),
        ("U+2060 WORD JOINER", '\u{2060}', false),
        ("U+2800 BRAILLE PATTERN BLANK", '\u{2800}', false),
        ("U+3164 HANGUL FILLER", '\u{3164}', false),
        ("U+FEFF ZERO WIDTH NO-BREAK SPACE", '\u{feff}', false),
        ("U+FFA0 HALFWIDTH HANGUL FILLER", '\u{ffa0}', false),
    ];

    for (name, c, is_ws) in table {
        // The `White_Space` column is still asserted, because it is what a
        // future "optimization" back to `trim()` would rely on — and it is
        // exactly the set that would silently reopen the hole.
        assert_eq!(
            c.is_whitespace(),
            *is_ws,
            "{name}: the Unicode table moved under this test"
        );

        // One copy, and sixty-four copies: length changes nothing. EVERY row
        // is refused now, whitespace or not — that is the repair.
        for reps in [1usize, 64] {
            let blank: String = std::iter::repeat_n(*c, reps).collect();
            assert!(
                !accepted("root", "tenant.delete", "acme", Some(&blank)),
                "{name} x{reps} was accepted as a written justification"
            );
        }
    }

    // Mixed ASCII + Unicode whitespace is still whitespace: refused. Good.
    assert!(!accepted(
        "root",
        "tenant.delete",
        "acme",
        Some(" \t\u{a0}\u{2007}\u{3000}\u{202f}\n ")
    ));

    // ── DEFECT B, REPAIRED ───────────────────────────────────────────────
    // A justification that draws literally nothing is no longer "written".
    for invisible in [
        "\u{200b}", "\u{feff}", "\u{2060}", "\u{ad}", "\u{2800}", "\u{0}",
    ] {
        assert!(
            renders_blank(invisible),
            "the test's own notion of 'blank' is wrong for {invisible:?}"
        );
        assert!(
            !accepted("root", "tenant.delete", "acme", Some(invisible)),
            "{invisible:?} is still accepted as a written justification"
        );
    }

    // And the composite that used to be the sharpest edge: whitespace *plus*
    // one zero-width character. `trim()` removed the whitespace and left the
    // invisible behind, so the whole thing counted as written. It does not any
    // more — the rule is about what the string draws, not what survives a trim.
    let padded_ghost = "   \t\u{a0}\u{200b}\u{3000}  ";
    assert!(renders_blank(padded_ghost));
    assert!(
        !accepted("root", "license.revoke", "lic-0001", Some(padded_ghost)),
        "an invisible padded with whitespace is still accepted"
    );
    // One legible character among the invisibles is still enough: the gate
    // guarantees a reason is *readable*, not that it is *good*. Judging the
    // quality of a written reason is not something a string check can do, and
    // pretending otherwise would only push operators to type "x".
    assert!(accepted(
        "root",
        "license.revoke",
        "lic-0001",
        Some("   \u{200b}breach of contract\u{feff} ")
    ));
}

// ─────────────────────────────────────────────────────────────────────────
// 4. DEFECT C — the bar for "written" is one byte high
// ─────────────────────────────────────────────────────────────────────────

/// `docs/HUMAN_APPROVAL_POLICIES.md`: "an approval record names: approver,
/// artifact hash, decision, timestamp, justification". The gate enforces the
/// *presence* of a justification and nothing else — there is no minimum
/// length, no character-class requirement and no schema. `"."` clears it.
#[test]
fn a_single_dot_is_a_written_justification() {
    for token in [".", "-", "x", "0", "\u{1f600}", "'", "\\", ";", "\u{202e}."] {
        assert!(
            accepted("root", "tenant.delete", "acme", Some(token)),
            "{token:?} was refused"
        );
    }

    // The audit trail cannot distinguish these from a real reason; only a
    // human reading them can, and nothing forces a human to.
    assert!(accepted(
        "root",
        "license.revoke",
        "lic-0001",
        Some("contract terminated 2026-07-01")
    ));

    // Nor is there any bound the other way: 1 MiB of `r` is equally "written".
    assert!(accepted(
        "root",
        "quota.override",
        "acme",
        Some(&repeat_to('r', MIB))
    ));
}

// ─────────────────────────────────────────────────────────────────────────
// 5. DEFECT D — only the justification is trimmed
// ─────────────────────────────────────────────────────────────────────────

/// `validate` trims the justification but tests `actor`/`action`/`target`
/// with `is_empty()`. So the crate holds two different opinions about what
/// "blank" means, in the same twelve lines: a whitespace justification is "the
/// same audit hole as `None`" (its own comment), but a whitespace **actor** —
/// the name of the human being accountable for the act — is a valid actor.
#[test]
fn blank_actor_and_target_are_accepted_because_only_the_justification_is_trimmed() {
    let reason = Some("contract terminated");

    // Truly empty is refused — the only case the gate covers.
    assert!(!accepted("", "tenant.delete", "acme", reason));
    assert!(!accepted("root", "tenant.delete", "", reason));
    assert!(!accepted("root", "", "acme", reason));

    // Whitespace is not empty. DEFECT D: a sensitive act, fully validated,
    // attributed to nobody.
    for ghost in [
        " ",
        "   \t\r\n",
        "\u{a0}",
        "\u{3000}\u{3000}",
        "\u{200b}",
        "\u{feff}\u{2060}",
        "\u{0}",
    ] {
        assert!(
            renders_blank(ghost),
            "the test's own notion of 'blank' is wrong for {ghost:?}"
        );
        assert!(
            accepted(ghost, "tenant.delete", "acme", reason),
            "DEFECT D regressed (good!): blank actor {ghost:?} is now refused"
        );
        assert!(
            accepted("root", "tenant.delete", ghost, reason),
            "DEFECT D regressed (good!): blank target {ghost:?} is now refused"
        );
        // Both at once, and the record still validates.
        assert!(accepted(ghost, "tenant.delete", ghost, reason));
    }

    // The asymmetry, stated as one assertion: the *same* string is a valid
    // actor and an invalid justification.
    let blank = "   \t ";
    assert!(accepted(blank, "tenant.delete", "acme", reason));
    assert!(!accepted("root", "tenant.delete", "acme", Some(blank)));
}

/// Error-message precedence: emptiness is reported before the missing
/// justification, so an operator who omits *both* is told only about the
/// former. Minor, but it means "which gate refused me" is not recoverable
/// from the message, and the two failures are not separately countable.
#[test]
fn emptiness_is_reported_before_the_missing_justification() {
    let both_wrong = act("root", "tenant.delete", "", None);
    let msg = validate(&both_wrong).expect_err("must be refused");
    assert!(msg.contains("required"), "{msg}");
    assert!(
        !msg.contains("justification"),
        "the justification failure is masked: {msg}"
    );

    let only_justification = act("root", "tenant.delete", "acme", None);
    let msg = validate(&only_justification).expect_err("must be refused");
    assert_eq!(msg, "'tenant.delete' requires a written justification");

    // The message interpolates `a.action` — but it is only reachable when the
    // action is byte-equal to one of five literals, so it is NOT an
    // attacker-controlled format sink. This is what HELD.
    for sensitive in JUSTIFICATION_REQUIRED {
        let m = validate(&act("root", sensitive, "t", None)).expect_err("refused");
        assert_eq!(m, format!("'{sensitive}' requires a written justification"));
        assert!(m.len() < 80, "the message cannot be grown by the caller");
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 6. DEFECT E — no field has a bound
// ─────────────────────────────────────────────────────────────────────────

/// EXHAUSTION VECTOR. `validate` is the only thing standing between an admin
/// API and the journal `docs/ENTERPRISE_SECURITY_MODEL.md` promises, and it
/// caps nothing: not the actor, not the target, not the justification. A
/// 1 MiB justification is a valid one, so `N` accepted admin acts cost the
/// operator `N × unbounded` memory and journal bytes — and the acts are
/// *accepted*, so they are precisely the ones that get persisted.
#[test]
fn one_mebibyte_fields_are_accepted_without_bound() {
    let huge = repeat_to('j', MIB);
    assert_eq!(huge.len(), MIB);

    // 1 MiB justification on a sensitive action: accepted.
    assert!(accepted("root", "tenant.delete", "acme", Some(&huge)));
    // 1 MiB actor, 1 MiB target, 1 MiB justification, all at once: accepted.
    assert!(accepted(&huge, "tenant.suspend", &huge, Some(&huge)));

    // 1 MiB of NO-BREAK SPACE: correctly refused — `trim` walks the whole
    // buffer, which is linear, not quadratic, but it does prove the gate
    // reads every byte an attacker sends.
    let huge_blank = repeat_to('\u{a0}', MIB);
    assert!(huge_blank.len() >= MIB);
    assert!(!accepted(
        "root",
        "tenant.delete",
        "acme",
        Some(&huge_blank)
    ));

    // 1 MiB of zero-width space: now REFUSED. Defect B is closed, so the
    // compounding with E is gone — an invisible justification is no
    // justification however many megabytes of it arrive.
    let huge_ghost = repeat_to('\u{200b}', MIB);
    assert!(renders_blank(&huge_ghost));
    assert!(!accepted(
        "root",
        "tenant.delete",
        "acme",
        Some(&huge_ghost)
    ));
    // DEFECT E itself is untouched and still pinned: a 1 MiB *legible*
    // justification is accepted with no length bound anywhere.
    let huge_real = format!("{}{}", "reason ".repeat(MIB / 7), "x");
    assert!(accepted("root", "tenant.delete", "acme", Some(&huge_real)));

    // A 1 MiB *action* name is likewise unbounded — and it is not sensitive,
    // because it is not byte-equal to any of five short literals.
    let huge_action = repeat_to('a', MIB);
    assert!(accepted("root", &huge_action, "acme", None));
}

/// The exhaustion vector at scale. 128 accepted, fully-valid administrative
/// acts, 1 MiB of justification each: 128 MiB of journal that `validate`
/// blesses. Off by default because of the memory footprint.
///
/// Run with:
///   cargo test -p ccos-enterprise-conformance --test stress_admin_fuzz -- --ignored
#[test]
#[ignore = "allocates ~128 MiB; run explicitly with --ignored"]
fn admin_journal_growth_is_unbounded() {
    let mut journal: Vec<AdminAction> = Vec::new();
    let mut bytes = 0usize;
    for i in 0..128u32 {
        let a = AdminAction {
            actor: "root".to_string(),
            action: "tenant.delete".to_string(),
            target: format!("tenant-{i}"),
            unix_time: T0 + u64::from(i),
            justification: Some(repeat_to('j', MIB)),
        };
        assert!(validate(&a).is_ok(), "record {i} must be accepted");
        bytes += a.justification.as_deref().map_or(0, str::len);
        journal.push(a);
    }
    assert_eq!(journal.len(), 128);
    assert!(
        bytes >= 128 * MIB,
        "the gate accepted {bytes} bytes of justification with no cap"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 7. DEFECT F — the list is narrower than the policy it implements
// ─────────────────────────────────────────────────────────────────────────

/// SPEC VIOLATION. `docs/HUMAN_APPROVAL_POLICIES.md` enumerates what is
/// "approval-gated by default":
///
/// > tenant deletion/suspension, quota overrides, policy disabling, license
/// > revocation, **model-allowlist changes**, **any Enterprise-side schema
/// > migration**.
///
/// `JUSTIFICATION_REQUIRED` implements the first four and stops. Model
/// allowlist edits — the gate `docs/MODEL_GOVERNANCE.md` calls the whole point
/// of model governance, and which `Deployment` really does key admission on —
/// and schema migrations (`docs/BACKUP_AND_RESTORE.md`'s
/// `schema_version`) carry no justification requirement at all.
#[test]
fn the_approval_policy_lists_categories_the_gate_does_not_cover() {
    // What is covered.
    let covered = [
        "tenant.delete",
        "tenant.suspend",
        "quota.override",
        "policy.disable",
        "license.revoke",
    ];
    let listed: BTreeSet<&str> = JUSTIFICATION_REQUIRED.iter().copied().collect();
    assert_eq!(listed, covered.iter().copied().collect::<BTreeSet<_>>());
    assert_eq!(
        JUSTIFICATION_REQUIRED.len(),
        5,
        "the list is exactly five entries"
    );

    // DEFECT F: the two categories the policy names but the list omits.
    // Every plausible spelling of them validates with no justification.
    for uncovered in [
        "model.allowlist.add",
        "model.allowlist.remove",
        "model.allowlist.set",
        "models.allow",
        "model.switch",
        "schema.migrate",
        "schema.upgrade",
        "migration.apply",
        "backup.restore",
    ] {
        assert!(
            !required_exactly(uncovered),
            "DEFECT F regressed (good!): {uncovered} is now justification-required"
        );
        assert!(
            accepted("root", uncovered, "acme", None),
            "{uncovered} must currently validate with no justification"
        );
    }

    // The same act, renamed to something the list *does* contain, is refused —
    // proving the gate is a name lookup, not a capability model.
    assert!(!accepted("root", "policy.disable", "acme", None));
    assert!(accepted("root", "policy.set", "acme", None));
    // …and `policy.set` with an empty allowlist *is* `policy.disable`.
}

// ─────────────────────────────────────────────────────────────────────────
// 8. DEFECT G — nothing composed ever calls the gate
// ─────────────────────────────────────────────────────────────────────────

/// MISSING BEHAVIOUR. The security model's layer 6 is "administrative acts
/// **validated and journaled** with justification". The crate provides the
/// validator; nothing provides the journal, and nothing in the composed
/// product calls the validator.
///
/// The proof used to be structural and total: `Call` had no justification
/// field, so a reason could not be supplied at the only admission point the
/// product has; `AuditRecord` had none, so it could not be recorded; and
/// `policy.set` — the deployment's one administrative tool — was forwarded and
/// journaled with no "why". The identical act was refused when expressed as an
/// `AdminAction` and admitted when expressed as a governed tool call: layer 6
/// was enforced on the surface nobody called and absent from the one everybody
/// called.
///
/// Both fields now exist, `Deployment::require_justification` marks a tool as
/// an administrative act, and the predicate is
/// `ccos_enterprise_admin::is_written_justification` itself rather than a
/// second copy of it — so the two surfaces cannot drift apart on what counts
/// as a written reason. This test keeps the same act and asserts the opposite
/// outcome.
#[test]
fn the_composed_path_now_demands_and_records_a_justification() {
    let mut d = two_tenant_deployment();
    // `memorithm` is the org that OWNS the `acme` tenant, so the caller here
    // is deliberately legitimate: the only thing under test is the reason.
    let root = actor("memorithm", "root", AuthStrength::Token);
    let req = request("acme", "root", "policy.set", "r-admin-1");

    let outcome = d.admit(Call {
        actor: &root,
        request: &req,
        model: "claude-opus",
        cost_tokens: 1,
        variant: None,
        justification: None,
    });
    assert_eq!(
        outcome.refusal(),
        Some(&Refusal::JustificationRequired),
        "the administrative tool call was admitted with no reason: {outcome:?}"
    );
    assert_eq!(d.spent("acme"), Some(0), "and it cost the tenant nothing");

    // The attempt is journaled — a refused administrative act is exactly the
    // event an audit trail exists to keep.
    let trail = d.audit_of("acme");
    let record = trail.last().expect("the attempt was journaled");
    assert_eq!(record.tool, "policy.set");
    assert_eq!(record.actor, "root");
    assert_eq!(record.request_id, "r-admin-1");
    assert!(!record.outcome.is_forwarded());

    // The two surfaces now agree, which was the whole complaint: the same act
    // is refused for the same reason whether it is named as an `AdminAction`
    // or called as a governed tool.
    assert!(!accepted("root", "policy.disable", "acme", None));

    // With a reason, the act goes through and the reason is in the record.
    let req = request("acme", "root", "policy.set", "r-admin-2");
    assert!(d
        .admit(Call {
            actor: &root,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
            justification: Some("closing the gpt-5 allowlist entry, ticket 881"),
        })
        .is_forwarded());
    assert_eq!(
        d.audit_of("acme")
            .last()
            .and_then(|r| r.justification.as_deref()),
        Some("closing the gpt-5 allowlist entry, ticket 881")
    );

    // The administrative path inherits the same effect-idempotent replay rule
    // as every other governed call. A captured request_id is acknowledged as a
    // replay at zero cost, but it is NOT eligible to execute the administrative
    // effect again. A fresh administrative act therefore needs a fresh request_id.
    let before = d.audit_of("acme").len();
    let again = d.admit(Call {
        actor: &root,
        request: &req,
        model: "claude-opus",
        cost_tokens: 1,
        variant: None,
        justification: Some("a different reason entirely"),
    });
    assert!(again.is_replayed());
    assert_eq!(d.audit_of("acme").len(), before + 1);
    assert_eq!(
        d.audit_of("acme")
            .iter()
            .filter(|r| r.request_id == "r-admin-2")
            .count(),
        2,
        "the same administrative request_id is journaled twice"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 9. The wire form: every bypass survives `Deserialize`
// ─────────────────────────────────────────────────────────────────────────

/// `AdminAction` derives `Serialize`/`Deserialize`, so the natural shape of an
/// admin API is `serde_json::from_str::<AdminAction>(body)` followed by
/// `validate`. This test walks that path and shows the bypasses are reachable
/// from a plain HTTP body — they are not an abstract property of the `const`.
#[test]
fn the_json_wire_form_inherits_the_repairs_and_the_remaining_gaps() {
    let parse = |body: &str| serde_json::from_str::<AdminAction>(body);

    // Baseline: the honest request is correctly refused.
    let honest =
        parse(r#"{"actor":"root","action":"tenant.delete","target":"acme","unix_time":0}"#)
            .expect("parses");
    assert!(
        honest.justification.is_none(),
        "a missing Option field is None"
    );
    assert!(validate(&honest).is_err());

    // Explicit null is the same thing.
    let nulled = parse(
        r#"{"actor":"root","action":"tenant.delete","target":"acme","unix_time":0,"justification":null}"#,
    )
    .expect("parses");
    assert!(nulled.justification.is_none());
    assert!(validate(&nulled).is_err());

    // HELD: duplicate keys are rejected, so a justification cannot be smuggled
    // past a validating proxy by repeating the field.
    let dup = parse(
        r#"{"actor":"root","action":"tenant.delete","target":"acme","unix_time":0,"justification":"real","justification":null}"#,
    );
    assert!(dup.is_err(), "serde must reject a duplicated field");

    // ── DEFECT A over the wire ───────────────────────────────────────────
    let shouted =
        parse(r#"{"actor":"root","action":"TENANT.DELETE","target":"acme","unix_time":0}"#)
            .expect("parses");
    assert!(
        validate(&shouted).is_err(),
        "the mixed-case wire form still bypasses the requirement"
    );

    let padded =
        parse(r#"{"actor":"root","action":"tenant.delete ","target":"acme","unix_time":0}"#)
            .expect("parses");
    assert!(
        validate(&padded).is_err(),
        "the padded wire form still bypasses the requirement"
    );

    // ── DEFECT B over the wire ───────────────────────────────────────────
    // Written the way a JSON client actually emits it: the six ASCII
    // characters backslash-u-2-0-0-b. The body therefore contains a
    // with a value, and the value draws nothing.
    let zwsp_escape = "\\u200b";
    let ghost_body = format!(
        r#"{{"actor":"root","action":"tenant.delete","target":"acme","unix_time":0,"justification":"{zwsp_escape}"}}"#
    );
    assert!(ghost_body.is_ascii(), "the wire bytes are plain ASCII");
    let ghost = parse(&ghost_body).expect("parses");
    assert_eq!(ghost.justification.as_deref(), Some("\u{200b}"));
    assert!(
        validate(&ghost).is_err(),
        "an invisible justification still passes over the wire"
    );

    // ── DEFECT D over the wire ───────────────────────────────────────────
    let anon = parse(
        r#"{"actor":" ","action":"tenant.delete","target":"acme","unix_time":0,"justification":"why"}"#,
    )
    .expect("parses");
    assert!(validate(&anon).is_ok(), "DEFECT D regressed (good!)");

    // Unknown fields are ignored (no `deny_unknown_fields`), so a caller can
    // decorate the body freely; this is benign on its own but means a typo'd
    // `Justification` is silently a missing justification rather than an error.
    let typo = parse(
        r#"{"actor":"root","action":"tenant.delete","target":"acme","unix_time":0,"Justification":"real reason"}"#,
    )
    .expect("unknown fields are ignored");
    assert!(typo.justification.is_none());
    assert!(validate(&typo).is_err(), "…which at least fails closed");

    // Round-trip: control bytes in a justification are escaped by serde_json,
    // so a JSON-lines journal is not injectable. HELD — for JSON sinks only;
    // `validate` itself imposes no canonicality, so a logfmt/CSV/plain-text
    // journal has no such protection (see the next test).
    let sneaky = act(
        "root",
        "tenant.delete",
        "acme",
        Some("ok\n2026-01-01 root APPROVED"),
    );
    assert!(validate(&sneaky).is_ok());
    let encoded = serde_json::to_string(&sneaky).expect("serializes");
    assert!(encoded.contains("\\n"), "the newline is escaped: {encoded}");
    assert!(!encoded.contains('\n'), "no raw newline reaches the wire");
    let decoded: AdminAction = serde_json::from_str(&encoded).expect("round-trips");
    assert_eq!(decoded.justification, sneaky.justification);
}

// ─────────────────────────────────────────────────────────────────────────
// 10. Residue: fields nobody validates
// ─────────────────────────────────────────────────────────────────────────

/// Control characters — including CR, LF, ESC and NUL — pass through every
/// field untouched. The gateway rejects them in tool names ("a tool name that
/// carries whitespace/control bytes is not a canonical name and is rejected
/// outright"); the admin gate accepts them in the actor, the action, the
/// target and the justification of a *sensitive* act. Any non-JSON journal
/// sink (logfmt, syslog, CSV, a terminal) is line-injectable as a result.
#[test]
fn control_characters_survive_every_field() {
    let forged_line = "ok\r\n2026-01-01T00:00:00Z root tenant.delete globex APPROVED";
    assert!(accepted("root", "tenant.delete", "acme", Some(forged_line)));

    // Terminal escapes in the actor name of an accepted sensitive act.
    let ansi_actor = "root\u{1b}[2K\u{1b}[1G";
    assert!(accepted(
        ansi_actor,
        "tenant.delete",
        "acme",
        Some("reason")
    ));

    // A bidi override in the target: renders as `emca` while naming `acme`.
    assert!(accepted(
        "root",
        "tenant.delete",
        "\u{202e}acme\u{202c}",
        Some("reason")
    ));

    // NUL in every field at once, sensitive action, still accepted.
    assert!(accepted(
        "ro\u{0}ot",
        "tenant.suspend",
        "ac\u{0}me",
        Some("re\u{0}ason")
    ));
}

/// DEFECT G, second half — the workspace performs `license.revoke` on three
/// surfaces, and the three disagree about what evidence a revocation needs:
///
/// | surface | evidence demanded |
/// |---|---|
/// | `ccos_enterprise_governance::vendor::RevocationEntry` | a **mandatory, typed** `RevocationReason` — you cannot construct one without it |
/// | `ccos_enterprise_admin::validate` | an `Option<String>` that `"."` satisfies, and that `"LICENSE.REVOKE"` skips entirely |
/// | `ccos_license_server::Entry` | **nothing**: `status` is a public field with no reason beside it, and revoking is an assignment |
///
/// The strongest of the three is the one furthest from the operator, and the
/// weakest is the one `docs/ENTERPRISE_SECURITY_MODEL.md` names as the audit
/// layer. Nothing reconciles them; `ccos_enterprise_admin` is not a dependency
/// of either other crate.
#[test]
fn the_three_revocation_surfaces_demand_three_different_reasons() {
    use ccos_enterprise_governance::vendor::{RevocationEntry, RevocationReason};
    use ccos_license_server::{Entry, Status, Vault};

    // 1. The governance crate: the reason is a field of a struct, so it is
    //    impossible to build a revocation without naming one, and the set of
    //    namable reasons is closed.
    let signed = RevocationEntry {
        license_id: Some("lic-0001".to_string()),
        token_sha256: None,
        revoked_at: T0,
        reason: RevocationReason::PolicyViolation,
    };
    assert_eq!(signed.reason, RevocationReason::PolicyViolation);

    // 2. The admin gate: the same act, with a full stop for a reason.
    assert!(accepted("root", "license.revoke", "lic-0001", Some(".")));
    // Shouting no longer helps: the spelling bypass is closed.
    assert!(!accepted("root", "LICENSE.REVOKE", "lic-0001", None));

    // 3. The counter's ledger: revocation is a field assignment. `Entry` has
    //    no reason, no justification and no actor — `label` is the only free
    //    text and it is optional, unsigned and unread by any gate.
    let mut vault = Vault::new();
    vault.entries.insert(
        "k-0001".to_string(),
        Entry {
            licensee: "Acme Corp".to_string(),
            label: None,
            days: Some(365),
            status: Status::Claimed,
            created_unix: T0,
            claimed_unix: Some(T0),
            exp_unix: Some(T0 + 365 * 86_400),
            machine: Some("fingerprint".to_string()),
        },
    );
    vault.entries.get_mut("k-0001").expect("present").status = Status::Revoked;
    assert_eq!(vault.entries["k-0001"].status, Status::Revoked);

    // The revoked entry, serialized in full: no reason, no actor, no time of
    // revocation. The ledger cannot answer "who revoked this, when, and why".
    let json = serde_json::to_string(&vault.entries["k-0001"]).expect("serializes");
    for absent in ["justification", "reason", "revoked_by", "revoked_at"] {
        assert!(
            !json.contains(absent),
            "expected no {absent} field in the ledger entry: {json}"
        );
    }
}

/// `unix_time` is never read by `validate`. `docs/HUMAN_APPROVAL_POLICIES.md`
/// requires an approval record to name a timestamp; the gate accepts 0 and
/// `u64::MAX` alike, so "when" is caller-asserted and unchecked.
#[test]
fn unix_time_is_accepted_unvalidated() {
    let reason = Some("contract terminated");
    for t in [0, 1, T0, u64::MAX, u64::MAX - 1] {
        let mut a = act("root", "tenant.delete", "acme", reason);
        a.unix_time = t;
        assert!(validate(&a).is_ok(), "timestamp {t} was rejected");
        // …and it makes no difference to the verdict either way.
        a.justification = None;
        assert!(validate(&a).is_err());
    }
}

/// Purity: `validate` takes `&AdminAction`, so it cannot mutate its input, and
/// the verdict does not depend on evaluation order or on how many acts came
/// before. Pinned because a future "rate-limit sensitive actions" or "remember
/// the last justification" change would silently break replay determinism.
#[test]
fn validate_is_pure_and_order_independent() {
    let corpus: Vec<AdminAction> = {
        let mut v = Vec::new();
        for action in JUSTIFICATION_REQUIRED
            .iter()
            .chain(NON_SENSITIVE_ACTIONS.iter())
        {
            for why in [
                None,
                Some(""),
                Some("  "),
                Some("."),
                Some("\u{200b}"),
                Some("real"),
            ] {
                v.push(act("root", action, "acme", why));
            }
        }
        v
    };

    let forward: Vec<bool> = corpus.iter().map(|a| validate(a).is_ok()).collect();

    // Same order, again.
    let repeat: Vec<bool> = corpus.iter().map(|a| validate(a).is_ok()).collect();
    assert_eq!(forward, repeat);

    // Reverse order.
    let mut backward: Vec<bool> = corpus.iter().rev().map(|a| validate(a).is_ok()).collect();
    backward.reverse();
    assert_eq!(forward, backward, "the verdict depends on evaluation order");

    // Interleaved with unrelated acts.
    let mut interleaved = Vec::with_capacity(corpus.len());
    for a in &corpus {
        let _ = validate(&act("noise", "tenant.create", "noise", None));
        interleaved.push(validate(a).is_ok());
    }
    assert_eq!(forward, interleaved);

    // The input is untouched: `validate` cannot normalize the record it blessed.
    let original = act("root", "tenant.delete", "acme", Some("  reason  "));
    let mut copy = original.clone();
    assert!(validate(&copy).is_ok());
    assert_eq!(copy.justification, original.justification);
    copy.justification = None;
    assert!(validate(&copy).is_err());
}
