//! # CCOS Enterprise — Administration
//!
//! Operator-facing administration surface (org/tenant/user lifecycle).
//! Foundation slice: the administrative action log — every admin act is an
//! auditable record before it is an effect.

use serde::{Deserialize, Serialize};

/// An administrative action, journaled before execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAction {
    pub actor: String,
    pub action: String,
    pub target: String,
    pub unix_time: u64,
    /// Free-form justification, required for sensitive actions.
    pub justification: Option<String>,
}

/// Actions that are refused without a written justification.
///
/// Entries are in canonical form (see [`canonical_action`]); membership is
/// tested against the canonicalized action, never against the raw string.
pub const JUSTIFICATION_REQUIRED: &[&str] = &[
    "tenant.delete",
    "tenant.suspend",
    "quota.override",
    "policy.disable",
    "license.revoke",
];

/// Characters that draw nothing but are **not** `White_Space`, so `str::trim`
/// leaves them in place.
///
/// This list exists because `char::is_whitespace` follows the Unicode
/// `White_Space` property, and the characters below are deliberately excluded
/// from it — they are formatting marks, not spaces. To an operator reading an
/// audit trail a justification made of them is indistinguishable from `None`,
/// which is exactly the hole the justification requirement exists to close.
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

/// The canonical form of an action name: padding stripped, case folded.
///
/// This is what a wire format, an HTTP router, a config loader or a SQL
/// `lower()` would each do on their own, so it is the form the policy list
/// must be compared against — otherwise `Tenant.Delete` and `tenant.delete `
/// are different actions to the gate and the same action to everything else.
pub fn canonical_action(action: &str) -> String {
    action.trim().to_lowercase()
}

/// Whether a canonicalized action name is one this gate can reason about:
/// dot-separated segments of ASCII `[a-z0-9_]`, each non-empty.
///
/// Anything else is **refused outright** rather than compared. That is the
/// fail-closed choice, and it is the whole repair for the homoglyph family:
/// case folding turns `TENANT.DELETE` into `tenant.delete`, but nothing turns
/// Cyrillic `е`, full-width `ｔ` or an embedded zero-width joiner into their
/// ASCII lookalikes. Such a name would silently *miss* the policy list and be
/// admitted with no justification, so the gate must refuse to guess.
pub fn is_canonical_action(action: &str) -> bool {
    !action.is_empty()
        && action.split('.').all(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
}

/// Whether a string draws anything at all.
///
/// `trim()` is a whitespace test, not a visibility test: `"\u{200b}"` survives
/// it and reads to a human as an empty audit entry.
fn renders_blank(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_whitespace() || c.is_control() || ZERO_WIDTH.contains(&c))
}

/// Validate an administrative action before it takes effect (fail closed).
///
/// Three rules, in order. The first two are refusals of *unreasonable input*
/// rather than of the act itself, and they run first so a malformed action can
/// never reach the policy comparison:
///
/// 1. actor, action and target must be present;
/// 2. the action name must be canonical (see [`is_canonical_action`]) — a name
///    this gate cannot compare is refused, not admitted;
/// 3. an action on the sensitive list needs a justification that renders
///    something a human can read.
pub fn validate(a: &AdminAction) -> Result<(), String> {
    if a.actor.is_empty() || a.action.is_empty() || a.target.is_empty() {
        return Err("actor, action and target are required".into());
    }

    let action = canonical_action(&a.action);
    if !is_canonical_action(&action) {
        return Err(format!(
            "'{}' is not a canonical action name (dot-separated [a-z0-9_]); \
             a name that cannot be compared with the policy list is refused",
            a.action
        ));
    }

    // A justification must be *readable*: `Some("")`, whitespace, control
    // bytes and zero-width formatting are all the same audit hole as `None`.
    let justified = a
        .justification
        .as_deref()
        .is_some_and(|j| !renders_blank(j));
    if JUSTIFICATION_REQUIRED.contains(&action.as_str()) && !justified {
        return Err(format!("'{action}' requires a written justification"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_actions_need_justification() {
        let mut a = AdminAction {
            actor: "root".into(),
            action: "tenant.delete".into(),
            target: "acme".into(),
            unix_time: 0,
            justification: None,
        };
        assert!(validate(&a).is_err());
        a.justification = Some("contract terminated 2026-07-01".into());
        assert!(validate(&a).is_ok());
    }

    /// **DEFECT A, repaired.** The gate matched the sensitive-action list
    /// byte for byte, so every re-spelling of a listed action skipped the
    /// justification requirement entirely: `Tenant.Delete`, `TENANT.DELETE`,
    /// `" tenant.delete "`, and the homoglyph family. Deleting a tenant with
    /// no recorded reason was one shift key away.
    #[test]
    fn no_respelling_of_a_sensitive_action_escapes_the_gate() {
        let unjustified = |action: &str| {
            validate(&AdminAction {
                actor: "root".into(),
                action: action.into(),
                target: "acme".into(),
                unix_time: 0,
                justification: None,
            })
        };

        for listed in JUSTIFICATION_REQUIRED {
            // Case and padding now canonicalize onto the listed name.
            for spelling in [
                listed.to_uppercase(),
                format!("  {listed}\t"),
                listed
                    .chars()
                    .enumerate()
                    .map(|(i, c)| {
                        if i % 2 == 0 {
                            c.to_ascii_uppercase()
                        } else {
                            c
                        }
                    })
                    .collect::<String>(),
            ] {
                assert!(
                    unjustified(&spelling).is_err(),
                    "{spelling:?} escaped the justification requirement"
                );
            }
        }

        // U+212A KELVIN SIGN lowercases to ASCII `k`, so it canonicalizes onto
        // the listed name rather than being refused as non-canonical.
        assert!(unjustified("license.revo\u{212a}e").is_err());

        // The homoglyph family cannot be folded onto ASCII, so it is refused
        // as non-canonical instead — which is the same outcome for the caller
        // and the only fail-closed one available.
        for hostile in [
            "t\u{0435}nant.delete",  // Cyrillic е
            "\u{ff54}enant.delete",  // full-width t
            "tenant.dele\u{200b}te", // smuggled zero-width
            "tenant.delete\u{202e}", // RTL override
        ] {
            let e = unjustified(hostile).expect_err("must not be admitted");
            assert!(e.contains("canonical"), "{hostile:?}: {e}");
        }

        // …and a *justified* sensitive action still passes, in any spelling
        // the gate can canonicalize.
        assert!(validate(&AdminAction {
            actor: "root".into(),
            action: " Tenant.Delete ".into(),
            target: "acme".into(),
            unix_time: 0,
            justification: Some("contract terminated 2026-07-01".into()),
        })
        .is_ok());
    }

    /// A non-sensitive action is still refused when it is not a name the gate
    /// can compare — the canonicality rule is about the gate's ability to
    /// reason, not about which actions are sensitive.
    #[test]
    fn a_non_canonical_action_is_refused_even_when_it_is_not_sensitive() {
        let e = validate(&AdminAction {
            actor: "root".into(),
            action: "tenant.renam\u{0435}".into(),
            target: "acme".into(),
            unix_time: 0,
            justification: Some("because".into()),
        })
        .expect_err("a name that cannot be compared is refused");
        assert!(e.contains("canonical"), "{e}");
        // The ASCII spelling of the same action passes without a reason.
        assert!(validate(&AdminAction {
            actor: "root".into(),
            action: "tenant.rename".into(),
            target: "acme".into(),
            unix_time: 0,
            justification: None,
        })
        .is_ok());
    }

    /// **DEFECT B, repaired.** `trim()` tests for whitespace, and the Unicode
    /// `White_Space` property deliberately excludes zero-width formatting
    /// marks — so a justification of `"\u{200b}"` passed a check whose whole
    /// purpose is to guarantee a human can read the reason.
    #[test]
    fn a_justification_that_draws_nothing_is_no_justification() {
        let with = |j: &str| {
            validate(&AdminAction {
                actor: "root".into(),
                action: "tenant.delete".into(),
                target: "acme".into(),
                unix_time: 0,
                justification: Some(j.into()),
            })
        };
        for blank in ZERO_WIDTH {
            assert!(
                with(&blank.to_string()).is_err(),
                "U+{:04X} rendered as a written justification",
                *blank as u32
            );
        }
        // Mixed invisibles, and invisibles around whitespace and control bytes.
        assert!(with("\u{200b}\u{feff} \t\u{202e}\r\n\u{0000}").is_err());
        // One visible character among them is enough — the gate guarantees a
        // reason is *legible*, not that it is *good*. Judging the quality of a
        // written reason is not something a string check can do.
        assert!(with("\u{200b}x\u{feff}").is_ok());
    }

    #[test]
    fn blank_justification_is_no_justification() {
        let mut a = AdminAction {
            actor: "root".into(),
            action: "license.revoke".into(),
            target: "lic-0001".into(),
            unix_time: 0,
            justification: Some(String::new()),
        };
        assert!(validate(&a).is_err(), "empty string is not written");
        a.justification = Some("  \t ".into());
        assert!(validate(&a).is_err(), "whitespace is not written");
        // Non-sensitive actions still pass without one.
        a.action = "tenant.rename".into();
        a.justification = None;
        assert!(validate(&a).is_ok());
    }
}
