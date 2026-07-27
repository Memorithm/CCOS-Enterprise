//! Claim-code primitives — the shared half of the **one-time license claim**
//! protocol (`ccos license claim` on the client, `tools/ccos-license-server`
//! on the vendor side).
//!
//! The protocol in one paragraph: at sale time the vendor generates a
//! high-entropy **claim code** (`CCOS-XXXXX-XXXXX-XXXXX-XXXXX`, 100 bits) and
//! records only its **hash** in the claim counter's vault. To activate, the
//! client sends `{sha256(code), machine_fingerprint}` — never the code itself,
//! and never a raw hardware identifier — and receives a signed annual,
//! single-seat token with the fingerprint bound into the signed payload. The
//! counter flips the code `unclaimed → claimed` atomically (that flip *is* the
//! single-use property; re-claiming from the **same** machine re-issues the
//! same license, any other machine is refused). Verification of the received
//! token stays exactly the existing offline path ([`crate::license`]): the
//! client checks the signature against the public key baked into its own
//! binary before installing anything, so a compromised counter can refuse
//! service but can never mint or tamper.
//!
//! Privacy: the machine fingerprint is `sha256("ccos-machine-v1|" + machine-id)`
//! — an opaque 32-byte value. The vendor never learns CPU serials, disk ids,
//! MACs or hostnames; binding and verification only ever compare hashes.
//!
//! This module is pure `std` + the hashes already in the tree (no feature
//! gate); the network halves live with their callers (the CLI behind `llm`,
//! the server in its own tool crate).

use serde::{Deserialize, Serialize};

/// Env var overriding the machine identity source — for containers without
/// `/etc/machine-id`, tests, and operators who prefer an explicit identity.
pub const MACHINE_ID_ENV: &str = "CCOS_MACHINE_ID";

/// The claim endpoint path on the vendor's counter.
pub const CLAIM_PATH: &str = "/claim";

/// Wire-schema tag for [`ClaimRequest`], bumped on any breaking change.
pub const CLAIM_SCHEMA: &str = "ccos.claim/v1";

/// Crockford base32 (no `I L O U`) — unambiguous to read over the phone,
/// case-insensitive to type. 5 bits per symbol.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A claim request: everything the client ever sends the vendor. Both fields
/// are already hashes — the code and the machine identity never leave the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRequest {
    /// [`CLAIM_SCHEMA`].
    pub schema: String,
    /// [`code_hash`] of the canonical claim code.
    pub code_hash: String,
    /// [`machine_fingerprint_of`] the host's machine id — bound into the
    /// signed token by the counter (single-seat).
    pub machine: String,
}

/// A successful claim: the signed license token, ready to verify and install.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimOk {
    pub token: String,
}

/// An announced refusal from the counter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimErr {
    pub error: String,
}

/// Format 16 bytes of entropy as a claim code: `CCOS-` + 4 groups of 5
/// Crockford-base32 symbols (100 of the 128 bits — comfortably beyond
/// brute-force at any conceivable rate limit). Deterministic: the vendor's
/// entropy source is the only randomness.
pub fn code_from_entropy(entropy: &[u8; 16]) -> String {
    // Consume the entropy as a bit stream, 5 bits per symbol, 20 symbols.
    let mut symbols = Vec::with_capacity(20);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in entropy {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 && symbols.len() < 20 {
            bits -= 5;
            symbols.push(ALPHABET[(acc >> bits) as usize & 31]);
        }
        if symbols.len() == 20 {
            break;
        }
    }
    let s = String::from_utf8(symbols).expect("alphabet is ASCII");
    format!(
        "CCOS-{}-{}-{}-{}",
        &s[0..5],
        &s[5..10],
        &s[10..15],
        &s[15..20]
    )
}

/// Normalize operator input to the canonical `CCOS-XXXXX-XXXXX-XXXXX-XXXXX`
/// form: case-insensitive, separators optional, and the usual Crockford
/// confusions folded (`O→0`, `I/L→1`). `None` when the input is not a claim
/// code (wrong length, symbol outside the alphabet).
pub fn canonical_code(input: &str) -> Option<String> {
    let mut symbols = String::with_capacity(24);
    for c in input.chars() {
        match c {
            '-' | ' ' | '_' | '\t' => continue,
            _ => {
                let c = match c.to_ascii_uppercase() {
                    'O' => '0',
                    'I' | 'L' => '1',
                    up => up,
                };
                if !ALPHABET.contains(&(c as u8)) {
                    return None;
                }
                symbols.push(c);
            }
        }
    }
    // "CCOS" itself survives the alphabet (C, 0, S are all members).
    let body = symbols.strip_prefix("CC0S").unwrap_or(&symbols);
    if body.len() != 20 {
        return None;
    }
    Some(format!(
        "CCOS-{}-{}-{}-{}",
        &body[0..5],
        &body[5..10],
        &body[10..15],
        &body[15..20]
    ))
}

/// The vault key and wire form of a claim code: domain-separated SHA-256 of
/// the canonical code. The counter stores and receives only this — a stolen
/// vault contains nothing redeemable.
pub fn code_hash(canonical_code: &str) -> String {
    ccos_core::util::sha256_hex(&format!("ccos-claim-code-v1|{canonical_code}"))
}

/// The opaque machine fingerprint bound into a single-seat token:
/// domain-separated SHA-256 of the host's machine id. Never reversible to the
/// identifier, and never derived from hardware serials.
pub fn machine_fingerprint_of(machine_id: &str) -> String {
    ccos_core::util::sha256_hex(&format!("ccos-machine-v1|{}", machine_id.trim()))
}

/// The host's machine fingerprint: [`MACHINE_ID_ENV`] when set (containers,
/// tests, explicit operator identity), else the standard Linux machine ids
/// (`/etc/machine-id`, `/var/lib/dbus/machine-id`). `None` when no stable
/// identity exists — callers must fail **closed and announced** (a
/// machine-bound license cannot bind to nothing).
pub fn host_fingerprint() -> Option<String> {
    if let Ok(id) = std::env::var(MACHINE_ID_ENV) {
        let id = id.trim().to_string();
        if !id.is_empty() {
            return Some(machine_fingerprint_of(&id));
        }
    }
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(id) = std::fs::read_to_string(path) {
            let id = id.trim();
            if !id.is_empty() {
                return Some(machine_fingerprint_of(id));
            }
        }
    }
    None
}

/// `true` iff `s` looks like one of our SHA-256 hex values (the wire-format
/// sanity check both halves apply before doing anything with a field).
pub fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_from_entropy_is_stable_and_well_formed() {
        let code = code_from_entropy(&[0xAB; 16]);
        assert_eq!(code, code_from_entropy(&[0xAB; 16]), "deterministic");
        assert_eq!(code.len(), "CCOS-XXXXX-XXXXX-XXXXX-XXXXX".len());
        assert!(code.starts_with("CCOS-"));
        // Distinct entropy → distinct codes.
        assert_ne!(code, code_from_entropy(&[0xAC; 16]));
        // Every generated symbol is in the unambiguous alphabet (the fixed
        // "CCOS-" prefix is branding, not payload — its O is folded to 0 by
        // canonical_code on the way back in).
        for c in code
            .strip_prefix("CCOS-")
            .unwrap()
            .chars()
            .filter(|c| *c != '-')
        {
            assert!(
                ALPHABET.contains(&(c as u8)),
                "symbol {c} outside the Crockford alphabet"
            );
        }
    }

    #[test]
    fn canonical_code_accepts_sloppy_input_and_rejects_garbage() {
        let code = code_from_entropy(&[7; 16]);
        // The canonical form round-trips.
        assert_eq!(canonical_code(&code).as_deref(), Some(code.as_str()));
        // Lowercase, missing dashes, stray spaces, Crockford confusions.
        let sloppy = code.replace('-', " ").to_lowercase();
        assert_eq!(canonical_code(&sloppy).as_deref(), Some(code.as_str()));
        let confused = code.replace('0', "O").replace('1', "l");
        assert_eq!(canonical_code(&confused).as_deref(), Some(code.as_str()));
        // Garbage is refused, not guessed.
        assert_eq!(canonical_code("CCOS-SHORT"), None);
        assert_eq!(canonical_code("CCOS-UUUUU-UUUUU-UUUUU-UUUUU"), None); // U outside alphabet
        assert_eq!(canonical_code(""), None);
    }

    #[test]
    fn hashes_are_domain_separated_and_stable() {
        let code = code_from_entropy(&[1; 16]);
        assert_eq!(code_hash(&code), code_hash(&code));
        assert!(is_sha256_hex(&code_hash(&code)));
        // The same string hashed under the two domains never collides.
        assert_ne!(code_hash(&code), machine_fingerprint_of(&code));
        // Fingerprints trim whitespace (machine-id files end in newline).
        assert_eq!(
            machine_fingerprint_of("abc123\n"),
            machine_fingerprint_of("abc123")
        );
    }

    #[test]
    fn host_fingerprint_honors_the_env_override() {
        // Serial with any other env-reading test via a unique var value; the
        // override is the documented container/test path.
        std::env::set_var(MACHINE_ID_ENV, "test-machine-xyz");
        assert_eq!(
            host_fingerprint().as_deref(),
            Some(machine_fingerprint_of("test-machine-xyz").as_str())
        );
        std::env::remove_var(MACHINE_ID_ENV);
    }

    #[test]
    fn sha256_hex_shape_check() {
        assert!(is_sha256_hex(&code_hash("CCOS-AAAAA-AAAAA-AAAAA-AAAAA")));
        assert!(!is_sha256_hex("abc"));
        assert!(!is_sha256_hex(&"Z".repeat(64)));
        assert!(!is_sha256_hex(&"A".repeat(64)), "uppercase hex is not ours");
    }
}
