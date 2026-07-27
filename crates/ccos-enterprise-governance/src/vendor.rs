//! Vendor-side license issuance: token signing (v0 machine-bound and v1
//! keyring formats) and offline revocation lists.
//!
//! Extracted from CCOS_EXTENDED `src/license.rs` (commit `fe094a3`, class B1)
//! — the issuer half of the license system. Verification of these artifacts
//! stays in `ccos-core` (v0/v1 tokens) and in this crate (revocation lists,
//! [`verify_revocation_list_with`]). Wire formats are unchanged so a token
//! signed here verifies byte-identically against `ccos-core`.
//!
//! Private key material is accepted only by these functions and is never
//! embedded anywhere: builds bake **public** keys only (see `ccos-core`'s
//! `build.rs` keyring).

use serde::{Deserialize, Serialize};

use ccos_core::license::LicenseError;

use crate::b64url;

/// Current signed-license token format version (mirrors `ccos-core`).
pub const LICENSE_TOKEN_VERSION: u32 = 1;
/// Hard limit for a signed offline revocation list.
pub const MAX_REVOCATION_LIST_BYTES: usize = 1024 * 1024;
/// Current signed revocation-list payload version.
pub const REVOCATION_LIST_VERSION: u32 = 1;

const ED25519_ALGORITHM: &str = "ed25519";
const MAX_REVOCATION_ENTRIES: usize = 10_000;

/// Validate key/license/licensee identifiers (bounded, URL-safe).
fn validate_token_identity(
    kid: &str,
    license_id: &str,
    licensee: &str,
) -> Result<(), LicenseError> {
    let valid_id = |value: &str, max: usize| {
        !value.is_empty()
            && value.len() <= max
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    };
    if !valid_id(kid, 64) {
        return Err(LicenseError::Invalid("invalid key id".into()));
    }
    if !valid_id(license_id, 128) {
        return Err(LicenseError::Invalid("invalid license id".into()));
    }
    if licensee.trim().is_empty() || licensee.len() > 512 {
        return Err(LicenseError::Invalid("invalid licensee".into()));
    }
    Ok(())
}

/// sha256(lowercase hex) of raw bytes — token digests inside revocation lists.
pub fn token_sha256(blob: &[u8]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(blob);
    hex_lower(&h.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 15) as usize] as char);
    }
    out
}

// ── License token signing ─────────────────────────────────────────────────

/// Legacy (v0) payload: `base64url(payload).base64url(signature)`.
#[derive(Serialize)]
struct TokenPayload {
    licensee: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exp: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    machine: Option<String>,
}

/// Production (v1) payload, carried by the `ccoslic1.ed25519.kid.` envelope.
#[derive(Serialize)]
struct TokenPayloadV1 {
    version: u32,
    license_id: String,
    licensee: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exp: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    machine: Option<String>,
}

/// Sign a v0 license token with optional single-seat machine binding
/// (`ccos-core` verifies these byte-identically; see its `sign_token`).
#[cfg(feature = "license-verify")]
pub fn sign_token_bound(
    signing_seed: &[u8; 32],
    licensee: &str,
    exp: Option<u64>,
    machine: Option<&str>,
) -> String {
    use ed25519_dalek::{Signer, SigningKey};
    let payload = TokenPayload {
        licensee: licensee.to_string(),
        exp,
        machine: machine.map(str::to_string),
    };
    let json = serde_json::to_vec(&payload).expect("payload serialises");
    let signing_input = b64url::encode(&json);
    let sk = SigningKey::from_bytes(signing_seed);
    let sig = sk.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64url::encode(&sig.to_bytes()))
}

/// Sign a production-format v1 token with explicit version, algorithm and
/// key identifier (`ccoslic1.ed25519.<kid>.<payload>.<sig>`).
#[cfg(feature = "license-verify")]
pub fn sign_token_v1(
    signing_seed: &[u8; 32],
    kid: &str,
    license_id: &str,
    licensee: &str,
    exp: Option<u64>,
    machine: Option<&str>,
) -> Result<String, LicenseError> {
    use ed25519_dalek::{Signer, SigningKey};
    validate_token_identity(kid, license_id, licensee)?;
    let payload = TokenPayloadV1 {
        version: LICENSE_TOKEN_VERSION,
        license_id: license_id.to_string(),
        licensee: licensee.to_string(),
        exp,
        machine: machine.map(str::to_string),
    };
    let json = serde_json::to_vec(&payload)
        .map_err(|e| LicenseError::Invalid(format!("payload JSON: {e}")))?;
    let payload_b64 = b64url::encode(&json);
    let signing_input = format!("ccoslic1.{ED25519_ALGORITHM}.{kid}.{payload_b64}");
    let sig = SigningKey::from_bytes(signing_seed).sign(signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        b64url::encode(&sig.to_bytes())
    ))
}

// ── Offline revocation lists ──────────────────────────────────────────────

/// A reason code in a vendor-signed, offline revocation list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RevocationReason {
    Compromised,
    Superseded,
    Refunded,
    PolicyViolation,
    Administrative,
}

/// One signed revocation. At least one of `license_id` and `token_sha256`
/// must be present; validation rejects ambiguous duplicates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_sha256: Option<String>,
    pub revoked_at: u64,
    pub reason: RevocationReason,
}

/// Canonical JSON payload carried by a signed `ccosrev1` envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationList {
    pub version: u32,
    pub key_id: String,
    pub generated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub entries: Vec<RevocationEntry>,
}

impl RevocationList {
    /// Structural + temporal validation against the signed envelope's key id.
    #[cfg(feature = "license-verify")]
    pub fn validate(&self, envelope_kid: &str, now: u64) -> Result<(), LicenseError> {
        if self.version != REVOCATION_LIST_VERSION {
            return Err(LicenseError::Invalid(format!(
                "unsupported revocation-list version: {}",
                self.version
            )));
        }
        validate_token_identity(&self.key_id, "revocation-list", "revocation-list")?;
        if self.key_id != envelope_kid {
            return Err(LicenseError::Invalid(
                "revocation-list key id does not match signed envelope".into(),
            ));
        }
        if self.entries.len() > MAX_REVOCATION_ENTRIES {
            return Err(LicenseError::Invalid(
                "revocation list exceeds 10,000 entries".into(),
            ));
        }
        if self.generated_at > now {
            return Err(LicenseError::Invalid(
                "revocation list was generated in the future".into(),
            ));
        }
        if let Some(exp) = self.expires_at {
            if now > exp {
                return Err(LicenseError::Invalid("revocation list has expired".into()));
            }
        }
        let mut seen_license_ids = std::collections::BTreeSet::new();
        let mut seen_digests = std::collections::BTreeSet::new();
        for entry in &self.entries {
            if entry.license_id.is_none() && entry.token_sha256.is_none() {
                return Err(LicenseError::Invalid(
                    "revocation entry has no license id or token digest".into(),
                ));
            }
            if entry.revoked_at > now {
                return Err(LicenseError::Invalid(
                    "revocation entry timestamp is in the future".into(),
                ));
            }
            if let Some(id) = &entry.license_id {
                validate_token_identity(envelope_kid, id, "revocation")?;
                if !seen_license_ids.insert(id.clone()) {
                    return Err(LicenseError::Invalid(
                        "duplicate license id in revocation list".into(),
                    ));
                }
            }
            if let Some(digest) = &entry.token_sha256 {
                let hex_ok = digest.len() == 64
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
                if !hex_ok {
                    return Err(LicenseError::Invalid(
                        "revocation token digest is not lowercase SHA-256".into(),
                    ));
                }
                if !seen_digests.insert(digest.clone()) {
                    return Err(LicenseError::Invalid(
                        "duplicate token digest in revocation list".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Sign an offline revocation list (`ccosrev1.ed25519.<kid>.<payload>.<sig>`).
#[cfg(feature = "license-verify")]
pub fn sign_revocation_list_ed25519(
    signing_seed: &[u8; 32],
    list: &RevocationList,
) -> Result<String, LicenseError> {
    use ed25519_dalek::{Signer, SigningKey};
    list.validate(&list.key_id, list.generated_at)?;
    let json = serde_json::to_vec(list)
        .map_err(|e| LicenseError::Invalid(format!("revocation-list JSON: {e}")))?;
    let payload_b64 = b64url::encode(&json);
    let signing_input = format!("ccosrev1.{ED25519_ALGORITHM}.{}.{payload_b64}", list.key_id);
    let sig = SigningKey::from_bytes(signing_seed).sign(signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        b64url::encode(&sig.to_bytes())
    ))
}

/// Verify a signed revocation list against an explicit vendor public key
/// (admin/operator tooling; deployments bind their own baked key).
/// Fail-closed: the all-zero placeholder verifies nothing.
#[cfg(feature = "license-verify")]
pub fn verify_revocation_list_with(
    public_key: &[u8; 32],
    blob: &[u8],
    now: u64,
) -> Result<RevocationList, LicenseError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    if public_key == &[0u8; 32] {
        return Err(LicenseError::Invalid(
            "no vendor public key is set (placeholder) — cannot verify revocations".into(),
        ));
    }
    if blob.len() > MAX_REVOCATION_LIST_BYTES {
        return Err(LicenseError::Invalid(
            "revocation list exceeds 1 MiB limit".into(),
        ));
    }
    let text = std::str::from_utf8(blob)
        .map_err(|_| LicenseError::Invalid("revocation list is not UTF-8".into()))?
        .trim();
    let parts: Vec<&str> = text.split('.').collect();
    let [prefix, algorithm, kid, payload_b64, sig_b64] = parts.as_slice() else {
        return Err(LicenseError::Invalid(
            "revocation list is not ccosrev1.algorithm.kid.payload.signature".into(),
        ));
    };
    if *prefix != "ccosrev1" || *algorithm != ED25519_ALGORITHM {
        return Err(LicenseError::Invalid(format!(
            "unknown revocation-list algorithm: {algorithm}"
        )));
    }
    let key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| LicenseError::Invalid("bad revocation verification key".into()))?;
    let sig_bytes = b64url::decode(sig_b64)
        .filter(|bytes| bytes.len() == 64)
        .ok_or_else(|| LicenseError::Invalid("signature is not 64 bytes".into()))?;
    let sig_array: [u8; 64] = sig_bytes.try_into().expect("length checked");
    let input = format!("{prefix}.{algorithm}.{kid}.{payload_b64}");
    key.verify(input.as_bytes(), &Signature::from_bytes(&sig_array))
        .map_err(|_| LicenseError::Invalid("bad revocation-list signature".into()))?;
    let json = b64url::decode(payload_b64)
        .filter(|bytes| bytes.len() <= MAX_REVOCATION_LIST_BYTES)
        .ok_or_else(|| {
            LicenseError::Invalid("revocation payload is invalid or oversized".into())
        })?;
    let list: RevocationList = serde_json::from_slice(&json)
        .map_err(|e| LicenseError::Invalid(format!("revocation-list JSON: {e}")))?;
    list.validate(kid, now)?;
    Ok(list)
}

#[cfg(all(test, feature = "license-verify"))]
mod tests {
    use super::*;

    fn seed() -> [u8; 32] {
        [7u8; 32]
    }

    fn public_key() -> [u8; 32] {
        use ed25519_dalek::SigningKey;
        SigningKey::from_bytes(&seed()).verifying_key().to_bytes()
    }

    fn list(now: u64) -> RevocationList {
        RevocationList {
            version: REVOCATION_LIST_VERSION,
            key_id: "vendor-2026".into(),
            generated_at: now,
            expires_at: None,
            entries: vec![RevocationEntry {
                license_id: Some("lic-0001".into()),
                token_sha256: None,
                revoked_at: now,
                reason: RevocationReason::Compromised,
            }],
        }
    }

    #[test]
    fn v1_token_signs_and_parses() {
        let token = sign_token_v1(&seed(), "vendor-2026", "lic-0001", "acme", None, None).unwrap();
        assert!(token.starts_with("ccoslic1.ed25519.vendor-2026."));
        assert_eq!(token.split('.').count(), 5);
    }

    #[test]
    fn revocation_roundtrip_and_tamper() {
        let now = 1_000;
        let signed = sign_revocation_list_ed25519(&seed(), &list(now)).unwrap();
        let verified = verify_revocation_list_with(&public_key(), signed.as_bytes(), now).unwrap();
        assert_eq!(verified.entries.len(), 1);
        // tamper with the payload
        let mut parts: Vec<String> = signed.split('.').map(str::to_string).collect();
        let mut payload = b64url::decode(&parts[3]).unwrap();
        payload[3] ^= 0x01;
        parts[3] = b64url::encode(&payload);
        assert!(
            verify_revocation_list_with(&public_key(), parts.join(".").as_bytes(), now).is_err()
        );
        // the placeholder verifies nothing
        assert!(verify_revocation_list_with(&[0u8; 32], signed.as_bytes(), now).is_err());
    }

    #[test]
    fn validate_rejects_duplicates_and_future() {
        let now = 1_000;
        let mut l = list(now);
        l.entries.push(l.entries[0].clone());
        assert!(
            l.validate("vendor-2026", now).is_err(),
            "duplicate license id"
        );
        let mut f = list(now);
        f.generated_at = now + 1;
        assert!(f.validate("vendor-2026", now).is_err(), "future list");
    }
}
