//! Signed **release manifests** — the update-time half of the licensing story
//! (`docs/LICENSING_SERVER.md`, "Updates").
//!
//! A release is published as two static files (any web space serves them, the
//! same shared hosting as the claim counter works): the binary artifact and a
//! one-line signed manifest describing it. `ccos update` fetches the manifest,
//! verifies the signature **against the vendor key already baked into the
//! running binary** — the same trust root as licenses, no new key to manage —
//! and only then considers downloading anything. The signature covers version,
//! release date, artifact hash and URL, so a hijacked mirror can serve
//! nothing the vendor did not sign.
//!
//! Wire form: `ccos-release.<b64url(payload)>.<b64url(sig)>`, the signature
//! taken over the ASCII `ccos-release.<b64url(payload)>`. The scheme tag is
//! **bound into the signed message** (the same discipline as the `slhdsa.`
//! license tokens), so a license token can never be replayed as a manifest
//! nor a manifest as a token — one keypair, two cleanly separated domains.
//!
//! License enforcement at update time is the caller's (`ccos update`): a
//! `tier: "pro"` manifest requires an active license on this machine — the
//! annual, single-seat rule, enforced by [`ccos_core::license::Licensing::detect`]
//! like everywhere else, with the same announced refusals.

use serde::{Deserialize, Serialize};

#[cfg(feature = "license-verify")]
use ccos_core::license::LicenseError;

/// The scheme tag prefixing (and signed into) every release manifest.
pub const MANIFEST_TAG: &str = "ccos-release";

/// What a release manifest asserts, under the vendor's signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseManifest {
    /// The released version (`CARGO_PKG_VERSION` form, e.g. `0.5.0`).
    pub version: String,
    /// Unix seconds of publication (informational; the annual license model
    /// gates on token validity *now*, not on release windows).
    pub released_unix: u64,
    /// SHA-256 (lowercase hex) of the binary artifact — verified after
    /// download, before anything is installed.
    pub sha256: String,
    /// Where the artifact lives.
    pub url: String,
    /// `"pro"` (requires an active license at update time) or `"community"`.
    pub tier: String,
}

/// Sign a manifest with the vendor's ed25519 seed (the same seed that signs
/// license tokens — one trust root). Emits the one-line wire form.
#[cfg(feature = "license-verify")]
pub fn sign_manifest(signing_seed: &[u8; 32], manifest: &ReleaseManifest) -> String {
    use ed25519_dalek::{Signer, SigningKey};
    let json = serde_json::to_vec(manifest).expect("manifest serialises");
    let signing_input = format!("{MANIFEST_TAG}.{}", crate::b64url::encode(&json));
    let sk = SigningKey::from_bytes(signing_seed);
    let sig = sk.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", crate::b64url::encode(&sig.to_bytes()))
}

/// Verify a manifest line against an explicit public key (the tests' path;
/// [`verify_manifest`] binds the baked-in vendor key). Pure: signature +
/// format only, no clock, no I/O.
#[cfg(feature = "license-verify")]
pub fn verify_manifest_with(
    public_key: &[u8; 32],
    text: &str,
) -> Result<ReleaseManifest, LicenseError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| LicenseError::Invalid("bad manifest verification key".into()))?;
    if public_key == &[0u8; 32] {
        // The unset placeholder verifies nothing — fail closed, like licenses.
        return Err(LicenseError::Invalid(
            "no vendor public key is set (placeholder) — cannot verify releases".into(),
        ));
    }
    let text = text.trim();
    let rest = text
        .strip_prefix(&format!("{MANIFEST_TAG}."))
        .ok_or_else(|| {
            LicenseError::Invalid(format!(
                "not a release manifest (expected `{MANIFEST_TAG}.…`)"
            ))
        })?;
    let (payload_b64, sig_b64) = rest
        .split_once('.')
        .ok_or_else(|| LicenseError::Invalid("manifest is not tag.payload.signature".into()))?;
    let sig_bytes = crate::b64url::decode(sig_b64)
        .filter(|s| s.len() == 64)
        .ok_or_else(|| LicenseError::Invalid("signature is not 64 base64url bytes".into()))?;
    let sig_array: [u8; 64] = sig_bytes.try_into().expect("length checked");
    let signing_input = format!("{MANIFEST_TAG}.{payload_b64}");
    key.verify(signing_input.as_bytes(), &Signature::from_bytes(&sig_array))
        .map_err(|_| LicenseError::Invalid("bad manifest signature".into()))?;
    let json = crate::b64url::decode(payload_b64)
        .ok_or_else(|| LicenseError::Invalid("payload is not base64url".into()))?;
    let manifest: ReleaseManifest = serde_json::from_slice(&json)
        .map_err(|e| LicenseError::Invalid(format!("manifest JSON: {e}")))?;
    if !crate::claim::is_sha256_hex(&manifest.sha256) {
        return Err(LicenseError::Invalid(
            "manifest sha256 is not lowercase 64-hex".into(),
        ));
    }
    Ok(manifest)
}

/// Verify a manifest line against the **baked-in vendor key**
/// ([`crate::VENDOR_PUBLIC_KEY`]) — what `ccos update` trusts.
#[cfg(feature = "license-verify")]
pub fn verify_manifest(text: &str) -> Result<ReleaseManifest, LicenseError> {
    verify_manifest_with(&crate::VENDOR_PUBLIC_KEY, text)
}

/// Compare two dotted versions numerically (`0.10.0` > `0.9.9`; a missing
/// segment reads as 0; non-numeric segments compare as 0 — good enough for
/// the `CARGO_PKG_VERSION` shapes we publish). Returns the usual ordering.
pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let parse = |v: &str| -> Vec<u64> {
        v.trim()
            .split('.')
            .map(|s| {
                s.chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .parse()
                    .unwrap_or(0)
            })
            .collect()
    };
    let (a, b) = (parse(a), parse(b));
    let n = a.len().max(b.len());
    for i in 0..n {
        let (x, y) = (a.get(i).unwrap_or(&0), b.get(i).unwrap_or(&0));
        match x.cmp(y) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[test]
    fn versions_compare_numerically() {
        assert_eq!(compare_versions("0.4.0", "0.5.0"), Ordering::Less);
        assert_eq!(compare_versions("0.10.0", "0.9.9"), Ordering::Greater);
        assert_eq!(compare_versions("1.0", "1.0.0"), Ordering::Equal);
        assert_eq!(compare_versions("1.0.1", "1.0"), Ordering::Greater);
    }

    #[cfg(feature = "license-verify")]
    mod signed {
        use super::super::*;
        const SEED: [u8; 32] = [7u8; 32];

        fn pk() -> [u8; 32] {
            use ed25519_dalek::SigningKey;
            SigningKey::from_bytes(&SEED).verifying_key().to_bytes()
        }

        fn manifest() -> ReleaseManifest {
            ReleaseManifest {
                version: "0.5.0".into(),
                released_unix: 1_234_567_890,
                sha256: "a".repeat(64),
                url: "https://releases.example/ccos-0.5.0".into(),
                tier: "pro".into(),
            }
        }

        #[test]
        fn manifest_round_trips_and_rejects_tampering() {
            let line = sign_manifest(&SEED, &manifest());
            assert!(line.starts_with("ccos-release."));
            let back = verify_manifest_with(&pk(), &line).expect("verifies");
            assert_eq!(back, manifest());
            // Whitespace from a fetched file is tolerated.
            assert!(verify_manifest_with(&pk(), &format!("{line}\n")).is_ok());

            // Any byte of the (base64url) payload breaks the signature: flip
            // one symbol in the middle segment.
            let mut parts: Vec<String> = line.split('.').map(str::to_string).collect();
            let flipped: String = parts[1]
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if i == 4 {
                        if c == 'A' {
                            'B'
                        } else {
                            'A'
                        }
                    } else {
                        c
                    }
                })
                .collect();
            assert_ne!(parts[1], flipped, "the tamper must actually change bytes");
            parts[1] = flipped;
            assert!(verify_manifest_with(&pk(), &parts.join(".")).is_err());
            // A different key verifies nothing.
            assert!(verify_manifest_with(&[9u8; 32], &line).is_err());
            // The all-zero placeholder fails closed.
            assert!(verify_manifest_with(&[0u8; 32], &line).is_err());
        }

        #[test]
        fn scheme_domains_are_separated() {
            // A license token must not verify as a manifest…
            let token = ccos_core::license::sign_token(&SEED, "acme", None);
            assert!(verify_manifest_with(&pk(), &token).is_err());
            // …and a manifest must not verify as a license token: the license
            // verifier signs over the FIRST segment only, but our signing input
            // includes the tag, so the signature cannot transfer.
            let line = sign_manifest(&SEED, &manifest());
            let as_token = line.strip_prefix("ccos-release.").unwrap();
            use ccos_core::license::{Ed25519Verifier, LicenseVerifier};
            let v = Ed25519Verifier::with_public_key(&pk());
            assert!(v.verify(as_token.as_bytes(), 0).is_err());
        }
    }
}
