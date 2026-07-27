//! # CCOS Enterprise — Governance
//!
//! License-claim protocol and signed release-manifest verification for
//! CCOS Enterprise, built on top of `ccos-core` (never a copy of it).
//!
//! - [`claim`] — the shared half of the one-time license claim protocol
//!   (imported from CCOS_EXTENDED `src/claim.rs`, commit `70d1004`; B1).
//! - [`release`] — signed release-manifest **verification** (imported from
//!   CCOS_EXTENDED `src/release.rs`, commit `8b762ea`; B1). The self-update
//!   *executor* is deliberately NOT part of this crate (charter decision D4):
//!   verification primitives only — what an operator does with a verified
//!   manifest is a deployment concern, never library behaviour.

pub mod claim;
#[cfg(feature = "license-verify")]
pub mod release;
#[cfg(feature = "license-verify")]
pub mod vendor;

/// The baked-in vendor verification key for release manifests.
///
/// Placeholder (all-zero) verifies **nothing** — fail-closed, mirroring the
/// `ccos-core` license key posture. A deployment bakes its own key through
/// its build pipeline; the zero default can never mint trust.
#[cfg(feature = "license-verify")]
pub const VENDOR_PUBLIC_KEY: [u8; 32] = [0u8; 32];

/// Base64url (no padding) helpers — local copy, because `ccos-core`'s are
/// crate-private. Alphabet and semantics identical to the license token
/// format so wire formats stay compatible.
#[cfg(feature = "license-verify")]
pub mod b64url {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// Encode bytes as base64url without padding.
    pub fn encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(ALPHABET[(n >> 18) as usize & 63] as char);
            out.push(ALPHABET[(n >> 12) as usize & 63] as char);
            if chunk.len() > 1 {
                out.push(ALPHABET[(n >> 6) as usize & 63] as char);
            }
            if chunk.len() > 2 {
                out.push(ALPHABET[n as usize & 63] as char);
            }
        }
        out
    }

    /// Inverse of [`encode`]. `None` on any non-alphabet byte or truncated group.
    pub fn decode(s: &str) -> Option<Vec<u8>> {
        fn val(b: u8) -> Option<u32> {
            match b {
                b'A'..=b'Z' => Some((b - b'A') as u32),
                b'a'..=b'z' => Some((b - b'a' + 26) as u32),
                b'0'..=b'9' => Some((b - b'0' + 52) as u32),
                b'-' => Some(62),
                b'_' => Some(63),
                _ => None,
            }
        }
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
        for chunk in bytes.chunks(4) {
            if chunk.len() == 1 {
                return None; // a lone 6-bit group cannot carry a byte
            }
            let mut n: u32 = 0;
            for (i, &c) in chunk.iter().enumerate() {
                n |= val(c)? << (18 - 6 * i);
            }
            out.push((n >> 16) as u8);
            if chunk.len() > 2 {
                out.push((n >> 8) as u8);
            }
            if chunk.len() > 3 {
                out.push(n as u8);
            }
        }
        Some(out)
    }
}

#[cfg(all(test, feature = "license-verify"))]
mod b64url_tests {
    use super::b64url;

    #[test]
    fn roundtrip() {
        for case in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            assert_eq!(b64url::decode(&b64url::encode(case)).as_deref(), Some(case));
        }
    }

    #[test]
    fn rejects_bad_alphabet_and_truncation() {
        assert!(b64url::decode("a+b/").is_none());
        assert!(b64url::decode("a").is_none());
    }
}
