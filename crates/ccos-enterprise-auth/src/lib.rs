//! # CCOS Enterprise — Authentication
//!
//! Agent/user identity: the types the admission path keys on, and the
//! mechanism that produces them.
//!
//! ## What this crate is for
//!
//! `ccos_enterprise_runtime::Deployment::admit` runs nine gates, and the first
//! four of them — strength, actor binding, organization ownership, RBAC — key
//! on an [`AuthenticatedActor`]. Everything downstream inherits that identity:
//! which tenant may be addressed, which permissions apply, whose budget is
//! charged, and whose name lands in the audit journal.
//!
//! Until this crate had a verifier, that type was a struct with three public
//! fields. **Anyone could construct one**, at any strength, for any
//! organization — so the gates were checking an assertion nobody had proved,
//! and the security model was a shape rather than a mechanism. A caller who
//! could reach `admit` at all could reach it as anyone.
//!
//! Two things close that:
//!
//! * an [`AuthenticatedActor`]'s fields are **private**, and the only way to
//!   obtain one is [`Authenticator::authenticate`] (or an explicitly-named
//!   test constructor behind a non-default feature, which production builds
//!   cannot compile);
//! * [`TokenAuthenticator`] verifies an ed25519-signed, audience-bound,
//!   expiring identity token before it will produce one.
//!
//! ## What the token deliberately does not carry
//!
//! **Strength.** [`AuthStrength`] is a property of the *mechanism*, declared
//! by the verifier that used it, never a field of the payload. A bearer token
//! that could name its own strength could name `Strong`, and
//! `require_strength(Strong)` — the deployment's way of demanding hardware or
//! mTLS proof for administrative surfaces — would be satisfiable by anyone
//! holding any signed token. The escalation is refused by construction rather
//! than by a check that could be forgotten.
//!
//! ## What is still absent, and named so it is not mistaken for present
//!
//! * **mTLS and OIDC.** [`Authenticator`] is the seam they land on: an mTLS
//!   terminator would attest [`AuthStrength::Strong`] from a verified peer
//!   certificate, an OIDC verifier would attest [`AuthStrength::Token`] from a
//!   JWKS-validated JWT. Neither exists yet, and no default authenticator is
//!   installed anywhere — a deployment that configures none can authenticate
//!   nobody, which is the correct failure.
//! * **Revocation.** A token is valid until it expires; there is no
//!   deny-list check. `ccos_enterprise_governance::vendor` has the shape of
//!   one for licenses, and identity tokens should reuse it. Until then the
//!   only revocation is key rotation ([`TokenAuthenticator::remove_issuer`])
//!   and short lifetimes, which is why [`MAX_TOKEN_LIFETIME_SECS`] is a
//!   ceiling the verifier enforces rather than advice.
//! * **Replay.** Nothing binds a token to one use. The runtime suppresses
//!   replayed *requests* by `request_id`, which is a different property.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A verified actor identity (user, agent, or service) inside an
/// organization. Opaque string, never an email, never a token.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActorId(pub String);

/// An organization boundary — the outermost administrative scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OrgId(pub String);

/// Proof strength attached to an authenticated actor.
///
/// Ordered, and the ordering is load-bearing: `Deployment::require_strength`
/// compares against it, so a mechanism that over-declares its own strength
/// defeats every stronger requirement in the product at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuthStrength {
    /// Identity asserted but not cryptographically verified.
    Anonymous,
    /// Shared-secret or token verified.
    Token,
    /// Strong proof (mTLS, hardware-backed key).
    Strong,
}

/// The envelope prefix of a CCOS Enterprise identity token.
///
/// Distinct from `ccoslic1` (license tokens) on purpose: both are ed25519 over
/// a base64url payload, so without a distinct prefix inside the **signed**
/// input a license token would verify as an identity token under the same
/// issuer key. The prefix is part of what is signed, not decoration.
pub const IDENTITY_TOKEN_PREFIX: &str = "ccosid1";

/// The only signature algorithm this build accepts.
pub const IDENTITY_TOKEN_ALGORITHM: &str = "ed25519";

/// The payload version this build accepts.
pub const IDENTITY_TOKEN_VERSION: u32 = 1;

/// Longest identity token accepted, in bytes. A verifier must be able to
/// refuse a megabyte of attacker-supplied text without decoding it.
pub const MAX_TOKEN_BYTES: usize = 4_096;

/// Longest lifetime an identity token may grant itself.
///
/// There is no revocation list for identity tokens yet, so lifetime *is* the
/// revocation window: a stolen token is valid until it expires. Twelve hours
/// is short enough that key rotation is a real remedy and long enough that a
/// working session does not re-authenticate mid-task. A token asking for more
/// is refused rather than clamped — clamping would hand back a credential the
/// issuer did not mean to grant, and silently.
pub const MAX_TOKEN_LIFETIME_SECS: u64 = 12 * 60 * 60;

/// Longest an org or actor identifier may be.
pub const MAX_IDENTITY_BYTES: usize = 128;

/// An authenticated actor in an organization.
///
/// **Unforgeable by construction.** The fields are private and the only
/// constructors are [`Authenticator::authenticate`] and, behind the
/// non-default `test-identities` feature, [`AuthenticatedActor::asserted`].
/// A production build cannot compile the second, so a production build cannot
/// mint an identity without verifying one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedActor {
    org: OrgId,
    actor: ActorId,
    strength: AuthStrength,
}

impl AuthenticatedActor {
    /// The organization the credential proves. Compared against the tenant's
    /// owner at gate 3.
    pub fn org(&self) -> &OrgId {
        &self.org
    }

    /// The actor the credential proves. Compared against the request's copy of
    /// it at gate 3, and the key RBAC uses at gate 5 — never the request's.
    pub fn actor(&self) -> &ActorId {
        &self.actor
    }

    /// What the mechanism that produced this identity was able to attest.
    pub fn strength(&self) -> AuthStrength {
        self.strength
    }

    /// Whether the actor may be considered for sensitive operations
    /// (license administration, tenant policy changes).
    pub fn is_strongly_authenticated(&self) -> bool {
        self.strength == AuthStrength::Strong
    }

    /// Assert an identity **without proving it**. Test scaffolding only.
    ///
    /// Behind a non-default feature because a public constructor is exactly
    /// the hole this type exists to close: naming it `asserted` rather than
    /// `new` says what it is, but a name is not a boundary and a feature flag
    /// is. The conformance suite enables it to drive the gates without
    /// standing up an issuer; nothing that ships does.
    #[cfg(feature = "test-identities")]
    pub fn asserted(org: &str, actor: &str, strength: AuthStrength) -> Self {
        Self {
            org: OrgId(org.to_string()),
            actor: ActorId(actor.to_string()),
            strength,
        }
    }
}

/// Why a credential was refused.
///
/// Every variant is an announced refusal. The *caller* is told nothing beyond
/// "not authenticated" — see [`AuthError::client_message`] — because the
/// distinctions below are exactly what an attacker probes for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// Not a well-formed token envelope (wrong prefix, algorithm, part count,
    /// or over [`MAX_TOKEN_BYTES`]).
    Malformed(String),
    /// The envelope names a key id this verifier does not hold.
    UnknownIssuer,
    /// The signature does not verify under the named issuer's key.
    BadSignature,
    /// The payload is not the claims this build understands.
    MalformedClaims(String),
    /// The token was issued for a different deployment.
    WrongAudience,
    /// `expires_at` is in the past (allowing for leeway).
    Expired,
    /// `not_before` is in the future (allowing for leeway).
    NotYetValid,
    /// The token grants itself more than [`MAX_TOKEN_LIFETIME_SECS`].
    LifetimeTooLong,
    /// The org or actor identifier is empty, oversized, or not canonical.
    MalformedIdentity(String),
}

impl AuthError {
    /// What a caller is told. One string for every cause.
    ///
    /// The distinctions this enum draws are an operator's diagnostic, not a
    /// client's: told apart, "unknown issuer" and "bad signature" reveal which
    /// key ids exist, and "expired" versus "wrong audience" reveals that a
    /// stolen token was otherwise valid. The detail belongs in the server's
    /// log, under the connection that presented it.
    pub fn client_message(&self) -> &'static str {
        "not authenticated"
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "malformed identity token: {why}"),
            Self::UnknownIssuer => {
                write!(f, "identity token names an issuer this build does not hold")
            }
            Self::BadSignature => write!(f, "identity token signature does not verify"),
            Self::MalformedClaims(why) => write!(f, "malformed identity claims: {why}"),
            Self::WrongAudience => {
                write!(f, "identity token was issued for a different deployment")
            }
            Self::Expired => write!(f, "identity token has expired"),
            Self::NotYetValid => write!(f, "identity token is not valid yet"),
            Self::LifetimeTooLong => write!(
                f,
                "identity token grants itself more than {MAX_TOKEN_LIFETIME_SECS}s"
            ),
            Self::MalformedIdentity(why) => write!(f, "malformed identity: {why}"),
        }
    }
}

impl std::error::Error for AuthError {}

/// Turn a presented credential into a proved identity, or refuse it.
///
/// This is the seam every mechanism lands on. An implementation must attest
/// **only what its mechanism actually proves**: an OIDC bearer token is
/// [`AuthStrength::Token`] however the issuer describes itself, and only a
/// verified peer certificate or a hardware-backed key is
/// [`AuthStrength::Strong`].
pub trait Authenticator {
    /// `presented` is the raw credential as it arrived (an `Authorization`
    /// header value with the scheme stripped, a token from an MCP handshake).
    /// `now` is unix seconds.
    fn authenticate(&self, presented: &str, now: u64) -> Result<AuthenticatedActor, AuthError>;
}

/// The claims an identity token carries.
///
/// `deny_unknown_fields` for the reason the vault learned the hard way: a
/// field name this build does not know is a refusal, not a shrug. A claim the
/// issuer meant as a restriction — a tenant scope, a permission ceiling —
/// must never be dropped silently by a build that does not implement it yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityClaims {
    pub version: u32,
    /// The organization the bearer acts for.
    pub org: String,
    /// The actor the bearer acts as.
    pub actor: String,
    /// Which deployment this token may be presented to. A token for one
    /// deployment replayed at another is refused: without it, a compromised
    /// staging issuer is a production credential.
    pub audience: String,
    pub issued_at: u64,
    /// Required. There is no perpetual identity, and no default — the vault's
    /// `days` taught that an absent field is the most expensive default there
    /// is.
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<u64>,
}

/// Whether an org or actor identifier is one this product will carry.
///
/// Dot-free, dash-and-underscore ASCII with an alphanumeric first byte — the
/// same rule `ccos_enterprise_runtime::is_canonical_identifier` applies to
/// tenants, restated here because auth is the lower crate and a dependency
/// cycle is not worth the reuse. A homoglyph or a leading `-` in an identity
/// is worse than in a tenant id: it is compared against a tenant's owner and
/// used as an RBAC key.
pub fn is_canonical_identity(id: &str) -> bool {
    let mut bytes = id.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return false;
    }
    id.len() <= MAX_IDENTITY_BYTES
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// Verifies ed25519-signed identity tokens against a set of issuer keys.
///
/// Envelope: `ccosid1.ed25519.<kid>.<payload_b64url>.<sig_b64url>`, where the
/// signature covers `ccosid1.ed25519.<kid>.<payload_b64url>` — prefix,
/// algorithm and key id included, so none of them can be swapped without
/// breaking the signature.
#[cfg(feature = "token-auth")]
pub struct TokenAuthenticator {
    issuers: BTreeMap<String, ed25519_dalek::VerifyingKey>,
    audience: String,
    attests: AuthStrength,
    leeway_secs: u64,
}

#[cfg(feature = "token-auth")]
impl TokenAuthenticator {
    /// A verifier for one deployment, holding no issuer keys yet.
    ///
    /// It authenticates nobody until an issuer is added, which is the correct
    /// state for a deployment that has not been configured: an authenticator
    /// that trusted a default key would be worse than none.
    ///
    /// `attests` is what this verifier is allowed to claim it proved. A bearer
    /// token is [`AuthStrength::Token`]; passing [`AuthStrength::Strong`] here
    /// is how an operator would defeat their own `require_strength`, so the
    /// parameter is deliberately explicit rather than defaulted.
    pub fn new(audience: &str, attests: AuthStrength) -> Self {
        Self {
            issuers: BTreeMap::new(),
            audience: audience.to_string(),
            attests,
            leeway_secs: 60,
        }
    }

    /// Tolerance for clock skew between issuer and verifier, in seconds.
    /// Applied to both `expires_at` and `not_before`.
    pub fn with_leeway(mut self, secs: u64) -> Self {
        self.leeway_secs = secs;
        self
    }

    /// Trust an issuer's public key under `kid`. Returns `false` — trusting
    /// nothing — for a key id that is not canonical, so a key cannot be
    /// registered under a name the envelope parser would reject.
    pub fn add_issuer(&mut self, kid: &str, key: ed25519_dalek::VerifyingKey) -> bool {
        if !is_canonical_identity(kid) {
            return false;
        }
        self.issuers.insert(kid.to_string(), key);
        true
    }

    /// Stop trusting an issuer. Returns whether it was trusted.
    ///
    /// This is the product's only revocation for identity tokens today, which
    /// is why it exists as an operation rather than as a restart: rotating a
    /// compromised issuer must not require taking the deployment down.
    pub fn remove_issuer(&mut self, kid: &str) -> bool {
        self.issuers.remove(kid).is_some()
    }

    /// How many issuers this verifier trusts.
    pub fn issuer_count(&self) -> usize {
        self.issuers.len()
    }
}

#[cfg(feature = "token-auth")]
impl Authenticator for TokenAuthenticator {
    fn authenticate(&self, presented: &str, now: u64) -> Result<AuthenticatedActor, AuthError> {
        use ed25519_dalek::{Signature, Verifier};

        // Cheapest first, and before anything decodes: a caller-sized string
        // must not buy a caller-sized allocation.
        if presented.len() > MAX_TOKEN_BYTES {
            return Err(AuthError::Malformed("over the size bound".into()));
        }

        let parts: Vec<&str> = presented.split('.').collect();
        if parts.len() != 5 {
            return Err(AuthError::Malformed(format!(
                "expected 5 dot-separated parts, found {}",
                parts.len()
            )));
        }
        if parts[0] != IDENTITY_TOKEN_PREFIX {
            return Err(AuthError::Malformed("not an identity token".into()));
        }
        if parts[1] != IDENTITY_TOKEN_ALGORITHM {
            // Named rather than negotiated: "alg" confusion is the classic JWT
            // wound, and the only cure is a build that accepts one algorithm.
            return Err(AuthError::Malformed("unsupported algorithm".into()));
        }
        let kid = parts[2];
        let payload_b64 = parts[3];
        let sig_b64 = parts[4];

        let Some(key) = self.issuers.get(kid) else {
            return Err(AuthError::UnknownIssuer);
        };

        let Some(sig_bytes) = ccos_enterprise_governance::b64url::decode(sig_b64) else {
            return Err(AuthError::Malformed(
                "signature is not canonical base64url".into(),
            ));
        };
        let sig_bytes: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| AuthError::Malformed("signature is not 64 bytes".into()))?;

        // The signature covers prefix, algorithm and key id as well as the
        // payload, so none of them can be swapped without breaking it.
        let signing_input =
            format!("{IDENTITY_TOKEN_PREFIX}.{IDENTITY_TOKEN_ALGORITHM}.{kid}.{payload_b64}");
        key.verify(signing_input.as_bytes(), &Signature::from_bytes(&sig_bytes))
            .map_err(|_| AuthError::BadSignature)?;

        // Only now. Parsing attacker-controlled JSON before the signature
        // verifies would hand the parser to anyone who can open a connection.
        let Some(payload) = ccos_enterprise_governance::b64url::decode(payload_b64) else {
            return Err(AuthError::Malformed(
                "payload is not canonical base64url".into(),
            ));
        };
        let claims: IdentityClaims = serde_json::from_slice(&payload)
            .map_err(|e| AuthError::MalformedClaims(e.to_string()))?;

        if claims.version != IDENTITY_TOKEN_VERSION {
            return Err(AuthError::MalformedClaims(format!(
                "unsupported claims version {}",
                claims.version
            )));
        }
        if claims.audience != self.audience {
            return Err(AuthError::WrongAudience);
        }
        if !is_canonical_identity(&claims.org) {
            return Err(AuthError::MalformedIdentity(format!(
                "org {:?}",
                claims.org
            )));
        }
        if !is_canonical_identity(&claims.actor) {
            return Err(AuthError::MalformedIdentity(format!(
                "actor {:?}",
                claims.actor
            )));
        }
        if claims.expires_at <= claims.issued_at {
            return Err(AuthError::MalformedClaims(
                "expires_at is not after issued_at".into(),
            ));
        }
        if claims.expires_at - claims.issued_at > MAX_TOKEN_LIFETIME_SECS {
            return Err(AuthError::LifetimeTooLong);
        }
        if now > claims.expires_at.saturating_add(self.leeway_secs) {
            return Err(AuthError::Expired);
        }
        if let Some(nbf) = claims.not_before {
            if now.saturating_add(self.leeway_secs) < nbf {
                return Err(AuthError::NotYetValid);
            }
        }

        Ok(AuthenticatedActor {
            org: OrgId(claims.org),
            actor: ActorId(claims.actor),
            // The verifier's, never the payload's.
            strength: self.attests,
        })
    }
}

/// Mint an identity token. **Issuer-side**, and behind the same feature as the
/// verifier so a build that cannot verify cannot sign either.
///
/// Present in the product because a verifier nothing can produce input for is
/// untestable, and because the deployment that issues identities is part of
/// the deployment that governs them.
#[cfg(feature = "token-auth")]
pub fn issue_identity_token(
    signing_seed: &[u8; 32],
    kid: &str,
    claims: &IdentityClaims,
) -> Result<String, AuthError> {
    use ed25519_dalek::{Signer, SigningKey};

    if !is_canonical_identity(kid) {
        return Err(AuthError::MalformedIdentity(format!("key id {kid:?}")));
    }
    if !is_canonical_identity(&claims.org) || !is_canonical_identity(&claims.actor) {
        return Err(AuthError::MalformedIdentity(
            "org and actor must be canonical".into(),
        ));
    }
    if claims.expires_at <= claims.issued_at {
        return Err(AuthError::MalformedClaims(
            "expires_at is not after issued_at".into(),
        ));
    }
    if claims.expires_at - claims.issued_at > MAX_TOKEN_LIFETIME_SECS {
        return Err(AuthError::LifetimeTooLong);
    }
    let json = serde_json::to_vec(claims)
        .map_err(|e| AuthError::MalformedClaims(format!("claims JSON: {e}")))?;
    let payload_b64 = ccos_enterprise_governance::b64url::encode(&json);
    let signing_input =
        format!("{IDENTITY_TOKEN_PREFIX}.{IDENTITY_TOKEN_ALGORITHM}.{kid}.{payload_b64}");
    let sig = SigningKey::from_bytes(signing_seed).sign(signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        ccos_enterprise_governance::b64url::encode(&sig.to_bytes())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strength_ordering() {
        assert!(AuthStrength::Strong > AuthStrength::Token);
        assert!(AuthStrength::Token > AuthStrength::Anonymous);
    }

    #[test]
    fn canonical_identities() {
        for good in ["acme", "agent-7", "a", "svc_ingest", "t0"] {
            assert!(is_canonical_identity(good), "{good:?} refused");
        }
        for bad in [
            "",
            "-rf",
            "_leading",
            "Acme",
            "acme corp",
            "acme.corp",
            "\u{0430}cme",
            "acme\u{202e}",
            &"a".repeat(MAX_IDENTITY_BYTES + 1),
        ] {
            assert!(!is_canonical_identity(bad), "{bad:?} admitted");
        }
        assert!(is_canonical_identity(&"a".repeat(MAX_IDENTITY_BYTES)));
    }

    #[test]
    fn every_refusal_tells_the_client_the_same_thing() {
        // The distinctions are the operator's; a caller learns only that it
        // failed. Told apart, they reveal which key ids exist and whether a
        // stolen token was otherwise valid.
        for e in [
            AuthError::Malformed("x".into()),
            AuthError::UnknownIssuer,
            AuthError::BadSignature,
            AuthError::MalformedClaims("x".into()),
            AuthError::WrongAudience,
            AuthError::Expired,
            AuthError::NotYetValid,
            AuthError::LifetimeTooLong,
            AuthError::MalformedIdentity("x".into()),
        ] {
            assert_eq!(e.client_message(), "not authenticated");
            // …while the operator-facing rendering does distinguish them.
            assert!(!e.to_string().is_empty());
        }
    }
}

/// The verifier under attack. Every test here is a way somebody gets to be
/// somebody else, and each asserts the specific refusal rather than "an error"
/// — a test that accepts any `Err` passes just as happily when the token is
/// rejected for the wrong reason, and stops noticing when a check disappears.
#[cfg(all(test, feature = "token-auth"))]
mod verifier_tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    const NOW: u64 = 1_700_000_000;
    const AUD: &str = "prod-eu";

    fn seed(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn verifier(kid: &str, s: &[u8; 32], attests: AuthStrength) -> TokenAuthenticator {
        let mut v = TokenAuthenticator::new(AUD, attests);
        assert!(v.add_issuer(kid, SigningKey::from_bytes(s).verifying_key()));
        v
    }

    fn claims(org: &str, actor: &str, aud: &str) -> IdentityClaims {
        IdentityClaims {
            version: IDENTITY_TOKEN_VERSION,
            org: org.into(),
            actor: actor.into(),
            audience: aud.into(),
            issued_at: NOW - 10,
            expires_at: NOW + 600,
            not_before: None,
        }
    }

    fn good_token() -> String {
        issue_identity_token(&seed(1), "issuer-a", &claims("acme", "agent-7", AUD)).unwrap()
    }

    #[test]
    fn a_signed_token_authenticates_the_actor_it_names() {
        let who = verifier("issuer-a", &seed(1), AuthStrength::Token)
            .authenticate(&good_token(), NOW)
            .expect("valid token refused");
        assert_eq!(who.org().0, "acme");
        assert_eq!(who.actor().0, "agent-7");
        assert_eq!(who.strength(), AuthStrength::Token);
    }

    #[test]
    fn strength_is_the_verifiers_claim_and_the_token_cannot_raise_it() {
        // The same bytes, presented to two deployments, are worth what each
        // deployment's *mechanism* attests — nothing the bearer controls. If
        // strength ever became a claim, `require_strength(Strong)` on the
        // administrative surfaces would be satisfiable by anyone holding any
        // signed token.
        let token = good_token();
        let weak = verifier("issuer-a", &seed(1), AuthStrength::Token)
            .authenticate(&token, NOW)
            .unwrap();
        let strong = verifier("issuer-a", &seed(1), AuthStrength::Strong)
            .authenticate(&token, NOW)
            .unwrap();
        assert_eq!(weak.strength(), AuthStrength::Token);
        assert_eq!(strong.strength(), AuthStrength::Strong);
        assert!(!weak.is_strongly_authenticated());

        // …and the claims type has nowhere to put one: a token that tries is
        // refused by `deny_unknown_fields` rather than silently ignored.
        let mut json: serde_json::Value =
            serde_json::to_value(claims("acme", "agent-7", AUD)).unwrap();
        json["strength"] = serde_json::json!("Strong");
        let payload = ccos_enterprise_governance::b64url::encode(
            serde_json::to_string(&json).unwrap().as_bytes(),
        );
        let input =
            format!("{IDENTITY_TOKEN_PREFIX}.{IDENTITY_TOKEN_ALGORITHM}.issuer-a.{payload}");
        let sig = ed25519_dalek::Signer::sign(&SigningKey::from_bytes(&seed(1)), input.as_bytes());
        let forged = format!(
            "{input}.{}",
            ccos_enterprise_governance::b64url::encode(&sig.to_bytes())
        );
        assert!(matches!(
            verifier("issuer-a", &seed(1), AuthStrength::Token).authenticate(&forged, NOW),
            Err(AuthError::MalformedClaims(_))
        ));
    }

    #[test]
    fn a_tampered_payload_breaks_the_signature() {
        let token = good_token();
        let mut parts: Vec<&str> = token.split('.').collect();
        let swapped = ccos_enterprise_governance::b64url::encode(
            serde_json::to_string(&claims("globex", "admin", AUD))
                .unwrap()
                .as_bytes(),
        );
        parts[3] = &swapped;
        assert_eq!(
            verifier("issuer-a", &seed(1), AuthStrength::Token).authenticate(&parts.join("."), NOW),
            Err(AuthError::BadSignature)
        );
    }

    #[test]
    fn the_key_id_is_covered_by_the_signature() {
        // Two trusted issuers. A token signed by A, relabelled as B, must not
        // verify — otherwise the weakest issuer's key compromises every
        // identity the deployment trusts.
        let mut v = TokenAuthenticator::new(AUD, AuthStrength::Token);
        v.add_issuer("issuer-a", SigningKey::from_bytes(&seed(1)).verifying_key());
        v.add_issuer("issuer-b", SigningKey::from_bytes(&seed(2)).verifying_key());
        let token = good_token();
        let relabelled = token.replacen("issuer-a", "issuer-b", 1);
        assert_eq!(
            v.authenticate(&relabelled, NOW),
            Err(AuthError::BadSignature)
        );
    }

    #[test]
    fn another_keys_signature_is_not_this_issuers() {
        let token =
            issue_identity_token(&seed(9), "issuer-a", &claims("acme", "agent-7", AUD)).unwrap();
        assert_eq!(
            verifier("issuer-a", &seed(1), AuthStrength::Token).authenticate(&token, NOW),
            Err(AuthError::BadSignature)
        );
    }

    #[test]
    fn an_untrusted_issuer_is_refused_before_any_crypto() {
        assert_eq!(
            verifier("issuer-b", &seed(1), AuthStrength::Token).authenticate(&good_token(), NOW),
            Err(AuthError::UnknownIssuer)
        );
    }

    #[test]
    fn removing_an_issuer_revokes_every_token_it_signed() {
        // The product's only revocation today, so it has to actually work on
        // credentials already in the wild.
        let mut v = verifier("issuer-a", &seed(1), AuthStrength::Token);
        let token = good_token();
        assert!(v.authenticate(&token, NOW).is_ok());
        assert!(v.remove_issuer("issuer-a"));
        assert_eq!(v.authenticate(&token, NOW), Err(AuthError::UnknownIssuer));
        assert!(!v.remove_issuer("issuer-a"));
        assert_eq!(v.issuer_count(), 0);
    }

    #[test]
    fn a_token_for_another_deployment_is_refused() {
        // Without this, a compromised staging issuer is a production
        // credential.
        let token =
            issue_identity_token(&seed(1), "issuer-a", &claims("acme", "agent-7", "staging"))
                .unwrap();
        assert_eq!(
            verifier("issuer-a", &seed(1), AuthStrength::Token).authenticate(&token, NOW),
            Err(AuthError::WrongAudience)
        );
    }

    #[test]
    fn expiry_and_not_before_are_enforced_with_leeway() {
        let v = verifier("issuer-a", &seed(1), AuthStrength::Token).with_leeway(30);
        let token = good_token(); // expires_at = NOW + 600

        assert!(v.authenticate(&token, NOW + 600).is_ok(), "at expiry");
        assert!(v.authenticate(&token, NOW + 630).is_ok(), "inside leeway");
        assert_eq!(
            v.authenticate(&token, NOW + 631),
            Err(AuthError::Expired),
            "one second past leeway"
        );

        let mut c = claims("acme", "agent-7", AUD);
        c.not_before = Some(NOW + 300);
        let later = issue_identity_token(&seed(1), "issuer-a", &c).unwrap();
        assert_eq!(v.authenticate(&later, NOW), Err(AuthError::NotYetValid));
        assert!(v.authenticate(&later, NOW + 270).is_ok(), "inside leeway");
    }

    #[test]
    fn the_lifetime_ceiling_binds_the_issuer_and_the_verifier() {
        // Enforced at issue so this build cannot mint one, and again at verify
        // so a token from an issuer that does not enforce it is still refused.
        let mut c = claims("acme", "agent-7", AUD);
        c.expires_at = c.issued_at + MAX_TOKEN_LIFETIME_SECS + 1;
        assert_eq!(
            issue_identity_token(&seed(1), "issuer-a", &c),
            Err(AuthError::LifetimeTooLong)
        );

        let payload = ccos_enterprise_governance::b64url::encode(
            serde_json::to_string(&c).unwrap().as_bytes(),
        );
        let input =
            format!("{IDENTITY_TOKEN_PREFIX}.{IDENTITY_TOKEN_ALGORITHM}.issuer-a.{payload}");
        let sig = ed25519_dalek::Signer::sign(&SigningKey::from_bytes(&seed(1)), input.as_bytes());
        let long = format!(
            "{input}.{}",
            ccos_enterprise_governance::b64url::encode(&sig.to_bytes())
        );
        assert_eq!(
            verifier("issuer-a", &seed(1), AuthStrength::Token).authenticate(&long, c.issued_at),
            Err(AuthError::LifetimeTooLong)
        );
    }

    #[test]
    fn the_envelope_is_not_negotiable() {
        let v = verifier("issuer-a", &seed(1), AuthStrength::Token);
        let token = good_token();
        for bad in [
            token.replacen(IDENTITY_TOKEN_PREFIX, "ccoslic1", 1), // a license token
            token.replacen(".ed25519.", ".none.", 1),             // the classic JWT wound
            token.replacen(".ed25519.", ".hs256.", 1),
            token.split('.').take(4).collect::<Vec<_>>().join("."), // truncated
            format!("{token}.extra"),
            "x".repeat(MAX_TOKEN_BYTES + 1),
            String::new(),
        ] {
            assert!(
                matches!(v.authenticate(&bad, NOW), Err(AuthError::Malformed(_))),
                "admitted {:?}",
                &bad[..bad.len().min(40)]
            );
        }
    }

    #[test]
    fn a_token_has_exactly_one_spelling() {
        // The vault's lesson, applied to identity: padded or re-spelled
        // base64url is a different string that must not be the same token, or
        // any deny-list keyed on the token text has as many holes as there are
        // spellings.
        let v = verifier("issuer-a", &seed(1), AuthStrength::Token);
        let token = good_token();
        let mut parts: Vec<String> = token.split('.').map(String::from).collect();
        for padded in [format!("{}=", parts[4]), format!("{}==", parts[4])] {
            let mut p = parts.clone();
            p[4] = padded;
            assert!(matches!(
                v.authenticate(&p.join("."), NOW),
                Err(AuthError::Malformed(_))
            ));
        }
        parts[3] = format!("{}=", parts[3]);
        assert!(matches!(
            v.authenticate(&parts.join("."), NOW),
            Err(AuthError::BadSignature | AuthError::Malformed(_))
        ));
    }

    #[test]
    fn a_signed_token_cannot_smuggle_a_homoglyph_identity() {
        // Signed by a trusted issuer, so the only thing standing between a
        // Cyrillic `а` and an `acme` tenant is the canonical-identity rule.
        for (org, actor) in [("\u{0430}cme", "agent-7"), ("acme", "agent\u{202e}7")] {
            let mut c = claims("acme", "agent-7", AUD);
            c.org = org.into();
            c.actor = actor.into();
            assert!(matches!(
                issue_identity_token(&seed(1), "issuer-a", &c),
                Err(AuthError::MalformedIdentity(_))
            ));

            let payload = ccos_enterprise_governance::b64url::encode(
                serde_json::to_string(&c).unwrap().as_bytes(),
            );
            let input =
                format!("{IDENTITY_TOKEN_PREFIX}.{IDENTITY_TOKEN_ALGORITHM}.issuer-a.{payload}");
            let sig =
                ed25519_dalek::Signer::sign(&SigningKey::from_bytes(&seed(1)), input.as_bytes());
            let forged = format!(
                "{input}.{}",
                ccos_enterprise_governance::b64url::encode(&sig.to_bytes())
            );
            assert!(matches!(
                verifier("issuer-a", &seed(1), AuthStrength::Token).authenticate(&forged, NOW),
                Err(AuthError::MalformedIdentity(_))
            ));
        }
    }

    #[test]
    fn a_key_cannot_be_trusted_under_a_name_the_parser_would_reject() {
        let mut v = TokenAuthenticator::new(AUD, AuthStrength::Token);
        let key = SigningKey::from_bytes(&seed(1)).verifying_key();
        for bad in ["", "Issuer", "issuer.a", "-issuer", &"k".repeat(200)] {
            assert!(!v.add_issuer(bad, key), "{bad:?} trusted");
        }
        assert_eq!(v.issuer_count(), 0);
    }

    #[test]
    fn an_unconfigured_verifier_authenticates_nobody() {
        assert_eq!(
            TokenAuthenticator::new(AUD, AuthStrength::Token).authenticate(&good_token(), NOW),
            Err(AuthError::UnknownIssuer)
        );
    }
}
