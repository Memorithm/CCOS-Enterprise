//! OIDC identity tokens, verified against pre-configured JWKS keys.
//!
//! # Two limits, stated before the API
//!
//! **EdDSA only.** Not RS256, which is what most identity providers actually
//! sign with. The pure-Rust `rsa` crate carries RUSTSEC-2023-0071 — the Marvin
//! timing attack — with no fixed release, and this workspace's `deny.toml`
//! ignores no advisories, so adding it would fail the supply-chain gate that
//! exists to catch exactly this. Shipping RS256 by silencing that gate would
//! trade a real, checked property for a feature, and the trade is worse than
//! the gap. A provider that can sign EdDSA (Ed25519, RFC 8037) works today;
//! one that cannot is not supported, and [`OidcAuthenticator`] refuses its
//! tokens rather than accepting them unverified.
//!
//! **No network.** Keys are configured, never fetched. A deployment that
//! resolved a JWKS URI on each verification would make the identity provider a
//! dependency of every request and its outage an outage here — and an
//! air-gapped install could not do it at all. Rotation is
//! [`OidcAuthenticator::add_key`] and [`remove_key`](OidcAuthenticator::remove_key),
//! driven by whatever the operator already uses to distribute configuration.
//!
//! # Why these claims are not `deny_unknown_fields`
//!
//! [`crate::IdentityClaims`] refuses a field it does not know, because this
//! product mints those tokens and an unknown field means an issuer meant
//! something this build would silently drop. An OIDC token is somebody else's
//! format: providers send `email`, `name`, `groups`, and a dozen vendor
//! extensions, all of them legitimate and none of them ours. Refusing them
//! would reject valid tokens.
//!
//! The safety that replaces it is different in kind: nothing here is inferred
//! from a claim this module does not name. `sub` and the configured
//! organization claim are read; everything else is ignored on purpose, so an
//! extension claim cannot widen an identity by being present.

use std::collections::BTreeMap;

use crate::{
    is_canonical_identity, ActorId, AuthError, AuthStrength, AuthenticatedActor, Authenticator,
    OrgId, SharedRevocations, MAX_TOKEN_BYTES, MAX_TOKEN_LIFETIME_SECS,
};

/// The only signature algorithm this verifier accepts.
pub const OIDC_ALGORITHM: &str = "EdDSA";

/// Verifies OIDC/JWT bearer tokens against configured Ed25519 JWKS keys.
///
/// Attests [`AuthStrength::Token`] and nothing more, whatever the provider
/// claims about how it authenticated the user. A bearer token is a string: the
/// party presenting it proved possession of a string, and an `acr` or `amr`
/// claim saying the user touched a hardware key describes something that
/// happened between the user and the provider, not between the client and this
/// deployment. Treating it as [`AuthStrength::Strong`] would let a stolen token
/// reach the surfaces `require_strength(Strong)` protects.
pub struct OidcAuthenticator {
    keys: BTreeMap<String, ed25519_dalek::VerifyingKey>,
    issuer: String,
    audience: String,
    /// Which claim carries the organization. Configurable because there is no
    /// standard one, and guessing would mean an identity whose tenancy came
    /// from whichever claim happened to be present.
    org_claim: String,
    leeway_secs: u64,
    /// The deployment deny-list, shared behind an interior handle so every
    /// verifier of one install consults the same list.
    revocations: SharedRevocations,
}

impl OidcAuthenticator {
    /// A verifier for one provider and one deployment, holding no keys.
    ///
    /// Authenticates nobody until a key is added — the correct state for an
    /// unconfigured install.
    pub fn new(issuer: &str, audience: &str, org_claim: &str) -> Self {
        Self {
            keys: BTreeMap::new(),
            issuer: issuer.to_string(),
            audience: audience.to_string(),
            org_claim: org_claim.to_string(),
            leeway_secs: 60,
            revocations: SharedRevocations::default(),
        }
    }

    /// Tolerance for clock skew, in seconds, applied to `exp` and `nbf`.
    pub fn with_leeway(mut self, secs: u64) -> Self {
        self.leeway_secs = secs;
        self
    }

    /// Trust a provider signing key under its JWKS `kid`.
    ///
    /// Refuses a non-canonical `kid` for the same reason the identity-token
    /// verifier does: a key registered under a name the parser would reject is
    /// a key that can never be selected, which is a silent misconfiguration
    /// rather than a trusted key.
    pub fn add_key(&mut self, kid: &str, key: ed25519_dalek::VerifyingKey) -> bool {
        if !is_canonical_identity(kid) {
            return false;
        }
        self.keys.insert(kid.to_string(), key);
        true
    }

    /// Stop trusting a provider key. Returns whether it was trusted.
    pub fn remove_key(&mut self, kid: &str) -> bool {
        self.keys.remove(kid).is_some()
    }

    /// How many provider keys this verifier trusts.
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Point this verifier at a **shared** deny-list instead of a fresh one.
    ///
    /// The same [`SharedRevocations`] the token and mTLS verifiers accept: one
    /// revoke call reaches every mechanism of the install, instead of each
    /// verifier learning about it separately — or, on a second replica, never.
    pub fn with_shared_revocations(mut self, revocations: SharedRevocations) -> Self {
        self.revocations = revocations;
        self
    }

    /// The shared deny-list this verifier consults.
    pub fn revocations_shared(&self) -> SharedRevocations {
        std::sync::Arc::clone(&self.revocations)
    }

    /// Revoke one credential by identifier on this verifier's deny-list.
    /// Returns whether the revocation took effect.
    pub fn revoke_token(&self, jti: &str, expires_at: u64, now: u64) -> bool {
        self.revocations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .revoke_token(jti, expires_at, now)
    }

    /// Revoke every credential an actor holds. Returns whether the entry was
    /// written.
    pub fn revoke_actor(&self, org: &OrgId, actor: &ActorId, issued_through: u64) -> bool {
        self.revocations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .revoke_actor(org, actor, issued_through)
    }

    fn string_claim<'a>(v: &'a serde_json::Value, name: &str) -> Option<&'a str> {
        v.get(name).and_then(serde_json::Value::as_str)
    }

    /// `aud` is a string or an array of strings (RFC 7519 §4.1.3). A token
    /// whose audiences include this deployment is for this deployment.
    fn audience_matches(claims: &serde_json::Value, want: &str) -> bool {
        match claims.get("aud") {
            Some(serde_json::Value::String(s)) => s == want,
            Some(serde_json::Value::Array(items)) => {
                items.iter().any(|i| i.as_str().is_some_and(|s| s == want))
            }
            _ => false,
        }
    }

    /// Whether the token's `aud` array names more than one deployment.
    fn audience_is_multiple(claims: &serde_json::Value) -> bool {
        matches!(
            claims.get("aud"),
            Some(serde_json::Value::Array(items)) if items.len() > 1
        )
    }
}

impl Authenticator for OidcAuthenticator {
    fn authenticate(&self, presented: &str, now: u64) -> Result<AuthenticatedActor, AuthError> {
        use ed25519_dalek::{Signature, Verifier};

        if presented.len() > MAX_TOKEN_BYTES {
            return Err(AuthError::Malformed("over the size bound".into()));
        }
        let parts: Vec<&str> = presented.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::Malformed(format!(
                "expected 3 dot-separated parts, found {}",
                parts.len()
            )));
        }

        let Some(header_bytes) = ccos_enterprise_governance::b64url::decode(parts[0]) else {
            return Err(AuthError::Malformed(
                "header is not canonical base64url".into(),
            ));
        };
        let header: serde_json::Value = serde_json::from_slice(&header_bytes)
            .map_err(|e| AuthError::Malformed(format!("header JSON: {e}")))?;

        // `alg` is read from the header only to *refuse* anything but the one
        // algorithm this build verifies. It never selects a verification path:
        // "alg" confusion — `none`, or an RSA public key replayed as an HMAC
        // secret — is the canonical JWT wound, and the cure is a verifier that
        // has one path and rejects every token that asks for another.
        match Self::string_claim(&header, "alg") {
            Some(OIDC_ALGORITHM) => {}
            _ => return Err(AuthError::Malformed("unsupported algorithm".into())),
        }
        let Some(kid) = Self::string_claim(&header, "kid") else {
            return Err(AuthError::Malformed("header names no key id".into()));
        };
        let Some(key) = self.keys.get(kid) else {
            return Err(AuthError::UnknownIssuer);
        };

        let Some(sig_bytes) = ccos_enterprise_governance::b64url::decode(parts[2]) else {
            return Err(AuthError::Malformed(
                "signature is not canonical base64url".into(),
            ));
        };
        let sig_bytes: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| AuthError::Malformed("signature is not 64 bytes".into()))?;

        // JWS signs the two encoded segments verbatim, separated by a dot, so
        // the header — including `kid` — is covered.
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        key.verify(signing_input.as_bytes(), &Signature::from_bytes(&sig_bytes))
            .map_err(|_| AuthError::BadSignature)?;

        // Only now: the payload is attacker-controlled until the signature says
        // otherwise.
        let Some(payload) = ccos_enterprise_governance::b64url::decode(parts[1]) else {
            return Err(AuthError::Malformed(
                "payload is not canonical base64url".into(),
            ));
        };
        let claims: serde_json::Value = serde_json::from_slice(&payload)
            .map_err(|e| AuthError::MalformedClaims(format!("payload JSON: {e}")))?;

        if Self::string_claim(&claims, "iss") != Some(self.issuer.as_str()) {
            // A token from another provider, signed by a key we trust for this
            // one, is a misconfigured trust store — not a misdirected
            // credential. It used to be reported as `WrongAudience`, which
            // told the operator to look at `aud` and sent them hunting in the
            // wrong claim; the audience check runs next and keeps its own
            // error.
            return Err(AuthError::UnknownIssuer);
        }
        if !Self::audience_matches(&claims, &self.audience) {
            return Err(AuthError::WrongAudience);
        }
        // A token minted for several deployments names, in `azp` (OIDC core
        // §3.1.3.3), the party it was issued *to*. Without this check any
        // deployment in the audience list could present a token that was never
        // meant for it: one relying party accepting on behalf of all of them.
        // A single-audience token carries no `azp`, which is legal, and a
        // string `aud` has nothing to be ambiguous about.
        if Self::audience_is_multiple(&claims) {
            match claims.get("azp").and_then(serde_json::Value::as_str) {
                Some(azp) if azp == self.audience => {}
                _ => return Err(AuthError::WrongAudience),
            }
        }

        let Some(exp) = claims.get("exp").and_then(serde_json::Value::as_u64) else {
            return Err(AuthError::MalformedClaims("no exp claim".into()));
        };
        // Required, and not only for the lifetime ceiling: without `iat` an
        // actor revocation has no issue time to compare against, so a token
        // that omitted it would survive "revoke everything this actor holds".
        let Some(iat) = claims.get("iat").and_then(serde_json::Value::as_u64) else {
            return Err(AuthError::MalformedClaims("no iat claim".into()));
        };
        if exp <= iat {
            return Err(AuthError::MalformedClaims("exp is not after iat".into()));
        }
        if exp - iat > MAX_TOKEN_LIFETIME_SECS {
            // This deployment's ceiling, applied to somebody else's issuer. A
            // provider handing out day-long access tokens does not get to
            // decide how long this product will honour one.
            return Err(AuthError::LifetimeTooLong);
        }
        if now > exp.saturating_add(self.leeway_secs) {
            return Err(AuthError::Expired);
        }
        if let Some(nbf) = claims.get("nbf").and_then(serde_json::Value::as_u64) {
            if now.saturating_add(self.leeway_secs) < nbf {
                return Err(AuthError::NotYetValid);
            }
        }

        let Some(sub) = Self::string_claim(&claims, "sub") else {
            return Err(AuthError::MalformedClaims("no sub claim".into()));
        };
        let Some(org) = Self::string_claim(&claims, &self.org_claim) else {
            return Err(AuthError::MalformedClaims(format!(
                "no {:?} claim",
                self.org_claim
            )));
        };
        if !is_canonical_identity(org) {
            return Err(AuthError::MalformedIdentity(format!("org {org:?}")));
        }
        if !is_canonical_identity(sub) {
            // Providers commonly use opaque UUIDs or emails as `sub`. An email
            // is refused here on purpose: this product's identifiers are
            // dot-free and case-folded, and admitting one would let two
            // spellings of the same address be two actors.
            return Err(AuthError::MalformedIdentity(format!("sub {sub:?}")));
        }

        let org = OrgId(org.to_string());
        let actor = ActorId(sub.to_string());
        let jti = Self::string_claim(&claims, "jti");
        if self
            .revocations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_revoked(jti, &org, &actor, iat)
        {
            return Err(AuthError::Revoked);
        }

        Ok(AuthenticatedActor::proved(org, actor, AuthStrength::Token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const NOW: u64 = 1_700_000_000;
    const ISS: &str = "https://idp.example/realms/memorithm";
    const AUD: &str = "ccos-prod-eu";

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    fn verifier() -> OidcAuthenticator {
        let mut v = OidcAuthenticator::new(ISS, AUD, "ccos_org");
        assert!(v.add_key("k1", key(1).verifying_key()));
        v
    }

    /// Mint a JWT with whatever header and payload the test wants — including
    /// shapes a real provider would never emit, which is the point.
    fn jwt(header: serde_json::Value, payload: serde_json::Value, signer: &SigningKey) -> String {
        let h = ccos_enterprise_governance::b64url::encode(header.to_string().as_bytes());
        let p = ccos_enterprise_governance::b64url::encode(payload.to_string().as_bytes());
        let input = format!("{h}.{p}");
        let sig = signer.sign(input.as_bytes());
        format!(
            "{input}.{}",
            ccos_enterprise_governance::b64url::encode(&sig.to_bytes())
        )
    }

    fn header() -> serde_json::Value {
        serde_json::json!({"alg": OIDC_ALGORITHM, "kid": "k1", "typ": "JWT"})
    }

    fn payload() -> serde_json::Value {
        serde_json::json!({
            "iss": ISS,
            "sub": "agent-7",
            "aud": AUD,
            "ccos_org": "acme",
            "iat": NOW - 10,
            "exp": NOW + 600,
        })
    }

    #[test]
    fn a_provider_signed_token_authenticates_its_subject() {
        let who = verifier()
            .authenticate(&jwt(header(), payload(), &key(1)), NOW)
            .expect("valid token refused");
        assert_eq!(who.org().0, "acme");
        assert_eq!(who.actor().0, "agent-7");
        assert_eq!(who.strength(), AuthStrength::Token);
    }

    #[test]
    fn a_bearer_token_is_never_strong_however_the_provider_describes_itself() {
        // `acr`/`amr` describe what happened between the user and the provider.
        // Between the client and this deployment, a bearer token proves
        // possession of a string — and treating it as Strong would let a stolen
        // one reach the surfaces `require_strength(Strong)` protects.
        let mut p = payload();
        p["acr"] = serde_json::json!("urn:mace:incommon:iap:silver");
        p["amr"] = serde_json::json!(["hwk", "mfa"]);
        let who = verifier()
            .authenticate(&jwt(header(), p, &key(1)), NOW)
            .unwrap();
        assert_eq!(who.strength(), AuthStrength::Token);
        assert!(!who.is_strongly_authenticated());
    }

    #[test]
    fn alg_never_selects_a_verification_path() {
        // The canonical JWT wound. `none` must not mean "skip", and naming
        // another algorithm must not mean "try it" — there is one path, and a
        // token that asks for another is refused before any key is consulted.
        let v = verifier();
        for alg in ["none", "None", "HS256", "RS256", "ES256", "EdDSA "] {
            let h = serde_json::json!({"alg": alg, "kid": "k1"});
            let token = jwt(h, payload(), &key(1));
            assert!(
                matches!(v.authenticate(&token, NOW), Err(AuthError::Malformed(_))),
                "admitted alg={alg:?}"
            );
        }
        // …and an unsigned token whose signature segment is empty.
        let h = ccos_enterprise_governance::b64url::encode(
            serde_json::json!({"alg": "none", "kid": "k1"})
                .to_string()
                .as_bytes(),
        );
        let p = ccos_enterprise_governance::b64url::encode(payload().to_string().as_bytes());
        assert!(matches!(
            v.authenticate(&format!("{h}.{p}."), NOW),
            Err(AuthError::Malformed(_))
        ));
    }

    #[test]
    fn the_header_is_covered_by_the_signature() {
        // JWS signs both encoded segments, so `kid` cannot be swapped to point
        // at a different trusted key.
        let mut v = OidcAuthenticator::new(ISS, AUD, "ccos_org");
        v.add_key("k1", key(1).verifying_key());
        v.add_key("k2", key(2).verifying_key());
        let token = jwt(header(), payload(), &key(1));
        let relabelled = {
            let parts: Vec<&str> = token.split('.').collect();
            let h = ccos_enterprise_governance::b64url::encode(
                serde_json::json!({"alg": OIDC_ALGORITHM, "kid": "k2", "typ": "JWT"})
                    .to_string()
                    .as_bytes(),
            );
            format!("{h}.{}.{}", parts[1], parts[2])
        };
        assert_eq!(
            v.authenticate(&relabelled, NOW),
            Err(AuthError::BadSignature)
        );
    }

    #[test]
    fn a_tampered_payload_breaks_the_signature() {
        let mut p = payload();
        p["ccos_org"] = serde_json::json!("globex");
        let token = jwt(header(), payload(), &key(1));
        let forged = {
            let parts: Vec<&str> = token.split('.').collect();
            let swapped = ccos_enterprise_governance::b64url::encode(p.to_string().as_bytes());
            format!("{}.{swapped}.{}", parts[0], parts[2])
        };
        assert_eq!(
            verifier().authenticate(&forged, NOW),
            Err(AuthError::BadSignature)
        );
    }

    #[test]
    fn another_providers_token_is_refused_even_when_the_key_is_trusted() {
        // An operator running two providers would otherwise let either mint
        // identities for both. The error names the issuer, not the audience:
        // the trust store is what is misconfigured here, and `WrongAudience`
        // sent the operator hunting in the wrong claim.
        let mut p = payload();
        p["iss"] = serde_json::json!("https://idp.attacker.example/");
        assert_eq!(
            verifier().authenticate(&jwt(header(), p, &key(1)), NOW),
            Err(AuthError::UnknownIssuer)
        );
    }

    #[test]
    fn a_multi_audience_token_must_name_this_deployment_as_azp() {
        // `aud: [a, b]` says the token may be presented to several parties.
        // Accepting on audience membership alone would let any party in the
        // list admit a token meant for another one, so `azp` (OIDC core
        // §3.1.3.3) must name *this* deployment.
        let v = verifier();
        let mut multi = payload();
        multi["aud"] = serde_json::json!(["other-service", AUD]);
        multi["azp"] = serde_json::json!(AUD);
        let multi_clone = multi.clone();
        assert!(v.authenticate(&jwt(header(), multi, &key(1)), NOW).is_ok());

        // Same token, missing `azp`: refused — an implementation that never
        // heard of `azp` gets no exemption.
        let mut no_azp = multi_clone.clone();
        no_azp.as_object_mut().unwrap().remove("azp");
        assert_eq!(
            v.authenticate(&jwt(header(), no_azp, &key(1)), NOW),
            Err(AuthError::WrongAudience)
        );

        // `azp` naming the *other* party: the token is not for us.
        let mut other_azp = multi_clone.clone();
        other_azp["azp"] = serde_json::json!("other-service");
        assert_eq!(
            v.authenticate(&jwt(header(), other_azp, &key(1)), NOW),
            Err(AuthError::WrongAudience)
        );

        // A single-audience token carries no `azp`, and that stays legal.
        assert!(v
            .authenticate(&jwt(header(), payload(), &key(1)), NOW)
            .is_ok());
    }

    #[test]
    fn the_audience_may_be_a_string_or_an_array_and_must_contain_us() {
        let v = verifier();
        let mut multi = payload();
        multi["aud"] = serde_json::json!(["other-service", AUD]);
        multi["azp"] = serde_json::json!(AUD);
        assert!(v.authenticate(&jwt(header(), multi, &key(1)), NOW).is_ok());

        for wrong in [
            serde_json::json!("other-service"),
            serde_json::json!(["a", "b"]),
            serde_json::json!([]),
            serde_json::json!(null),
            serde_json::json!(42),
            // A near miss must not match: substring or prefix logic here would
            // let `ccos-prod-eu-staging` speak for production.
            serde_json::json!("ccos-prod-eu-staging"),
            serde_json::json!("ccos-prod"),
        ] {
            let mut p = payload();
            p["aud"] = wrong.clone();
            assert_eq!(
                v.authenticate(&jwt(header(), p, &key(1)), NOW),
                Err(AuthError::WrongAudience),
                "admitted aud={wrong}"
            );
        }
        let mut none = payload();
        none.as_object_mut().unwrap().remove("aud");
        assert_eq!(
            v.authenticate(&jwt(header(), none, &key(1)), NOW),
            Err(AuthError::WrongAudience)
        );
    }

    #[test]
    fn this_deployments_lifetime_ceiling_binds_somebody_elses_issuer() {
        // A provider handing out day-long access tokens does not get to decide
        // how long this product will honour one.
        let mut p = payload();
        p["iat"] = serde_json::json!(NOW);
        p["exp"] = serde_json::json!(NOW + MAX_TOKEN_LIFETIME_SECS + 1);
        assert_eq!(
            verifier().authenticate(&jwt(header(), p, &key(1)), NOW),
            Err(AuthError::LifetimeTooLong)
        );
    }

    #[test]
    fn expiry_and_not_before_are_enforced_with_leeway() {
        let v = verifier().with_leeway(30);
        let token = jwt(header(), payload(), &key(1));
        assert!(v.authenticate(&token, NOW + 600).is_ok(), "at expiry");
        assert!(v.authenticate(&token, NOW + 630).is_ok(), "inside leeway");
        assert_eq!(v.authenticate(&token, NOW + 631), Err(AuthError::Expired));

        let mut p = payload();
        p["nbf"] = serde_json::json!(NOW + 300);
        let later = jwt(header(), p, &key(1));
        assert_eq!(v.authenticate(&later, NOW), Err(AuthError::NotYetValid));
        assert!(v.authenticate(&later, NOW + 270).is_ok());
    }

    #[test]
    fn a_token_without_the_claims_this_build_reasons_about_is_refused() {
        let v = verifier();
        for missing in ["exp", "iat", "sub", "ccos_org"] {
            let mut p = payload();
            p.as_object_mut().unwrap().remove(missing);
            assert!(
                matches!(
                    v.authenticate(&jwt(header(), p, &key(1)), NOW),
                    Err(AuthError::MalformedClaims(_))
                ),
                "admitted a token with no {missing}"
            );
        }
        // `iat` is required for a reason beyond the ceiling: without it an
        // actor revocation has no issue time to compare against.
        let mut p = payload();
        p["exp"] = serde_json::json!(NOW - 1);
        p["iat"] = serde_json::json!(NOW);
        assert!(matches!(
            v.authenticate(&jwt(header(), p, &key(1)), NOW),
            Err(AuthError::MalformedClaims(_))
        ));
    }

    #[test]
    fn unknown_claims_are_ignored_rather_than_refused() {
        // The deliberate difference from `IdentityClaims`. Providers send
        // `email`, `groups`, and vendor extensions; refusing them would reject
        // valid tokens. The safety is that nothing here is *inferred* from a
        // claim this module does not name.
        let mut p = payload();
        p["email"] = serde_json::json!("agent-7@acme.example");
        p["groups"] = serde_json::json!(["admins", "everyone"]);
        p["org"] = serde_json::json!("globex");
        p["strength"] = serde_json::json!("Strong");
        p["https://vendor.example/claims/role"] = serde_json::json!("root");
        let who = verifier()
            .authenticate(&jwt(header(), p, &key(1)), NOW)
            .unwrap();
        assert_eq!(who.org().0, "acme", "the configured claim, not `org`");
        assert_eq!(who.actor().0, "agent-7");
        assert_eq!(who.strength(), AuthStrength::Token);
    }

    #[test]
    fn a_signed_token_cannot_smuggle_a_non_canonical_identity() {
        let v = verifier();
        for (sub, org) in [
            ("agent-7@acme.example", "acme"), // an email as `sub`
            ("\u{0430}gent-7", "acme"),
            ("agent-7", "\u{0430}cme"),
            ("Agent-7", "acme"),
            ("agent-7", "ACME"),
            ("", "acme"),
            ("agent-7", ""),
            ("../../etc/passwd", "acme"),
        ] {
            let mut p = payload();
            p["sub"] = serde_json::json!(sub);
            p["ccos_org"] = serde_json::json!(org);
            assert!(
                matches!(
                    v.authenticate(&jwt(header(), p, &key(1)), NOW),
                    Err(AuthError::MalformedIdentity(_))
                ),
                "admitted sub={sub:?} org={org:?}"
            );
        }
    }

    #[test]
    fn revocation_reaches_oidc_tokens_by_actor_and_by_jti_when_present() {
        let v = verifier();
        let plain = jwt(header(), payload(), &key(1));
        let mut with_id = payload();
        with_id["jti"] = serde_json::json!("t-42");
        let identified = jwt(header(), with_id, &key(1));

        assert!(v.authenticate(&plain, NOW).is_ok());
        assert!(v.authenticate(&identified, NOW).is_ok());

        // A provider that sends `jti` can have one token revoked.
        v.revoke_token("t-42", NOW + 600, NOW);
        assert_eq!(v.authenticate(&identified, NOW), Err(AuthError::Revoked));
        assert!(v.authenticate(&plain, NOW).is_ok(), "unrelated token");

        // Actor revocation reaches both, including the one with no identifier —
        // which is the case individual revocation cannot serve.
        v.revoke_actor(&OrgId("acme".into()), &ActorId("agent-7".into()), NOW);
        assert_eq!(v.authenticate(&plain, NOW), Err(AuthError::Revoked));
    }

    #[test]
    fn an_unconfigured_verifier_authenticates_nobody() {
        let v = OidcAuthenticator::new(ISS, AUD, "ccos_org");
        assert_eq!(v.key_count(), 0);
        assert_eq!(
            v.authenticate(&jwt(header(), payload(), &key(1)), NOW),
            Err(AuthError::UnknownIssuer)
        );
    }

    #[test]
    fn rotating_a_key_out_refuses_the_tokens_it_signed() {
        let mut v = verifier();
        let token = jwt(header(), payload(), &key(1));
        assert!(v.authenticate(&token, NOW).is_ok());
        assert!(v.remove_key("k1"));
        assert_eq!(v.authenticate(&token, NOW), Err(AuthError::UnknownIssuer));
        assert!(!v.remove_key("k1"));
    }

    #[test]
    fn a_key_cannot_be_trusted_under_a_name_the_parser_would_reject() {
        let mut v = OidcAuthenticator::new(ISS, AUD, "ccos_org");
        for bad in ["", "K1", "k.1", "-k1", &"k".repeat(200)] {
            assert!(!v.add_key(bad, key(1).verifying_key()), "{bad:?} trusted");
        }
        assert_eq!(v.key_count(), 0);
    }

    #[test]
    fn the_envelope_is_not_negotiable() {
        let v = verifier();
        let token = jwt(header(), payload(), &key(1));
        let parts: Vec<&str> = token.split('.').collect();
        for bad in [
            format!("{}.{}", parts[0], parts[1]),
            format!("{token}.extra"),
            String::new(),
            "....".into(),
            format!("{}=.{}.{}", parts[0], parts[1], parts[2]), // padded b64
            format!("{}.{}.{}=", parts[0], parts[1], parts[2]),
            "x".repeat(MAX_TOKEN_BYTES + 1),
        ] {
            assert!(
                matches!(v.authenticate(&bad, NOW), Err(AuthError::Malformed(_))),
                "admitted {:?}",
                &bad[..bad.len().min(40)]
            );
        }
    }
}
