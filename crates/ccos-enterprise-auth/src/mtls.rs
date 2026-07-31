//! Identity from a verified peer certificate.
//!
//! # What this module does not do, stated first
//!
//! **It does not verify certificates.** It parses no X.509, walks no chain,
//! checks no CRL or OCSP responder, and validates no signature. A crate that
//! did those things would be a TLS implementation, and this product has no
//! business shipping a second one.
//!
//! It consumes the *result* of a verification somebody else performed — the TLS
//! terminator, whether that is a reverse proxy in front of the deployment or a
//! `rustls` `ServerConfig` inside it — and turns that result into an identity
//! the admission path can key on. Everything below the [`VerifiedPeer`]
//! boundary is somebody else's guarantee; everything above it is this crate's.
//!
//! # Where the trust boundary actually is
//!
//! [`VerifiedPeer::attested`] is the seam, and it is worth being exact about
//! what a seam can and cannot be. Inside one process, any code that can call
//! the authenticator can also call `attested` — no Rust type keeps a caller in
//! the same binary from asserting something false. The boundary is real at the
//! *deployment* level (only the terminator has a verified chain to describe)
//! and advisory at the language level.
//!
//! Saying so is the point. An earlier version of this crate had an
//! `AuthenticatedActor` with public fields and a doc comment describing a
//! security model, and the gap between the two was the vulnerability. The way
//! that does not happen again is to name which guarantees are structural and
//! which are contractual, rather than letting a reader assume the stronger one.
//!
//! What *is* structural here: an attested peer still has to satisfy the trust
//! anchor allowlist, the canonical-identity rule, and its own validity window
//! before it becomes an [`AuthenticatedActor`]. A terminator that hands over a
//! peer signed by an unknown authority, or naming a homoglyph organization, or
//! whose certificate expired last week, is refused by this crate regardless of
//! how confidently it attested.

use std::collections::BTreeSet;

use crate::{is_canonical_identity, ActorId, AuthError, AuthStrength, AuthenticatedActor, OrgId};

/// A peer whose certificate chain **the transport has already verified**.
///
/// Constructing one is an assertion that a chain was walked to a trust anchor,
/// that the signature verified, and that the subject fields below were read
/// from the leaf certificate rather than from anything the client sent in
/// band. Call [`attested`](Self::attested) from a TLS terminator and nowhere
/// else.
///
/// The fields are private for the same reason [`AuthenticatedActor`]'s are: a
/// struct literal is not a mechanism, and a type anybody can fill in field by
/// field is a suggestion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPeer {
    issuer_spki_sha256: [u8; 32],
    org: String,
    actor: String,
    not_after: u64,
}

impl VerifiedPeer {
    /// Describe a peer whose chain the caller has verified.
    ///
    /// * `issuer_spki_sha256` — SHA-256 of the issuing CA's
    ///   `SubjectPublicKeyInfo`. The key, not the name: a Distinguished Name is
    ///   chosen by whoever issues the certificate, so two authorities can claim
    ///   the same one, and pinning a string would let the wrong CA inherit the
    ///   right CA's trust. The SPKI hash changes when the key changes, which is
    ///   the event that should invalidate the pin.
    /// * `org` / `actor` — read from the leaf's subject or SAN by the
    ///   terminator, which is the only party that knows which field its PKI
    ///   puts them in.
    /// * `not_after` — the leaf's expiry, unix seconds.
    pub fn attested(issuer_spki_sha256: [u8; 32], org: &str, actor: &str, not_after: u64) -> Self {
        Self {
            issuer_spki_sha256,
            org: org.to_string(),
            actor: actor.to_string(),
            not_after,
        }
    }

    /// SHA-256 of the issuing authority's public key info.
    pub fn issuer_spki_sha256(&self) -> &[u8; 32] {
        &self.issuer_spki_sha256
    }

    /// The organization the terminator read from the certificate.
    pub fn org(&self) -> &str {
        &self.org
    }

    /// The actor the terminator read from the certificate.
    pub fn actor(&self) -> &str {
        &self.actor
    }

    /// The leaf certificate's expiry, unix seconds.
    pub fn not_after(&self) -> u64 {
        self.not_after
    }
}

/// Turn a verified transport peer into a proved identity, or refuse it.
///
/// Separate from [`crate::Authenticator`] because the credential is not a
/// string the client presents. Folding both into one trait would have meant an
/// `authenticate(&str)` that mTLS implements by parsing something the client
/// controls — which is the whole difference between a bearer token and a
/// transport-proved identity, erased for the sake of one trait.
pub trait TransportAuthenticator {
    /// `now` is unix seconds.
    fn authenticate_peer(
        &self,
        peer: &VerifiedPeer,
        now: u64,
    ) -> Result<AuthenticatedActor, AuthError>;
}

/// Attests [`AuthStrength::Strong`] for peers issued by a pinned authority.
///
/// This is the mechanism `require_strength(Strong)` was written for: a private
/// key the client had to possess to complete the handshake, rather than a
/// bearer string that anybody who read a log can present.
#[derive(Debug, Default)]
pub struct MtlsAuthenticator {
    anchors: BTreeSet<[u8; 32]>,
    leeway_secs: u64,
}

impl MtlsAuthenticator {
    /// A verifier trusting no authority, which authenticates nobody.
    ///
    /// The correct state for a deployment that has not been configured: an
    /// authenticator that trusted whatever the terminator handed it would make
    /// the trust anchor list the terminator's choice, and the terminator is
    /// exactly the component whose compromise this pin is meant to survive.
    pub fn new() -> Self {
        Self {
            anchors: BTreeSet::new(),
            leeway_secs: 60,
        }
    }

    /// Tolerance for clock skew against the certificate's expiry, in seconds.
    pub fn with_leeway(mut self, secs: u64) -> Self {
        self.leeway_secs = secs;
        self
    }

    /// Trust an issuing authority by the SHA-256 of its `SubjectPublicKeyInfo`.
    pub fn trust_anchor(&mut self, issuer_spki_sha256: [u8; 32]) -> bool {
        self.anchors.insert(issuer_spki_sha256)
    }

    /// Stop trusting an authority. Returns whether it was trusted.
    ///
    /// The counterpart of `TokenAuthenticator::remove_issuer`: a compromised CA
    /// must be droppable without taking the deployment down.
    pub fn distrust_anchor(&mut self, issuer_spki_sha256: &[u8; 32]) -> bool {
        self.anchors.remove(issuer_spki_sha256)
    }

    /// How many authorities this verifier trusts.
    pub fn anchor_count(&self) -> usize {
        self.anchors.len()
    }
}

impl TransportAuthenticator for MtlsAuthenticator {
    fn authenticate_peer(
        &self,
        peer: &VerifiedPeer,
        now: u64,
    ) -> Result<AuthenticatedActor, AuthError> {
        // The anchor first. Everything after this trusts the terminator's
        // reading of a certificate, and there is no reason to read a
        // certificate from an authority this deployment does not accept.
        if !self.anchors.contains(&peer.issuer_spki_sha256) {
            return Err(AuthError::UntrustedIssuer);
        }
        // Checked here as well as by the terminator. A proxy that forgets to
        // reject an expired client certificate is a plausible misconfiguration,
        // and this is the cheapest place to make it not matter.
        if now > peer.not_after.saturating_add(self.leeway_secs) {
            return Err(AuthError::PeerExpired);
        }
        if !is_canonical_identity(&peer.org) {
            return Err(AuthError::MalformedIdentity(format!("org {:?}", peer.org)));
        }
        if !is_canonical_identity(&peer.actor) {
            return Err(AuthError::MalformedIdentity(format!(
                "actor {:?}",
                peer.actor
            )));
        }
        Ok(AuthenticatedActor::proved(
            OrgId(peer.org.clone()),
            ActorId(peer.actor.clone()),
            // A completed mutual handshake proves possession of a private key.
            AuthStrength::Strong,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;
    const CA: [u8; 32] = [7u8; 32];
    const OTHER_CA: [u8; 32] = [8u8; 32];

    fn verifier() -> MtlsAuthenticator {
        let mut m = MtlsAuthenticator::new();
        m.trust_anchor(CA);
        m
    }

    fn peer(org: &str, actor: &str) -> VerifiedPeer {
        VerifiedPeer::attested(CA, org, actor, NOW + 86_400)
    }

    #[test]
    fn a_verified_peer_from_a_pinned_authority_is_strongly_authenticated() {
        // The mechanism `require_strength(Strong)` was written for: the client
        // held a private key, rather than a string anybody who read a log has.
        let who = verifier()
            .authenticate_peer(&peer("acme", "agent-7"), NOW)
            .expect("verified peer refused");
        assert_eq!(who.org().0, "acme");
        assert_eq!(who.actor().0, "agent-7");
        assert_eq!(who.strength(), AuthStrength::Strong);
        assert!(who.is_strongly_authenticated());
    }

    #[test]
    fn an_unpinned_authority_proves_nothing_however_well_it_verified() {
        // The terminator did its job — the chain is valid. It is valid up to a
        // CA this deployment never accepted, which is the whole point of
        // pinning: a real certificate from the wrong authority is the attack.
        let rogue = VerifiedPeer::attested(OTHER_CA, "acme", "agent-7", NOW + 86_400);
        assert_eq!(
            verifier().authenticate_peer(&rogue, NOW),
            Err(AuthError::UntrustedIssuer)
        );
    }

    #[test]
    fn an_unconfigured_verifier_authenticates_nobody() {
        assert_eq!(
            MtlsAuthenticator::new().authenticate_peer(&peer("acme", "agent-7"), NOW),
            Err(AuthError::UntrustedIssuer)
        );
        assert_eq!(MtlsAuthenticator::new().anchor_count(), 0);
    }

    #[test]
    fn distrusting_an_authority_takes_effect_on_peers_already_issued() {
        // A compromised CA must be droppable without taking the deployment
        // down, and without waiting for anybody's certificate to expire.
        let mut m = verifier();
        assert!(m.authenticate_peer(&peer("acme", "agent-7"), NOW).is_ok());
        assert!(m.distrust_anchor(&CA));
        assert_eq!(
            m.authenticate_peer(&peer("acme", "agent-7"), NOW),
            Err(AuthError::UntrustedIssuer)
        );
        assert!(!m.distrust_anchor(&CA));
        assert_eq!(m.anchor_count(), 0);
    }

    #[test]
    fn an_expired_certificate_is_refused_here_too() {
        // Belt and braces on purpose: a proxy that forgets to reject an expired
        // client certificate is a plausible misconfiguration, and this is the
        // cheapest place to make it not matter.
        let m = verifier().with_leeway(30);
        let p = VerifiedPeer::attested(CA, "acme", "agent-7", NOW);
        assert!(m.authenticate_peer(&p, NOW).is_ok(), "at expiry");
        assert!(m.authenticate_peer(&p, NOW + 30).is_ok(), "inside leeway");
        assert_eq!(
            m.authenticate_peer(&p, NOW + 31),
            Err(AuthError::PeerExpired)
        );
    }

    #[test]
    fn a_certificate_cannot_smuggle_a_homoglyph_identity() {
        // Signed by the pinned CA, so the canonical-identity rule is the only
        // thing between a Cyrillic `а` and an `acme` tenant.
        let m = verifier();
        for (org, actor) in [
            ("\u{0430}cme", "agent-7"),
            ("acme", "agent\u{202e}7"),
            ("ACME", "agent-7"),
            ("acme.corp", "agent-7"),
            ("", "agent-7"),
            ("acme", ""),
        ] {
            assert!(
                matches!(
                    m.authenticate_peer(&peer(org, actor), NOW),
                    Err(AuthError::MalformedIdentity(_))
                ),
                "admitted org={org:?} actor={actor:?}"
            );
        }
    }

    #[test]
    fn the_anchor_is_checked_before_anything_is_read_from_the_certificate() {
        // Ordering, asserted rather than assumed: a peer that is wrong in two
        // ways must fail on the authority, because everything after that point
        // trusts the terminator's reading of a certificate this deployment has
        // no reason to read.
        let rogue = VerifiedPeer::attested(OTHER_CA, "\u{0430}cme", "agent-7", NOW - 1);
        assert_eq!(
            verifier().authenticate_peer(&rogue, NOW),
            Err(AuthError::UntrustedIssuer)
        );
    }

    #[test]
    fn the_issuer_is_pinned_by_key_and_not_by_name() {
        // Two authorities can put the same Distinguished Name in a certificate,
        // so a name pin lets the wrong CA inherit the right CA's trust. The
        // SPKI hash changes when the key changes, which is the event that
        // should invalidate the pin.
        let mut m = MtlsAuthenticator::new();
        m.trust_anchor(CA);
        let same_name_other_key = VerifiedPeer::attested(OTHER_CA, "acme", "agent-7", NOW + 600);
        assert_eq!(
            m.authenticate_peer(&same_name_other_key, NOW),
            Err(AuthError::UntrustedIssuer)
        );
        assert_ne!(peer("acme", "agent-7").issuer_spki_sha256(), &OTHER_CA);
    }
}
