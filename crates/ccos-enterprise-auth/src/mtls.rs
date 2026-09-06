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
//! What this crate *does* consult on its own is the deployment's deny-list: a
//! principal the deployment has revoked is refused here even though the
//! certificate itself is cryptographically perfect — see
//! [`MtlsAuthenticator::with_shared_revocations`].
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

use crate::{
    is_canonical_identity, ActorId, AuthError, AuthStrength, AuthenticatedActor, OrgId,
    SharedRevocations,
};

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
    /// The leaf's own validity start, when the terminator reports it. A
    /// certificate that is not yet valid is refused, symmetrically with the
    /// expiry check — both are the terminator's job that this verifier repeats
    /// because a forgotten proxy check must not matter.
    not_before: Option<u64>,
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
    ///
    /// **Behind `test-identities`, and only for tests.** Freezing the whole
    /// peer — validity window included — from four strings was a constructor
    /// production code could compile, and the window was the one field a
    /// caller could set to whatever made admission easiest. Production callers
    /// describe the peer through [`Self::attested_with_anchor`], which carries
    /// the leaf's own `not_before` as well and is the shape a terminator
    /// actually knows. A production build cannot compile this constructor at
    /// all — the same gate `AuthenticatedActor::asserted` lives behind.
    #[cfg(any(test, feature = "test-identities"))]
    pub fn attested(issuer_spki_sha256: [u8; 32], org: &str, actor: &str, not_after: u64) -> Self {
        Self::attested_with_anchor(issuer_spki_sha256, org, actor, not_after, None)
    }

    /// Describe a peer whose chain **the transport has verified**.
    ///
    /// This is the production constructor. It is still an assertion — no Rust
    /// type keeps a caller inside the same process from asserting something
    /// false (see the module docs on where the trust boundary sits) — but it
    /// can make the assertion carry what a real terminator knows and nothing
    /// more: the pinned issuer key, the subject names, and the leaf's own
    /// validity window. The window is an input the verifier checks, not a
    /// claim the peer gets to drop.
    ///
    /// Call this from a TLS terminator and nowhere else.
    pub fn attested_with_anchor(
        issuer_spki_sha256: [u8; 32],
        org: &str,
        actor: &str,
        not_after: u64,
        not_before: Option<u64>,
    ) -> Self {
        Self {
            issuer_spki_sha256,
            org: org.to_string(),
            actor: actor.to_string(),
            not_after,
            not_before,
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

    /// The leaf certificate's validity start, when the terminator reported
    /// one, unix seconds.
    pub fn not_before(&self) -> Option<u64> {
        self.not_before
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
    /// The deployment deny-list, shared behind an interior handle so every
    /// verifier of one install — mTLS and token alike — can consult the same
    /// list, and a revoke reaches all of them at once.
    revocations: SharedRevocations,
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
            revocations: SharedRevocations::default(),
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

    /// Point this verifier at a **shared** deny-list instead of a fresh one.
    ///
    /// `revoke_actor` used to answer tokens and never reach the mTLS path: a
    /// principal the deployment had withdrawn still connected on the strength
    /// of a perfectly valid certificate, because pinning, expiry and
    /// canonicality were the only checks here. Peer certificates are
    /// typically long-lived, so nothing else bounds a withdrawn principal's
    /// access. The list is the same [`SharedRevocations`] the token verifiers
    /// accept, so one revoke call covers every mechanism of the install.
    pub fn with_shared_revocations(mut self, revocations: SharedRevocations) -> Self {
        self.revocations = revocations;
        self
    }

    /// The shared deny-list this verifier consults.
    pub fn revocations_shared(&self) -> SharedRevocations {
        std::sync::Arc::clone(&self.revocations)
    }

    /// Revoke every credential an actor holds on this verifier's deny-list.
    /// Returns whether the entry was written.
    pub fn revoke_actor(&self, org: &OrgId, actor: &ActorId, issued_through: u64) -> bool {
        self.revocations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .revoke_actor(org, actor, issued_through)
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
        // Revocation second. A peer certificate carries no issue instant an
        // actor entry could be compared against, so the deny-list is consulted
        // with `now`: an entry revokes the principal from the instant it was
        // written onward, and a peer presented after that instant is refused
        // no matter how valid its chain. This is the check the token verifiers
        // always had and this path never consulted — the gap between
        // "revoke_actor returned true" and "the actor can no longer connect".
        if self
            .revocations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_revoked(
                None,
                &OrgId(peer.org.clone()),
                &ActorId(peer.actor.clone()),
                now,
            )
        {
            return Err(AuthError::Revoked);
        }
        // Checked here as well as by the terminator. A proxy that forgets to
        // reject an expired client certificate is a plausible misconfiguration,
        // and this is the cheapest place to make it not matter.
        if now > peer.not_after.saturating_add(self.leeway_secs) {
            return Err(AuthError::PeerExpired);
        }
        // The other end of the window, symmetrically: a proxy that forgets to
        // reject a certificate whose validity has not started yet is the same
        // class of misconfiguration, refused here so the omission does not
        // matter.
        if let Some(not_before) = peer.not_before {
            if now.saturating_add(self.leeway_secs) < not_before {
                return Err(AuthError::NotYetValid);
            }
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
    fn a_not_yet_valid_certificate_is_refused_here_too() {
        // The other end of the window. A verifier that checks expiry but not
        // validity start lets a certificate issued for next month authenticate
        // today whenever the terminator's own check is misconfigured.
        let m = verifier().with_leeway(30);
        let p =
            VerifiedPeer::attested_with_anchor(CA, "acme", "agent-7", NOW + 600, Some(NOW + 10));
        assert!(
            m.authenticate_peer(&p, NOW).is_ok(),
            "the window opened within leeway"
        );
        assert_eq!(
            m.authenticate_peer(&p, NOW - 60),
            Err(AuthError::NotYetValid)
        );
    }

    #[test]
    fn a_revoked_actor_is_refused_at_the_transport_boundary_too() {
        // `revoke_actor` used to answer tokens and never reach this path: a
        // principal the deployment had withdrawn kept connecting on the
        // strength of a valid certificate. Peer certificates are long-lived,
        // so the deny-list is the only thing that answers "this principal must
        // not connect any more" without waiting for expiry.
        let m = verifier();
        assert!(m.authenticate_peer(&peer("acme", "agent-7"), NOW).is_ok());
        m.revoke_actor(&OrgId("acme".into()), &ActorId("agent-7".into()), NOW);
        assert_eq!(
            m.authenticate_peer(&peer("acme", "agent-7"), NOW),
            Err(AuthError::Revoked)
        );
        // A different actor under the same authority is untouched.
        assert!(m.authenticate_peer(&peer("acme", "agent-9"), NOW).is_ok());
    }

    #[test]
    fn a_revocation_is_shared_by_every_verifier_pointed_at_the_same_list() {
        // The deployment fact, not a verifier detail: revoking on one verifier
        // must refuse on the other, the way it already does across the token
        // verifiers of a shared install.
        let shared = SharedRevocations::default();
        let a = verifier().with_shared_revocations(shared.clone());
        let b = verifier().with_shared_revocations(shared);
        assert!(a.authenticate_peer(&peer("acme", "agent-7"), NOW).is_ok());
        assert!(a.revoke_actor(&OrgId("acme".into()), &ActorId("agent-7".into()), NOW));
        assert_eq!(
            b.authenticate_peer(&peer("acme", "agent-7"), NOW),
            Err(AuthError::Revoked)
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
