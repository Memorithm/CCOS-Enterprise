//! Revocation and replay suppression.
//!
//! Both answer questions a signature cannot. A signature says the issuer minted
//! this credential; it says nothing about whether the issuer has since changed
//! its mind, or whether the bearer is the party the issuer minted it for.
//!
//! ## Why these are bounded, and what happens when the bound is reached
//!
//! Every structure here holds attacker-influenced keys, so every one of them
//! has a cap and prunes on expiry. A store that grows with traffic is a way to
//! take the deployment down by presenting credentials, and an audit `Vec` that
//! grew without limit is a defect this product has already had once.
//!
//! When a cap is reached after pruning, the answer is **refusal**, never
//! eviction. Evicting the oldest entry from a replay set is how a full set
//! stops suppressing replays — exactly when it is under the load that suggests
//! somebody is trying. Refusing is a denial of service against tokens that
//! would otherwise be admitted; admitting is a denial of the property the
//! structure exists to provide. The first is recoverable and visible.

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::{ActorId, AuthError, OrgId};

/// How many revoked token ids one deny-list holds.
///
/// Entries leave on their own when the token they name expires, so this bounds
/// how many *unexpired* tokens an operator can revoke individually — well past
/// what a human incident response produces, and far short of memory pressure.
pub const MAX_REVOKED_TOKENS: usize = 65_536;

/// How many actors one deny-list holds. Actor revocations do not expire on
/// their own (see [`Revocations::revoke_actor`]), so this is the real ceiling.
pub const MAX_REVOKED_ACTORS: usize = 65_536;

/// How many unexpired token ids one replay guard remembers.
pub const MAX_REPLAY_ENTRIES: usize = 1_048_576;

/// The deployment's answer to "this credential is no longer good", for
/// credentials already in the wild.
///
/// Key rotation was the only revocation this product had, and it is the wrong
/// tool twice over: it cannot revoke one token without revoking every token
/// that issuer signed, and it cannot revoke an actor at all.
///
/// Two granularities, because incidents come in two shapes:
///
/// * **A token leaked.** [`revoke_token`](Self::revoke_token) — one identifier,
///   dropped automatically once it expires.
/// * **An actor should no longer act.** [`revoke_actor`](Self::revoke_actor) —
///   every token issued at or before an instant, whatever its identifier. This
///   is the one that answers "somebody left the company", and it works on
///   credentials nobody has a copy of.
#[derive(Debug)]
pub struct Revocations {
    /// jti → the expiry of the token it names, so the entry can be pruned.
    tokens: BTreeMap<String, u64>,
    /// (org, actor) → tokens issued at or before this instant are refused.
    actors: BTreeMap<(String, String), u64>,
    max_tokens: usize,
    max_actors: usize,
}

impl Default for Revocations {
    fn default() -> Self {
        Self {
            tokens: BTreeMap::new(),
            actors: BTreeMap::new(),
            max_tokens: MAX_REVOKED_TOKENS,
            max_actors: MAX_REVOKED_ACTORS,
        }
    }
}

impl Revocations {
    /// An empty deny-list: nothing is revoked.
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty deny-list with explicit ceilings.
    ///
    /// The defaults are sized for a deployment nobody has measured. One that
    /// has — a large install revoking in bulk, or a small one on a memory
    /// budget — should say so rather than discover the ceiling during an
    /// incident.
    pub fn with_capacity(max_tokens: usize, max_actors: usize) -> Self {
        Self {
            max_tokens,
            max_actors,
            ..Self::default()
        }
    }

    /// Refuse one token by its identifier, until `expires_at` passes.
    ///
    /// `expires_at` is the token's own expiry, not a policy choice: past it the
    /// verifier refuses the token anyway, so holding the entry longer would
    /// spend memory to repeat an answer that is already `Expired`.
    ///
    /// Returns `false` if the deny-list is full — the caller is being told the
    /// revocation did **not** take effect, which is a fact an operator has to
    /// see. It is never silently dropped.
    pub fn revoke_token(&mut self, jti: &str, expires_at: u64, now: u64) -> bool {
        self.prune(now);
        if self.tokens.len() >= self.max_tokens && !self.tokens.contains_key(jti) {
            return false;
        }
        self.tokens.insert(jti.to_string(), expires_at);
        true
    }

    /// Refuse every token this actor holds that was issued at or before
    /// `issued_through`.
    ///
    /// Deliberately *not* self-pruning. A token-id entry can go when the token
    /// dies, because it names one credential; an actor entry has no such
    /// horizon — dropping it would silently re-admit an actor whose issuer is
    /// still minting. Removing it is [`restore_actor`](Self::restore_actor), an
    /// act somebody performs, not a timeout.
    ///
    /// Passing a later `issued_through` widens the revocation; an earlier one
    /// is ignored, so a stale call cannot narrow a revocation already in force.
    pub fn revoke_actor(&mut self, org: &OrgId, actor: &ActorId, issued_through: u64) -> bool {
        let key = (org.0.clone(), actor.0.clone());
        if let Some(existing) = self.actors.get_mut(&key) {
            *existing = (*existing).max(issued_through);
            return true;
        }
        if self.actors.len() >= self.max_actors {
            return false;
        }
        self.actors.insert(key, issued_through);
        true
    }

    /// Let an actor act again. Returns whether it had been revoked.
    pub fn restore_actor(&mut self, org: &OrgId, actor: &ActorId) -> bool {
        self.actors
            .remove(&(org.0.clone(), actor.0.clone()))
            .is_some()
    }

    /// Whether this credential is refused. `issued_at` is the token's own
    /// claim, which is why the token id is checked too: an actor revocation
    /// keyed on issue time cannot catch a token whose issuer back-dates it,
    /// and the token id can.
    ///
    /// `jti` is optional because an OIDC provider need not send one. A token
    /// without an identifier cannot be revoked individually — only its actor
    /// can be — and that is a property of the provider's format, not something
    /// to paper over by inventing an identifier that would differ between two
    /// presentations of the same credential.
    pub fn is_revoked(
        &self,
        jti: Option<&str>,
        org: &OrgId,
        actor: &ActorId,
        issued_at: u64,
    ) -> bool {
        if jti.is_some_and(|j| self.tokens.contains_key(j)) {
            return true;
        }
        self.actors
            .get(&(org.0.clone(), actor.0.clone()))
            .is_some_and(|through| issued_at <= *through)
    }

    /// Drop token entries whose tokens have expired.
    pub fn prune(&mut self, now: u64) {
        self.tokens.retain(|_, expires_at| *expires_at >= now);
    }

    /// Revoked token ids currently held.
    pub fn revoked_token_count(&self) -> usize {
        self.tokens.len()
    }

    /// Revoked actors currently held.
    pub fn revoked_actor_count(&self) -> usize {
        self.actors.len()
    }
}

/// Suppresses a second presentation of the same credential.
///
/// **Opt-in, and the reason matters.** An identity token is a bearer credential
/// valid for a window, and an agent presenting the same token on each of its
/// calls is not an attack — it is the normal shape of the thing. Making every
/// token single-use would break that and buy nothing, because the credential
/// would still be replayable for the one call the thief races the owner to.
///
/// Where it does pay is a token minted for a single operation: an
/// administrative action, an enrolment, a one-shot grant. There, a second
/// presentation is always either a thief or a bug, and both deserve a refusal.
///
/// What this is **not**: it does not make a stolen token useless, it makes it
/// useful once. A thief who presents it before the legitimate holder wins, and
/// the holder gets the refusal. That is a detection property as much as a
/// prevention one, and it is worth saying plainly rather than describing this
/// as replay protection and leaving somebody to assume more.
#[derive(Debug)]
pub struct ReplayGuard {
    seen: Mutex<BTreeMap<String, u64>>,
    capacity: usize,
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self {
            seen: Mutex::new(BTreeMap::new()),
            capacity: MAX_REPLAY_ENTRIES,
        }
    }
}

impl ReplayGuard {
    /// A guard that has seen nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// A guard with an explicit ceiling on unexpired identifiers.
    ///
    /// Worth setting deliberately: the ceiling is what a deployment is willing
    /// to spend to keep the promise, and reaching it means refusing tokens that
    /// would otherwise be admitted.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            ..Self::default()
        }
    }

    /// Record this token id as used, or refuse it as already used.
    ///
    /// `expires_at` sets how long the entry has to be remembered: exactly as
    /// long as the token could still be presented. A guard that forgot sooner
    /// would admit the replay it exists to refuse.
    pub fn witness(&self, jti: &str, expires_at: u64, now: u64) -> Result<(), AuthError> {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        seen.retain(|_, exp| *exp >= now);
        if seen.contains_key(jti) {
            return Err(AuthError::Replayed);
        }
        if seen.len() >= self.capacity {
            // Refusing, not evicting. An evicting guard stops suppressing
            // replays precisely when it is full, which is precisely when
            // somebody may be filling it.
            return Err(AuthError::ReplayCapacity);
        }
        seen.insert(jti.to_string(), expires_at);
        Ok(())
    }

    /// How many unexpired token ids are remembered. Pruning is lazy, so this
    /// reflects the last [`witness`](Self::witness) call rather than `now`.
    pub fn len(&self) -> usize {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Whether nothing is remembered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(org: &str, actor: &str) -> (OrgId, ActorId) {
        (OrgId(org.into()), ActorId(actor.into()))
    }

    const NOW: u64 = 1_700_000_000;

    #[test]
    fn a_revoked_token_stays_revoked_until_it_expires() {
        let mut r = Revocations::new();
        let (org, actor) = ids("acme", "agent-7");
        assert!(r.revoke_token("t-1", NOW + 600, NOW));
        assert!(r.is_revoked(Some("t-1"), &org, &actor, NOW));
        assert!(!r.is_revoked(Some("t-2"), &org, &actor, NOW));

        // Past its own expiry the entry is dropped: the verifier answers
        // `Expired` from then on, so holding it would spend memory to repeat an
        // answer already given.
        r.prune(NOW + 601);
        assert_eq!(r.revoked_token_count(), 0);
    }

    #[test]
    fn revoking_an_actor_kills_credentials_nobody_has_a_copy_of() {
        // The incident this exists for: somebody leaves, and the operator does
        // not know which tokens they hold.
        let mut r = Revocations::new();
        let (org, actor) = ids("acme", "agent-7");
        assert!(r.revoke_actor(&org, &actor, NOW));

        assert!(r.is_revoked(Some("unknown-a"), &org, &actor, NOW - 100));
        assert!(r.is_revoked(Some("unknown-b"), &org, &actor, NOW));
        assert!(r.is_revoked(None, &org, &actor, NOW));

        // A token the issuer mints *after* the revocation instant is not
        // covered — that is the operator re-issuing on purpose, and treating it
        // as revoked would make restoring an actor impossible.
        assert!(!r.is_revoked(Some("later"), &org, &actor, NOW + 1));

        // Keyed on the pair, so neither half alone is enough: the same actor
        // name in another organization is another actor, and a tenant that
        // revokes its `admin` must not revoke everybody else's.
        let (other_org, other_actor) = ids("globex", "agent-9");
        assert!(!r.is_revoked(Some("x"), &other_org, &actor, NOW));
        assert!(!r.is_revoked(Some("x"), &org, &other_actor, NOW));
    }

    #[test]
    fn a_stale_call_cannot_narrow_a_revocation_already_in_force() {
        // Two operators acting on the same incident, the second holding an
        // older timestamp. Taking the max means the wider revocation wins,
        // rather than the last writer.
        let mut r = Revocations::new();
        let (org, actor) = ids("acme", "agent-7");
        r.revoke_actor(&org, &actor, NOW);
        r.revoke_actor(&org, &actor, NOW - 3600);
        assert!(r.is_revoked(None, &org, &actor, NOW));
        assert_eq!(r.revoked_actor_count(), 1);
    }

    #[test]
    fn an_actor_revocation_does_not_expire_on_its_own() {
        // A token entry can go when the token dies. An actor entry has no such
        // horizon: dropping it would silently re-admit somebody whose issuer is
        // still minting.
        let mut r = Revocations::new();
        let (org, actor) = ids("acme", "agent-7");
        r.revoke_actor(&org, &actor, NOW);
        r.prune(NOW + 10 * 365 * 24 * 3600);
        assert!(r.is_revoked(None, &org, &actor, NOW));
        assert!(r.restore_actor(&org, &actor));
        assert!(!r.is_revoked(None, &org, &actor, NOW));
        assert!(!r.restore_actor(&org, &actor));
    }

    #[test]
    fn a_full_deny_list_says_so_instead_of_dropping_the_revocation() {
        // An operator who is told a revocation took effect when it did not has
        // been handed a false belief about a live credential.
        let mut r = Revocations::with_capacity(64, 64);
        for i in 0..64 {
            assert!(r.revoke_token(&format!("t-{i}"), NOW + 600, NOW));
        }
        assert!(!r.revoke_token("one-too-many", NOW + 600, NOW));
        // …but re-revoking something already on the list is not a new entry.
        assert!(r.revoke_token("t-0", NOW + 900, NOW));
    }

    #[test]
    fn a_second_presentation_is_refused_and_the_first_is_not() {
        let g = ReplayGuard::new();
        assert!(g.is_empty());
        assert_eq!(g.witness("t-1", NOW + 600, NOW), Ok(()));
        assert_eq!(g.witness("t-1", NOW + 600, NOW), Err(AuthError::Replayed));
        assert_eq!(g.witness("t-2", NOW + 600, NOW), Ok(()));
        assert_eq!(g.len(), 2);
    }

    #[test]
    fn the_guard_remembers_exactly_as_long_as_a_token_could_be_presented() {
        // Forgetting sooner would admit the replay it exists to refuse;
        // forgetting later spends memory on a token the verifier already
        // refuses as expired.
        let g = ReplayGuard::new();
        g.witness("t-1", NOW + 600, NOW).unwrap();
        assert_eq!(
            g.witness("t-1", NOW + 600, NOW + 600),
            Err(AuthError::Replayed)
        );
        // One second past expiry the entry is pruned — and the token is
        // refused by expiry rather than by this guard.
        g.witness("t-2", NOW + 600, NOW + 601).unwrap();
        assert_eq!(g.len(), 1, "the expired entry was pruned");
    }

    #[test]
    fn a_full_guard_refuses_rather_than_forgetting_what_it_has_seen() {
        // The property under load. An evicting guard stops suppressing replays
        // exactly when somebody may be filling it, and reports success while
        // doing so.
        let g = ReplayGuard::with_capacity(64);
        for i in 0..64 {
            g.witness(&format!("t-{i}"), NOW + 600, NOW).unwrap();
        }
        assert_eq!(
            g.witness("one-too-many", NOW + 600, NOW),
            Err(AuthError::ReplayCapacity)
        );
        // The credentials already witnessed are still witnessed: nothing was
        // evicted to make room.
        assert_eq!(g.witness("t-0", NOW + 600, NOW), Err(AuthError::Replayed));
    }

    #[test]
    fn expiring_entries_make_room_again() {
        let g = ReplayGuard::with_capacity(64);
        for i in 0..64 {
            g.witness(&format!("t-{i}"), NOW + 600, NOW).unwrap();
        }
        assert!(g.witness("new", NOW + 600, NOW).is_err());
        assert_eq!(g.witness("new", NOW + 1200, NOW + 601), Ok(()));
    }
}
