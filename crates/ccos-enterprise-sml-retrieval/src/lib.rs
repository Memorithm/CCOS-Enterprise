//! # SML retrieval adapter (concurrent arm)
//!
//! Contract for plugging an SML-GENIUS / GROK-ICM retriever into the Enterprise governed
//! recall path as a **concurrent alternative arm** next to `ccos-enterprise-docmemory`
//! (`GovernedDocumentMemory`, lexical default / fused MiniLM validated by BEIR #239).
//!
//! Status (2026-10-29): SML-GENIUS `main` (`d9ba318`) exposes GROK-ICM as an *integrity*
//! layer (`sml_core::icm_guard::GuardedPage`, SECDED(72,64)+CRC-32, feature `icm`). It has
//! **no text-query → ranked-document API**. This crate therefore ships the trait, the
//! governance wrapper and a fail-closed [`UnavailableSmlRetrieval`] backend; it fabricates no
//! scores and does not depend on SML yet. See
//! `docs/roadmap/2026-10-29-sml-retrieval-concurrent-arm.md`.
//!
//! Contracts:
//! * The adapter never touches `DocumentMemory`; selecting it is an explicit caller choice.
//! * Every request carries a `TenantScope` and an explicit [`MemoryLoadout`]; candidates
//!   outside the loadout, non-finite scores or duplicate ids make the whole recall fail closed.
//! * Output is [`GovernedMemoryObservation`]s that must still pass `admit_governed_recall`.
//!   Scores are ordering data only, never authority.

use std::collections::BTreeSet;
use std::fmt;

use ccos_enterprise_memory::{
    GovernedMemoryObservation, MemoryAssetId, MemoryError, MemoryLoadout, MemorySpace,
};
use ccos_enterprise_tenancy::TenantId;
#[cfg(feature = "concurrent-arm")]
use ccos_enterprise_tenancy::TenantScope;

/// Stable arm label for preregistered campaigns (never reuse for another backend).
pub const SML_CONCURRENT_ARM_ID: &str = "sml-grok-icm-concurrent";

/// A text query over an explicit loadout.
#[derive(Debug, Clone, Copy)]
pub struct SmlRetrievalRequest<'a> {
    pub text: &'a str,
    pub k: usize,
    pub loadout: &'a MemoryLoadout,
}

/// One scored candidate as produced by a backend.
#[derive(Debug, Clone, PartialEq)]
pub struct SmlRetrievalCandidate {
    pub asset_id: MemoryAssetId,
    pub space: MemorySpace,
    pub payload: Vec<u8>,
    pub score: f32,
}

impl From<SmlRetrievalCandidate> for GovernedMemoryObservation {
    fn from(c: SmlRetrievalCandidate) -> Self {
        GovernedMemoryObservation {
            asset_id: c.asset_id,
            space: c.space,
            payload: c.payload,
            similarity: c.score,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SmlRetrievalError {
    EmptyQuery,
    /// The backend has no ranking capability (current SML-GENIUS state).
    BackendUnavailable(&'static str),
    Backend(String),
    SpaceOutsideLoadout(MemoryAssetId),
    NonFiniteScore(MemoryAssetId),
    DuplicateAsset(MemoryAssetId),
    Memory(MemoryError),
}

impl fmt::Display for SmlRetrievalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyQuery => write!(f, "empty query"),
            Self::BackendUnavailable(why) => write!(f, "SML retrieval backend unavailable: {why}"),
            Self::Backend(e) => write!(f, "SML retrieval backend error: {e}"),
            Self::SpaceOutsideLoadout(id) => write!(f, "candidate {id:?} outside loadout"),
            Self::NonFiniteScore(id) => write!(f, "candidate {id:?} has non-finite score"),
            Self::DuplicateAsset(id) => write!(f, "duplicate candidate {id:?}"),
            Self::Memory(e) => write!(f, "memory error: {e:?}"),
        }
    }
}

impl std::error::Error for SmlRetrievalError {}

impl From<MemoryError> for SmlRetrievalError {
    fn from(e: MemoryError) -> Self {
        Self::Memory(e)
    }
}

/// Backend contract. Implementations receive the already-scoped tenant and must only return
/// candidates of that tenant; the wrapper re-checks loadout, scores and ids.
pub trait SmlRetrievalAdapter {
    /// Stable backend identifier (recorded in campaign artefacts).
    fn backend_id(&self) -> &'static str;

    fn retrieve(
        &mut self,
        tenant: &TenantId,
        request: SmlRetrievalRequest<'_>,
    ) -> Result<Vec<SmlRetrievalCandidate>, SmlRetrievalError>;
}

/// Fail-closed backend: the honest state until SML-GENIUS exposes a ranking API.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableSmlRetrieval;

impl SmlRetrievalAdapter for UnavailableSmlRetrieval {
    fn backend_id(&self) -> &'static str {
        "sml-unavailable"
    }

    fn retrieve(
        &mut self,
        _tenant: &TenantId,
        _request: SmlRetrievalRequest<'_>,
    ) -> Result<Vec<SmlRetrievalCandidate>, SmlRetrievalError> {
        Err(SmlRetrievalError::BackendUnavailable(
            "SML-GENIUS GROK-ICM has no document ranking API yet",
        ))
    }
}

/// Governance wrapper turning any [`SmlRetrievalAdapter`] into a concurrent recall arm.
#[cfg(feature = "concurrent-arm")]
#[derive(Debug)]
pub struct GovernedSmlRetrieval<A: SmlRetrievalAdapter> {
    adapter: A,
}

#[cfg(feature = "concurrent-arm")]
impl<A: SmlRetrievalAdapter> GovernedSmlRetrieval<A> {
    pub fn new(adapter: A) -> Self {
        Self { adapter }
    }

    pub fn arm_id(&self) -> &'static str {
        SML_CONCURRENT_ARM_ID
    }

    pub fn backend_id(&self) -> &'static str {
        self.adapter.backend_id()
    }

    /// Ranked observations (score desc, asset id asc, at most `k`). Output must still go
    /// through `admit_governed_recall`.
    pub fn recall(
        &mut self,
        scoped: TenantScope<SmlRetrievalRequest<'_>>,
    ) -> Result<Vec<GovernedMemoryObservation>, SmlRetrievalError> {
        let q = scoped.inner;
        if q.text.trim().is_empty() {
            return Err(SmlRetrievalError::EmptyQuery);
        }
        if q.k == 0 {
            return Ok(Vec::new());
        }
        let allowed: BTreeSet<&MemorySpace> = q.loadout.spaces().collect();
        for s in &allowed {
            s.validate()?;
        }
        let candidates = self.adapter.retrieve(&scoped.tenant, q)?;
        validate_candidates(&allowed, &candidates)?;
        let mut out: Vec<GovernedMemoryObservation> =
            candidates.into_iter().map(Into::into).collect();
        out.sort_by(|a, b| {
            b.similarity
                .total_cmp(&a.similarity)
                .then_with(|| a.asset_id.cmp(&b.asset_id))
        });
        out.truncate(q.k);
        Ok(out)
    }
}

/// Fail-closed checks applied to backend output (public for campaign harnesses).
pub fn validate_candidates(
    allowed: &BTreeSet<&MemorySpace>,
    candidates: &[SmlRetrievalCandidate],
) -> Result<(), SmlRetrievalError> {
    let mut seen = BTreeSet::new();
    for c in candidates {
        if !allowed.contains(&c.space) {
            return Err(SmlRetrievalError::SpaceOutsideLoadout(c.asset_id.clone()));
        }
        if !c.score.is_finite() {
            return Err(SmlRetrievalError::NonFiniteScore(c.asset_id.clone()));
        }
        if !seen.insert(&c.asset_id) {
            return Err(SmlRetrievalError::DuplicateAsset(c.asset_id.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_backend_fails_closed_without_feature() {
        let tenant = TenantId::new("acme").unwrap();
        let loadout = MemoryLoadout::tenant_only();
        let r = UnavailableSmlRetrieval.retrieve(
            &tenant,
            SmlRetrievalRequest {
                text: "q",
                k: 3,
                loadout: &loadout,
            },
        );
        assert!(matches!(r, Err(SmlRetrievalError::BackendUnavailable(_))));
    }

    #[test]
    fn candidate_converts_preserving_identity_and_score() {
        let id = MemoryAssetId::new("memory:asset:1").unwrap();
        let o: GovernedMemoryObservation = SmlRetrievalCandidate {
            asset_id: id.clone(),
            space: MemorySpace::Tenant,
            payload: b"x".to_vec(),
            score: 0.5,
        }
        .into();
        assert_eq!((o.asset_id, o.similarity), (id, 0.5));
    }
}
