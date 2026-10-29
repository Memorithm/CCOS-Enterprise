//! Real SML-GENIUS backend (feature `sml-backend`): wraps
//! `sml_core::icm_rank::SignaturePageRanker` (sigpage-v0, Ochiai over ICM-guarded signature
//! pages). **Experimental, not BEIR-validated**; no retrieval-quality claim.

use std::collections::{BTreeMap, BTreeSet};

use ccos_enterprise_memory::{MemoryAssetId, MemorySpace};
use ccos_enterprise_tenancy::TenantId;
use sml_core::icm_rank::{
    DocumentRanker, RankError, RankedList, SignaturePageRanker, ValidationStatus, ARM_ID,
};

use crate::{
    SmlRetrievalAdapter, SmlRetrievalCandidate, SmlRetrievalError, SmlRetrievalRequest,
    SML_CONCURRENT_ARM_ID,
};

/// Evidence status propagated from SML (`ValidationStatus::NotBeirValidated`).
pub const SML_VALIDATION_STATUS: &str = "NotBeirValidated";

#[derive(Debug, Clone)]
struct Doc {
    space: MemorySpace,
    payload: Vec<u8>,
}

#[derive(Debug, Clone)]
struct TenantIndex {
    ranker: SignaturePageRanker,
    docs: BTreeMap<MemoryAssetId, Doc>,
}

/// Per-tenant `SignaturePageRanker` indexes. A tenant only ever ranks its own index.
#[derive(Debug, Clone)]
pub struct SmlSignaturePageAdapter {
    seed: u64,
    tenants: BTreeMap<TenantId, TenantIndex>,
    last_status: Option<ValidationStatus>,
}

impl SmlSignaturePageAdapter {
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            tenants: BTreeMap::new(),
            last_status: None,
        }
    }

    /// Index one document for `tenant`: `text` is signed into an ICM-guarded page, `payload` is
    /// returned verbatim on recall. Duplicate asset ids within a tenant are rejected.
    pub fn insert(
        &mut self,
        tenant: &TenantId,
        asset_id: MemoryAssetId,
        space: MemorySpace,
        text: &str,
        payload: Vec<u8>,
    ) -> Result<(), SmlRetrievalError> {
        space.validate()?;
        let seed = self.seed;
        let idx = self
            .tenants
            .entry(tenant.clone())
            .or_insert_with(|| TenantIndex {
                ranker: SignaturePageRanker::new(seed),
                docs: BTreeMap::new(),
            });
        if idx.docs.contains_key(&asset_id) {
            return Err(SmlRetrievalError::DuplicateAsset(asset_id));
        }
        idx.ranker
            .insert(asset_id.as_str(), text)
            .map_err(map_err)?;
        idx.docs.insert(asset_id, Doc { space, payload });
        Ok(())
    }

    /// Validation status of the last successful ranking (always `NotBeirValidated` today).
    pub fn last_validation_status(&self) -> Option<&'static str> {
        self.last_status.map(|s| match s {
            ValidationStatus::NotBeirValidated => SML_VALIDATION_STATUS,
        })
    }

    pub fn validation_status(&self) -> &'static str {
        SML_VALIDATION_STATUS
    }

    pub fn arm_id(&self) -> &'static str {
        SML_CONCURRENT_ARM_ID
    }
}

fn map_err(e: RankError) -> SmlRetrievalError {
    match e {
        RankError::EmptyQuery => SmlRetrievalError::EmptyQuery,
        RankError::Unavailable(why) => SmlRetrievalError::BackendUnavailable(why),
        other => SmlRetrievalError::Backend(other.to_string()),
    }
}

impl SmlRetrievalAdapter for SmlSignaturePageAdapter {
    fn backend_id(&self) -> &'static str {
        SignaturePageRanker::BACKEND_ID
    }

    fn retrieve(
        &mut self,
        tenant: &TenantId,
        request: SmlRetrievalRequest<'_>,
    ) -> Result<Vec<SmlRetrievalCandidate>, SmlRetrievalError> {
        let Some(idx) = self.tenants.get_mut(tenant) else {
            return Ok(Vec::new());
        };
        // Rank the whole tenant index, then filter to the loadout before the wrapper cuts at k,
        // so out-of-loadout documents never displace in-loadout ones.
        let n = idx.ranker.len();
        let list: RankedList = idx.ranker.rank(request.text, n).map_err(map_err)?;
        if list.arm_id != ARM_ID || ARM_ID != SML_CONCURRENT_ARM_ID {
            return Err(SmlRetrievalError::Backend(format!(
                "unexpected arm id {}",
                list.arm_id
            )));
        }
        self.last_status = Some(list.status);
        let allowed: BTreeSet<&MemorySpace> = request.loadout.spaces().collect();
        let mut out = Vec::new();
        for c in list.candidates {
            let asset_id = MemoryAssetId::new(c.id.clone())?;
            let doc = idx
                .docs
                .get(&asset_id)
                .ok_or_else(|| SmlRetrievalError::Backend(format!("unknown id {}", c.id)))?;
            if !c.score.is_finite() {
                return Err(SmlRetrievalError::NonFiniteScore(asset_id));
            }
            if !allowed.contains(&doc.space) {
                continue;
            }
            out.push(SmlRetrievalCandidate {
                asset_id,
                space: doc.space.clone(),
                payload: doc.payload.clone(),
                score: c.score,
            });
        }
        Ok(out)
    }
}
