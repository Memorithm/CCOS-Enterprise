//! # Governed document memory
//!
//! Puts Core [`DocumentMemory`] (BM25 / dense / fused, the path measured by the BEIR campaigns)
//! behind the Enterprise governed recall path. Closes the "front 3" gap of
//! `docs/roadmap/2026-10-28-fronts-map.md`: until now `DocumentMemory` was only reachable from
//! campaign examples.
//!
//! Contracts:
//! * **Tenant + space isolation first.** Every write and query carries a [`TenantScope`]; each
//!   `(tenant, space)` pair owns its own `DocumentMemory` (own BM25 statistics, own vectors). A
//!   query can only reach the spaces of its explicit [`MemoryLoadout`] inside its own tenant.
//! * **Identity preserved.** Results are [`GovernedMemoryObservation`]s keyed by the CCOS
//!   [`MemoryAssetId`], so they must still pass `admit_governed_recall` (trust, lineage,
//!   quarantine) before reaching a context. Scores are ordering data only, never authority.
//! * **Fail-closed ingest.** Blank text is rejected. An optional [`IngestGuard`] wraps a calibrated
//!   Core [`ConformalGuard`] over an injected nonconformity scorer; flagged documents are refused
//!   and never indexed. An uncalibrated guard (threshold `+inf`, Core's fail-open state) is
//!   rejected at construction instead of silently accepting everything.
//! * **No persistence here.** The index is in-memory and rebuildable from governed assets; where
//!   it is persisted is a separate architecture decision (see roadmap).
//!
//! Cross-space merge: each space ranks independently (fused scores are min-max normalised per
//! space), then candidates are merged by score desc, asset id asc. With a single-space loadout the
//! ranking is exactly `DocumentMemory::rank` (parity test).

use std::collections::BTreeMap;
use std::fmt;

use ccos_core::conformal::ConformalGuard;
use ccos_core::doc_memory::{DocRankConfig, DocumentMemory};
use ccos_core::retrieval::Encoder;
use ccos_enterprise_memory::{
    GovernedMemoryObservation, MemoryAssetId, MemoryError, MemoryLoadout, MemorySpace,
};
use ccos_enterprise_tenancy::{TenantId, TenantScope};

/// One document to index under a governed asset identity.
#[derive(Debug, Clone, Copy)]
pub struct GovernedDocumentWrite<'a> {
    pub asset_id: &'a MemoryAssetId,
    pub space: &'a MemorySpace,
    pub text: &'a str,
}

/// A text query over an explicit loadout.
#[derive(Debug, Clone, Copy)]
pub struct DocumentRecallQuery<'a> {
    pub text: &'a str,
    pub k: usize,
    pub loadout: &'a MemoryLoadout,
}

/// Nonconformity score of a document at ingest (higher = more anomalous), e.g. an injection
/// classifier probability. Must be calibrated on the same scale as the guard.
pub trait IngestScorer {
    fn nonconformity(&mut self, text: &str) -> f64;
}

impl<F: FnMut(&str) -> f64> IngestScorer for F {
    fn nonconformity(&mut self, text: &str) -> f64 {
        self(text)
    }
}

/// A calibrated conformal check applied before indexing.
pub struct IngestGuard<S: IngestScorer> {
    guard: ConformalGuard,
    scorer: S,
}

impl<S: IngestScorer> IngestGuard<S> {
    /// Refuses an uncalibrated guard (too few benign samples => `+inf` threshold => fail-open).
    pub fn new(guard: ConformalGuard, scorer: S) -> Result<Self, DocumentMemoryError> {
        if !guard.threshold().is_finite() {
            return Err(DocumentMemoryError::UncalibratedGuard);
        }
        Ok(Self { guard, scorer })
    }

    pub fn alarm_bound(&self) -> f64 {
        self.guard.alarm_bound()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum DocumentMemoryError {
    Memory(MemoryError),
    EmptyDocument,
    EmptyQuery,
    UncalibratedGuard,
    /// The ingest guard flagged the document; it was not indexed.
    Flagged {
        score: f64,
        threshold: f64,
    },
}

impl fmt::Display for DocumentMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memory(e) => write!(f, "{e}"),
            Self::EmptyDocument => write!(f, "document text must not be blank"),
            Self::EmptyQuery => write!(f, "query text must not be blank"),
            Self::UncalibratedGuard => {
                write!(f, "ingest guard is not calibrated (fail-open refused)")
            }
            Self::Flagged { score, threshold } => {
                write!(
                    f,
                    "ingest guard flagged document: score {score} > threshold {threshold}"
                )
            }
        }
    }
}

impl std::error::Error for DocumentMemoryError {}

impl From<MemoryError> for DocumentMemoryError {
    fn from(e: MemoryError) -> Self {
        Self::Memory(e)
    }
}

struct Partition<E: Encoder> {
    memory: DocumentMemory<E>,
    by_asset: BTreeMap<MemoryAssetId, u64>,
    by_slot: BTreeMap<u64, MemoryAssetId>,
    // Payload copy kept in the adapter so Core `DocumentMemory` stays unchanged.
    texts: BTreeMap<u64, String>,
    next: u64,
}

/// Tenant/space-partitioned `DocumentMemory`. `make_encoder` builds the (identical) encoder for
/// each new partition, so a fitted campaign encoder can be injected unchanged.
pub struct GovernedDocumentMemory<E: Encoder, F: Fn() -> E, S: IngestScorer = fn(&str) -> f64> {
    make_encoder: F,
    config: DocRankConfig,
    guard: Option<IngestGuard<S>>,
    partitions: BTreeMap<(TenantId, MemorySpace), Partition<E>>,
}

impl<E: Encoder, F: Fn() -> E> GovernedDocumentMemory<E, F> {
    pub fn new(make_encoder: F, config: DocRankConfig) -> Self {
        Self {
            make_encoder,
            config,
            guard: None,
            partitions: BTreeMap::new(),
        }
    }
}

impl<E: Encoder, F: Fn() -> E, S: IngestScorer> GovernedDocumentMemory<E, F, S> {
    pub fn with_guard(make_encoder: F, config: DocRankConfig, guard: IngestGuard<S>) -> Self {
        Self {
            make_encoder,
            config,
            guard: Some(guard),
            partitions: BTreeMap::new(),
        }
    }

    /// Insert or replace a document. Guard runs before any state change.
    pub fn insert_document(
        &mut self,
        scoped: TenantScope<GovernedDocumentWrite<'_>>,
    ) -> Result<(), DocumentMemoryError> {
        let w = scoped.inner;
        w.space.validate()?;
        if w.text.trim().is_empty() {
            return Err(DocumentMemoryError::EmptyDocument);
        }
        if let Some(g) = self.guard.as_mut() {
            let score = g.scorer.nonconformity(w.text);
            if score.is_nan() || g.guard.flags(score) {
                return Err(DocumentMemoryError::Flagged {
                    score,
                    threshold: g.guard.threshold(),
                });
            }
        }
        let key = (scoped.tenant, w.space.clone());
        let (make, config) = (&self.make_encoder, self.config);
        let p = self.partitions.entry(key).or_insert_with(|| Partition {
            memory: DocumentMemory::new(make(), config),
            by_asset: BTreeMap::new(),
            by_slot: BTreeMap::new(),
            texts: BTreeMap::new(),
            next: 0,
        });
        let slot = match p.by_asset.get(w.asset_id) {
            Some(s) => *s,
            None => {
                let s = p.next;
                p.next += 1;
                p.by_asset.insert(w.asset_id.clone(), s);
                p.by_slot.insert(s, w.asset_id.clone());
                s
            }
        };
        p.memory.upsert(slot, w.text);
        p.texts.insert(slot, w.text.to_string());
        Ok(())
    }

    /// Remove a document; returns whether it was present.
    pub fn delete_document(
        &mut self,
        tenant: &TenantId,
        space: &MemorySpace,
        asset_id: &MemoryAssetId,
    ) -> bool {
        let Some(p) = self.partitions.get_mut(&(tenant.clone(), space.clone())) else {
            return false;
        };
        match p.by_asset.remove(asset_id) {
            Some(slot) => {
                p.by_slot.remove(&slot);
                p.texts.remove(&slot);
                p.memory.delete(slot)
            }
            None => false,
        }
    }

    /// Live documents in one tenant space.
    pub fn len(&self, tenant: &TenantId, space: &MemorySpace) -> usize {
        self.partitions
            .get(&(tenant.clone(), space.clone()))
            .map_or(0, |p| p.memory.len())
    }

    /// Ranked observations over the loadout's spaces in the scoped tenant only. Output must still
    /// go through `admit_governed_recall`.
    pub fn recall_documents(
        &mut self,
        scoped: TenantScope<DocumentRecallQuery<'_>>,
    ) -> Result<Vec<GovernedMemoryObservation>, DocumentMemoryError> {
        let q = scoped.inner;
        if q.text.trim().is_empty() {
            return Err(DocumentMemoryError::EmptyQuery);
        }
        if q.k == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for space in q.loadout.spaces() {
            space.validate()?;
            let Some(p) = self
                .partitions
                .get_mut(&(scoped.tenant.clone(), space.clone()))
            else {
                continue;
            };
            for s in p.memory.rank(q.text, q.k) {
                let asset_id = p
                    .by_slot
                    .get(&s.id)
                    .cloned()
                    .ok_or(DocumentMemoryError::Memory(
                        MemoryError::InvalidConfiguration("document slot without asset id"),
                    ))?;
                let payload = p
                    .texts
                    .get(&s.id)
                    .map(|t| t.as_bytes().to_vec())
                    .unwrap_or_default();
                out.push(GovernedMemoryObservation {
                    asset_id,
                    space: space.clone(),
                    payload,
                    similarity: s.score,
                });
            }
        }
        out.sort_by(|a, b| {
            b.similarity
                .partial_cmp(&a.similarity)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.asset_id.cmp(&b.asset_id))
        });
        out.truncate(q.k);
        Ok(out)
    }
}
