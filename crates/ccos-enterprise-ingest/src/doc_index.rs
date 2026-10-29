//! Ingest -> [`GovernedDocumentMemory`] wiring.
//!
//! Trigger: a document is indexed right after a successful, tenant-scoped fetch
//! ([`KnowledgeSource::fetch`] returned a hash-pinned [`RawArtifact`]), not at promotion. This is
//! the smallest path that closes "ingest -> index -> governed recall"; promotion-time indexing
//! remains possible because the index is keyed by the same stable asset id and is rebuildable.
//!
//! * The tenant comes from the artifact itself and is wrapped in a [`TenantScope`] before any
//!   memory access; spaces are explicit.
//! * Indexing is opt-in: callers who never call this module keep the previous behaviour.
//! * Encoding budget: no encoder is imposed. [`lexical_only_memory`] gives a BM25-only index
//!   ([`LexicalOnly`] never produces vectors); dense/fused needs an encoder injected by the caller
//!   through [`GovernedDocumentMemory::new`].
//! * Optional [`IngestGuard`](ccos_enterprise_docmemory::IngestGuard): built by the caller with a
//!   calibrated scorer via [`GovernedDocumentMemory::with_guard`]; nothing here builds a guard.
//!   Flagged / blank / non-UTF-8 documents are reported as refusals and never indexed.
//! * Results of recall still have to pass `admit_governed_recall`.

use std::fmt;

use ccos_core::doc_memory::{DocRankConfig, RankMode};
use ccos_core::retrieval::Encoder;
use ccos_enterprise_docmemory::{
    DocumentMemoryError, GovernedDocumentMemory, GovernedDocumentWrite, IngestScorer,
};
use ccos_enterprise_memory::{MemoryAssetId, MemorySpace};
use ccos_enterprise_tenancy::TenantScope;

use crate::{IngestError, KnowledgeSource, RawArtifact};

/// Encoder for lexical-only indexing: produces no vector. Only valid with [`RankMode::Lexical`].
#[derive(Debug, Clone, Copy, Default)]
pub struct LexicalOnly;

impl Encoder for LexicalOnly {
    fn embedding_dim(&self) -> usize {
        0
    }
    fn encode(&mut self, _text: &str) -> Vec<f32> {
        Vec::new()
    }
}

/// Lexical-only governed memory alias.
pub type LexicalDocumentMemory = GovernedDocumentMemory<LexicalOnly, fn() -> LexicalOnly>;

/// BM25-only governed document memory (no dense encoding cost).
pub fn lexical_only_memory() -> LexicalDocumentMemory {
    GovernedDocumentMemory::new(
        (|| LexicalOnly) as fn() -> LexicalOnly,
        DocRankConfig {
            mode: RankMode::Lexical,
            ..Default::default()
        },
    )
}

/// Stable governed asset id of an artifact (derived from its tenant-scoped source id).
pub fn artifact_asset_id(artifact: &RawArtifact) -> Result<MemoryAssetId, ArtifactIndexError> {
    MemoryAssetId::new(format!("artifact:{}", artifact.source_id.as_str()))
        .map_err(|e| ArtifactIndexError::Memory(DocumentMemoryError::Memory(e)))
}

#[derive(Debug, Clone, PartialEq)]
pub enum ArtifactIndexError {
    NonUtf8,
    Memory(DocumentMemoryError),
}

impl fmt::Display for ArtifactIndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonUtf8 => write!(f, "artifact is not UTF-8 text; not indexed"),
            Self::Memory(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ArtifactIndexError {}

impl From<DocumentMemoryError> for ArtifactIndexError {
    fn from(e: DocumentMemoryError) -> Self {
        Self::Memory(e)
    }
}

/// Index one fetched artifact under its own tenant, in `space`. Returns the asset id.
pub fn index_artifact<E: Encoder, F: Fn() -> E, S: IngestScorer>(
    memory: &mut GovernedDocumentMemory<E, F, S>,
    artifact: &RawArtifact,
    space: &MemorySpace,
) -> Result<MemoryAssetId, ArtifactIndexError> {
    let text = std::str::from_utf8(&artifact.bytes).map_err(|_| ArtifactIndexError::NonUtf8)?;
    let asset_id = artifact_asset_id(artifact)?;
    memory.insert_document(TenantScope::new(
        artifact.tenant.clone(),
        GovernedDocumentWrite {
            asset_id: &asset_id,
            space,
            text,
        },
    ))?;
    Ok(asset_id)
}

/// Outcome of [`ingest_and_index`]. Refusals are kept, never silently dropped.
#[derive(Debug, Default)]
pub struct IndexReport {
    pub indexed: Vec<(RawArtifact, MemoryAssetId)>,
    pub refused: Vec<(RawArtifact, ArtifactIndexError)>,
}

/// Enumerate + fetch every artifact of `source`, indexing each successful fetch. Source errors
/// (I/O, limits, escapes) abort; per-document index refusals are reported in [`IndexReport`].
pub fn ingest_and_index<K, E, F, S>(
    source: &K,
    memory: &mut GovernedDocumentMemory<E, F, S>,
    space: &MemorySpace,
) -> Result<IndexReport, IngestError>
where
    K: KnowledgeSource,
    E: Encoder,
    F: Fn() -> E,
    S: IngestScorer,
{
    let mut report = IndexReport::default();
    for d in source.enumerate()? {
        let artifact = source.fetch(&d)?;
        match index_artifact(memory, &artifact, space) {
            Ok(id) => report.indexed.push((artifact, id)),
            Err(e) => report.refused.push((artifact, e)),
        }
    }
    Ok(report)
}
