//! Server-side ranking choice for `memory.document_recall`.
//!
//! The served document index is derived and rebuilt from governed assets. By default it is
//! **lexical-only** (BM25, [`LexicalOnly`] encoder, no vectors): exactly the behaviour shipped in
//! #237. A deployment may inject a CPU [`Encoder`] (e.g. the pure-Rust all-MiniLM-L6-v2 of
//! `ccos-dense-encoder`, no GPU / CUDA) and select `dense` or `fused` ranking. The chosen mode is
//! reported honestly in every response (`ranking`, plus `ranking_alpha` / `ranking_pool` when
//! fused); no retrieval-quality metric is claimed by the server.
//!
//! Security order is unchanged: ranking only orders candidates, every result still passes
//! `admit_governed_recall` and the context budget in [`recall_governed_documents`].

use std::fmt;
use std::sync::{Arc, Mutex};

use ccos_core::doc_memory::{DocRankConfig, RankMode};
use ccos_core::retrieval::Encoder;
use ccos_enterprise_docmemory::GovernedDocumentMemory;
use ccos_enterprise_ingest::doc_index::{lexical_only_memory, LexicalDocumentMemory};
use ccos_enterprise_memory::{
    GovernedMemoryContextAssembly, GovernedMemoryProjection, GovernedRecallTrustPolicy,
    MemoryContextBudget,
};
use ccos_enterprise_tenancy::TenantId;
use serde_json::{json, Value};

use crate::{recall_governed_documents, DocumentRecallError};

/// Default fused dense weight (the BEIR-validated configuration's α; not a served metric).
pub const DEFAULT_FUSED_ALPHA: f32 = 0.5;
/// Default candidates per side before fusion (campaign value).
pub const DEFAULT_FUSED_POOL: usize = 100;
const MAX_FUSED_POOL: usize = 10_000;

/// Ranking mode of the served document index.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DocumentRankingMode {
    /// BM25 only (default).
    LexicalBm25,
    /// Injected encoder only (cosine).
    Dense,
    /// `(1 - alpha)·bm25 + alpha·dense`, min-max normalised over each side's top `pool`.
    Fused { alpha: f32, pool: usize },
}

impl DocumentRankingMode {
    /// Wire label reported in `structuredContent.ranking`.
    pub fn label(&self) -> &'static str {
        match self {
            Self::LexicalBm25 => "lexical_bm25",
            Self::Dense => "dense",
            Self::Fused { .. } => "fused",
        }
    }

    pub fn needs_encoder(&self) -> bool {
        !matches!(self, Self::LexicalBm25)
    }

    fn rank_mode(&self) -> RankMode {
        match *self {
            Self::LexicalBm25 => RankMode::Lexical,
            Self::Dense => RankMode::Dense,
            Self::Fused { alpha, pool } => RankMode::Fused { alpha, pool },
        }
    }

    /// Parse operator configuration (e.g. env values). `None` mode means the default
    /// (`lexical_bm25`). `alpha` / `pool` are only accepted for `fused`.
    pub fn parse(
        mode: Option<&str>,
        alpha: Option<&str>,
        pool: Option<&str>,
    ) -> Result<Self, DocumentRankingConfigError> {
        let bad = |m: &str| DocumentRankingConfigError(m.to_string());
        let mode = match mode.map(str::trim) {
            None | Some("lexical_bm25") => Self::LexicalBm25,
            Some("dense") => Self::Dense,
            Some("fused") => {
                let alpha = match alpha {
                    None => DEFAULT_FUSED_ALPHA,
                    Some(v) => v
                        .trim()
                        .parse::<f32>()
                        .ok()
                        .filter(|a| a.is_finite() && (0.0..=1.0).contains(a))
                        .ok_or_else(|| bad("fused alpha must be a number in [0, 1]"))?,
                };
                let pool = match pool {
                    None => DEFAULT_FUSED_POOL,
                    Some(v) => v
                        .trim()
                        .parse::<usize>()
                        .ok()
                        .filter(|p| (1..=MAX_FUSED_POOL).contains(p))
                        .ok_or_else(|| bad("fused pool must be an integer in 1..=10000"))?,
                };
                return Ok(Self::Fused { alpha, pool });
            }
            Some(_) => return Err(bad("ranking must be lexical_bm25, dense or fused")),
        };
        if alpha.is_some() || pool.is_some() {
            return Err(bad("fused alpha/pool are only valid with ranking=fused"));
        }
        Ok(mode)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentRankingConfigError(pub String);

impl fmt::Display for DocumentRankingConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid document ranking configuration: {}", self.0)
    }
}

impl std::error::Error for DocumentRankingConfigError {}

/// One encoder instance shared by every tenant/space partition and every rebuild (loaded once
/// at boot). Cloning shares the instance; encoding is serialised by a mutex.
#[derive(Clone)]
pub struct SharedEncoder {
    inner: Arc<Mutex<Box<dyn Encoder + Send>>>,
    dim: usize,
}

impl SharedEncoder {
    pub fn new(encoder: Box<dyn Encoder + Send>) -> Self {
        let dim = encoder.embedding_dim();
        Self {
            inner: Arc::new(Mutex::new(encoder)),
            dim,
        }
    }
}

impl fmt::Debug for SharedEncoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedEncoder")
            .field("dim", &self.dim)
            .finish()
    }
}

impl Encoder for SharedEncoder {
    fn embedding_dim(&self) -> usize {
        self.dim
    }
    fn encode(&mut self, text: &str) -> Vec<f32> {
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.encode(text)
    }
    fn encode_batch(&mut self, texts: &[String]) -> Vec<Vec<f32>> {
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.encode_batch(texts)
    }
}

pub type EncoderFactory = Box<dyn Fn() -> SharedEncoder + Send>;
/// Governed document memory backed by an injected encoder.
pub type EncodedDocumentMemory = GovernedDocumentMemory<SharedEncoder, EncoderFactory>;

/// Boot-time ranking configuration: mode + optional encoder. Builds empty indexes for rebuilds.
#[derive(Debug, Clone)]
pub struct DocumentRanker {
    mode: DocumentRankingMode,
    encoder: Option<(SharedEncoder, String)>,
}

impl Default for DocumentRanker {
    fn default() -> Self {
        Self::lexical()
    }
}

impl DocumentRanker {
    /// Lexical-only BM25 (default, no encoder).
    pub fn lexical() -> Self {
        Self {
            mode: DocumentRankingMode::LexicalBm25,
            encoder: None,
        }
    }

    /// Dense or fused ranking with an injected encoder. `encoder_label` is an operator-facing
    /// identifier (e.g. `all-MiniLM-L6-v2`) echoed as `ranking_encoder`; it must not be a secret.
    pub fn with_encoder(
        mode: DocumentRankingMode,
        encoder: Box<dyn Encoder + Send>,
        encoder_label: impl Into<String>,
    ) -> Result<Self, DocumentRankingConfigError> {
        let bad = |m: &str| DocumentRankingConfigError(m.to_string());
        if !mode.needs_encoder() {
            return Err(bad("an encoder was supplied but ranking is lexical_bm25"));
        }
        if encoder.embedding_dim() == 0 {
            return Err(bad("encoder has embedding dimension 0"));
        }
        let label = encoder_label.into();
        if label.is_empty() || label.len() > 128 || label.chars().any(char::is_control) {
            return Err(bad("encoder label must be 1..=128 printable characters"));
        }
        Ok(Self {
            mode,
            encoder: Some((SharedEncoder::new(encoder), label)),
        })
    }

    pub fn mode(&self) -> DocumentRankingMode {
        self.mode
    }

    /// A fresh, empty index for this configuration (to be filled by
    /// `RecoveredGovernedMemory::rebuild_document_index`).
    pub fn empty_memory(&self) -> ServedDocumentMemory {
        match &self.encoder {
            None => ServedDocumentMemory {
                index: ServedIndex::Lexical(lexical_only_memory()),
                ranking: self.ranking_fields(),
            },
            Some((encoder, _)) => {
                let shared = encoder.clone();
                let factory: EncoderFactory = Box::new(move || shared.clone());
                ServedDocumentMemory {
                    index: ServedIndex::Encoded(GovernedDocumentMemory::new(
                        factory,
                        DocRankConfig {
                            mode: self.mode.rank_mode(),
                            ..Default::default()
                        },
                    )),
                    ranking: self.ranking_fields(),
                }
            }
        }
    }

    fn ranking_fields(&self) -> Value {
        let mut v = json!({ "ranking": self.mode.label() });
        if let DocumentRankingMode::Fused { alpha, pool } = self.mode {
            v["ranking_alpha"] = json!(alpha);
            v["ranking_pool"] = json!(pool);
        }
        if let Some((_, label)) = &self.encoder {
            v["ranking_encoder"] = json!(label);
        }
        v
    }
}

enum ServedIndex {
    Lexical(LexicalDocumentMemory),
    Encoded(EncodedDocumentMemory),
}

/// The served, derived document index (lexical or encoder-backed).
pub struct ServedDocumentMemory {
    index: ServedIndex,
    ranking: Value,
}

/// Borrowed index handed to a rebuild; dispatches on the concrete memory type.
pub enum ServedIndexMut<'a> {
    Lexical(&'a mut LexicalDocumentMemory),
    Encoded(&'a mut EncodedDocumentMemory),
}

impl ServedDocumentMemory {
    /// The concrete memory, for `rebuild_document_index`.
    pub fn index_mut(&mut self) -> ServedIndexMut<'_> {
        match &mut self.index {
            ServedIndex::Lexical(m) => ServedIndexMut::Lexical(m),
            ServedIndex::Encoded(m) => ServedIndexMut::Encoded(m),
        }
    }

    /// Governed recall (tenant check, bootstrap loadout, `admit_governed_recall`, budget).
    pub fn recall(
        &mut self,
        expected_tenant: &TenantId,
        projection: &GovernedMemoryProjection,
        policy: GovernedRecallTrustPolicy,
        query: &str,
        k: usize,
        context_budget: MemoryContextBudget,
    ) -> Result<GovernedMemoryContextAssembly, DocumentRecallError> {
        match &mut self.index {
            ServedIndex::Lexical(m) => recall_governed_documents(
                m,
                expected_tenant,
                projection,
                policy,
                query,
                k,
                context_budget,
            ),
            ServedIndex::Encoded(m) => recall_governed_documents(
                m,
                expected_tenant,
                projection,
                policy,
                query,
                k,
                context_budget,
            ),
        }
    }

    /// Writes `ranking` (and `ranking_alpha` / `ranking_pool` / `ranking_encoder` when set) into
    /// an MCP result's `structuredContent`.
    pub fn annotate(&self, result: &mut Value) {
        if let (Some(target), Some(fields)) = (
            result
                .get_mut("structuredContent")
                .and_then(Value::as_object_mut),
            self.ranking.as_object(),
        ) {
            for (k, v) in fields {
                target.insert(k.clone(), v.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed;
    impl Encoder for Fixed {
        fn embedding_dim(&self) -> usize {
            2
        }
        fn encode(&mut self, _t: &str) -> Vec<f32> {
            vec![1.0, 0.0]
        }
    }

    #[test]
    fn parse_defaults_to_lexical_and_rejects_ambiguity() {
        let p = DocumentRankingMode::parse;
        assert_eq!(p(None, None, None), Ok(DocumentRankingMode::LexicalBm25));
        assert_eq!(p(Some("dense"), None, None), Ok(DocumentRankingMode::Dense));
        assert_eq!(
            p(Some("fused"), None, None),
            Ok(DocumentRankingMode::Fused {
                alpha: 0.5,
                pool: 100
            })
        );
        assert_eq!(
            p(Some("fused"), Some("0.3"), Some("50")),
            Ok(DocumentRankingMode::Fused {
                alpha: 0.3,
                pool: 50
            })
        );
        for (m, a, k) in [
            (Some("bm25"), None, None),
            (Some("fused"), Some("1.5"), None),
            (Some("fused"), Some("NaN"), None),
            (Some("fused"), None, Some("0")),
            (None, Some("0.5"), None),
            (Some("dense"), None, Some("10")),
        ] {
            assert!(p(m, a, k).is_err(), "{m:?} {a:?} {k:?}");
        }
    }

    #[test]
    fn encoder_requires_non_lexical_mode_and_nonzero_dim() {
        assert!(DocumentRanker::with_encoder(
            DocumentRankingMode::LexicalBm25,
            Box::new(Fixed),
            "x"
        )
        .is_err());
        assert!(DocumentRanker::with_encoder(
            DocumentRankingMode::Dense,
            Box::new(ccos_enterprise_ingest::doc_index::LexicalOnly),
            "x"
        )
        .is_err());
        assert!(
            DocumentRanker::with_encoder(DocumentRankingMode::Dense, Box::new(Fixed), "").is_err()
        );
    }

    #[test]
    fn annotate_reports_mode_honestly() {
        let mut r = json!({"structuredContent": {}});
        DocumentRanker::lexical().empty_memory().annotate(&mut r);
        assert_eq!(r["structuredContent"], json!({"ranking": "lexical_bm25"}));
        let mut r = json!({"structuredContent": {}});
        DocumentRanker::with_encoder(
            DocumentRankingMode::Fused {
                alpha: 0.5,
                pool: 100,
            },
            Box::new(Fixed),
            "test-encoder",
        )
        .unwrap()
        .empty_memory()
        .annotate(&mut r);
        assert_eq!(
            r["structuredContent"],
            json!({"ranking": "fused", "ranking_alpha": 0.5, "ranking_pool": 100, "ranking_encoder": "test-encoder"})
        );
    }
}
