//! # Flat document memory — a ranked-document recall path (not causal-region expansion).
//!
//! [`CcosMemory`](crate::CcosMemory) answers `recall` with the *causal region* around one entry
//! node. That is the right shape for a code graph and the wrong shape for a corpus of prose: the
//! 2026-10-27 BEIR campaign measured it at nDCG@10 ≈ 0 on SciFact because the region of a node in an
//! edge-less corpus is roughly one document. [`DocumentMemory`] is the dedicated path for that task:
//! every stored document is scored against the query and the result is a **flat ranking**.
//!
//! * **Lexical**: BM25 over the shared [`bm25_tokenize`] tokenizer, optionally with RM3-style
//!   pseudo-relevance feedback ([`PrfConfig`]).
//! * **Dense**: exact cosine search with an **injected** [`Encoder`], so a campaign can hand the
//!   memory arm the very same fitted encoder its dense baselines use (no opaque internal encoder).
//! * **Fused**: a convex combination of per-query min-max-normalised lexical and dense scores over the
//!   union of both candidate pools.
//!
//! Everything is deterministic: ties break on ascending id, iteration is over ordered maps. Deletes
//! and replacements take effect immediately (the lexical index is rebuilt lazily on the next query,
//! so corpus statistics never include removed text). No governance (tenant, ACL, lineage) is applied
//! here; callers must filter the corpus they insert.

use crate::retrieval::{bm25_tokenize, vector, Bm25Index, Encoder, Scored};
use std::collections::{BTreeMap, BTreeSet};

/// RM3-style pseudo-relevance feedback for the lexical path.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PrfConfig {
    /// Feedback documents taken from the first-pass ranking.
    pub fb_docs: usize,
    /// Expansion terms added to the query.
    pub fb_terms: usize,
    /// Weight of the original query in `[0, 1]`; `1 - orig_weight` goes to the expansion terms.
    pub orig_weight: f32,
    /// Terms whose document frequency exceeds this fraction of the corpus are never expansion terms
    /// (a stopword proxy, since the tokenizer keeps stopwords).
    pub max_df_ratio: f32,
}

/// How [`DocumentMemory::rank`] scores documents.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RankMode {
    /// BM25 only.
    Lexical,
    /// Injected encoder only (exact cosine).
    Dense,
    /// `(1 - alpha)·lexical + alpha·dense`, both min-max normalised over the candidate union of
    /// each side's top `pool`.
    Fused {
        /// Dense weight in `[0, 1]`.
        alpha: f32,
        /// Candidates taken from each side before fusion.
        pool: usize,
    },
}

/// Configuration for a [`DocumentMemory`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DocRankConfig {
    /// BM25 `k1`.
    pub k1: f32,
    /// BM25 `b`.
    pub b: f32,
    /// Scoring mode.
    pub mode: RankMode,
    /// Optional pseudo-relevance feedback on the lexical side.
    pub prf: Option<PrfConfig>,
}

impl Default for DocRankConfig {
    fn default() -> Self {
        Self {
            k1: 1.2,
            b: 0.75,
            mode: RankMode::Lexical,
            prf: None,
        }
    }
}

/// A flat, deterministic document store that ranks its documents for a query.
pub struct DocumentMemory<E: Encoder> {
    encoder: E,
    config: DocRankConfig,
    docs: BTreeMap<u64, String>,
    vectors: BTreeMap<u64, Vec<f32>>,
    lexical: Option<Bm25Index>,
}

impl<E: Encoder> DocumentMemory<E> {
    /// An empty memory using `encoder` for its dense side.
    pub fn new(encoder: E, config: DocRankConfig) -> Self {
        Self {
            encoder,
            config,
            docs: BTreeMap::new(),
            vectors: BTreeMap::new(),
            lexical: None,
        }
    }

    /// The injected encoder.
    pub fn encoder(&self) -> &E {
        &self.encoder
    }

    /// The active configuration.
    pub fn config(&self) -> DocRankConfig {
        self.config
    }

    /// Number of live documents.
    pub fn len(&self) -> usize {
        self.docs.len()
    }

    /// Whether no document is stored.
    pub fn is_empty(&self) -> bool {
        self.docs.is_empty()
    }

    /// Insert or replace document `id`.
    pub fn upsert(&mut self, id: u64, text: &str) {
        let v = vector::normalized(&self.encoder.encode(text));
        self.vectors.insert(id, v);
        self.docs.insert(id, text.to_string());
        self.lexical = None;
    }

    /// Remove document `id`; returns whether it was present.
    pub fn delete(&mut self, id: u64) -> bool {
        self.vectors.remove(&id);
        let hit = self.docs.remove(&id).is_some();
        if hit {
            self.lexical = None;
        }
        hit
    }

    fn lexical_index(&mut self) -> &Bm25Index {
        if self.lexical.is_none() {
            let mut idx = Bm25Index::new(self.config.k1, self.config.b);
            for (id, text) in &self.docs {
                idx.add(*id, text);
            }
            self.lexical = Some(idx);
        }
        self.lexical.as_ref().expect("built above")
    }

    fn lexical_rank(&mut self, query: &str, k: usize) -> Vec<Scored> {
        let prf = self.config.prf;
        let n_docs = self.docs.len();
        let first = self
            .lexical_index()
            .search(query, k.max(prf.map_or(0, |p| p.fb_docs)));
        let Some(p) = prf else {
            return first.into_iter().take(k).collect();
        };
        if first.is_empty() || p.fb_docs == 0 || p.fb_terms == 0 {
            return first.into_iter().take(k).collect();
        }
        // Relevance model: P(t|R) ∝ Σ_d P(t|d)·score(d) over the feedback docs.
        let fb: Vec<Scored> = first.iter().take(p.fb_docs).copied().collect();
        let total: f32 = fb
            .iter()
            .map(|s| s.score.max(0.0))
            .sum::<f32>()
            .max(f32::MIN_POSITIVE);
        let mut rm: BTreeMap<String, f32> = BTreeMap::new();
        for s in &fb {
            let toks = bm25_tokenize(&self.docs[&s.id]);
            if toks.is_empty() {
                continue;
            }
            let w = s.score.max(0.0) / total / toks.len() as f32;
            for t in toks {
                *rm.entry(t).or_insert(0.0) += w;
            }
        }
        let max_df = (p.max_df_ratio * n_docs as f32).max(1.0) as usize;
        let idx = self.lexical_index();
        let mut cands: Vec<(String, f32)> = rm
            .into_iter()
            .filter(|(t, _)| idx.doc_freq(t) <= max_df)
            .collect();
        cands.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(core::cmp::Ordering::Equal)
                .then(a.0.cmp(&b.0))
        });
        cands.truncate(p.fb_terms);
        let exp_sum: f32 = cands
            .iter()
            .map(|c| c.1)
            .sum::<f32>()
            .max(f32::MIN_POSITIVE);
        let q: BTreeSet<String> = bm25_tokenize(query).into_iter().collect();
        let mut terms: Vec<(String, f32)> = q
            .iter()
            .map(|t| (t.clone(), p.orig_weight / q.len().max(1) as f32))
            .collect();
        terms.extend(
            cands
                .into_iter()
                .map(|(t, w)| (t, (1.0 - p.orig_weight) * w / exp_sum)),
        );
        self.lexical_index().search_weighted(&terms, k)
    }

    fn dense_rank(&mut self, query: &str, k: usize) -> Vec<Scored> {
        let q = vector::normalized(&self.encoder.encode(query));
        let mut scored: Vec<Scored> = self
            .vectors
            .iter()
            .map(|(id, v)| Scored {
                id: *id,
                score: vector::dot(&q, v),
            })
            .collect();
        sort_scored(&mut scored);
        scored.truncate(k);
        scored
    }

    /// The top-`k` live documents for `query` under the configured [`RankMode`], score-descending
    /// with an ascending-id tie-break. A flat ranking: no causal expansion, no token budget.
    pub fn rank(&mut self, query: &str, k: usize) -> Vec<Scored> {
        if k == 0 || self.docs.is_empty() {
            return Vec::new();
        }
        match self.config.mode {
            RankMode::Lexical => self.lexical_rank(query, k),
            RankMode::Dense => self.dense_rank(query, k),
            RankMode::Fused { alpha, pool } => {
                let pool = pool.max(k);
                let lex = minmax(&self.lexical_rank(query, pool));
                let den = minmax(&self.dense_rank(query, pool));
                let ids: BTreeSet<u64> = lex.keys().chain(den.keys()).copied().collect();
                let mut fused: Vec<Scored> = ids
                    .into_iter()
                    .map(|id| Scored {
                        id,
                        score: (1.0 - alpha) * lex.get(&id).copied().unwrap_or(0.0)
                            + alpha * den.get(&id).copied().unwrap_or(0.0),
                    })
                    .collect();
                sort_scored(&mut fused);
                fused.truncate(k);
                fused
            }
        }
    }
}

fn sort_scored(v: &mut [Scored]) {
    v.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(core::cmp::Ordering::Equal)
            .then(a.id.cmp(&b.id))
    });
}

fn minmax(r: &[Scored]) -> BTreeMap<u64, f32> {
    let (lo, hi) = r
        .iter()
        .fold((f32::INFINITY, f32::NEG_INFINITY), |(l, h), s| {
            (l.min(s.score), h.max(s.score))
        });
    let span = hi - lo;
    r.iter()
        .map(|s| {
            (
                s.id,
                if span > 0.0 {
                    (s.score - lo) / span
                } else {
                    1.0
                },
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retrieval::{CcosEncoder, SemanticRetriever};

    fn corpus() -> Vec<String> {
        [
            "database connection timeout retry backoff",
            "cooking pasta with tomato sauce and basil",
            "network socket timeout errors on reconnect",
            "tomato basil soup recipe",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn mem(mode: RankMode, prf: Option<PrfConfig>) -> DocumentMemory<CcosEncoder> {
        let c = corpus();
        let mut m = DocumentMemory::new(
            CcosEncoder::fit(&c, 64),
            DocRankConfig {
                mode,
                prf,
                ..Default::default()
            },
        );
        for (i, d) in c.iter().enumerate() {
            m.upsert(i as u64, d);
        }
        m
    }

    fn ids(v: &[Scored]) -> Vec<u64> {
        v.iter().map(|s| s.id).collect()
    }

    #[test]
    fn ranks_every_matching_document_not_one_region() {
        let mut m = mem(RankMode::Lexical, None);
        let r = ids(&m.rank("timeout", 10));
        assert_eq!(r.len(), 2);
        assert!(r.contains(&0) && r.contains(&2));
        assert_eq!(ids(&m.rank("pasta sauce", 1)), vec![1]);
    }

    #[test]
    fn lexical_matches_plain_bm25() {
        let c = corpus();
        let mut b = Bm25Index::new(1.2, 0.75);
        for (i, d) in c.iter().enumerate() {
            b.add(i as u64, d);
        }
        let mut m = mem(RankMode::Lexical, None);
        assert_eq!(m.rank("tomato timeout", 10), b.search("tomato timeout", 10));
    }

    #[test]
    fn dense_uses_the_injected_encoder_like_a_dense_baseline() {
        let c = corpus();
        let mut base = SemanticRetriever::new(CcosEncoder::fit(&c, 64));
        for (i, d) in c.iter().enumerate() {
            base.index_text(i as u64, d).unwrap();
        }
        let mut m = mem(RankMode::Dense, None);
        assert_eq!(
            ids(&m.rank("basil tomato", 4)),
            ids(&base.retrieve("basil tomato", 4))
        );
    }

    #[test]
    fn fused_endpoints_reduce_to_each_side() {
        let q = "timeout reconnect";
        let lex = ids(&mem(RankMode::Lexical, None).rank(q, 4));
        let f0 = ids(&mem(
            RankMode::Fused {
                alpha: 0.0,
                pool: 10,
            },
            None,
        )
        .rank(q, 2));
        assert_eq!(f0, lex[..2].to_vec());
        let den = ids(&mem(RankMode::Dense, None).rank(q, 1));
        assert_eq!(
            ids(&mem(
                RankMode::Fused {
                    alpha: 1.0,
                    pool: 10
                },
                None
            )
            .rank(q, 1)),
            den
        );
    }

    #[test]
    fn delete_and_replace_take_effect_and_refresh_statistics() {
        let mut m = mem(RankMode::Lexical, None);
        assert!(m.delete(0));
        assert!(!m.delete(0));
        assert_eq!(ids(&m.rank("timeout", 10)), vec![2]);
        m.upsert(2, "nothing relevant here");
        assert!(m.rank("timeout", 10).is_empty());
        assert_eq!(m.len(), 3);
    }

    #[test]
    fn prf_expands_with_feedback_terms_and_is_deterministic() {
        let prf = PrfConfig {
            fb_docs: 1,
            fb_terms: 3,
            orig_weight: 0.5,
            max_df_ratio: 1.0,
        };
        let mut m = mem(RankMode::Lexical, Some(prf));
        // "pasta" only hits doc 1; feedback terms (tomato/basil) pull in doc 3 as well.
        let r = m.rank("pasta", 10);
        assert_eq!(ids(&r)[0], 1);
        assert!(ids(&r).contains(&3));
        assert_eq!(r, m.rank("pasta", 10));
    }

    #[test]
    fn empty_and_zero_k() {
        let mut m = DocumentMemory::new(CcosEncoder::fit(&corpus(), 64), DocRankConfig::default());
        assert!(m.rank("x", 5).is_empty());
        let mut m = mem(RankMode::Lexical, None);
        assert!(m.rank("timeout", 0).is_empty());
    }
}
