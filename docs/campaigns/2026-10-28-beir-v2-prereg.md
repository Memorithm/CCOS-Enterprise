# Preregistration v2 — BEIR retrieval, `DocumentMemory` vs RAG baselines

Status: **preregistered, not yet run on any test split.** Supersedes nothing: v1
([prereg](2026-10-27-beir-retrieval-prereg.md), results in PR #218, primary negative) stays as is.
Run gate: the test split runs only once `DocumentMemory` (PR #219) is on `main`, from a binary built
from the merge commit with the harness file of this commit unchanged.

## What changed since v1

v1 measured `CcosMemory::recall` (a causal region around one entry node) at nDCG@10 ≈ 0.
v2 measures the new flat ranking path `ccos_core::doc_memory::DocumentMemory` (#219). Its dense side
receives **the same fitted `LsaEncoder` (d=512, rank 128)** used by the `lsa_dense` baseline (one
fit per dataset, cloned), so dense memory and dense baseline are encoder-matched.

## Data

Same BEIR SciFact / NFCorpus files and sha256 as v1. Tuning used **only the train qrels**
(`qrels/train.tsv`, presented to the strict importer as the evaluated split). SciFact has no dev
split. The test qrels were not read for tuning. The grid output is committed in
`2026-10-28-beir-v2-train-grid/`.

Train-grid readout (nDCG@10, train qrels):

| config | SciFact train | NFCorpus train |
|---|---|---|
| lexical (= BM25) | 0.6704 | 0.3031 |
| fused_lsa α=0.1 | **0.6735** (+0.0031) | 0.3003 (−0.003) |
| best PRF on SciFact (d=3 t=20 ow=0.7 df=0.25) | 0.6633 (−0.007) | — |
| best PRF on NFCorpus (d=5 t=20 ow=0.3 df=0.05) | — | **0.3259** (+0.023) |

Expectation stated now: on train, the best SciFact gain (+0.003) is **below** the +0.01 bar. A
primary success on test is therefore not expected.

## Frozen arms (`core/examples/beir_campaign_v2.rs`)

Baselines: bm25 (k1=1.2, b=0.75), tfidf_dense (d=512), lsa_dense (d=512/r=128),
hybrid_bm25_lsa_rrf (k=60). Memory arms: docmem_lexical (sanity: must equal bm25),
docmem_dense_lsa (sanity: must equal lsa_dense up to ties), docmem_prf
(fb_docs=5, fb_terms=20, orig_weight=0.3, max_df_ratio=0.05; frozen from NFCorpus train),
**docmem_fused_lsa** (α=0.1, pool=100; frozen from SciFact train) and docmem_prf_fused_lsa.
Depth 100. Nothing is tuned on test.

## Decision rule

- **Primary:** SciFact test nDCG@10, `docmem_fused_lsa` vs `bm25`. Success only if the mean
  paired delta is ≥ +0.01 **and** the 95% paired percentile bootstrap lower bound is > 0 for seeds
  1, 2 and 3 (10,000 query resamples). Otherwise: "no improvement shown".
- **Secondary, exploratory (no multiplicity correction):** all other arms vs bm25 on both
  datasets. The NFCorpus docmem_prf result is the pre-stated secondary of interest.
- Sanity failures (docmem_lexical ≠ bm25) invalidate the run and are reported.
- Determinism: two runs per dataset with byte-identical stdout (sha256 recorded).
- Negatives kept: every judged query counts; no query, arm or dataset is dropped.
- `superiority_claim: false` in every case. This is retrieval only. The end-to-end RAG campaign is
  still blocked (no generator or adjudication), and SML-GENIUS is still deferred.
