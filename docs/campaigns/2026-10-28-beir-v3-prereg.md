# Preregistration v3 — BEIR SciFact, `DocumentMemory` fused with a real dense encoder

Status: **preregistered, not yet run on any test split.** v1 and v2 stay as they are. v2's primary
(fused LSA) did not reach the bar, and LSA is **not** re-run here.
Run gate: the test split runs only after this document is merged to `main`. The binary is built from
that merge commit, with `crates/ccos-dense-encoder/examples/beir_campaign_v3.rs` unchanged from
this commit.

## What changed since v2

The dense side of `ccos_core::doc_memory::DocumentMemory` now gets a real pretrained sentence
encoder instead of LSA. It comes from the Enterprise crate `ccos-dense-encoder` (PR #227), behind
the unchanged `ccos_core::retrieval::Encoder` trait. Core is untouched.

| item | frozen value |
|---|---|
| model | `sentence-transformers/all-MiniLM-L6-v2`, HF revision `c9745ed1d9f207416be6d2e6f8de32d1f16199bf` |
| files (sha256) | pinned in `crates/ccos-dense-encoder/fetch-model.sh` (config.json, tokenizer.json, model.safetensors) |
| dim | 384 (6 layers, 12 heads, hidden 384, FFN 1536, exact GELU, LayerNorm eps 1e-12) |
| backend | pure safe Rust, CPU, f32. No CUDA/NVIDIA, no candle, no `tokenizers` crate |
| preprocessing | BERT uncased WordPiece (clean text, CJK split, accent strip, lower-case); `[CLS] … [SEP]`; truncation 256 tokens; no padding; mean pooling; L2 normalisation |
| validation | oracle test vs sentence-transformers 3.3.1 (cos > 0.9999, max abs diff < 1e-3). Token ids matched HF on all 13,162 SciFact+NFCorpus corpus/query texts (local one-off check, 0 mismatches) |

## Data and anti-leakage

These are the same BEIR files as v1 and v2.

| file | sha256 |
|---|---|
| SciFact `corpus.jsonl` | `dec31c8182f3d744c7d2c09423756fd1d17cbef75808db13ba01cc0aab4d1ac6` |
| SciFact `queries.jsonl` | `8ff84a7c903f722981cd8d595c022660140c51867b27608a6d4910db86080313` |
| SciFact `qrels/test.tsv` | `0864bb985e0ca2367ba217977e72004d549054b2b06666ed9d4825ac7c21284c` |
| SciFact `qrels/train.tsv` | `a53f2114831916c096b6c37d9e54da68cef4efdcdbd5ed46533601af972acf1d` |
| NFCorpus `qrels/test.tsv` | `f8fba6ef3d4dd9c3a242a8ba4ae38276fc3622fce7dcbae764766d564542fd2a` |

- Tuning used **only the SciFact train qrels** (809 queries, 919 rows). They were presented to the
  strict importer as the evaluated split. The test qrels were never read for tuning.
- Train and test query ids are disjoint (809 train, 300 test, 0 overlap). The corpus is shared, as
  is standard in BEIR.
- The encoder is off-the-shelf. It was not fine-tuned on BEIR data. (MiniLM's public training mix
  is outside our control. This is the usual caveat for pretrained encoders.)

## Train grid (SciFact train qrels, nDCG@10)

Raw output: `2026-10-28-beir-v3-train-grid/grid-scifact-train.tsv`. The pure-Rust encoder
reproduced the earlier candle-backend grid to 4 decimals.

| config | nDCG@10 |
|---|---|
| lexical (= BM25) | 0.6704 |
| dense_minilm only | 0.6602 |
| fused α=0.3 / 0.4 | 0.7072 / 0.7149 |
| **fused α=0.5** | **0.7212** (+0.0508 vs lexical) |
| fused α=0.6 / 0.7 | 0.7178 / 0.6979 |

Frozen: **α = 0.5** (weight on dense; `(1-α)·lexical + α·dense`, both min-max normalised over the
candidate union), pool = 100. The train gain is above the +0.01 bar. On train, a test success is
therefore plausible but not assured.

## Frozen arms and budgets

These are set in `crates/ccos-dense-encoder/examples/beir_campaign_v3.rs`.

- **Baseline:** bm25 (k1=1.2, b=0.75).
- **Controls:**
  - `docmem_lexical` (sanity: must equal bm25).
  - `docmem_dense_minilm` (dense only, reported).
  - `hybrid_bm25_minilm_rrf` (RRF k=60, outside memory).
- **Primary arm:** `docmem_fused_minilm` (α=0.5, pool=100).
- **Secondary arms:**
  - `docmem_prf` (v2 PRF unchanged: fb_docs=5, fb_terms=20, orig_weight=0.3, max_df_ratio=0.05).
  - `docmem_prf_fused_minilm`.
- **Budgets:** retrieval depth 100. Bootstrap uses 10,000 query resamples and seeds 1, 2 and 3.
  Nothing is tuned on test.

## Decision rule (same as v2)

- **Primary:** SciFact test nDCG@10, `docmem_fused_minilm` vs `bm25`.
  - **CONFIRMED** only if the mean paired delta is ≥ +0.01 **and** the 95% paired percentile
    bootstrap lower bound is > 0 for each of seeds 1, 2 and 3.
  - Otherwise **NOT CONFIRMED**.
- **Secondary, exploratory (no multiplicity correction):** all other arms vs bm25. NFCorpus test
  with the same frozen settings is optional, secondary, and cannot change the primary verdict.
- **Sanity:** a sanity failure (`docmem_lexical` ≠ bm25) invalidates the run and is reported.
- **Determinism:** each dataset is run twice, and stdout must be byte-identical (sha256 recorded).
- **Negatives kept:** every judged query counts. No query, arm or dataset is dropped.
- **Scope:** `superiority_claim: false` in every case. This is retrieval only. The end-to-end RAG
  campaign is still blocked, and SML-GENIUS is untouched.
