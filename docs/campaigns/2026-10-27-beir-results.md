# Results — BEIR retrieval campaign (prereg `ba80f4f`)

Preregistration: [2026-10-27-beir-retrieval-prereg.md](2026-10-27-beir-retrieval-prereg.md),
committed at `ba80f4f12b199f1883ebfbe9f169078434154185` before any test-split run. Harness and
binary built from that exact commit. Data hashes match the prereg. Raw stdout (per-query nDCG@10
for every arm) is in `2026-10-27-beir-results/`.

Determinism: two runs per dataset; stdout byte-identical.
SciFact `4286f71b1983885079e62ed2aab33c3d10392fe9c8de251e943ec3d07c622cf5`,
NFCorpus `969120867c64814cdd7fb6b1d68a50902a52cf93c7c29584722c580ff58ea2b6`.
Wall time: ~16 s for SciFact (indexes 8.8 s, memory ingest 6.8 s, scoring 2.9 s), 8 cores.

## Primary outcome: **no improvement shown (negative)**

SciFact nDCG@10, `ccos_memory_hybrid` vs `bm25`: **0.0000 vs 0.6617**, delta −0.6617,
95% CI [−0.706, −0.616] (all three seeds), 0 wins / 243 losses / 57 ties.

## All arms (nDCG@10 / R@10 / R@100 / MRR@10 / MAP)

| arm | SciFact | NFCorpus |
|---|---|---|
| bm25 | **0.662** / 0.791 / 0.886 / 0.628 / 0.620 | **0.307** / 0.149 / 0.237 / 0.515 / 0.139 |
| tfidf_dense | 0.313 / 0.417 / 0.671 / 0.286 / 0.287 | 0.110 / 0.053 / 0.151 / 0.212 / 0.041 |
| lsa_dense | 0.190 / 0.282 / 0.636 / 0.164 / 0.173 | 0.100 / 0.046 / 0.153 / 0.185 / 0.037 |
| hybrid_bm25_lsa_rrf | 0.503 / 0.705 / 0.885 / 0.447 / 0.443 | 0.261 / 0.127 / 0.239 / 0.435 / 0.108 |
| ccos_memory_semantic | 0.000 / 0.000 / 0.000 / 0.000 / 0.000 | 0.003 / 0.002 / 0.002 / 0.006 / 0.002 |
| ccos_memory_hybrid | 0.000 / 0.000 / 0.000 / 0.000 / 0.000 | 0.003 / 0.002 / 0.002 / 0.006 / 0.002 |

Every arm is significantly below BM25 on both datasets (all 95% CIs exclude 0, all seeds).
The baseline numbers reproduce `core/docs/MEASUREMENT_beir.md` exactly.

## Reading (post-hoc diagnosis, not preregistered)

- `CcosMemory` is a causal **code-graph** memory. `recall` picks a single entry node and returns
  that node's *region*. A flat prose corpus has no causal edges, so the region collapses to
  roughly one document. A toy check (3 docs) shows that `Recall::Hybrid` returns the same
  document for unrelated queries and `Recall::Semantic` returns an empty window. As shipped, the
  memory arm is not a document retriever. The result measures a mismatch between this API and
  the task. It is not an encoder-quality result.
- Dense arms sharing the 128-rank LSA encoder are weak on these lexical-overlap corpora. RRF
  fusion dilutes BM25. These are the same findings as the prior measurement.
- Not encoder-matched: the memory arms use CcosMemory's internal encoder (declared in the prereg).

## Not run / blocked

- End-to-end RAG campaign (generator + blinded adjudication): blocked, not run.
- SML-GENIUS `SemanticMemoryProvider`: deferred (no retrieval API in SML-GENIUS `588143af`).

`superiority_claim: false`.
