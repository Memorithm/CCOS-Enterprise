# BEIR campaign v2 — results (DocumentMemory vs BM25)

Preregistration: `docs/campaigns/2026-10-28-beir-v2-prereg.md` (committed before this run; hyperparameters frozen on train qrels).
Binary: `cargo run --release -p ccos-core --example beir_campaign_v2 -- <dir>` built from the prereg branch on top of main containing `DocumentMemory` (#219, b2d86be). Test qrels only. Same LSA encoder (d=512, r=128) for every dense/fused arm.

## Verdict

**Primary hypothesis NOT supported.** SciFact `docmem_fused_lsa` − bm25 = **+0.0030** nDCG@10, 95% paired bootstrap CI ≈ [−0.0020, +0.0084] (seeds 1/2/3). The preregistered threshold was +0.01 with CI lower bound > 0. This matches the train-grid prediction (+0.003).

## nDCG@10 (test)

| Arm | SciFact | NFCorpus |
|---|---|---|
| bm25 | 0.6617 | 0.3069 |
| tfidf_dense | 0.3132 | 0.1097 |
| lsa_dense | 0.1902 | 0.0997 |
| hybrid_bm25_lsa_rrf | 0.5025 | 0.2608 |
| docmem_lexical (sanity = bm25) | 0.6617 | 0.3069 |
| docmem_dense_lsa | 0.1902 | 0.0997 |
| docmem_prf | 0.6266 | 0.3266 |
| **docmem_fused_lsa (PRIMARY)** | **0.6646** | 0.2984 |
| docmem_prf_fused_lsa | 0.6257 | 0.3282 |

## Paired Δ vs bm25 (seed-1 CI)

| Arm | SciFact | NFCorpus |
|---|---|---|
| docmem_fused_lsa | +0.0030 [−0.0019, +0.0084] | −0.0085 [−0.0145, −0.0032] |
| docmem_prf | −0.0350 [−0.0590, −0.0119] | +0.0197 [+0.0081, +0.0316] |
| docmem_prf_fused_lsa | −0.0359 [−0.0595, −0.0129] | +0.0212 [+0.0104, +0.0323] |

Seeds 2 and 3 give CIs within ±0.001 of these (see raw outputs).

## Interpretation (exploratory, not confirmatory)

- Sanity arm `docmem_lexical` equals bm25 exactly (Δ = 0, 0 wins/losses).
- Fusion with LSA is neutral on SciFact and slightly harmful on NFCorpus.
- PRF hurts SciFact but significantly helps NFCorpus (+0.02, CI excludes 0). This is a secondary finding; NFCorpus is not the primary dataset; it is reported only as a hypothesis for a future preregistration.
- The weak dense encoder (LSA) remains the bottleneck; a stronger shared encoder is the obvious next lever.

## Determinism

Two runs per dataset, byte-identical stdout:

- scifact: `1a9b2c6f27385979566500598c22476347d59736e915b5e838007b74eda26827`
- nfcorpus: `0f29b4c7a58f71d770410eaef5319347c3b12b4b159704bb0b163a85f91f3539`
