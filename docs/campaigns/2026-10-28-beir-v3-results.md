# BEIR campaign v3 — SciFact test results (DocumentMemory fused with all-MiniLM-L6-v2 vs BM25)

Prereg: `docs/campaigns/2026-10-28-beir-v3-prereg.md` (merged in #228 at `a8afc9e`). Binary built from
`a8afc9e`, harness unchanged (`beir_campaign_v3`, sha256 `4ec8ab434482d53f2a86809174e44018c9ca8d22555bf6f54ee013bbfdab243d`). SciFact files match the prereg sha256.
Encoder: pure-Rust CPU all-MiniLM-L6-v2 at the pinned revision (no NVIDIA). Raw outputs: `2026-10-28-beir-v3-test/`.

## Primary verdict: **CONFIRMED**

| | value |
|---|---|
| bm25 nDCG@10 | 0.6617 |
| docmem_fused_minilm (α=0.5) nDCG@10 | 0.7137 |
| mean paired Δ | **+0.0521** (wins 72 / losses 23, 300 judged queries) |
| 95% bootstrap CI seed 1 / 2 / 3 | [+0.0309, +0.0739] / [+0.0311, +0.0740] / [+0.0309, +0.0739] |

Rule: Δ ≥ +0.01 and lower bound > 0 for every seed → met.

## Controls and secondary (exploratory, no multiplicity correction)

| arm | nDCG@10 | Δ vs bm25 | 95% CI (seed 1) |
|---|---|---|---|
| docmem_lexical (sanity) | 0.6617 | +0.0000 | [+0.0000, +0.0000] — **sanity passed** |
| docmem_dense_minilm | 0.6451 | −0.0166 | [−0.0545, +0.0215] |
| hybrid_bm25_minilm_rrf | 0.6789 | +0.0173 | [−0.0047, +0.0389] |
| docmem_prf | 0.6266 | **−0.0350** | [−0.0590, −0.0119] (negative, kept) |
| docmem_prf_fused_minilm | 0.7024 | +0.0407 | [+0.0152, +0.0661] |

## Determinism
Two runs, byte-identical stdout: sha256 `6409e184b0ed8376d0548fd8f5a8524576b59d40e05d975b0bc3a16a93ce2cb7` (both). Encoding ~333 s CPU per run (stderr).

## Scope
superiority_claim: false. Retrieval only, one dataset (SciFact test); NFCorpus optional secondary not run.
The test gain (+0.0521) is in line with the train grid (+0.0508). Dense alone does not beat BM25, and v2 PRF still hurts.
The end-to-end RAG campaign is still blocked. SML-GENIUS untouched.
