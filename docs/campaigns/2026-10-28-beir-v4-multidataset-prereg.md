# Preregistration v4 — BEIR multi-dataset generalisation of v3 (`DocumentMemory` fused MiniLM vs BM25)

Status: **preregistered, not yet run on any v4 test split.** Run gate: the NFCorpus and FiQA test
splits run only after this document is merged to `main`. The binary is built from that merge commit
with `crates/ccos-dense-encoder/examples/beir_campaign_v3.rs` **unchanged** (same arms, budgets,
seeds and constants as v3, #228).

## Question

v3 CONFIRMED `docmem_fused_minilm` (α=0.5) over BM25 on SciFact test (Δ=+0.0521 nDCG@10, #230).
Does that win generalise to other BEIR domains with **nothing re-tuned**?

## Frozen settings (no new tuning)

- Encoder: all-MiniLM-L6-v2, HF revision `c9745ed1d9f207416be6d2e6f8de32d1f16199bf`, same pinned
  files and pure-Rust CPU backend as v3.
- α = **0.5**, pool = 100, depth = 100, BM25 k1=1.2 b=0.75, PRF as v2/v3. α was frozen from the
  **SciFact train** grid in v3; no NFCorpus/FiQA train or dev grid is run for v4, so no v4 test
  dataset contributes any tuning signal.
- Bootstrap: 10,000 query resamples, seeds 1, 2, 3 (paired percentile, 95%).

## Datasets (sha256)

| dataset | file | sha256 |
|---|---|---|
| NFCorpus | `corpus.jsonl` | `10cc83ef1826b1425e6a87090b5140b39b27755d5a27e48215a88611c899991f` |
| NFCorpus | `queries.jsonl` | `d024e6621b84925d485ae473d316a0c3af31c62c8068a59fb29d22f7613aef2a` |
| NFCorpus | `qrels/test.tsv` | `f8fba6ef3d4dd9c3a242a8ba4ae38276fc3622fce7dcbae764766d564542fd2a` |
| FiQA-2018 | `corpus.jsonl` | `ff593e4df9933955dc3af83be0c3fa28ac7465f627e08c2e53593e734d506517` |
| FiQA-2018 | `queries.jsonl` | `eede1e61d4a0188940239b53ebc2da91f577a6a34679c812d1eb9090c29877bc` |
| FiQA-2018 | `qrels/test.tsv` | `6adc2a640dcdd22bb8b3858f89107adef2a7c3db20a63550dfa7a0f71e379e44` |

SciFact test (v3, #230) is the **frozen anchor**: it is not re-run and its verdict is not changed.

## Anti-leakage disclosure

- The FiQA test qrels have never been read by this project.
- The NFCorpus test qrels were used in v1/v2 (BM25, LSA and PRF arms). The **fused MiniLM** arm
  has never been evaluated on NFCorpus test (v3 listed it as optional and did not run it). No
  parameter of v4 was chosen by looking at NFCorpus test numbers. This prior exposure is disclosed;
  it is why the family rule below requires FiQA too.
- MiniLM is off-the-shelf; its public training mix is outside our control (usual caveat).

## Decision rule

Per dataset D ∈ {NFCorpus, FiQA}, test nDCG@10, `docmem_fused_minilm` vs `bm25`:
- **CONFIRMED(D)** only if mean paired delta ≥ **+0.01** and the 95% bootstrap lower bound is
  **> 0** for each of seeds 1, 2, 3. Otherwise **NOT CONFIRMED(D)**.

Family decision (co-primary, both must hold — conservative, no multiplicity inflation):
- **GENERALISES** iff CONFIRMED(NFCorpus) **and** CONFIRMED(FiQA).
- **PARTIAL** if exactly one is CONFIRMED (reported as such, no general claim).
- **DOES NOT GENERALISE** otherwise.

Secondary, exploratory (no correction, cannot change the verdict): all other v3 arms vs bm25
(`docmem_dense_minilm`, `hybrid_bm25_minilm_rrf`, `docmem_prf`, `docmem_prf_fused_minilm`).

- **Sanity:** `docmem_lexical` must equal bm25 per dataset, otherwise that dataset's run is invalid
  and reported as such (not re-run with changes).
- **Determinism:** each dataset run twice; stdout must be byte-identical (sha256 recorded).
- **Negatives kept:** every judged query counts; no query, arm or dataset is dropped; a negative
  or partial result is published with the same weight as a positive one.
- **Scope:** `superiority_claim: false`. Retrieval only. Not a RAG E2E claim; SML-GENIUS untouched.

## Commands (after merge)

```bash
cargo build --release -p ccos-dense-encoder --example beir_campaign_v3
target/release/examples/beir_campaign_v3 /workspace/beir-data/nfcorpus <model-dir>
target/release/examples/beir_campaign_v3 /workspace/beir-data/fiqa <model-dir>
```
Outputs go to `docs/campaigns/2026-10-28-beir-v4-test/`.
