# Results v4 — BEIR multi-dataset (prereg #231, merge 82e208533b06b7dbbea2ff4fea8f78cae9a5782d)

Binary built from the prereg merge commit; `beir_campaign_v3.rs` unchanged since v3. Raw outputs and
sha256 in `2026-10-28-beir-v4-test/`.

## NFCorpus test (323 judged queries, 3633 docs) — **CONFIRMED(NFCorpus)**

Determinism: run1 = run2 stdout sha256 `9d308b93…4558`. Sanity: `docmem_lexical` = bm25 (Δ=0).

| arm | nDCG@10 | Δ vs bm25 | 95% CI seeds 1/2/3 |
|---|---|---|---|
| bm25 | 0.3069 | — | — |
| **docmem_fused_minilm (primary)** | **0.3423** | **+0.0354** | [+0.0210,+0.0503] / [+0.0209,+0.0503] / [+0.0209,+0.0505] |
| docmem_dense_minilm | 0.3167 | +0.0097 | lower bounds < 0 (NS) |
| hybrid_bm25_minilm_rrf | 0.3442 | +0.0372 | lower bounds > 0 |
| docmem_prf | 0.3266 | +0.0197 | lower bounds > 0 |
| docmem_prf_fused_minilm | 0.3510 | +0.0440 | lower bounds > 0 |

Secondary arms are exploratory (no correction). Disclosure from the prereg applies: NFCorpus test
was seen by v1/v2 for other arms; the fused arm and α were not chosen on it.

## FiQA-2018 test — **NOT RUN (invalid import), no verdict**

Both runs aborted at load: `fiqa/corpus.jsonl:742: document title and text are both blank` (strict
importer). No retrieval or scoring happened; empty stdout recorded. The frozen binary is not
modified here. Running FiQA needs an amendment prereg defining blank-document handling (e.g. keep as
empty docs vs drop) **before** any FiQA number is seen.

## Family verdict

Per the prereg rule, **GENERALISES cannot be declared**; family verdict **pending FiQA**. Current
evidence: SciFact (anchor, #230) and NFCorpus CONFIRMED. `superiority_claim: false`.
