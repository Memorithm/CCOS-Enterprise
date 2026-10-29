# Results v5 — FiQA-2018 test (amendment prereg #238, merge 34442e18a9a81e5202c6858c6c0a4d8ae2682cdc)

Binary `beir_campaign_v3` built (release) from the #238 merge commit; sha256 in
`2026-10-29-beir-v5-fiqa-test/binary.sha256`. Command, run twice:

```bash
target/release/examples/beir_campaign_v3 /workspace/beir-data/fiqa /workspace/models/minilm-pinned --skip-blank-docs
```

Raw stdout/stderr and sha256 in `2026-10-29-beir-v5-fiqa-test/`.

## Validity checks

- Blank-doc import (both runs, stderr): `qrel_rows=1705 positive=1705 skipped_blank_docs=38
  reattached_unretrievable_judgments=1`. Skipped count = **38**, as preregistered → run valid.
  One judged relevant document is blank; it stays in that query's ideal DCG and is unretrievable
  by every arm. Indexed docs = 57,600; judged queries = 648 (none dropped).
- Sanity: `docmem_lexical` = bm25 (Δ=+0.0000, wins=0, losses=0).
- Determinism: run1 = run2 stdout sha256 `15ed0b0b84d2f2a5bcdea5e6c758874905811308d8b36a642b945917bb2ac5a5`
  (byte-identical).
- Note: an earlier run2 attempt was interrupted before writing stdout (empty file, no numbers);
  it was discarded and run2 re-executed with the identical binary and flags.

## FiQA test (648 judged queries, 57,600 docs) — **CONFIRMED(FiQA)**

| arm | nDCG@10 | Δ vs bm25 | wins/losses | 95% CI seed 1 / 2 / 3 |
|---|---|---|---|---|
| bm25 | 0.2360 | — | — | — |
| docmem_lexical (sanity) | 0.2360 | +0.0000 | 0/0 | [0,0] ×3 |
| **docmem_fused_minilm (primary)** | **0.3774** | **+0.1414** | 323/44 | [+0.1244,+0.1583] / [+0.1247,+0.1588] / [+0.1243,+0.1586] |
| docmem_dense_minilm | 0.3687 | +0.1327 | 313/111 | [+0.1072,+0.1581] / [+0.1071,+0.1589] / [+0.1067,+0.1587] |
| hybrid_bm25_minilm_rrf | 0.3528 | +0.1168 | 303/51 | [+0.0999,+0.1333] / [+0.0998,+0.1338] / [+0.0995,+0.1337] |
| docmem_prf | 0.1873 | **−0.0487** | 86/192 | [−0.0620,−0.0356] / [−0.0623,−0.0355] / [−0.0619,−0.0355] |
| docmem_prf_fused_minilm | 0.3447 | +0.1087 | 299/79 | [+0.0905,+0.1272] / [+0.0904,+0.1277] / [+0.0898,+0.1272] |

Other metrics (primary vs bm25): R@10 0.4541 vs 0.2982, R@100 0.6954 vs 0.5102, MRR@10 0.4539 vs
0.2936, MAP 0.3150 vs 0.1886.

Decision rule (v4/v5): mean paired Δ ≥ +0.01 **and** 95% lower bound > 0 for seeds 1, 2, 3.
Primary Δ=+0.1414, lower bounds +0.1244 / +0.1247 / +0.1243 → **CONFIRMED(FiQA)**.

**Negative kept:** `docmem_prf` (lexical PRF) is significantly *worse* than bm25 on FiQA
(Δ=−0.0487, CI entirely < 0), unlike NFCorpus where it was positive. PRF fused with MiniLM still
beats bm25 but is below the plain fused arm. Secondary arms are exploratory (no multiplicity
correction) and do not affect the verdict.

## Family verdict — **GENERALISES**

| dataset | verdict | primary Δ nDCG@10 | source |
|---|---|---|---|
| SciFact test (anchor) | CONFIRMED | +0.0521 | v3, #230 |
| NFCorpus test | CONFIRMED | +0.0354 | v4, #233 |
| FiQA-2018 test | CONFIRMED | +0.1414 | v5, this document |

Rule: GENERALISES iff CONFIRMED(NFCorpus) and CONFIRMED(FiQA), SciFact frozen anchor → **GENERALISES**
across the three preregistered BEIR domains, with α=0.5 frozen from SciFact train and nothing tuned
on NFCorpus or FiQA.

Scope: retrieval-only (nDCG@10 vs BM25 on three BEIR test sets). `superiority_claim: false`; no claim
about end-to-end product quality, other encoders, or other datasets. SML-GENIUS untouched.
