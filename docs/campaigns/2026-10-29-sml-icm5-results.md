# Results — SML-GROK-ICM-5 PR3: `sml-grok-icm-concurrent` (sigpage-v0) on BEIR

Prereg: SML-GENIUS `docs/SML-GROK-ICM-5-DOCUMENT-RANKING-PREREGISTRATION.md` (#761, `6fe51bee`).
Ranker: `sml_core::icm_rank::SignaturePageRanker` @ SML #762 (`538d17da`), **unchanged, no tuning**
(no DEV step was run; nothing was fitted on train or test). Backend wiring: CCOS #242 (`a281be3`).

Harness: `crates/ccos-enterprise-sml-retrieval/examples/beir_sml_icm5.rs` (feature `sml-backend`).
Strict BEIR importer (unchanged), BM25(1.2, 0.75) from `ccos_core::retrieval` (the #217 reference),
signature seeds {0,1,2}, depth 100, paired percentile bootstrap 10 000 resamples seed 20261029.
`docmem_fused_minilm` is **not re-encoded**: its per-query nDCG@10 is read from the published
v3 (SciFact) / v4 (NFCorpus) stdout; the harness aborts unless its own per-query BM25 equals the
published BM25 column for every query (it did, on both datasets). CPU box x86_64, 8 cores.
Raw outputs, binary sha256 and stdout sha256 in `2026-10-29-sml-icm5-test/`; run1 = run2.

Reproduce:
```bash
cargo build --release -p ccos-enterprise-sml-retrieval --features sml-backend --example beir_sml_icm5
target/release/examples/beir_sml_icm5 <beir>/scifact docs/campaigns/2026-10-28-beir-v3-test/scifact-test-run1.stdout
```

## SciFact test (primary; 300 judged queries, 5183 docs) — **NEGATIVE** (H1 and H2)

| arm | nDCG@10 | R@100 | MRR@10 |
|---|---|---|---|
| bm25 | 0.6617 | 0.8859 | 0.6276 |
| sml seed0 | 0.4174 | 0.7408 | 0.3817 |
| sml seed1 | 0.4136 | 0.7484 | 0.3778 |
| sml seed2 | 0.4061 | 0.7287 | 0.3709 |
| docmem_fused_minilm (published #230) | 0.7137 | — | — |

sml mean of seeds nDCG@10 = 0.4124, min = 0.4061.

| comparison | seed | Δ nDCG@10 | wins/losses | IC95 |
|---|---|---|---|---|
| sml − bm25 | 0 | −0.2443 | 15/148 | [−0.2838, −0.2055] |
| sml − bm25 | 1 | −0.2481 | 19/139 | [−0.2888, −0.2084] |
| sml − bm25 | 2 | −0.2556 | 12/147 | [−0.2960, −0.2161] |
| sml − fused | 0 | −0.2963 | 13/164 | [−0.3400, −0.2534] |
| sml − fused | 1 | −0.3001 | 16/159 | [−0.3445, −0.2568] |
| sml − fused | 2 | −0.3077 | 14/165 | [−0.3515, −0.2650] |

Upper IC95 bound < 0 for all 3 seeds ⇒ **NEGATIVE** vs BM25 (H1) and vs fused (H2).
Wall 35.6 s per run (3 seeds together), max RSS 41 MiB: within budget.

## NFCorpus test (secondary; 323 queries, 3633 docs) — **NEGATIVE**

| arm | nDCG@10 | R@100 | MRR@10 |
|---|---|---|---|
| bm25 | 0.3069 | 0.2369 | 0.5151 |
| sml seed0 / 1 / 2 | 0.1925 / 0.1835 / 0.1814 | 0.1914 / 0.2032 / 0.1905 | 0.3356 / 0.3120 / 0.3236 |
| docmem_fused_minilm (published v4) | 0.3423 | — | — |

Δ vs bm25: −0.1145 [−0.1349, −0.0957] / −0.1235 [−0.1433, −0.1049] / −0.1256 [−0.1471, −0.1050].
Δ vs fused: −0.1498 [−0.1745, −0.1259] / −0.1588 [−0.1828, −0.1357] / −0.1609 [−0.1862, −0.1360].

## FiQA test (secondary) — **NOT RUN, no verdict**

The strict importer aborts at `fiqa/corpus.jsonl:742: document title and text are both blank`
(log in `fiqa-test-strict.stderr`). The SML prereg #761 defines no blank-document policy, so the
CCOS v5 `--skip-blank-docs` rule was **not** applied (would need an SML amendment prereg first).

## Verdict

**NEGATIVE** on the primary (SciFact test) vs BM25 and vs `docmem_fused_minilm`; NFCorpus NEGATIVE;
FiQA not run. GENERALISES not claimable. Per prereg, CCOS stays on `UnavailableSmlRetrieval` by
default (the `sml-backend` feature remains opt-in, experimental, `NotBeirValidated`).
Expected and documented for sigpage-v0 (no IDF/stemming/length norm; 4096-bit saturation).
`superiority_claim: false`. No retuning after TEST. Note: sigpage-v0's tokenizer (ASCII alnum,
len ≥ 2, set-of-tokens) differs from the BM25 tokenizer; the prereg compares against the #217 BM25.

License flag: `sml-core` is PolyForm-Noncommercial-1.0.0 and is pulled by `--all-features` builds
via #242 (optional dep). Not changed here.
