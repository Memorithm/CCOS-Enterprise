# Preregistration v5 — amendment to v4 (#231): FiQA-2018 blank-document import rule

Status: **preregistered amendment, FiQA test not yet scored.** Run gate: the FiQA test split runs only
after this document (and the importer change in the same PR) is merged to `main`. The binary is built
from that merge commit.

## Why this amendment

v4 (#231, results #233) aborted both FiQA runs at load: the strict importer rejects
`fiqa/corpus.jsonl:742` (`_id` `7915`) because title and text are both blank. No retrieval or scoring
happened; no FiQA test number has been seen by anyone in this project. A scan of `corpus.jsonl` only
(no qrels or queries read) finds **38 blank records out of 57,638** (first: lines 742, 1159, 1330,
3209, …). v4 left blank-document handling undefined, so it must be fixed here **before** any FiQA
number exists.

## What changes

1. **Import rule — skip-unretrievable (not fail, not keep-as-empty).** With the new opt-in flag
   `--skip-blank-docs`, a corpus record whose title and text are both blank (after `trim`) is
   **not indexed** by any arm. Its ID stays reserved under a sentinel (counting down from `u64::MAX`)
   so that:
   - a qrel pointing at it is **not** an "unknown document" error and is **not** dropped;
   - it still counts in the ideal DCG of its query, and no arm can ever retrieve it (a conservative
     penalty applied identically to bm25 and to the fused arm);
   - no judged query is dropped.
   Rejected alternatives: *fail* (v4 behaviour, makes FiQA unrunnable); *keep as empty document*
   (an empty string still gets a MiniLM embedding and could be ranked by the dense side, giving the
   fused arm a spurious, content-free hit); *drop the qrels* (silently removes judged evidence).
   All other strict checks (IDs, duplicates, unknown IDs, JSON shape, blank queries) are unchanged.
2. `beir_campaign_v3` gains only the `--skip-blank-docs` flag and prints `skipped_blank_docs=N reattached_unretrievable_judgments=M` on
   stderr. Without the flag, behaviour is byte-identical to v4 (default policy = `Fail`).
3. The FiQA run uses `--skip-blank-docs`; the expected skipped count is **38**. Any other count makes
   the run invalid (reported, not re-run with changes).

## What does not change

- Arms, budgets (pool 100, depth 100), BM25 k1=1.2 b=0.75, PRF, encoder all-MiniLM-L6-v2 (HF
  revision `c9745ed1d9f207416be6d2e6f8de32d1f16199bf`, pure-Rust CPU backend, same pinned files),
  α = **0.5** frozen from SciFact train (v3). No FiQA train/dev grid; nothing is tuned on FiQA.
- Primary metric: test **nDCG@10**, `docmem_fused_minilm` vs `bm25`. Bootstrap 10,000 paired query
  resamples, seeds **1, 2, 3**, 95% percentile.
- FiQA dataset sha256 as in v4 (`corpus.jsonl` `ff593e4d…6517`, `queries.jsonl` `eede1e61…77bc`,
  `qrels/test.tsv` `6adc2a64…9e44`).
- **CONFIRMED(FiQA)** iff mean paired Δ ≥ **+0.01** and 95% lower bound **> 0** for each of seeds
  1, 2, 3; otherwise NOT CONFIRMED(FiQA).
- Family rule unchanged: **GENERALISES** iff CONFIRMED(NFCorpus) and CONFIRMED(FiQA) (SciFact v3,
  #230, is the frozen anchor). PARTIAL if exactly one; DOES NOT GENERALISE otherwise.
- SciFact (#230) and NFCorpus (#233) verdicts and thresholds are **not** re-opened or re-run; neither
  corpus has blank records, so the new flag would not affect them anyway.
- Sanity (`docmem_lexical` = bm25), determinism (two runs, byte-identical stdout, sha256 recorded),
  negatives kept, `superiority_claim: false`, retrieval-only scope, SML-GENIUS untouched.
- Secondary arms remain exploratory and cannot change the verdict. Dense-only was already NS on
  NFCorpus; the fused arm is the primary.

## Anti-leakage

FiQA test qrels and query texts have still not been read; only `corpus.jsonl` was scanned for blank
records to write this amendment. Whether any blank record is judged relevant is unknown and will be
reported from the run's stderr/outputs, not inspected beforehand.

## Commands (after merge)

```bash
cargo build --release -p ccos-dense-encoder --example beir_campaign_v3
target/release/examples/beir_campaign_v3 /workspace/beir-data/fiqa <model-dir> --skip-blank-docs
```
Run twice; outputs go to `docs/campaigns/2026-10-29-beir-v5-fiqa-test/`.
