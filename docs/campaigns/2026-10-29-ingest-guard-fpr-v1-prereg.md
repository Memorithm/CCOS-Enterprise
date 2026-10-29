# Preregistration — IngestGuard / ConformalGuard false-alarm rate (FPR-v1)

Status: **preregistered, nothing scored.** Run gate: the harness may only be run on a binary built
from a `main` commit that contains this document. Any deviation is reported as a deviation, never
silently fixed and re-run. Negative results are kept.

Open item addressed: #234–#237 — "IngestGuard false-alarm rate ≤ α is not measured; no calibrated
product scorer chosen".

## 1. Question

When `IngestGuard` (Enterprise, `ccos-enterprise-docmemory`) wraps a Core `ConformalGuard`
calibrated on benign documents, is the **empirical false-alarm rate** on *held-out benign* documents
of the same distribution ≤ α, as the split-conformal guarantee claims?

This is a validation of the false-alarm side only. **Detection rate on injections is out of scope**
and nothing in this campaign may be cited as evidence of detection quality.

## 2. Definitions

- **False alarm**: a benign test document whose `GovernedDocumentMemory::insert_document` returns
  `DocumentMemoryError::Flagged` (score `>` threshold, or NaN score). Measured through the real
  Enterprise insert path (`with_guard` + `insert_document`), not a re-implementation.
- **Benign document**: a record of a public BEIR corpus (scientific abstracts / financial forum
  answers / medical articles). These are assumed to contain no prompt injection; this assumption is
  a stated limitation, not verified per document.
- Blank records (title and text blank after `trim`) are excluded from both calibration and test
  (they are rejected as `EmptyDocument`, which is not a false alarm). Their count is reported.

## 3. Scorer (frozen)

The only existing product scorer that `ConformalGuard` was designed for (`calibrate_guard`):

- `ccos_core::injection_classifier::shared_detector()` — embedded `LinearModel::default_injection()`
  + default `HashingTokenizer`. The model fingerprint (`LinearModel::fingerprint`) is printed by the
  harness and recorded in results.
- Nonconformity score of a document: `injection_probability(defang(title + "\n\n" + text).0)` as
  `f64` (Core `sanitizer::defang`, per the detector's documented input contract).
- No training, no tuning, no threshold choice other than the conformal quantile. Core is used only
  through existing public APIs; Core is not modified.

## 4. Data (frozen, pinned by SHA-256 of the local files)

| Role | Corpus | Records | SHA-256 `corpus.jsonl` |
|---|---|---|---|
| Calibration + in-distribution test (**primary**) | BEIR SciFact | 5,183 | `dec31c8182f3d744c7d2c09423756fd1d17cbef75808db13ba01cc0aab4d1ac6` |
| Shift probe (secondary, no guarantee) | BEIR NFCorpus | 3,633 | `10cc83ef1826b1425e6a87090b5140b39b27755d5a27e48215a88611c899991f` |
| Shift probe (secondary, no guarantee) | BEIR FiQA-2018 | 57,638 | `ff593e4df9933955dc3af83be0c3fa28ac7465f627e08c2e53593e734d506517` |

Only `corpus.jsonl` is read; no queries or qrels. A hash mismatch invalidates the run.

**Split.** For split seed `s`, a SciFact record goes to calibration iff the first byte of
`SHA-256("ingest-fpr-v1:{s}:{_id}")` is even, else to test. Disjoint by construction (each `_id` in
exactly one side). Seeds `s = 0..19` (20 splits); **seed 0 is the primary split.**

**Leakage.** Calibration and test never share a record. No attack set is used. The embedded
injection model was not trained by this project on BEIR (assumption; its training corpus is not
re-audited here — stated limitation). NFCorpus/FiQA are never used for calibration.

## 5. α and guard

- Primary α = **0.05**. Secondary α ∈ {0.01, 0.10} (reported, do not drive the verdict).
- Guard: `ConformalGuard::calibrate(cal_scores, α)`, wrapped by `IngestGuard::new` (which refuses
  an uncalibrated `+∞` threshold). With n_cal ≈ 2,590, `α ≥ 1/(n+1)` holds for all α above.

## 6. Metrics

- **Primary**: mean over the 20 seeds of empirical FPR = `#Flagged / #test` on SciFact-test, α = 0.05.
- Reported per seed: n_cal, n_test, threshold, #flagged, FPR, Clopper–Pearson 95% interval.
- Reported: score distribution summary (min/median/max, number of distinct values) — a degenerate
  scorer (e.g. all-equal scores ⇒ threshold equal to every score ⇒ FPR 0) is called out explicitly.
- Secondary: FPR of the seed-0 SciFact-calibrated guard on all of NFCorpus and FiQA (distribution
  shift; the conformal guarantee does **not** apply; descriptive only).

## 7. Decision rule (primary, α = 0.05)

Split-conformal guarantees `E[FPR] ≤ α` marginally over the calibration draw (and for ties the strict
`>` only makes it more conservative). Requiring a single-split CI upper bound ≤ α would reject an
*exactly* calibrated guard about half the time, so the repo's conformal design is tested on the mean:

- Let `m` = mean FPR over 20 seeds, `se` = sample std / √20.
- **CONFIRMED** iff `m ≤ α` **and** the scorer is non-degenerate (≥ 100 distinct score values over
  SciFact).
- **REFUTED** iff `m − 1.729·se > α` (one-sided 95% t, 19 df).
- **INCONCLUSIVE** otherwise, or if the scorer is degenerate.
- The verdict covers *exchangeable benign SciFact-like ingest with this scorer only*. It does not
  license enabling the guard by default, and says nothing about detection.

## 8. Deliverables of the execution PR

1. Harness `ingest_guard_fpr` (Enterprise example, `ccos-enterprise-docmemory`) taking the three
   corpus paths, verifying SHA-256, printing one JSON line per (seed, α) and the shift probes.
2. Results doc `docs/campaigns/2026-10-29-ingest-guard-fpr-v1-results.md` with the raw output.
3. Guard stays **off by default** everywhere (ingest and server rebuild). Any rebuild wiring is
   opt-in only and not enabled until a CONFIRMED verdict *and* a separate decision.
