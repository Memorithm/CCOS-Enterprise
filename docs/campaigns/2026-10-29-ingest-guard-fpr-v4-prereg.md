# Preregistration — IngestGuard / ConformalGuard FPR-v4 (ingest-domain recalibration)

Status: **preregistered, nothing scored under the v4 protocol.** Run gate: the harness may only be
run on a binary built from a `main` commit that contains this document. Deviations are reported,
never silently fixed and re-run. Negative / trivial results are kept.

Follows FPR-v3 (#249 prereg `8723d78`, #250 results `9625d45`): with the length-normalised score,
SciFact-calibrated FPR **CONFIRMED** (mean 0.0465) and detection **NON-TRIVIAL** (seed-0 TPR 0.426,
CP95 [0.365, 0.488]), but severe drift: FiQA FPR 0.281, deepset label 0 FPR 0.231, NFCorpus 0.037.
v4 changes **only the calibration corpus**: same score, same model, same tokenizer, new threshold
estimated on a benign corpus from the product's ingest domain. **No retraining.**

## 1. Questions

- **Q1 (FPR, primary).** Calibrated on held-out-split benign FiQA, is the empirical false-alarm rate
  on the other FiQA half ≤ α, with a non-degenerate guard?
- **Q2 (detection, co-primary).** At that FiQA-calibrated threshold, is TPR on the pinned deepset
  injections non-trivially above α?
- **Q3 (descriptive).** Drift of the FiQA-calibrated guard on SciFact, NFCorpus, deepset label 0;
  and a descriptive chat arm calibrated on deepset label 0 (§3.2).

## 2. Score (frozen, identical to v3 §2)

`t = defang(doc).0`, `e = shared_detector().explain(t)`, `n = HashingTokenizer::new().features(t).len()`
(Core default tokenizer: lowercase, `D = 2048`, word unigrams + char 3-grams),
`s = (e.margin − e.prior_margin) / max(1, n)` in f64. Higher = more injection-like; flag iff
`s > threshold` (Core `ConformalGuard::flags`). Harness asserts tokenizer dim == model dim and model
fingerprint `1a21468ef60e681eaffc91bbfa92b94e77d10ca5dd11a5400e9a53586d4dfce8`. Core **not modified**.
Document text `title + "\n\n" + text` (BEIR) / `text` (deepset).

## 3. Data and split

### 3.1 Primary calibration corpus: FiQA (justification)

BEIR FiQA-2018 `corpus.jsonl`, SHA-256 `ff593e4df9933955dc3af83be0c3fa28ac7465f627e08c2e53593e734d506517`
(57,638 lines; v3 found 38 blank → excluded). Chosen as primary because (i) it is user-written,
informal, variable-length financial forum text — closer to the documents a tenant ingests into
document memory than SciFact abstracts; (ii) it is large (≈ 28.8k per half), so the conformal
quantile and FPR have small sampling error; (iii) it was the worst-drifting large BEIR set under
v3 (0.281), so it is the hardest honest test of "recalibrate on own domain"; (iv) it is disjoint
from the injection source (different dataset, different authors) — no leakage path.

Split: calibration iff first byte of `SHA-256("ingest-fpr-v4:fiqa:{s}:{_id}")` is even, test
otherwise; seeds `s = 0..19`, seed 0 primary (same scheme as v1–v3, new tag). Calibration and test
are disjoint by construction; the harness asserts the two halves are disjoint and non-empty.

### 3.2 Secondary, descriptive chat arm: deepset label 0

The 399 non-blank `label == 0` rows of the pinned deepset JSONL (below). Too small and too close to
the injection source (same dataset, same collection process) to be primary; reported descriptively
only. Split: calibration iff first byte of `SHA-256("ingest-fpr-v4:ds0:{s}:{split}:{row}")` is even.
Per seed: n_cal, n_test, threshold, FPR on the ds0 test half, TPR on injections. **No verdict.**

### 3.3 Detection corpus (identical to v2/v3)

`deepset/prompt-injections` revision `4f61ecb038e9c3fb77e21034b22511b523772cdd`, converted by
`2026-10-29-ingest-guard-fpr-v2/convert_deepset.py` to JSONL SHA-256
`2c46bfa481330b1067af917d783190663f9aa22aaae5c579581f3828a3822ef8`. Positives = `label == 1`,
non-blank, same leakage exclusion against `core/examples/train_injection.rs` (v3: 0 excluded,
263 included). Injections are **never** in any calibration set.

### 3.4 Drift probes (descriptive, no guarantee)

SciFact (`dec31c81…1ac6`), NFCorpus (`10cc83ef…991f`) full corpora, deepset label 0 (399), each
scored by the seed-0 α = 0.05 FiQA guard.

## 4. α and guard

Primary α = **0.05**; secondary {0.01, 0.10}. `ConformalGuard::calibrate(cal, α)` wrapped by
`IngestGuard::new`, measured through `GovernedDocumentMemory::insert_document` (`Flagged` = alarm).

## 5. Metrics

Per (seed, α): n_cal, n_test, threshold, flagged, FPR + CP95, TPR + CP95. FiQA score and `n`
distributions; ties; Spearman ρ(s, n) on FiQA; drift probes; chat arm (§3.2); v3 SciFact-calibrated
seed-0 threshold recomputed as reference (FiQA FPR must reproduce 0.281 — a reproduction check).

## 6. Decision rules (primary α = 0.05)

**DEGENERATE if any holds** (v3 checks transposed to FiQA): (a) < 100 distinct FiQA scores; (b) seed-0
threshold not finite; (c) > 1 % of FiQA scores tied with the seed-0 threshold; (d) > 1 % of FiQA
scores equal the FiQA maximum; (e) seed-0 threshold ≥ max score over FiQA ∪ injections; (f) seed-0
FiQA test flagged count is 0; (g) > 1 % of FiQA docs have `n ≤ 1`.

**FPR verdict** (m = mean FiQA-test FPR over 20 seeds, se = sd/√20): REFUTED iff m − 1.729·se > α;
else INCONCLUSIVE if DEGENERATE; else CONFIRMED iff m ≤ α; else INCONCLUSIVE.

**Detection verdict** (seed 0, α = 0.05): NON-TRIVIAL iff TPR CP95 lower bound > α; else
TRIVIAL/NEGATIVE. TPR ≥ 0.5 noted as "useful" (descriptive). Mean TPR over seeds reported.

**Wiring gate (rebuild):** FPR CONFIRMED **and** detection NON-TRIVIAL. If met, a *later, separate*
PR may add opt-in, **default-off** wiring that requires calibration on the tenant's own benign
corpus; the v4 results PR itself changes **no product code or default** in any case. If the gate
fails, nothing is wired and the results say so.

`superiority_claim = false`: no comparison with any other detector is claimed.

## 7. Deviations

Allowed (must be logged): formatting-only commits (`cargo fmt`), not re-run. Forbidden: changing
score, tokenizer, model, split tags, seeds, α, corpora or pins after seeing data; dropping seeds;
re-running for a better number. Any SHA / fingerprint mismatch = run invalid, reported.

## 8. Risks stated in advance

- An in-domain conformal threshold is expected to give FPR ≈ α on FiQA (exchangeability); the
  substantive question is the TPR cost: FiQA scores sit higher than SciFact, so the threshold rises
  and TPR may fall below v3's 0.426, possibly to TRIVIAL.
- Short-text drift (deepset label 0) may remain > α even after FiQA calibration.
- deepset labels as-is; benign corpora assumed injection-free (FiQA forum posts may contain
  instruction-like text; not relabelled); leakage check only against the in-repo trainer corpus.

## 9. Deliverables of the execution PR

1. Harness `ingest_guard_fpr_v4` (Enterprise example); v1–v3 harnesses untouched.
2. `docs/campaigns/2026-10-29-ingest-guard-fpr-v4-results.md` + `…-fpr-v4/raw.jsonl`.
3. No product default changed.
