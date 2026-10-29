# Preregistration — IngestGuard / ConformalGuard FPR-v5 (retrained detector on disjoint splits)

Status: **preregistered, nothing trained or scored under the v5 protocol.** Run gate: the harness
may only be run on a binary built from a `main` commit that contains this document. Deviations are
reported, never silently fixed and re-run. Negative / trivial results are kept.

Follows FPR-v4 (#251 prereg `be6382f`, #252 results `b870eca`): FiQA-calibrated v3 score gives FPR
0.0501 (INCONCLUSIVE under the strict rule), TPR 0.247 (NON-TRIVIAL, weak), deepset label 0 FPR
0.105. v4 concluded the limit is the **model**, not the calibration. v5 changes the **detector**.

## 0. Audit — why the v3 score separates poorly (evidence, not speculation)

1. **Training corpus is tiny and off-domain.** `core/examples/train_injection.rs` fits the embedded
   model (`1a21468e…dfce8`) on 30 hand-written benign strings — almost all code, shell, SQL, logs —
   and 25 hand-written injections (+ obfuscated variants). No natural prose, no forum/chat text.
   Any informal English is therefore "far from benign" for this model.
2. **Multinomial NB weights are log-likelihood ratios over 2048 hashed buckets.** With 30 benign
   strings almost every bucket's benign likelihood is Laplace-smoothed noise; common English
   function-word / char-3-gram buckets get a sign set by chance co-occurrence in the 55 strings.
   Long prose accumulates these per-occurrence terms → v1/v2 margin saturation, which v3 fixed only
   by dividing by `n` (a per-token *mean*, still dominated by generic-English buckets).
3. **Observed effect matches (1)–(2):** v3 SciFact-calibrated FPR on FiQA 0.281 and on deepset
   label 0 0.231 (v3 results); FiQA calibration triples the threshold (0.069 → 0.212) and halves
   TPR (0.426 → 0.247) (v4 results). The benign domains that are flagged are exactly the
   informal-prose domains absent from training.
4. Calibration is not the bottleneck: v4 FPR ≈ α at every α in-domain (0.0100 / 0.0501 / 0.0998).

Conclusion: the detector must be fit on the benign domains it will see, with injections, and
evaluated on disjoint splits. The Core model / score / tokenizer stay untouched.

## 1. Approach (primary, single): A — retrain, research-only artefact

**Model:** L2-regularised binary **logistic regression** over the Core `HashingTokenizer::new()`
count vector (D = 2048, unchanged), feature map `φ(x) = log1p(x) / ‖log1p(x)‖₂` (zero vector stays
zero) plus an unpenalised bias. Score `s = w·φ + b` (logit, higher = more injection-like) on
`defang(text).0`. Trained inside the harness, CPU, deterministic: full-batch **Nesterov accelerated
gradient**, step 1/(0.25 + λ), **400 iterations**, w = 0, b = 0 init, f64, fixed-order reductions
(per-thread partial sums over fixed contiguous chunks, summed in chunk order — bit-reproducible for a
fixed thread count; thread count fixed to 8 and logged).

**Weights:** class-balanced; within the benign class each training source (FiQA, SciFact, deepset
label 0) carries an equal share of the benign mass; total injection mass = total benign mass.

**λ selection (inside the training split only):** grid λ ∈ {1e-5, 1e-4, 1e-3}. Inner split of the
training set: inner-val iff byte[1] of the split hash (below) is `% 4 == 0`. Fit on inner-train;
criterion = inner-val injection TPR at the threshold equal to the empirical 95 % quantile of
inner-val FiQA scores; ties → larger λ. Refit on the full training split with the chosen λ. No
calibration or test item is ever seen during fit or selection.

The artefact is research-only (seed-0 weights written to `…-fpr-v5/model_seed0.json` with SHA-256
logged). **Core is not modified; the embedded model and its fingerprint are unchanged** (harness
asserts `1a21468e…dfce8`).

## 2. Data and splits (redefined for v5, disjoint, leakage-controlled)

Pinned inputs (SHA-256 asserted, unchanged): FiQA `ff593e4d…6517`, SciFact `dec31c81…1ac6`,
NFCorpus `10cc83ef…991f`, deepset JSONL `2c46bfa4…2ef8` (rev `4f61ecb0…`, converter unchanged).
Text = `title + "\n\n" + text` (BEIR) / `text` (deepset); blanks excluded and counted.

Per seed `s ∈ {0..9}` (seed 0 primary), `h = SHA-256("ingest-fpr-v5:{corpus}:{s}:{key}")`
(`key` = BEIR `_id`, deepset `{split}:{row}`), `r = h[0] % 4`:

| Corpus | train (fit + λ) | calibration | test / probe |
|---|---|---|---|
| FiQA | r ∈ {0,1} | r = 2 | r = 3 (FPR, primary) |
| deepset label 1 (injections) | r ∈ {0,1} | — never | r ∈ {2,3} (TPR, primary) |
| deepset label 0 (chat benign) | r ∈ {0,1} | — | r ∈ {2,3} (control FPR) |
| SciFact | r ∈ {0,1} | — | r ∈ {2,3} (drift probe) |
| NFCorpus | — never | — | all (out-of-domain benign probe) |
| Core trainer `INJECTION` literals (25) | — never | — | all (out-of-distribution injection probe, descriptive) |

**Leakage control (asserted / counted):** key sets of train, cal, test pairwise disjoint (assert).
Exact-text leakage: any cal/test/probe item whose normalised text (`lowercase`, whitespace
collapsed, after `defang`) equals a training item's normalised text is **excluded** from evaluation
and counted per seed (reported; expected ≈ 0, deepset has 0 duplicate texts). Injections never enter
calibration. deepset injections that match the Core trainer corpus are excluded as in v2–v4.

## 3. Guard and α

`ConformalGuard::calibrate(cal_scores, α)` on the FiQA calibration quarter; wrapped by
`IngestGuard::new` with the v5 scorer closure; FPR/TPR measured through
`GovernedDocumentMemory::insert_document` (`Flagged` = alarm). Primary α = **0.05**; secondary
{0.01, 0.10}.

## 4. Baseline arm (mandatory comparison, same seeds/splits)

v3 score (`(margin − prior_margin)/max(1,n)`, embedded model) calibrated on the **same** FiQA
calibration quarter, evaluated on the same FiQA test quarter, the same test injections, the same
deepset label 0 control and probes. This is the v4 protocol re-run on v5 splits (calibration set is
a quarter instead of a half; v4 numbers are also quoted as-is).

## 5. Metrics (per seed, α, arm)

n_train / n_cal / n_test per corpus, chosen λ, final training loss, threshold, FiQA-test FPR + CP95,
test-injection TPR + CP95, deepset label 0 control FPR + CP95, SciFact / NFCorpus probe FPR, OOD
injection probe TPR, leakage exclusions, score summaries (distinct, ties at threshold, max).
Paired per-seed Δ TPR (v5 − baseline) at α = 0.05, descriptive.

## 6. Decision rules (primary α = 0.05, v5 arm)

**DEGENERATE if any (seed 0):** (a) < 100 distinct FiQA-cal scores; (b) threshold not finite;
(c) > 1 % of FiQA-cal scores tied with the threshold; (d) threshold ≥ max score over FiQA-test ∪
test injections; (e) seed-0 FiQA-test flagged = 0; (f) training diverged (non-finite loss/weights).

**FPR verdict** (m = mean FiQA-test FPR over 10 seeds, se = sd/√10, t₀.₉₅,₉ = 1.833):
REFUTED iff m − 1.833·se > α; else INCONCLUSIVE if DEGENERATE; else **CONFIRMED iff m ≤ α + δ with
δ = 0.0025** (new finite-sample tolerance for split-conformal sampling noise, fixed here, applies
to v5 only, **never retroactively to v4**); else INCONCLUSIVE. The strict `m ≤ α` outcome is also
reported.

**Detection verdict** (seed 0): NON-TRIVIAL iff TPR CP95 lower > α, else TRIVIAL/NEGATIVE. "Useful"
iff seed-0 TPR ≥ 0.5 — **descriptive label only**. Mean TPR over seeds reported.

**Control:** seed-0 deepset label 0 control FPR reported with CP95; "not exploding" iff point
FPR ≤ 0.105 (v4 level).

**Separation vs baseline (descriptive):** mean over seeds of paired Δ TPR at α = 0.05, and number
of seeds with Δ > 0. `superiority_claim = false` (no significance claim).

**Wiring gate (rebuild):** FPR CONFIRMED **and** NON-TRIVIAL **and** control "not exploding" **and**
mean v5 TPR > mean baseline TPR on the same splits. If met, a *later, separate* prereg/PR may add
opt-in, **default-off** wiring with a separately pinned model artefact and tenant calibration. The
v5 results PR changes **no product code or default** in any case.

## 7. Deviations

Allowed (logged): `cargo fmt`-only commits, not re-run. Forbidden after seeing data: changing
model class, features, optimiser, iterations, λ grid, weights, split tags/fractions, seeds, α, δ,
corpora or pins; dropping seeds; re-running for a better number. Any SHA / fingerprint mismatch =
run invalid, reported. A crash before completion may be fixed and re-run only if no metric was
printed; otherwise reported.

## 8. Risks stated in advance

- **In-distribution optimism:** train and test injections are both deepset (same collection), so
  TPR is an in-distribution estimate; the 25 Core-trainer injections give only a small OOD probe.
- **Dataset artefacts:** deepset injections are short and partly German; the model may learn
  length/language cues. deepset label 0 (short, mixed language) in training and the control arm
  measure this; NFCorpus (never trained) measures benign OOD.
- Only ~130 injections for training per seed; λ grid small; no hyper-search beyond §1.
- FiQA assumed injection-free; labels as-is; guarantee marginal and FiQA-exchangeable only.

## 9. Deliverables of the execution PR

1. Harness `ingest_guard_fpr_v5` (Enterprise example; v1–v4 untouched; Core untouched).
2. `docs/campaigns/2026-10-29-ingest-guard-fpr-v5-results.md`, `…-fpr-v5/raw.jsonl`,
   `…-fpr-v5/model_seed0.json`.
3. No product default changed.
