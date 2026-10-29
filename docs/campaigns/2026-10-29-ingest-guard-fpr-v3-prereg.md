# Preregistration — IngestGuard / ConformalGuard FPR-v3 (length-normalised margin)

Status: **preregistered, nothing scored with the v3 score.** Run gate: the harness may only be run on
a binary built from a `main` commit that contains this document. Deviations are reported, never
silently fixed and re-run. Negative / trivial results are kept.

Follows FPR-v1 (#245/#246, CONFIRMED-but-vacuous: probability saturation) and FPR-v2 (#247 prereg
`ac4d35d`, #248 results `65d421b`): FPR **CONFIRMED, non-degenerate** (mean 0.0467) but detection
**TRIVIAL** (seed-0 TPR 0.061, CP95 lower 0.035 ≤ α) with TPR ≈ FPR at every α. The v2 results
hypothesised (exploratory, untested) that the raw margin is an unnormalised sum over feature counts
and therefore tracks document length. v3 tests one fixed length normalisation.

## 1. Questions

- **Q1 (FPR, primary).** With the length-normalised score below, is the empirical false-alarm rate of
  `IngestGuard` on held-out benign SciFact ≤ α, and is the guard non-degenerate?
- **Q2 (detection, co-primary).** At that calibrated threshold, is TPR on the pinned deepset
  injections non-trivially above α?

## 2. Score (frozen, exact)

Let `t = defang(doc).0` (Core `ccos_core::sanitizer::defang`, unchanged), `e =
shared_detector().explain(t)`, and `n = HashingTokenizer::new().features(t).len()` — the number of
feature **occurrences** produced by the Core default tokenizer (`ccos_core::hashing_tokenizer`,
default config: lowercase, `D = 2048`, word unigrams split on non-alphanumeric-non-`_`, plus all
character 3-gram windows of the lowercased text). `n` equals the L1 norm of the count vector the
model consumes. Then

```
s(doc) = (e.margin − e.prior_margin) / max(1, n)        (computed in f64 from the f32 fields)
```

i.e. the **mean per-feature-occurrence log-likelihood-ratio contribution** (injection − benign). The
class prior is subtracted because it is a length-independent constant; dividing it by `n` would
re-introduce a length term. **Direction: higher = more injection-like**; flag iff `s > threshold`
(Core `ConformalGuard::flags`, strict `>`; NaN flags).

- The harness asserts `HashingTokenizer::new().dim() == shared_detector().model().dim` and the model
  fingerprint `1a21468ef60e681eaffc91bbfa92b94e77d10ca5dd11a5400e9a53586d4dfce8` (= v1/v2).
- Document text `title + "\n\n" + text` (as v1/v2). Core is **not modified**; only public APIs.
- No training, no tuning, no alternative normalisation scored. The raw v2 margin is recomputed only
  as a descriptive reference (§6), never for a verdict.

## 3. Benign data and split (identical to v1/v2)

BEIR SciFact `corpus.jsonl`, SHA-256 `dec31c8182f3d744c7d2c09423756fd1d17cbef75808db13ba01cc0aab4d1ac6`.
Split: calibration iff first byte of `SHA-256("ingest-fpr-v1:{s}:{_id}")` is even (v1 tag kept, splits
byte-identical to v1/v2), seeds `s = 0..19`, seed 0 primary. NFCorpus
(`10cc83ef…991f`) / FiQA (`ff593e4d…6517`) shift probes, same pins, descriptive only.

## 4. Injection set (identical to v2)

`deepset/prompt-injections` revision `4f61ecb038e9c3fb77e21034b22511b523772cdd` (Apache-2.0), parquet
pins as v2 prereg §4, converted by `2026-10-29-ingest-guard-fpr-v2/convert_deepset.py` to JSONL
SHA-256 `2c46bfa481330b1067af917d783190663f9aa22aaae5c579581f3828a3822ef8`. Positives = `label == 1`,
non-blank, same leakage exclusion against `core/examples/train_injection.rs` (v2 found 0 excluded,
263 included). `label == 0` rows: descriptive shift probe only.

## 5. α and guard

Primary α = **0.05**; secondary {0.01, 0.10} reported. `ConformalGuard::calibrate(cal, α)` wrapped by
`IngestGuard::new`, measured through `GovernedDocumentMemory::insert_document` (`Flagged` = alarm).

## 6. Metrics

Per (seed, α): n_cal, n_test, threshold, flagged, FPR + CP95, TPR + CP95. Score distributions
(min/median/max/#distinct) on SciFact and injections; `n` distributions; ties at threshold and at
benign max; Spearman ρ(s, n) on SciFact and on injections (length-confound diagnostic, descriptive);
shift probes with the seed-0 α=0.05 guard; v2 raw margin seed-0 TPR recomputed as reference.

## 7. Decision rules (primary α = 0.05)

**DEGENERATE if any holds** (v1/v2 checks a–e plus new trivial-threshold checks f–g):
(a) < 100 distinct SciFact scores; (b) seed-0 threshold not finite; (c) > 1 % of SciFact scores tied
with the seed-0 threshold; (d) > 1 % of SciFact scores equal the benign maximum (ceiling saturation);
(e) seed-0 threshold ≥ max score over benign ∪ injection; (f) seed-0 held-out SciFact flagged count
is 0 (guard never fires on benign — vacuous calibration, the v1 failure); (g) > 1 % of SciFact docs
have `n ≤ 1` (normaliser collapses: score ≈ raw margin on degenerate inputs).

**FPR verdict** (m = mean FPR over 20 seeds, se = sd/√20): REFUTED iff m − 1.729·se > α; else
INCONCLUSIVE if DEGENERATE; else CONFIRMED iff m ≤ α; else INCONCLUSIVE.

**Detection verdict** (seed 0, α = 0.05): **NON-TRIVIAL** iff CP95 lower bound of TPR > α; otherwise
**TRIVIAL/NEGATIVE**. Mean TPR over seeds reported alongside; TPR ≥ 0.5 noted as "useful" only.

**Gate for rebuild wiring:** FPR CONFIRMED **and** detection NON-TRIVIAL. Even then any wiring is
opt-in, **default off**, documented; if the gate fails, nothing is wired.

## 8. Risks and limitations stated in advance

- **Domain drift (from v2):** calibrated on SciFact, the v2 guard had FPR 0.137 on FiQA (~2.7× α).
  Normalisation may change this either way; FiQA/NFCorpus/deepset-label-0 remain descriptive, no
  guarantee claimed outside SciFact.
- Length normalisation may *invert* the length bias (short texts get higher-variance means), so
  short benign text could be over-flagged; probed descriptively via deepset label 0 and ρ(s, n).
- Benign (long scientific EN) vs injections (short chat EN/DE): detection may still partly measure
  domain shift. deepset labels taken as-is. Leakage check covers the in-repo trainer corpus only.

## 9. Deliverables of the execution PR

1. Harness `ingest_guard_fpr_v3` (Enterprise example); v1/v2 harnesses untouched.
2. `docs/campaigns/2026-10-29-ingest-guard-fpr-v3-results.md` + `…-fpr-v3/raw.jsonl`.
3. No product default changed unless the §7 gate passes (and then opt-in, default off).
