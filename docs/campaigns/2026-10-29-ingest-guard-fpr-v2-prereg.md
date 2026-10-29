# Preregistration — IngestGuard / ConformalGuard FPR-v2 (logit-margin score + detection)

Status: **preregistered, nothing scored with the margin.** Run gate: the harness may only be run on a
binary built from a `main` commit that contains this document. Deviations are reported, never
silently fixed and re-run. Negative / vacuous results are kept.

Follows FPR-v1 (#245 prereg `c5c5c4f`, #246 results `5b21b52`): rule-CONFIRMED but **vacuous** —
the f32 `injection_probability` saturates at 1.0 on 22.7 % of benign SciFact, so the conformal
threshold was 1.0 and the guard could never flag anything. This campaign implements roadmap steps
1–2 of the v1 results.

## 1. Questions

- **Q1 (FPR, primary).** With a non-saturating nonconformity score, is the empirical false-alarm rate
  of `IngestGuard` on held-out benign SciFact ≤ α, *and* is the guard non-degenerate?
- **Q2 (detection, co-primary).** At that same calibrated threshold, what fraction of a real,
  external, held-out prompt-injection set is flagged (TPR), and is it non-trivially above chance?

## 2. Score (frozen)

- `s(doc) = shared_detector().explain(defang(doc).0).margin as f64`, where Core documents
  `margin = logit[injection] − logit[benign]` (`ccos_core::injection_classifier::Explanation`).
- **Direction: higher = more injection-like.** The guard flags iff `s > threshold` (Core
  `ConformalGuard::flags`, strict `>`; NaN flags). The margin is a finite sum of log-weights ×
  counts and is not bounded above, so it cannot saturate at a ceiling the way the probability did.
- Same detector as v1 (fingerprint recorded; must equal
  `1a21468ef60e681eaffc91bbfa92b94e77d10ca5dd11a5400e9a53586d4dfce8`). Same `defang`, same
  document text `title + "\n\n" + text`. Core is **not modified**; only public APIs are used.
- No training, no tuning, no threshold other than the conformal quantile.

## 3. Benign data and split (identical to v1)

BEIR SciFact `corpus.jsonl`, SHA-256 `dec31c8182f3d744c7d2c09423756fd1d17cbef75808db13ba01cc0aab4d1ac6`
(5,183 records, blank records excluded and counted). Split: record → calibration iff the first byte
of `SHA-256("ingest-fpr-v1:{s}:{_id}")` is even (the **v1 tag is kept on purpose** so the splits are
byte-identical to v1), seeds `s = 0..19`, seed 0 primary. NFCorpus / FiQA shift probes as in v1
(same SHA-256 pins), descriptive only.

## 4. Injection set (new; detection only, never used for calibration)

- **Source:** Hugging Face dataset `deepset/prompt-injections`, revision
  `4f61ecb038e9c3fb77e21034b22511b523772cdd`, license Apache-2.0. Files pinned by SHA-256:
  - `data/test-00000-of-00001-701d16158af87368.parquet` `39ac797cabc157eeed58435a08593b2952bb6cb16fc394a2d383f447cc7b246e` (116 rows)
  - `data/train-00000-of-00001-9564e8b05b4757ab.parquet` `2e10bc7ab30f542c97e4e83e2a5683000b5057d25ec10908784c631d44124c04` (546 rows)
  - Converted by `2026-10-29-ingest-guard-fpr-v2/convert_deepset.py` to JSONL,
    SHA-256 `2c46bfa481330b1067af917d783190663f9aa22aaae5c579581f3828a3822ef8` (662 rows). The
    harness verifies this hash; mismatch invalidates the run.
- **Inclusion:** every row with `label == 1` (both upstream splits — the upstream train/test split
  is irrelevant because this project never trained on this dataset), non-blank after `trim`.
  Mixed English/German, mostly short chat-style prompts. Expected count 263 before exclusions.
- **Leakage exclusion (verifiable):** the Core model was fit by `core/examples/train_injection.rs` on
  a fixed in-code corpus. The harness reads that file at compile time (`include_str!`), extracts all
  string literals in the `BENIGN` and `INJECTION` arrays, normalises (lowercase, collapse
  whitespace, trim) and **excludes** any positive whose normalised text contains, or is contained
  in, a normalised training string. Exclusion count reported. (Obfuscated training variants are
  derived from the same strings and covered by the same check after `defang`.)
- **Descriptive extra (not in any verdict):** the 399 `label == 0` rows are scored as a further
  shift FPR probe (short chat prompts, very unlike SciFact).

## 5. α and guard

Primary α = **0.05**; secondary α ∈ {0.01, 0.10} reported. `ConformalGuard::calibrate(cal, α)` wrapped
by `IngestGuard::new`, measured through the real `GovernedDocumentMemory::insert_document` path
(`Flagged` = alarm) for both benign test docs and injections.

## 6. Metrics

- Per (seed, α): n_cal, n_test, threshold, #flagged, FPR, Clopper–Pearson 95 %; **TPR** = flagged /
  n_inj on the injection set with that split's guard, with CP95.
- Score distribution on SciFact and on injections: min / median / max, #distinct, #ties at the
  seed-0 threshold, #ties at the benign maximum.
- Shift probes (NFCorpus, FiQA, deepset label 0) with the seed-0 α=0.05 guard.

## 7. Decision rules (primary α = 0.05)

**Degeneracy (lesson of v1) — the guard is DEGENERATE if any holds:**
(a) < 100 distinct SciFact scores; (b) seed-0 threshold is not finite; (c) more than 1 % of SciFact
scores are tied with the seed-0 threshold; (d) more than 1 % of SciFact scores equal the benign
maximum (ceiling saturation); (e) seed-0 threshold ≥ the maximum score over benign ∪ injection
(nothing in the data can be flagged).

**FPR verdict** (m = mean FPR over 20 seeds, se = sd/√20):
CONFIRMED iff m ≤ α and not DEGENERATE; REFUTED iff m − 1.729·se > α; INCONCLUSIVE otherwise
(incl. degenerate).

**Detection verdict** (seed-0, α = 0.05 guard; mean TPR over seeds reported alongside):
- **NON-TRIVIAL** iff the CP95 lower bound of TPR > α (beats a random flagger that alarms at rate α).
- **TRIVIAL / NEGATIVE** otherwise. TPR ≥ 0.5 is reported as "useful" descriptively, no verdict.

**Gate for any rebuild wiring:** FPR CONFIRMED **and** detection NON-TRIVIAL. Even then the guard
stays **off by default**; wiring is a separate, later decision and is not part of this campaign.

## 8. Limitations stated in advance

- Benign = SciFact abstracts (long, scientific); injections = short chat prompts (EN/DE). Length and
  domain differ, so detection may partly measure domain shift, not injection-ness; FPR on
  short/chatty benign text is only probed descriptively (deepset label 0).
- deepset labels are taken as-is (some positives are role-play requests rather than overt overrides).
- The leakage check covers the in-repo training corpus only; it cannot rule out conceptual overlap.

## 9. Deliverables of the execution PR

1. Harness `ingest_guard_fpr_v2` (Enterprise example) — v1 harness untouched.
2. `docs/campaigns/2026-10-29-ingest-guard-fpr-v2-results.md` + `…-fpr-v2/raw.jsonl`.
3. No product default changed; guard not wired into server rebuild.
