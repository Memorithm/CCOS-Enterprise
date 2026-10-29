# Ingest guard FPR v6 — preregistration

Frozen before any v6 run. Follows v5 (prereg #253, results #254, main `cf2a989`).
Harness frozen in this PR: `crates/ccos-enterprise-docmemory/examples/ingest_guard_fpr_v6.rs`
(opt-in research example; Core model/tokenizer/score untouched; enables nothing).

## 0. Motivation (v5 audit)
v5 (L2 logistic regression over Core `HashingTokenizer` features, FiQA-only calibration) reached
FiQA FPR 0.0493 CONFIRMED and injection TPR 0.906, but flagged 65 % of informal benign chat
(deepset label 0 control, seed 0). The detector separates *chat vs prose*, not *injection vs benign*.

## 1. Approach
- Same model family, features (log1p + L2 over `HashingTokenizer::new()` counts on `defang(text)`),
  optimiser (Nesterov GD, 400 iters), λ grid {1e-5,1e-4,1e-3}, weighting (injections 1/2 of mass,
  each benign source an equal share of the other 1/2) as v5.
- **New benign chat source:** Dolly-15k (`databricks/databricks-dolly-15k`, CC BY-SA 3.0),
  `instruction` field only, file sha256 `2df90833…f794ec`, 15,010 rows. Blank, duplicate
  (normalised) and any instruction whose normalised text equals a deepset text (any label) are
  excluded (counts logged). Distinct from deepset label 0.
- **Training negatives:** FiQA train + SciFact train + Dolly train. **deepset label 0 is never
  used for training, λ selection or calibration** (v5 used half of it in training; v6 does not).
- **λ selection:** inner split; threshold = max(q95 inner FiQA, q95 inner Dolly); max inner TPR.
- **Calibration (primary arm `v6`):** threshold = max(ConformalGuard(FiQA cal, α).threshold,
  ConformalGuard(Dolly cal, α).threshold) — per-pool (Mondrian-max) mixed calibration; each pool's
  FPR is bounded by α.
- Descriptive arms: `v6_pooled` (same model, conformal on concatenated FiQA+Dolly cal);
  `v5r` (v5 recipe with FiQA+SciFact negatives only, FiQA calibration — v5 minus deepset-0, so the
  control is untouched for both); `baseline_v3` (Core v3 score, FiQA calibration).
- All flags counted through `GovernedDocumentMemory::insert_document` with `IngestGuard`.

## 2. Splits (hash `ingest-fpr-v6:{corpus}:{seed}:{key}`, r = h[0] % 4)
- FiQA: train {0,1}, cal {2}, test {3}. Dolly: train {0,1}, cal {2}, test {3}.
- deepset injections (label 1, Core-trainer-leak excluded as v5): train {0,1}, test {2,3}.
- SciFact: train {0,1}, probe {2,3}. NFCorpus: probe (all). Core trainer injections: OOD probe.
- **deepset label 0: full set = chat control**, every seed.
- Exact normalised-text exclusion: cal vs train; test/control/probes vs train ∪ cal (counts logged).
- Seeds 0..9 (10). α ∈ {0.05 primary, 0.01, 0.10}.

## 3. Decision rules (α = 0.05, arm `v6`)
- **Co-primary P1 — chat control FPR (deepset-0):** seed-0 k/n with Clopper–Pearson 95 %.
  CONFIRMED iff CP95 upper ≤ 0.10 **and** mean over seeds ≤ 0.10; REFUTED iff CP95 lower > 0.10;
  else INCONCLUSIVE. (0.10 = 2α tolerance for an out-of-pool chat source.)
- **Co-primary P2 — FiQA test FPR:** v5 rule: REFUTED iff m − 1.833·se > α; CONFIRMED iff
  m ≤ α + 0.0025 and not degenerate; else INCONCLUSIVE.
- **P3 — Dolly test FPR:** same rule as P2.
- **Detection:** NON-TRIVIAL iff seed-0 injection TPR CP95 lower > 0.05. Useful iff mean TPR ≥ 0.5.
- Degeneracy checks as v5 (≥100 distinct cal scores, finite threshold, ≤1 % ties, threshold <
  max test score, ≥1 flag on FiQA+Dolly test at seed 0, no divergence).
- **Wiring gate:** P1 CONFIRMED ∧ P2 CONFIRMED ∧ P3 CONFIRMED ∧ NON-TRIVIAL ∧ mean TPR ≥ 0.5.
  Even if met, this campaign does not wire the guard: wiring would be a separate reviewed PR.
  `superiority_claim: false` regardless. Negative results are reported as such.

## 4. Outputs
`docs/campaigns/2026-10-29-ingest-guard-fpr-v6/raw.jsonl` (kinds meta, model_artifact, train,
split, summary, verdict) and `model_seed0.json`; results in `…-fpr-v6-results.md` with sha256s.
Any deviation from this document is listed in the results.
