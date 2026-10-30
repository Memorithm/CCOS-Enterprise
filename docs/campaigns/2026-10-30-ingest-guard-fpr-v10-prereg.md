# Ingest guard FPR v10 — preregistration

Frozen before any v10 run (2026-10-30, Europe/Paris). Follows v9 (prereg #262 `135159f`, results
#263 `a421ed2`): arm v9 (hash φ, chat_v7 + 15k `nq_short`) deepset-0 control mean **0.400
REFUTED** (seed-0 CP95 lower 0.348), OASST1 in-pool **0.0531 REFUTED** (P3), FiQA CONFIRMED
(0.0125), TPR 0.842, `wired: false`. Earlier: v7 ds0 0.415; v8 (hash ⊕ EN MiniLM) ds0 0.527 (worse);
`v9_and` (Core ∧ v9) ds0 0.035 but TPR 0.212 (not useful); baseline_v3 (published, #263 table)
ds0 ≈ 0.106, TPR ≈ 0.239. Harness frozen here:
`crates/ccos-enterprise-docmemory/examples/ingest_guard_fpr_v10.rs` (opt-in research example; Core
untouched — only public `shared_detector().explain` / `HashingTokenizer` / `defang` are called;
enables nothing; no new dependency; CPU only, no NVIDIA requirement).

## 0. Hypothesis (frozen)
A linear model on hash features trained on chat negatives fails on deepset-0 because its decision
boundary ignores signals Core v3 already exploits on that control (baseline_v3 ds0 ≈ 0.106).
**v10 tests whether concatenating a small explicit scalar block s(x) — the Core FPR-v3 score plus
length / script / German-orthography signals — to the 2048-d hash φ(x) brings the deepset-0
control FPR to ≤ 0.10 while keeping FiQA / in-pool chat FPR and useful detection.**

Motivation (descriptive audit, no labels used for any threshold): heuristic language mix of the
399 deepset label-0 rows ≈ 251 ASCII/EN-like, ≈ 146 DE-like, ≈ 2 other; label 1 is also heavily
DE. `nq_short` is EN-only, so v9's style hypothesis did not address the DE part; an EN MiniLM
cannot fix DE either. Only the published baseline_v3 numbers above are cited; no deepset-0 score
was inspected to choose features, standardisation or thresholds.

## 1. Data
- Unchanged inputs and SHAs from v9: SciFact, NFCorpus, FiQA, deepset (`2c46bfa4…22ef8`), Core
  model fp `1a21468e…dfce8`, **`chat_v9.jsonl` sha256
  `aaa6cc3b331baeb48418afaac6f6c3a15b1308e0306882600a8940810d13d882`** (dolly / oasst1 /
  hh_helpful / nq_short; built by the v9 script; stays outside git, SHA asserted at run). No new
  corpus is added.
- **Deferred:** SentencePiece / XLM-R / multilingual encoders are still not in the repo
  (`ccos-dense-encoder` is WordPiece only). Out of scope for v10; needs its own engineering PR +
  prereg. MiniLM is dropped entirely.

## 2. Splits (paired with v7–v9)
Identical to v9: `ingest-fpr-v7:{corpus}:{seed}:{key}` for shared corpora,
`ingest-fpr-v9:nq_short:{seed}:{key}` for nq_short; byte0 % 4: {0,1} train, 2 cal, 3 test; byte1
% 4 == 0 inner λ split; seeds 0..9; α ∈ {0.05 primary, 0.01, 0.10}; same exact-text leakage
exclusion. **deepset label 0 (399) is never used for training, λ selection, standardisation or
calibration.** All flags go through `GovernedDocumentMemory::insert_document`.

## 3. Features, model, arms
- h(x): v7/v9 φ = log1p + L2 over `HashingTokenizer::new()` counts on `defang(x)` (2048-d).
- s(x) (4 scalars, computed on `defang(x)`):
  1. Core FPR-v3 score `(margin − prior_margin) / max(1, n_features)` (same formula as
     `ingest_guard_fpr_v3`, via the Core detector `explain` API);
  2. `log1p(char count)`;
  3. `ascii_ratio` = fraction of code points < 128;
  4. `de_orthography_ratio` = fraction of chars in `äöüÄÖÜß` (the optional DE stop-word indicator
     is **not** used; frozen).
  Each scalar is standardised `(s − mean) / sd` with mean / population sd computed **per seed on
  the outer training split** (FiQA, SciFact, all four chat sources and injection train rows,
  unweighted; sd < 1e-12 → 1). The same constants are used for inner λ fits, final fit,
  calibration and test, and are written to the seed-0 artefact (`scalar_std_mean_sd`) and every
  `train` record. (Inner-split fits therefore see standardisation constants that include the inner
  λ-validation rows: 8 numbers, declared here as a known minor leak within train.)
- Model: L2 logistic regression on [h ; s] (dim 2052), Nesterov, 400 iters, λ ∈ {1e-5, 1e-4, 1e-3}
  with the max-of-pools inner rule, same weighting (injections ½ mass; each benign source equal
  share of the other ½), threshold = max of ConformalGuard thresholds over calibration pools FiQA,
  Dolly, OASST1, HH, nq_short.
- Arms:
  - **`v10` (primary, gating):** [h ; s] as above.
  - `v9` (sanity): hash only, same benign sources/pools/splits; expected to reproduce #263 within
    noise (mismatch reported as deviation, not re-run).
  - `v10_and` (descriptive): refuse iff baseline_v3 guard AND v10 guard (min(z_v10 − thr_v10,
    s_v3 − thr_v3) through a threshold-0 guard, strict `>`).
  - `baseline_v3`: Core v3 score, FiQA calibration.

## 4. Decision rules (α = 0.05, arm `v10`) — identical to v7–v9
- **P1 deepset-0 control:** CONFIRMED iff seed-0 CP95 upper ≤ 0.10 and mean ≤ 0.10; REFUTED iff
  CP95 lower > 0.10; else INCONCLUSIVE.
- **P2 FiQA FPR:** REFUTED iff m − 1.833·se > α; CONFIRMED iff m ≤ α + 0.0025, not degenerate.
- **P3 in-pool chat FPR:** P2 rule on Dolly, OASST1, HH; all must be CONFIRMED. nq_short
  descriptive only.
- **Detection:** NON-TRIVIAL iff seed-0 TPR CP95 lower > 0.05; useful iff mean TPR ≥ 0.5.
- Degeneracy checks as v7. Secondary arms descriptive. `superiority_claim: false`.
- **Wiring gate = P1 ∧ P2 ∧ P3 ∧ NON-TRIVIAL ∧ useful (arm `v10` only).** If met, a separate
  follow-up PR may wire an opt-in, off-by-default guard; otherwise `wired: false`. No wiring here.

## 5. Outputs / out of scope
One uninterrupted CPU run from the merged prereg commit:
`cargo run --release -p ccos-enterprise-docmemory --example ingest_guard_fpr_v10 -- <scifact>
<nfcorpus> <fiqa> <deepset.jsonl> /workspace/chat-data/chat_v9.jsonl <model_seed0.json>`.
Outputs `docs/campaigns/2026-10-30-ingest-guard-fpr-v10/{raw.jsonl,model_seed0.json}` + results
doc; deviations listed there. Negative results are kept. **No run is performed in this PR.**
