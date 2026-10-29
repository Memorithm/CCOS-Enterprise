# Ingest guard FPR v6 — results

Prereg: `docs/campaigns/2026-10-29-ingest-guard-fpr-v6-prereg.md` (PR #255, frozen harness
`ingest_guard_fpr_v6.rs`). Raw: `docs/campaigns/2026-10-29-ingest-guard-fpr-v6/raw.jsonl`
(sha256 `edecc549…88c68a`); seed-0 model `model_seed0.json` (sha256 `52da816c…8f4555`).
Inputs: Dolly-15k sha256 `2df90833…f794ec` (14,760 instructions kept; 242 dup, 9 equal to a
deepset text excluded), deepset `2c46bfa4…`, BEIR FiQA/SciFact/NFCorpus as v5. Core model fp
`1a21468e…dfce8` unchanged. 10 seeds, α = 0.05 primary.

## Verdict (arm `v6`, α = 0.05)
- **P1 chat control (deepset label 0, n = 399, never trained/calibrated on): REFUTED.**
  Seed 0: 241/399 = 0.604, CP95 [0.554, 0.652] > 0.10. Mean over seeds 0.642 (0.604–0.674).
- **P2 FiQA FPR: CONFIRMED** (mean 0.0154, conservative because threshold = max of pools).
- **P3 Dolly FPR: CONFIRMED** (mean 0.0489).
- **Detection: NON-TRIVIAL, useful.** Seed 0 TPR 102/135 = 0.756 CP95 [0.674, 0.825]; mean 0.901.
- **Wiring gate: NOT met → guard NOT wired.** `wired: false`, `superiority_claim: false`.

## Table (α = 0.05, means over 10 seeds)
| Arm | FiQA FPR | Dolly FPR | deepset-0 control FPR | Inj TPR |
|---|---|---|---|---|
| v5 (results #254; trained on half of deepset-0, control = other half) | 0.0493 | — | 0.65 (seed 0, n=200) | 0.906 |
| v5r (v5 recipe, no deepset-0, FiQA cal) | 0.0494 | 0.947 | 0.988 | 0.976 |
| **v6** (Dolly negatives, max-of-pools cal) | 0.0154 | 0.0489 | **0.642** | 0.901 |
| v6_pooled (descriptive) | 0.0355 | 0.103 REFUTED | 0.732 | 0.947 |
| baseline_v3 (Core score, FiQA cal) | 0.0499 | 0.0946 | 0.105 | 0.251 |

Seed-0 probes (v6): SciFact 0/2525, NFCorpus 0/3632, OOD Core injections 15/25 (v5r 25/25).
α = 0.01: v6 control 0.437, TPR 0.781; α = 0.10: control 0.728, TPR 0.940.
Leakage exclusions small (≤2 per split per seed, logged). No degeneracy flags.

## Interpretation
- Adding Dolly chat negatives fixes FPR **on Dolly-like chat** (CONFIRMED) and cuts deepset-0
  false alarms vs the same recipe without chat (0.988 → 0.642, paired mean −0.346), but not to
  the 0.10 bound: deepset label 0 is a different benign distribution than Dolly (it contains
  role-play "act as …" prompts and non-English, e.g. German, requests — hypothesis, not measured
  here), and the bag-of-hashed-tokens linear model does not generalise across chat sources.
- Only the Core v3 score keeps the chat control near 0.10, at TPR ≈ 0.25. No arm reaches both.
- The v5 control 0.65 was partly helped by training on deepset-0 itself; v6 shows the honest
  out-of-source figure.

## Deviations
None. Harness and rules ran as frozen in #255.

## Next steps (would need a v7 prereg)
- Multi-source informal benign training (several chat corpora incl. multilingual, role-play
  prompts), with leave-one-source-out evaluation; deepset-0 stays held-out.
- Richer features (e.g. small multilingual sentence encoder) — CPU budget to be assessed.
