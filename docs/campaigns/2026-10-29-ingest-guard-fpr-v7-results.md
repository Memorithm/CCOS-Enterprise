# Ingest guard FPR v7 — results

Prereg: `docs/campaigns/2026-10-29-ingest-guard-fpr-v7-prereg.md` (PR #257, main `6f9a650`, frozen
harness `ingest_guard_fpr_v7.rs`). Raw: `docs/campaigns/2026-10-29-ingest-guard-fpr-v7/raw.jsonl`
(sha256 `3b78cab7…fb33d8648`); seed-0 model `model_seed0.json` (sha256 `d082f059…c3d1dd70`).
Inputs: `build_chat_v7.py` sha256 `c6c4f5d8…e024f5`, `chat_v7.jsonl` sha256 `7aa8ff2b…ff2be`
(both match the prereg; the harness asserts the latter). Chat sizes after deepset-overlap/blank
exclusion: Dolly 14,760, OASST1 14,999, HH 14,998 (1/1/2 excluded). Core model fp `1a21468e…dfce8`
unchanged. 10 seeds (0..9), 400 iters, λ ∈ {1e-5, 1e-4, 1e-3}; α = 0.05 primary.

## Verdict (arm `v7`, α = 0.05)
- **P1 deepset-0 chat control (n = 399, never trained/calibrated on): REFUTED.**
  Seed 0: 166/399 = 0.416, CP95 [0.367, 0.466], lower > 0.10. Mean over seeds 0.415 (0.381–0.466).
- **P2 FiQA FPR: CONFIRMED** (mean 0.0103, se 0.0014).
- **P3 in-pool chat FPR: NOT CONFIRMED.** Dolly 0.0151 CONFIRMED, HH 0.0117 CONFIRMED,
  **OASST1 0.0531 INCONCLUSIVE** (m > α + 0.0025, and m − 1.833·se = 0.0499 ≤ α).
- **Detection: NON-TRIVIAL, useful.** Seed 0 TPR 118/140 = 0.843 CP95 [0.772, 0.899]; mean 0.839.
- **Wiring gate (P1 ∧ P2 ∧ P3 ∧ NON-TRIVIAL ∧ useful): NOT met → guard NOT wired.**
  `wired: false`, `superiority_claim: false`.

## Table (α = 0.05, means over 10 seeds)
| Arm | FiQA FPR | Dolly | OASST1 | HH | deepset-0 control | Inj TPR |
|---|---|---|---|---|---|---|
| v6 (results #256, Dolly only) | 0.0154 | 0.0489 | — | — | 0.642 | 0.901 |
| **v7** (3 chat sources, max-of-4-pools cal) | 0.0103 | 0.0151 | 0.0531 | 0.0117 | **0.415** | 0.839 |
| loo_dolly | 0.0087 | *0.0366* | 0.0533 | 0.0133 | 0.427 | 0.834 |
| loo_oasst1 | 0.0212 | 0.0492 | ***0.2568*** | 0.0430 | 0.638 | 0.894 |
| loo_hh_helpful | 0.0103 | 0.0174 | 0.0531 | *0.0264* | 0.412 | 0.844 |
| baseline_v3 (Core score, FiQA cal) | 0.0496 | 0.0981 | 0.1167 | 0.1775 | 0.106 | 0.239 |

Italic = held-out source (LOO, descriptive, not gating). LOO held-out FPR ≤ 0.10: Dolly yes,
HH yes, **OASST1 no (0.257)**.

Other α (v7): α = 0.01 control 0.154, TPR 0.612, all in-pool chat CONFIRMED; α = 0.10 control
0.548, TPR 0.895, OASST1 INCONCLUSIVE.
Seed-0 probes (v7): SciFact 1/2626, NFCorpus 5/3631, OOD Core injections 15/25. Seed-0 threshold
−1.550 (1 calibration tie). No degeneracy flags.

## Interpretation
- Multi-source chat negatives cut deepset-0 false alarms from 0.642 (v6) to 0.415, but still far
  above 0.10. P1 stays REFUTED.
- OASST1 drives most of the gain: holding it out puts the control back at v6 level (0.638), and
  its own held-out FPR is 0.257. That fits the hypothesis that multilingual informal text is what
  the hashed-token linear model misses. Dolly/HH transfer to each other fine.
- OASST1 in-pool FPR sits right at α (0.053), so it is the pool that sets the max-of-pools
  threshold. P3 fails only marginally (INCONCLUSIVE, not REFUTED).
- As in v6, only the Core v3 score keeps the control near 0.10, at TPR ≈ 0.24.

## Deviations
None to the protocol. Operational note: the harness was run once, uninterrupted, from main `6f9a650`
(seeds 0..9 in a single process). A status snapshot during the run showed only seeds 0..7 because the run was not finished yet;
no seeds were appended or re-run.

## Next steps (would need a v8 prereg)
- Small multilingual CPU sentence-encoder features (e.g. a MiniLM-class model), same splits/rules,
  deepset-0 stays held-out; check CPU budget and licence first.
- Keep the guard off; Core v3 score remains the only low-control-FPR option (with low TPR).
