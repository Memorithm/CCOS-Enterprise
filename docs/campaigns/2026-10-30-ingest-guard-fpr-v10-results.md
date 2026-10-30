# Ingest guard FPR v10 — results

Prereg: `docs/campaigns/2026-10-30-ingest-guard-fpr-v10-prereg.md` (PR #264, main `c77f1ec`, frozen
harness `ingest_guard_fpr_v10.rs`). One CPU run (8 threads, no GPU) from a dedicated worktree detached
at `c77f1ec`, finished 2026-10-30 10:34 (Europe/Paris), `EXIT 0`.
Raw: `docs/campaigns/2026-10-30-ingest-guard-fpr-v10/raw.jsonl` (sha256
`1fd3fb92159de32c23d292259d480176c828b55eb339bcdcb57160f89b69619e`, 145 lines: 1 meta,
1 model artefact, 10 train, 120 split, 12 summary, 1 verdict; seeds 0–9 once each, valid JSON, no NUL bytes).
Seed-0 model `model_seed0.json` (sha256 `a0d113a44c50c6ea91d7764e7944a71d1b9722fae18bee513fdd99d6cb26fac2`).

## Fingerprints
- Core model fp `1a21468e…dfce8` (asserted by harness).
- `chat_v9.jsonl` `aaa6cc3b331baeb48418afaac6f6c3a15b1308e0306882600a8940810d13d882` (unchanged).
- Chat sizes dolly/oasst1/hh/nq_short = 14,760 / 14,999 / 14,998 / 15,000 (1/1/2/0 exclusions; as v9).

## Verdict (arm `v10`, α = 0.05)
| Criterion | Numbers | Verdict |
|---|---|---|
| P1 deepset-0 control | seed 0: 150/399 = 0.376, CP95 [0.328, 0.425]; mean 0.384 (0.336–0.454) | **REFUTED** |
| P2 FiQA FPR | mean 0.0149, se 0.0011 | **CONFIRMED** |
| P3 in-pool chat | Dolly 0.0153 ✔, HH 0.0130 ✔, **OASST1 0.0533 (se 0.0014; m − 1.833·se = 0.0507 > α)** | **REFUTED** (OASST1) |
| nq_short in-pool (descriptive) | 0.0062 | CONFIRMED (not gating) |
| Detection | seed 0 TPR 118/140 = 0.843, CP95 [0.772, 0.899]; mean 0.844 | **NON-TRIVIAL, useful** |
| **Wiring gate** P1∧P2∧P3∧NT∧useful | P1 and P3 fail | **NOT met → `wired: false`** |

`superiority_claim: false`. No degeneracy flags. Seed-0 threshold −1.507 (λ = 1e-5); probes SciFact
1/2626, NFCorpus 6/3631, OOD Core injections 19/25.

## Table (α = 0.05, means over 10 seeds)
| Arm | FiQA | Dolly | OASST1 | HH | nq_short | deepset-0 control | Inj TPR |
|---|---|---|---|---|---|---|---|
| **v10** ([hash ; scalars], primary) | 0.0149 | 0.0153 | 0.0533 | 0.0130 | 0.0062 | **0.384** | 0.844 |
| v9 (rerun in v10 harness) | 0.0125 | 0.0138 | 0.0531 | 0.0113 | 0.0057 | 0.400 | 0.842 |
| v10_and (v3 AND v10) | 0.0030 | 0.0045 | 0.0116 | 0.0066 | 0.0023 | 0.041 | 0.213 |
| baseline_v3 (Core, FiQA cal) | 0.0496 | 0.0981 | 0.1167 | 0.1775 | 0.0754 | 0.106 | 0.239 |
| *ref.* v8 (#260) | 0.0132 | 0.0129 | 0.0518 | 0.0050 | — | 0.527 | 0.888 |
| *ref.* v7 (#263 rerun) | 0.0103 | 0.0151 | 0.0531 | 0.0117 | 0.0167* | 0.415 | 0.839 |

\* out-of-pool for v7. Other α (v10): α = 0.01 control 0.138, TPR 0.630, all in-pool CONFIRMED;
α = 0.10 control 0.502, TPR 0.892.

## Interpretation
- Adding Core-v3 / length / script / DE scalars to the hash features moves the held-out deepset-0
  control only 0.400 → 0.384 (seed-0 CP95 lower 0.328 ≫ 0.10). Scalar features do not separate
  deepset-0 benign prompts from injections; the gap is not a feature-engineering detail of v9.
- OASST1 stays at the marginal 0.053 (REFUTED by ~0.0007 margin), as in v7/v9.
- `v10_and` reaches control 0.041 but TPR 0.21 (not useful), inheriting Core v3's low recall.
  Guard stays off.

## Deviations
- v9 sanity arm reproduces #263 exactly (FiQA 0.0125, OASST1 0.0531, control 0.400, TPR 0.842).
- Operational: the supervising agent session was interrupted mid-run; the campaign process itself was
  never killed or restarted (single wrapper + single binary, exit code via side file). No re-run, no
  protocol change.

## Next steps (would need a new prereg)
- Lineage v7→v10 is saturated on deepset-0 (0.38–0.53). Options: a license-clean instruction-like
  benign calibration source distinct from deepset, or a multilingual/SentencePiece encoder.
