# Ingest guard FPR v11 — results

Prereg: `docs/campaigns/2026-10-30-ingest-guard-fpr-v11-prereg.md` (PR #267, main `2d95e91`, frozen
harness `ingest_guard_fpr_v11.rs`). One CPU run (8 threads, no GPU) from a dedicated worktree detached
at `2d95e91`, started ≈ 12:08, finished 2026-10-30 13:31 (Europe/Paris), `EXIT 0` (≈ 1 h 24 min wall,
inside the 2–5 h budget). Encoding: 126,767 unique texts in 3,319 s (≈ 38 docs/s), 0 zero embeddings.
Raw: `docs/campaigns/2026-10-30-ingest-guard-fpr-v11/raw.jsonl` (sha256
`844dc0898b9b5e599ae7c5d5934027572ffbda5d46bf9f964aa877181a1a82b0`, 178 lines: 1 meta,
1 model artefact, 10 train, 150 split, 15 summary, 1 verdict; seeds 0–9 once each, valid JSON, no NUL bytes).
Seed-0 model `model_seed0.json` (sha256 `a00f198eea667b75df3d6945c8199a5f5bb414e3c35c5ca97120777f4dadf4f8`).

## Fingerprints
- Core model fp `1a21468e…dfce8`; `chat_v9.jsonl` `aaa6cc3b…d882` (asserted by harness).
- Encoder `paraphrase-multilingual-MiniLM-L12-v2` rev `e8f8c211…`, config/tokenizer/safetensors sha256
  as preregistered (asserted), Unigram tokenizer, max_len 128, dim 384.
- Chat sizes dolly/oasst1/hh/nq_short = 14,760 / 14,999 / 14,998 / 15,000 (1/1/2/0 exclusions; as v9).

## Verdict (arm `v11` = [hash ; multilingual MiniLM-L12], α = 0.05)
| Criterion | Numbers | Verdict |
|---|---|---|
| P1 deepset-0 control | seed 0: 143/399 = 0.358, CP95 [0.311, 0.408]; mean 0.396 | **REFUTED** |
| P2 FiQA FPR | mean 0.0180 | **CONFIRMED** |
| P3 in-pool chat | Dolly 0.0115 ✔, HH 0.0049 ✔, OASST1 0.0496 (se 0.0010) ✔ | **CONFIRMED** |
| nq_short in-pool (descriptive) | 0.0043 | CONFIRMED (not gating) |
| Detection | seed 0 TPR 122/140 = 0.871, CP95 [0.804, 0.922]; mean 0.885 | **NON-TRIVIAL, useful** |
| **Wiring gate** P1∧P2∧P3∧NT∧useful | P1 fails | **NOT met → `wired: false`** |

`superiority_claim: false`. No degeneracy flags. Seed-0 λ = 1e-4.

## Table (α = 0.05, means over 10 seeds)
| Arm | FiQA | Dolly | OASST1 | HH | nq_short | deepset-0 control | Inj TPR |
|---|---|---|---|---|---|---|---|
| **v11** ([hash ; mMiniLM], primary) | 0.0180 | 0.0115 | 0.0496 | 0.0049 | 0.0043 | **0.396** | 0.885 |
| v11_enc (mMiniLM only) | 0.0165 | 0.0097 | 0.0471 | 0.0048 | 0.0040 | 0.181 | 0.735 |
| v9 (rerun in v11 harness) | 0.0125 | 0.0138 | 0.0531 | 0.0113 | 0.0057 | 0.400 | 0.842 |
| v11_and (v3 AND v11) | 0.0021 | 0.0025 | 0.0112 | 0.0016 | 0.0010 | 0.044 | 0.218 |
| baseline_v3 (Core, FiQA cal) | 0.0496 | 0.0981 | 0.1167 | 0.1775 | 0.0754 | 0.106 | 0.239 |
| *ref.* v10 (#265) | 0.0149 | 0.0153 | 0.0533 | 0.0130 | 0.0062 | 0.384 | 0.844 |
| *ref.* v8 (#260) | 0.0132 | 0.0129 | 0.0518 | 0.0050 | — | 0.527 | 0.888 |
| *ref.* v7 (#263 rerun) | 0.0103 | 0.0151 | 0.0531 | 0.0117 | 0.0167* | 0.415 | 0.839 |

\* out-of-pool for v7. Other α (v11): α = 0.01 control 0.174, TPR 0.735, all in-pool CONFIRMED;
α = 0.10 control 0.529, TPR 0.930. v11_enc α = 0.01: control 0.038, TPR 0.471 (descriptive).

## Interpretation
- Concatenating multilingual sentence features with the hash features does **not** move the deepset-0
  control (0.400 → 0.396): the 2048-d hash block dominates the decision boundary. P1 refuted again.
- It does fix the marginal OASST1 failure (0.053 → 0.0496, P3 CONFIRMED for the first time in the
  v7–v11 lineage) and raises TPR to 0.885.
- The encoder-only secondary arm halves the control (0.181) at TPR 0.735 — the first clear movement on
  deepset-0 in the lineage, supporting the multilingual hypothesis in direction, but still far above
  0.10 and descriptive only (not the gating arm; no post-hoc promotion).
- `v11_and` reaches control 0.044 but TPR 0.22 (not useful). Guard stays off.

## Deviations
- None to protocol. v9 sanity arm reproduces #263 (FiQA 0.0125, OASST1 0.0531, control 0.400, TPR 0.842).
- Operational: the supervising agent session was interrupted mid-run; the campaign process was never
  killed or restarted (single wrapper + single binary, exit code via side file). No re-run.

## Next steps (would need a new prereg)
- Encoder-only (or encoder-weighted) primary arm, possibly with a non-English benign instruction
  calibration source; v11_enc is the only lineage arm to move deepset-0 materially.
