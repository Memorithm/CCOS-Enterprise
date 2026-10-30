# Ingest guard FPR v12 — results

Prereg: `docs/campaigns/2026-10-30-ingest-guard-fpr-v12-prereg.md` (PR #271, main `37150e8`, frozen
harness `ingest_guard_fpr_v12.rs`). One CUDA run via the manual workflow
`fpr-v12-campaign-thor.yml` (PR #272, main `5b58e4a`; #272 only adds the workflow and SHA-asserted
inputs, the harness is byte-identical to `37150e8`), GitHub Actions run
[41094227650](https://github.com/Memorithm/CCOS-Enterprise/actions/runs/41094227650) on the Jetson Thor
runner `tarek-scirust-arm64-01`, under `thor_gpu_guard.py` (`gpu_reservation=acquired`).
Started 2026-10-30 17:56, finished 20:25 (Europe/Paris), `EXIT 0` (≈ 2 h 30 min wall, inside the 10 h
cap). Meta: `encoder.backend = "cuda"`, 126,767 unique texts encoded in 6,999 s, 0 zero embeddings.

Raw: `docs/campaigns/2026-10-30-ingest-guard-fpr-v12/raw.jsonl` (sha256
`e3755062aa6edfefa5f57d1fe44877133856dc6d39f2f71e28d273ccbaa8e5a7`, 178 lines: 1 meta,
1 model artefact, 10 train, 150 split, 15 summary, 1 verdict; seeds 0–9 once each, valid JSON, no NUL
bytes). Seed-0 model `model_seed0.json` (sha256
`6580bd1e826efd657600db896f173ce09b5897a9eb50af275fea67663dce4f85`).

## CUDA parity precondition
`dense-encoder-cuda-thor.yml` run
[41091482323](https://github.com/Memorithm/CCOS-Enterprise/actions/runs/41091482323) @ `37150e8`, same
runner `tarek-scirust-arm64-01`, green before the campaign. Probe output (bound 0.999):
```
{"backend":"cuda","bound":0.9990000128746033,"cpu_ms":540.627256,"cuda_ms":284.564727,"items":4,"min_cos_cuda_vs_cpu":0.9999774098396301,"min_cos_cuda_vs_oracle":0.9999773502349854,"model":"all-MiniLM-L6-v2","pass":true}
{"backend":"cuda","bound":0.9990000128746033,"cpu_ms":87.522005,"cuda_ms":157.384427,"items":4,"min_cos_cuda_vs_cpu":0.9999920725822449,"min_cos_cuda_vs_oracle":0.9999921321868896,"model":"paraphrase-multilingual-MiniLM-L12-v2","pass":true}
```

## Fingerprints
- Core model fp `1a21468e…dfce8`; `chat_v9.jsonl` `aaa6cc3b…d882` (asserted by harness/workflow).
- Encoder `paraphrase-multilingual-MiniLM-L12-v2` rev `e8f8c211…5f42`, config/tokenizer/safetensors
  sha256 as preregistered (asserted), Unigram tokenizer, max_len 128, dim 384.
- Chat sizes dolly/oasst1/hh/nq_short = 14,760 / 14,999 / 14,998 / 15,000 (1/1/2/0 exclusions; as v9–v11).
  deepset label 0 control n = 399, injections n = 263, 0 Core-leak exclusions.

## Verdict (arm `v12` = multilingual MiniLM-L12 only, α = 0.05)
| Criterion | Numbers | Verdict |
|---|---|---|
| P1 deepset-0 control | seed 0: 75/399 = 0.188, CP95 [0.151, 0.230]; mean 0.181 | **REFUTED** (CP95 lower > 0.10) |
| P2 FiQA FPR | mean 0.0165 (se 0.0008) | **CONFIRMED** |
| P3 in-pool chat | Dolly 0.0097 ✔, HH 0.0047 ✔, OASST1 0.0471 (se 0.0015) ✔ | **CONFIRMED** |
| nq_short in-pool (descriptive) | 0.0041 | CONFIRMED (not gating) |
| Detection | seed 0 TPR 96/140 = 0.686, CP95 [0.602, 0.761]; mean 0.735 | **NON-TRIVIAL, useful** |
| **Wiring gate** P1∧P2∧P3∧NT∧useful | P1 fails | **NOT met → `wired: false`** |

`superiority_claim: false`. No degeneracy flags. Seed-0 λ: v12 1e-5, v11 1e-4, v9 1e-5.

## Table (α = 0.05, means over 10 seeds)
| Arm | FiQA | Dolly | OASST1 | HH | nq_short | deepset-0 control | Inj TPR |
|---|---|---|---|---|---|---|---|
| **v12** (mMiniLM only, primary) | 0.0165 | 0.0097 | 0.0471 | 0.0047 | 0.0041 | **0.181** | 0.735 |
| v11 ([hash ; mMiniLM], sanity) | 0.0180 | 0.0115 | 0.0496 | 0.0050 | 0.0044 | 0.396 | 0.886 |
| v9 (hash only, sanity) | 0.0125 | 0.0138 | 0.0531 | 0.0113 | 0.0057 | 0.400 | 0.842 |
| v12_and (v3 AND v12) | 0.0015 | 0.0018 | 0.0099 | 0.0012 | 0.0008 | 0.017 | 0.195 |
| baseline_v3 (Core, FiQA cal) | 0.0496 | 0.0981 | 0.1167 | 0.1775 | 0.0754 | 0.106 | 0.239 |
| *ref.* v11 primary (#268, CPU) | 0.0180 | 0.0115 | 0.0496 | 0.0049 | 0.0043 | 0.396 | 0.885 |
| *ref.* v11_enc (#268, CPU) | 0.0165 | 0.0097 | 0.0471 | 0.0048 | 0.0040 | 0.181 | 0.735 |

In v9 OASST1 0.0531 is REFUTED (as in #263); all other in-pool cells CONFIRMED. Other α (v12):
α = 0.01 control 0.038, TPR 0.471 (not useful), all in-pool CONFIRMED; α = 0.10 control 0.293,
TPR 0.825. v12_and α = 0.10: control 0.050, TPR 0.287 (descriptive).

## Interpretation
- Promoting encoder-only features to the primary arm reproduces the v11 secondary arm almost exactly
  on CUDA (control 0.181, TPR 0.735 vs v11_enc 0.181 / 0.735). The CUDA path (bf16 linear layers,
  cos ≥ 0.99998 vs fp32) does not change the conclusion; the v11 and v9 sanity arms also reproduce
  #268/#263 to the third decimal.
- P1 is refuted: deepset-0 at 0.18 is the lineage's best gating-arm result (v7–v11 were 0.38–0.53),
  but it is still ~1.8× the 0.10 target, and the seed-0 CP95 lower bound (0.151) excludes it.
- P2/P3 hold with margin (OASST1 0.047 < 0.05), so the encoder alone keeps benign FPR controlled; the
  price is TPR (0.885 → 0.735).
- The only arms reaching control ≤ 0.10 are v12 at α = 0.01 (0.038, TPR 0.47) and v12_and
  (0.017, TPR 0.20): neither is useful, and both are descriptive only (no post-hoc promotion).
  Guard stays off.

## Deviations
- None to protocol. The harness, data, splits and decision rules are those of the merged prereg.
- Operational: the uploaded artefact `raw.jsonl` contained one leading non-JSON line
  (`gpu_reservation=acquired occupancy=idle_under_lock`, stdout of `thor_gpu_guard.py`); original
  artefact sha256 `3d194593d1ac1073e2a8184be1410f9a98674d69062e7893ec7fa9115f3832f7`, 179 lines. That
  line was removed for the committed file; the 178 JSON lines are unchanged.
- Observation, not a deviation: CUDA encoding took 6,999 s, slower than the v11 CPU encoding (3,319 s)
  and above the prereg's "well under 1 h" expectation (total run still within budget). Throughput of
  the CUDA encoder on Thor deserves a separate engineering look (batching / host-device transfers);
  it does not affect the scientific results.

## Next steps (would need a new prereg)
- The encoder alone halves deepset-0 but plateaus at ~0.18 at a useful TPR. Remaining options: a
  non-English (German) benign instruction calibration/training source, or a different/fine-tuned
  encoder; both need a fresh prereg. Product default stays off.
