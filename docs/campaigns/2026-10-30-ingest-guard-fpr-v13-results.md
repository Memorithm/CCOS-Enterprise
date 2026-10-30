# Ingest guard FPR v13 — results

Prereg: `docs/campaigns/2026-10-30-ingest-guard-fpr-v13-prereg.md` (PR #274, main `3d30f8a`, frozen
harness `ingest_guard_fpr_v13.rs`, workflow `fpr-v13-campaign-thor.yml`). One CUDA run from `3d30f8a`,
GitHub Actions run [41122687354](https://github.com/Memorithm/CCOS-Enterprise/actions/runs/41122687354)
on the Jetson Thor runner `tarek-scirust-arm64-01`, under `thor_gpu_guard.py`
(`gpu_reservation=acquired`). Started 2026-10-30 21:23, finished 23:54 (Europe/Paris), `EXIT 0`
(≈ 2 h 31 min wall, inside the 10 h cap). Meta: `encoder.backend = "cuda"`, 127,436 unique texts
encoded in 7,128 s, 0 zero embeddings.

Raw: `docs/campaigns/2026-10-30-ingest-guard-fpr-v13/raw.jsonl` (sha256
`7d9b75aa6e31ea3b7b0caa559d09ca5462f7e389975f2c7977176da0bbaae3da`, 178 lines: 1 meta,
1 model artefact, 10 train, 150 split, 15 summary, 1 verdict; seeds 0–9 once each, valid JSON, no NUL
bytes). Seed-0 model `model_seed0.json` (sha256
`fdf9a47606261ca2f22d51ca6094bb7364bcbf6a7d7cf2a64332e3c835d3d97b`).

## CUDA parity precondition
- Before the campaign: `dense-encoder-cuda-thor.yml` run
  [41122435002](https://github.com/Memorithm/CCOS-Enterprise/actions/runs/41122435002) @ `3d30f8a`, same
  runner, green (finished 21:22 Europe/Paris), but its probe output covers **all-MiniLM-L6-v2 only**:
  ```
  {"backend":"cuda","bound":0.9990000128746033,"cpu_ms":540.20446,"cuda_ms":277.029218,"items":4,"min_cos_cuda_vs_cpu":0.9999774098396301,"min_cos_cuda_vs_oracle":0.9999773502349854,"model":"all-MiniLM-L6-v2","pass":true}
  ```
- Multi-L12 parity (the encoder actually used by the campaign) was re-run as
  [41122944234](https://github.com/Memorithm/CCOS-Enterprise/actions/runs/41122944234) @ `3d30f8a`, same
  runner; it queued behind the campaign on the exclusive GPU lock and ran right after it (23:54–23:55
  Europe/Paris), green, bound 0.999:
  ```
  {"backend":"cuda","bound":0.9990000128746033,"cpu_ms":544.219921,"cuda_ms":267.962582,"items":4,"min_cos_cuda_vs_cpu":0.9999774098396301,"min_cos_cuda_vs_oracle":0.9999773502349854,"model":"all-MiniLM-L6-v2","pass":true}
  {"backend":"cuda","bound":0.9990000128746033,"cpu_ms":87.654764,"cuda_ms":147.080208,"items":4,"min_cos_cuda_vs_cpu":0.9999920725822449,"min_cos_cuda_vs_oracle":0.9999921321868896,"model":"paraphrase-multilingual-MiniLM-L12-v2","pass":true}
  ```
  min_cos multi-L12 = 0.99999 (identical to v12 parity run 41091482323). See Deviations.

## Fingerprints
- Core model fp `1a21468e…dfce8`; `chat_v13.jsonl` `14de7a08…762a` (asserted by harness/workflow).
- Encoder `paraphrase-multilingual-MiniLM-L12-v2` rev `e8f8c211…5f42`, config/tokenizer/safetensors
  sha256 as preregistered (asserted), Unigram tokenizer, max_len 128, dim 384.
- Chat sizes dolly/oasst1/hh/nq_short/oasst1_de = 14,760 / 14,999 / 14,998 / 15,000 / 669
  (1/1/2/0/0 exclusions). deepset label 0 control n = 399, injections n = 263, 0 Core-leak exclusions.

## Verdict (arm `v13` = multilingual MiniLM-L12 only, six benign pools incl. `oasst1_de`, α = 0.05)
| Criterion | Numbers | Verdict |
|---|---|---|
| P1 deepset-0 control | seed 0: 75/399 = 0.188, CP95 [0.151, 0.230]; mean 0.178 (min 0.133, max 0.221) | **REFUTED** (CP95 lower > 0.10) |
| P2 FiQA FPR | mean 0.0195 (se 0.0008) | **CONFIRMED** |
| P3 in-pool chat | Dolly 0.0092 ✔, HH 0.0051 ✔, OASST1 0.0463 (se 0.0021) ✔ | **CONFIRMED** |
| nq_short / oasst1_de in-pool (descriptive) | 0.0041 / 0.0387 (se 0.0055) | CONFIRMED (not gating) |
| Detection | seed 0 TPR 96/140 = 0.686, CP95 [0.602, 0.761]; mean 0.716 | **NON-TRIVIAL, useful** |
| **Wiring gate** P1∧P2∧P3∧NT∧useful | P1 fails | **NOT met → `wired: false`** |

`superiority_claim: false`. No degeneracy flags. Seed-0 λ: v13 1e-4, v13_cat 1e-5, v13_hash 1e-4.

## Table (α = 0.05, means over 10 seeds)
| Arm | FiQA | Dolly | OASST1 | HH | nq_short | oasst1_de | deepset-0 control | Inj TPR |
|---|---|---|---|---|---|---|---|---|
| **v13** (mMiniLM only, primary) | 0.0195 | 0.0092 | 0.0463 | 0.0051 | 0.0041 | 0.0387 | **0.178** | 0.716 |
| v13_cat ([hash ; mMiniLM], sanity) | 0.0148 | 0.0058 | 0.0280 | 0.0030 | 0.0019 | 0.0444 | 0.216 | 0.821 |
| v13_hash (hash only, sanity) | 0.0047 | 0.0058 | 0.0150 | 0.0051 | 0.0019 | 0.0437 | 0.121 | 0.718 |
| v13_and (v3 AND v13) | 0.0017 | 0.0019 | 0.0098 | 0.0012 | 0.0006 | 0.0000 | 0.019 | 0.194 |
| baseline_v3 (Core, FiQA cal) | 0.0496 | 0.0981 | 0.1167 | 0.1775 | 0.0754 | 0.0062 | 0.106 | 0.239 |
| *ref.* v12 primary (#273) | 0.0165 | 0.0097 | 0.0471 | 0.0047 | 0.0041 | — | 0.181 | 0.735 |
| *ref.* v12 v11 sanity / v9 hash (#273) | 0.0180 / 0.0125 | — | — | — | — | — | 0.396 / 0.400 | 0.886 / 0.842 |

baseline_v3 reproduces v12 (out-of-pool chat REFUTED as before; it is not gating). Other α (v13):
α = 0.01 control 0.018, TPR 0.365 (not useful), all in-pool CONFIRMED; α = 0.10 control 0.294,
TPR 0.814. v13_and α = 0.10: control 0.053, TPR 0.291 (descriptive).

## Interpretation
- The preregistered hypothesis is refuted for the gating arm: adding 669 German benign instructions
  as a sixth pool barely moves the encoder-only arm (deepset-0 mean 0.181 → 0.178; seed 0 identical
  at 75/399), and TPR drops slightly (0.735 → 0.716). The encoder representation already places
  German benign text near the multilingual benign mass; the residual deepset-0 false positives are
  not explained by missing German benign calibration data.
- P2/P3 stay CONFIRMED (OASST1 0.046 < 0.05); `oasst1_de` itself is well controlled (0.039).
- Descriptive only, not promoted: the **hash-only** sanity arm benefits strongly from the German pool
  (deepset-0 0.400 in v9/v12 → 0.121, TPR 0.842 → 0.718), and `[hash ; encoder]` drops 0.396 → 0.216.
  So the language gap mattered for lexical features, not for the encoder. v13_hash is still > 0.10 and
  is a secondary arm; per the prereg it is never promoted post hoc. Any test of a hash-based primary
  with the German pool needs its own prereg.
- Arms with control ≤ 0.10 (v13 at α = 0.01, v13_and) have TPR < 0.5: not useful. Guard stays off.

## Deviations
- Protocol: harness, data, splits and decision rules are those of the merged prereg.
- Parity precondition: the pre-campaign parity run (41122435002) only printed the all-MiniLM-L6-v2
  probe, not the multilingual L12 model used by the harness. The L12 parity was re-run (41122944234),
  which, because of the exclusive GPU concurrency group, executed immediately after the campaign
  rather than before it. It is green with min_cos 0.99999 ≥ 0.999 on the same host and SHA, so the
  CUDA path is validated for this campaign, but the ordering differs from the prereg's "precondition"
  wording. Documented, not hidden.
- Operational: the uploaded artefact `raw.jsonl` contained one leading non-JSON line
  (`gpu_reservation=acquired occupancy=idle_under_lock`, stdout of `thor_gpu_guard.py`); original
  artefact sha256 `66475642b964f93073c0b95bb1934c842dba2fd56c91b247884d75b7ca1df605`, 179 lines. That
  line was removed for the committed file; the 178 JSON lines are unchanged (as in v12).
- Observation: CUDA encoding took 7,128 s at `3d30f8a` (pre-#275 serial path); the packed-batch encode
  of #275 (`0d8e584`) was not used by this run and still needs its own Thor throughput measurement.

## Next steps (would need a new prereg)
- Encoder-only plateaus at ~0.18 on deepset-0 regardless of German benign data. Options: a
  preregistered hash-only (or hash-weighted) primary with the six pools, which looked promising
  descriptively (0.121) but still misses 0.10; or a different/fine-tuned encoder. Product default
  stays off.
