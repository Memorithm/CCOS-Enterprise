# Ingest guard FPR v14 — results

Prereg: `docs/campaigns/2026-10-31-ingest-guard-fpr-v14-prereg.md` (PR #279, main `a552cd0`, frozen
harness `ingest_guard_fpr_v14.rs`, workflow `fpr-v14-campaign-thor.yml`). One CUDA run from `a552cd0`,
GitHub Actions run [41284989036](https://github.com/Memorithm/CCOS-Enterprise/actions/runs/41284989036)
on the Jetson Thor runner `tarek-scirust-arm64-01`, under `thor_gpu_guard.py`
(`gpu_reservation=acquired`). Harness started 2026-11-01 08:30, finished 09:40 (Europe/Paris), `EXIT 0`
(≈ 2 h 10 min wall, inside the 10 h cap). Meta: `encoder.backend = "cuda"`, 127,436 unique texts
encoded in 2,244 s (packed encode of #275), 0 zero embeddings.

Raw: `docs/campaigns/2026-10-31-ingest-guard-fpr-v14/raw.jsonl` (sha256
`c0a1dcfe4385464c0f3379124b2ee312692b3ca676855a49e52da14a95125582`, 178 lines: 1 meta,
1 model artefact, 10 train, 150 split, 15 summary, 1 verdict; seeds 0–9 once each, valid JSON, no NUL
bytes). Seed-0 primary (hash) model `model_seed0.json` (sha256
`060d6d260c2b8ba4f1ef509b5a56762db1f28834f385d67769d14c5928a67f0f`).

## Fingerprints
- Core model fp `1a21468e…dfce8`; `chat_v13.jsonl` `14de7a08…762a` (asserted by harness/workflow).
- Encoder `paraphrase-multilingual-MiniLM-L12-v2` rev `e8f8c211…5f42`, config/tokenizer/safetensors
  sha256 as preregistered (asserted), Unigram tokenizer, max_len 128, dim 384.
- Chat sizes dolly/oasst1/hh/nq_short/oasst1_de = 14,760 / 14,999 / 14,998 / 15,000 / 669
  (1/1/2/0/0 exclusions). deepset label 0 control n = 399, injections n = 263, 0 Core-leak exclusions.

## Verdict (arm `v14` = hash features only, six benign pools incl. `oasst1_de`, α = 0.05)
| Criterion | Numbers | Verdict |
|---|---|---|
| P1 deepset-0 control | seed 0: 49/399 = 0.123, CP95 [0.092, 0.159]; mean 0.121 (min 0.068, max 0.190) | **INCONCLUSIVE** (CP95 upper > 0.10 and mean > 0.10, CP95 lower ≤ 0.10) |
| P2 FiQA FPR | mean 0.0047 (se 0.0009) | **CONFIRMED** |
| P3 in-pool chat | Dolly 0.0058 ✔, HH 0.0051 ✔, OASST1 0.0150 (se 0.0021) ✔ | **CONFIRMED** |
| nq_short / oasst1_de in-pool (descriptive) | 0.0019 / 0.0437 (se 0.0050) | CONFIRMED (not gating) |
| Detection | seed 0 TPR 97/140 = 0.693, CP95 [0.609, 0.768]; mean 0.718 | **NON-TRIVIAL, useful** |
| **Wiring gate** P1∧P2∧P3∧NT∧useful | P1 not CONFIRMED | **NOT met → `wired: false`** |

`superiority_claim: false`. No degeneracy flags. Seed-0 λ: v14 1e-4, v14_enc 1e-4, v14_cat 1e-5.

## Table (α = 0.05, means over 10 seeds)
| Arm | FiQA | Dolly | OASST1 | HH | nq_short | oasst1_de | deepset-0 control | Inj TPR |
|---|---|---|---|---|---|---|---|---|
| **v14** (hash only, primary) | 0.0047 | 0.0058 | 0.0150 | 0.0051 | 0.0019 | 0.0437 | **0.121** | 0.718 |
| v14_enc (mMiniLM only, sanity) | 0.0195 | 0.0092 | 0.0463 | 0.0051 | 0.0041 | 0.0393 | 0.178 | 0.716 |
| v14_cat ([hash ; mMiniLM], sanity) | 0.0148 | 0.0058 | 0.0280 | 0.0030 | 0.0019 | 0.0444 | 0.216 | 0.821 |
| v14_and (v3 AND v14) | 0.0011 | 0.0021 | 0.0061 | 0.0026 | 0.0008 | 0.0000 | 0.018 | 0.197 |
| baseline_v3 (Core, FiQA cal) | 0.0496 | 0.0981 | 0.1167 | 0.1775 | 0.0754 | 0.0062 | 0.106 | 0.239 |
| *ref.* v13 primary / v13_hash (#276) | 0.0195 / 0.0047 | 0.0092 / 0.0058 | 0.0463 / 0.0150 | 0.0051 / 0.0051 | 0.0041 / 0.0019 | 0.0387 / 0.0437 | 0.178 / 0.121 | 0.716 / 0.718 |

Sanity arms reproduce v13: `v14_enc` matches the v13 primary (0.178 / 0.716) and `v14_cat` matches
`v13_cat` (0.216 / 0.821); the primary `v14` reproduces the descriptive `v13_hash` (0.121 / 0.718), as
expected since the only harness change is which arm gates. baseline_v3 reproduces v12/v13 (not gating).

Other α (descriptive, never promoted): v14 α = 0.01 control 0.024, TPR 0.494 (not useful, < 0.5);
α = 0.10 control 0.197, TPR 0.792. v14_enc α = 0.01 0.018 / 0.365; α = 0.10 0.294 / 0.814. v14_cat
α = 0.01 0.028 / 0.557. v14_and α = 0.10 control 0.031, TPR 0.271.

## Interpretation
- The preregistered hypothesis is **not confirmed**: the hash-only primary with six benign pools
  lands at deepset-0 mean 0.121, seed-0 CP95 [0.092, 0.159]. The interval straddles 0.10, so P1 is
  INCONCLUSIVE rather than REFUTED, exactly the "most likely outcome" stated in the prereg (§0).
- P2/P3 are CONFIRMED with comfortable margins (FiQA 0.005, OASST1 0.015) and detection stays
  NON-TRIVIAL and useful (0.718). The hash arm is the best α = 0.05 arm on deepset-0 in this family
  that is still useful, but it does not clear the gate.
- Seed variance on deepset-0 is large (0.068–0.190, sd 0.037), so the hash arm's control FPR is not
  stable enough across splits to be relied on.
- The only configurations with control ≤ 0.10 (v14 at α = 0.01, v14_enc at α = 0.01, v14_and) have
  TPR < 0.5: not useful. Guard stays off; product default unchanged.

## Deviations
- Protocol: harness, data, splits and decision rules are those of the merged prereg; one run, no
  re-run.
- Parity precondition: no `dense-encoder-cuda-thor.yml` run was triggered at `a552cd0` before the
  campaign. The latest parity run on the same host is
  [41144823758](https://github.com/Memorithm/CCOS-Enterprise/actions/runs/41144823758) @ `a55d61f`
  (2026-10-31 00:30 Europe/Paris, green, multi-L12 min_cos 0.99999 ≥ 0.999, documented in #277).
  Between `a55d61f` and `a552cd0` the only code change under `crates/` is the new opt-in example
  `ingest_guard_fpr_v14.rs`; the encoder/CUDA path is unchanged. The gating arm `v14` does not use the
  encoder at all, so this deviation cannot affect the P1/P2/P3/detection verdicts; it only concerns
  the sanity arms, which reproduce v13 to the reported precision. Documented, not hidden.
- Operational: the uploaded artefact `raw.jsonl` contained one leading non-JSON line
  (`gpu_reservation=acquired occupancy=idle_under_lock`, stdout of `thor_gpu_guard.py`); original
  artefact sha256 `039bb4a9b75c01b4d7f58a4e0b7ae035458d4a48a9b408b89653848d754c482c`, 179 lines. That
  line was removed for the committed file; the 178 JSON lines are unchanged (as in v12/v13).
- Observation: CUDA encode took 2,244 s with the packed encode of #275 (v13: 7,128 s pre-#275).
  Single-run wall-clock observation, not a throughput benchmark.

## Next steps (would need a new prereg)
- Hash-only with six pools sits at ~0.12 on deepset-0 with high seed variance. Options: more or more
  diverse non-English benign pools for the lexical model, a different or fine-tuned encoder, or a
  preregistered combination rule. Product default stays off.
