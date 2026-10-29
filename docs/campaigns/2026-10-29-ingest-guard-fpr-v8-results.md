# Ingest guard FPR v8 — results

Prereg: `docs/campaigns/2026-10-29-ingest-guard-fpr-v8-prereg.md` (PR #259, main `412f888`, frozen
harness `ingest_guard_fpr_v8.rs`). Raw: `docs/campaigns/2026-10-29-ingest-guard-fpr-v8/raw.jsonl`
(sha256 `240130464b0a…5f5c5c68`, 178 lines: meta, model artefact, 10 train, 150 split, 15 summary,
1 verdict); seed-0 model `model_seed0.json` (sha256 `377e69b6c885…87ba86cd`).

## Fingerprints (all match prereg)
- MiniLM all-MiniLM-L6-v2 @ `c9745ed1`: config `953f9c0d…`, tokenizer `be50c362…`, safetensors
  `53aa5117…` (asserted by harness); dim 384, max_len 128, 0 zero embeddings; encode 2162 s (8 threads).
- `chat_v7.jsonl` sha256 `7aa8ff2b…ff2be` (asserted); chat sizes 14,760 / 14,999 / 14,998
  (1/1/2 excluded), identical to v7. Core model fp `1a21468e…dfce8` unchanged.
- Sanity: arm `v7` reproduces #258 to the 4th decimal (FiQA 0.0103, Dolly 0.0151, OASST1 0.0531,
  HH 0.0117, control 0.415, TPR 0.839; seed-0 threshold −1.550, 166/399, 118/140).

## Verdict (arm `v8` = [hash ; MiniLM], α = 0.05)
- **P1 deepset-0 control: REFUTED.** Seed 0: 209/399 = 0.524, CP95 [0.474, 0.574]; mean 0.527
  (0.494–0.579). **Worse than v7 (0.415).**
- **P2 FiQA FPR: CONFIRMED** (mean 0.0132, se 0.0012).
- **P3 in-pool chat FPR: CONFIRMED** — Dolly 0.0129, OASST1 0.0518 (≤ α + 0.0025), HH 0.0050.
- **Detection: NON-TRIVIAL, useful.** Seed 0 TPR 121/140 = 0.864 CP95 [0.796, 0.916]; mean 0.888.
- **Wiring gate: NOT met (P1 fails) → `wired: false`**, no wiring PR. `superiority_claim: false`.
  No degeneracy flags.

## Table (α = 0.05, means over 10 seeds)
| Arm | FiQA FPR | Dolly | OASST1 | HH | deepset-0 control | Inj TPR |
|---|---|---|---|---|---|---|
| **v8** ([h ; e], primary) | 0.0132 | 0.0129 | 0.0518 | 0.0050 | **0.527** | 0.888 |
| v8_enc (e only) | 0.0096 | 0.0102 | 0.0510 | 0.0045 | 0.441 | 0.717 |
| loo_oasst1_v8 | 0.0298 | 0.0508 | ***0.5828*** | 0.0230 | 0.745 | 0.957 |
| v7 (h only, rerun) | 0.0103 | 0.0151 | 0.0531 (INCONCL.) | 0.0117 | 0.415 | 0.839 |
| baseline_v3 (Core, FiQA cal) | 0.0496 | 0.0981 | 0.1167 | 0.1775 | 0.106 | 0.239 |

Other α (v8): α = 0.01 control 0.243, TPR 0.724, all in-pool CONFIRMED; α = 0.10 control 0.655,
TPR 0.940, all in-pool CONFIRMED. (v7 at 0.01: control 0.154, TPR 0.612.)
Seed-0 probes (v8): SciFact 2/2626, NFCorpus 5/3631, OOD Core injections 21/25. Seed-0 threshold −2.163.

## Interpretation
- The English MiniLM encoder raises TPR (+0.05) and makes P3 pass (OASST1 no longer marginal), but
  it **increases** false alarms on the held-out deepset-0 benign prompts (0.415 → 0.527); encoder-only
  is 0.441, still worse than hash-only. This fits the audit finding that the encoder is not
  multilingual: the semantic features seem to push deepset's benign prompts (often non-English or
  instruction-like) toward the injection side.
- Holding OASST1 out is worse than in v7 (held-out FPR 0.583 vs 0.257; control 0.745 vs 0.638):
  the encoder space generalises less across chat sources, not more.
- Only Core v3 keeps the control near 0.10 (TPR ≈ 0.24). Guard stays off.

## Deviations
- Operational: a duplicate unwrapped process of the same frozen binary (same args, same stdout file)
  was found running alongside the official run; it was killed at ~00:02 (Europe/Paris) after seeds
  0–1 were written. The official wrapped run (single process from `412f888`) completed with `EXIT 0`.
  The final file has 178 valid JSON lines, no NUL bytes, exactly one `verdict`, and seeds 0..9 once
  each. The v7 arm reproduces #258 exactly, which is consistent with deterministic output.
  No re-run, no protocol change.

## Next steps (would need a v9 prereg)
- A genuinely multilingual encoder (XLM-R tokenizer support) or language-ID-aware calibration;
  or accept Core v3 as the only low-control-FPR option.
