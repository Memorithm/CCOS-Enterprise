# Ingest guard FPR v9 — results

Prereg: `docs/campaigns/2026-10-30-ingest-guard-fpr-v9-prereg.md` (PR #262, main `135159f`, frozen
harness `ingest_guard_fpr_v9.rs`). One uninterrupted CPU run (8 threads, no GPU) from a dedicated
worktree detached at `135159f33d79`, 2026-10-30 08:26 → 08:48 (Europe/Paris), `EXIT 0`.
Raw: `docs/campaigns/2026-10-30-ingest-guard-fpr-v9/raw.jsonl` (sha256
`14a4b4c9fceca53d7e31bba2600706501b6eb94d61a324097630d4be3f0e9896`, 145 lines: 1 meta,
1 model artefact, 10 train, 120 split, 12 summary, 1 verdict; seeds 0–9 once each, no NUL bytes).
Seed-0 model `model_seed0.json` (sha256 `e13e2441572638fe42b9119c3f1705fee3d6f790084c722fae10e5dfa2c72c66`).

## Fingerprints (all asserted by the harness, all match prereg)
- SciFact `dec31c81…1ac6`, NFCorpus `10cc83ef…991f`, FiQA `ff593e4d…6517`, deepset `2c46bfa4…22ef8`,
  Core model fp `1a21468e…dfce8`.
- `chat_v9.jsonl` `aaa6cc3b331baeb48418afaac6f6c3a15b1308e0306882600a8940810d13d882` (not rebuilt; present).
- Chat sizes dolly/oasst1/hh/nq_short = 14,760 / 14,999 / 14,998 / 15,000 (1/1/2/0 deepset-overlap
  exclusions; first three identical to v7/v8).

## Verdict (arm `v9`, α = 0.05)
| Criterion | Numbers | Verdict |
|---|---|---|
| P1 deepset-0 control | seed 0: 158/399 = 0.396, CP95 [0.348, 0.446]; mean 0.400 (0.356–0.461) | **REFUTED** |
| P2 FiQA FPR | mean 0.0125, se 0.0013 | **CONFIRMED** |
| P3 in-pool chat | Dolly 0.0138 ✔, HH 0.0113 ✔, **OASST1 0.0531 (se 0.0016; m − 1.833·se = 0.0502 > α)** | **REFUTED** (OASST1) |
| nq_short in-pool (descriptive) | 0.0057 | CONFIRMED (not gating) |
| Detection | seed 0 TPR 118/140 = 0.843, CP95 [0.772, 0.899]; mean 0.842 | **NON-TRIVIAL, useful** |
| **Wiring gate** P1∧P2∧P3∧NT∧useful | P1 and P3 fail | **NOT met → `wired: false`** |

`superiority_claim: false`. No degeneracy flags. Seed-0 threshold −1.394; probes SciFact 0/2626,
NFCorpus 5/3631, OOD Core injections 14/25.

## Table (α = 0.05, means over 10 seeds)
| Arm | FiQA | Dolly | OASST1 | HH | nq_short | deepset-0 control | Inj TPR |
|---|---|---|---|---|---|---|---|
| **v9** (hash, +nq_short, primary) | 0.0125 | 0.0138 | 0.0531 | 0.0113 | 0.0057 | **0.400** | 0.842 |
| v7 (rerun in v9 harness) | 0.0103 | 0.0151 | 0.0531 (INCONCL.) | 0.0117 | 0.0167* | 0.415 | 0.839 |
| v9_and (v3 AND v9) | 0.0024 | 0.0035 | 0.0102 | 0.0052 | 0.0017 | 0.035 | 0.212 |
| baseline_v3 (Core, FiQA cal) | 0.0496 | 0.0981 | 0.1167 | 0.1775 | 0.0754 | 0.106 | 0.239 |
| *ref.* v8 (#260) | 0.0132 | 0.0129 | 0.0518 | 0.0050 | — | 0.527 | 0.888 |

\* out-of-pool for v7. Other α (v9): α = 0.01 control 0.149, TPR 0.637, all in-pool CONFIRMED;
α = 0.10 control 0.529, TPR 0.892.

## Interpretation
- Adding a short-query benign source barely moves the held-out deepset-0 control (0.415 → 0.400,
  seed-0 CP95 lower 0.348 ≫ 0.10). The style-shift hypothesis (short informal queries) explains at
  most a small part of the deepset-0 false alarms; the hash model itself generalises nq_short-style
  text well (in-pool 0.006, and v7 already only 0.017 out-of-pool), so deepset-0 is not "just short
  queries".
- OASST1 sits at the same marginal 0.053 as in v7; with v9's slightly smaller se it crosses into
  REFUTED. This is a borderline result, not a material regression.
- `v9_and` reaches control 0.035 but with TPR 0.21 (fails "useful"), i.e. it essentially inherits
  Core v3's low recall. Guard stays off.

## Deviations
- v7 sanity arm: reproduces #258/#260 to the 4th decimal (FiQA 0.0103, Dolly 0.0151, OASST1 0.0531,
  HH 0.0117, control 0.415, TPR 0.839) — the extra nq_short leakage-exclusion texts produced no
  visible drift.
- Operational: none. Single process (checked with `pgrep` before start and during the run), wrapped
  with an exit-code side file; no orphan/duplicate. No re-run, no protocol change.

## Next steps (would need a new prereg)
- Multilingual/SentencePiece encoder (deferred in v9 prereg), or treat deepset-0 as a distinct
  instruction-like benign domain requiring its own (license-clean, non-deepset) calibration source.
