# Ingest guard FPR v5 — results

Prereg: `docs/campaigns/2026-10-29-ingest-guard-fpr-v5-prereg.md` (merged in PR #253, main `9e8e0fa`).
Harness: `crates/ccos-enterprise-docmemory/examples/ingest_guard_fpr_v5.rs` (opt-in example; Core unchanged).
Raw: `docs/campaigns/2026-10-29-ingest-guard-fpr-v5/raw.jsonl` (sha256 `f0b14e52…235d2`, 79 lines, 10 seeds).
Seed-0 model artefact: `model_seed0.json` (sha256 `2ead1a54…e0a5a3`).

## Verdict (α = 0.05, primary)
- **FPR (v5, FiQA test, 10 seeds): CONFIRMED.** Mean 0.04929, se 0.00085 (m ≤ α).
  Baseline v3 on the same splits: mean 0.05131 → REFUTED.
- **Detection: NON-TRIVIAL and "useful" (descriptive).** Seed 0 deepset inj test: 123/141,
  TPR 0.872 CP95 [0.806, 0.923]. Mean TPR v5 0.906 vs baseline 0.246; paired ΔTPR +0.660, positive on 10/10 seeds.
- **Control (deepset label-0 chat, seed 0): FAILED.** 130/200 flagged = 0.65 CP95 [0.580, 0.716] ≫ 0.105.
  Baseline: 0.095.
- **Wiring gate: NOT met → guard NOT wired.** `superiority_claim: false`.

## Comparison with v4 / baseline (α = 0.05)
| Metric | v4 (MNB v3-score, FiQA cal) | baseline v3 (v5 splits) | v5 (logreg) |
|---|---|---|---|
| Mean FiQA FPR | 0.0501 INCONCLUSIVE | 0.0513 REFUTED | 0.0493 CONFIRMED |
| Seed-0 inj TPR | 0.247 [0.196, 0.304] (n=263) | 0.227 [0.161, 0.305] (n=141) | 0.872 [0.806, 0.923] (n=141) |
| Mean inj TPR | 0.247 | 0.246 | 0.906 |
| Seed-0 chat benign flagged | ~0.105 (v4 note) | 0.095 | **0.65** |
| Seed-0 SciFact / NFCorpus probe | — | 2/2611, 1/3633 | 0/2611, 0/3633 |
| Seed-0 OOD Core injections | — | 25/25 | 24/25 |

Other α (mean FiQA FPR v5 / baseline): α=0.01 0.00952 / 0.01013; α=0.10 0.09885 / 0.10137.
Seed 0 α=0.01 v5: TPR 0.752, chat flagged 0.295; α=0.10: TPR 0.929, chat 0.745.

## Interpretation
v5 separates injections from **formal** benign text (FiQA/SciFact/NFCorpus) much better than v1–v4,
but it largely learned "short conversational chat vs. document prose": informal benign messages are
flagged at 30–75 % depending on α. The core problem (informal benign vs injection) is **not solved**.
Training negatives are FiQA/SciFact only; deepset label-0 was held out as control by design.

## Deviations
None beyond the pre-run correction already committed in the prereg (Nesterov step bound 0.25 → 0.5).
Leakage: 0 exact-text overlaps between injection train/test.

## Next steps (proposal, requires new prereg)
- v6: include informal benign chat (separate source, disjoint from control) in training negatives
  and calibrate on a mixed formal+chat benign pool; keep an untouched chat control.
- Primary endpoint should be chat-benign FPR, not only FiQA FPR.
