# Ingest guard FPR v7 — preregistration

Frozen before any v7 run. Follows v6 (prereg #255, results #256, main `b66b9f6`): v6 confirmed
FiQA and Dolly FPR but the deepset label-0 chat control was REFUTED (0.604 seed 0, mean 0.642).
Harness frozen here: `crates/ccos-enterprise-docmemory/examples/ingest_guard_fpr_v7.rs`
(opt-in research example; Core untouched; enables nothing).

## 1. Data: three informal benign chat sources (none is deepset)
Built deterministically by `docs/campaigns/2026-10-29-ingest-guard-fpr-v7/build_chat_v7.py`
(sha256 `c6c4f5d8…e024f5`) into `chat_v7.jsonl` (sha256 `7aa8ff2b…ff2be`, asserted by the harness).
Each source: normalised-text dedup, then deterministic cap of 15,000 by sha256(`v7cap:{src}:{key}`).
| Source | Licence | Raw file sha256 | Rows kept |
|---|---|---|---|
| Dolly-15k `instruction` | CC BY-SA 3.0 | `2df90833…f794ec` | 14,761 |
| OASST1 prompter turns (all languages; not deleted, review_result true) — multilingual (en, es, ru, zh, de, fr…) | Apache-2.0 | `286a6e9a…a185c` (`2023-04-12_oasst_ready.messages.jsonl.gz`) | 15,000 |
| Anthropic HH-RLHF helpful-base train, first human turn | MIT | `518a5bf2…58f6f4` | 15,000 |
The harness also drops any chat text equal (normalised) to any deepset text. No role-play
("act as") corpus is added: deepset labels such prompts as injections, so it would mislabel.
**deepset label 0 is never used for training, λ selection or calibration.**

## 2. Model and arms
Same features/optimiser/λ grid/weighting as v5–v6 (each benign source an equal share of the benign
half). Benign train = FiQA + SciFact + every chat source in the arm.
- **`v7` (primary):** all three chat sources. Threshold = max of ConformalGuard thresholds on the
  calibration pools FiQA, Dolly, OASST1, HH (each at α). λ chosen on inner split with the same max rule.
- **`loo_<source>` (secondary, 3 arms):** source held out of train, λ selection and calibration;
  its test split is a leave-one-source-out chat FPR.
- **`baseline_v3`:** Core v3 score, FiQA calibration.
Splits: hash `ingest-fpr-v7:{corpus}:{seed}:{key}`, r = h[0]%4. FiQA & each chat source: train
{0,1}, cal {2}, test {3}. deepset injections: train {0,1}, test {2,3}. SciFact train {0,1}/probe
{2,3}; NFCorpus and 25 Core-trainer injections: probes. deepset label 0 (399): full control.
Exact normalised-text exclusion: cal vs train; tests/control/probes vs train ∪ cal. Seeds 0..9.
α ∈ {0.05 primary, 0.01, 0.10}. All flags through `GovernedDocumentMemory::insert_document`.

## 3. Decision rules (α = 0.05, arm `v7`)
- **P1 deepset-0 chat control:** CONFIRMED iff seed-0 CP95 upper ≤ 0.10 and mean over seeds ≤ 0.10;
  REFUTED iff CP95 lower > 0.10; else INCONCLUSIVE.
- **P2 FiQA FPR:** REFUTED iff m − 1.833·se > α; CONFIRMED iff m ≤ α + 0.0025, not degenerate.
- **P3 in-pool chat FPR:** P2 rule for each of Dolly, OASST1, HH test; all must be CONFIRMED.
- **Detection:** NON-TRIVIAL iff seed-0 TPR CP95 lower > 0.05; useful iff mean TPR ≥ 0.5.
- **Secondary (descriptive, not gating):** LOO held-out-source FPR (≤ 0.10 reported).
- Degeneracy checks as v6.
- **Wiring gate = P1 ∧ P2 ∧ P3 ∧ NON-TRIVIAL ∧ useful.** If met: a follow-up PR wires the guard as
  an **opt-in** (documented, off by default) using the seed-0 model artefact and the frozen
  calibration rule, CI exact-head. If not met: `wired: false`. `superiority_claim: false` always.

## 4. Budget / out of scope
CPU only. A sentence-encoder arm is **not** in v7 (no in-repo CPU encoder; would need its own
prereg). Outputs: `docs/campaigns/2026-10-29-ingest-guard-fpr-v7/{raw.jsonl,model_seed0.json}`
plus results doc; deviations listed there.
