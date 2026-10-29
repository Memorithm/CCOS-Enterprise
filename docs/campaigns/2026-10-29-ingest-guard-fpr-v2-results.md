# Results — IngestGuard / ConformalGuard FPR-v2 (logit-margin score + detection)

Prereg: `docs/campaigns/2026-10-29-ingest-guard-fpr-v2-prereg.md`, merged in #247 (`ac4d35d`)
**before** any margin run. Harness `crates/ccos-enterprise-docmemory/examples/ingest_guard_fpr_v2.rs`
(built and run on `ac4d35d` + this PR's harness commit). Raw output:
`2026-10-29-ingest-guard-fpr-v2/raw.jsonl`. All SHA-256 pins (SciFact, NFCorpus, FiQA, deepset JSONL)
and the model fingerprint matched the prereg.

## Verdict

- **FPR (Q1, α = 0.05): CONFIRMED, non-degenerate.** Mean FPR over 20 seeds = **0.0467**
  (sd 0.0051, range 0.039–0.056) ≤ 0.05. Degeneracy checks (a)–(e) all pass: 5,146 distinct SciFact
  scores, seed-0 threshold **99.42** (finite), 1 SciFact score tied at threshold, 1 at benign max,
  threshold < max score. Unlike v1 the guard actually fires (131 / 2,607 benign flagged on seed 0).
  α = 0.01 → 0.0086, α = 0.10 → 0.0964: also CONFIRMED.
- **Detection (Q2): TRIVIAL / NEGATIVE.** Seed 0, α = 0.05: **16 / 263 injections flagged, TPR =
  0.061, CP95 [0.035, 0.097]**; lower bound 0.035 ≤ α = 0.05 ⇒ not distinguishable from a random
  flagger at rate α. Mean TPR over 20 seeds 0.059 (≈ α); at α = 0.01 → 0.009, α = 0.10 → 0.109.
  TPR ≈ FPR at every α: **the calibrated guard has essentially no discrimination** between SciFact
  and real prompt injections.
- **Gate (prereg §7): NOT met.** Guard stays off by default and is **not** wired into server rebuild.

## Numbers

| Item | Value |
|---|---|
| Score | `explain(defang(title\n\ntext)).margin`, higher = more injection-like |
| Model fingerprint | `1a21468e…dfce8` (= v1) |
| SciFact (blank) | 5,183 (0); seed 0 n_cal 2,576 / n_test 2,607 |
| SciFact margin min / median / max | −968.8 / −52.1 / 385.3 |
| Injections (deepset label 1) | 263 included, 0 leakage-excluded, 0 blank |
| Injection margin min / median / max | −232.9 / 2.01 / 1,224.8 |
| Threshold seed 0, α = 0.01 / 0.05 / 0.10 | 168.39 / 99.42 / 64.11 |
| Seed 0 α=0.05 FPR | 131 / 2,607 = 0.0502, CP95 [0.042, 0.059] |
| Seed 0 α=0.05 TPR | 16 / 263 = 0.061, CP95 [0.035, 0.097] |
| Mean FPR / mean TPR, 20 seeds, α=0.05 | 0.0467 / 0.0586 |
| Shift NFCorpus (3,633) | FPR 0.0435 (no guarantee) |
| Shift FiQA (57,600; 38 blank) | FPR **0.137** (no guarantee; ~2.7× α) |
| Shift deepset label 0 (399) | FPR 0.000 (no guarantee) |

## Interpretation (exploratory, not preregistered)

- The saturation of v1 is fixed: the margin gives a real, finite, non-tied threshold.
- But the margin is an **unnormalised sum over token counts**, so it scales with document length.
  Long SciFact abstracts reach margins of +385 while the median injection (short chat prompt) sits at
  +2; the 95th percentile of benign is ~+99, above most injections. The guard therefore flags long
  benign text and short injections roughly equally. Benign short chat text (deepset label 0) is never
  flagged, also consistent with a length effect. Not tested here; hypothesis only.
- FiQA (forum answers) breaks the α bound under shift (0.137): calibration on SciFact does not
  transfer to other benign domains.

## Deviations

None. Harness written while #247 CI ran; first and only run after merge.

## Limitations

As prereg §8: domain/length mismatch between benign and injection sets; deepset labels as-is;
leakage check only against the in-repo trainer corpus; benign corpora assumed injection-free.

## Consequences / roadmap (each needs its own prereg)

- Open item "usable calibrated ingest guard": **still open**. The FPR guarantee is now real and
  non-vacuous, but detection is at chance — wiring would only add α false alarms.
- Candidate next steps: length-normalised margin (margin / token count, or mean per-token
  contribution); calibrating on a benign set matching the ingest domain; a retrained detector on a
  larger corpus. Detection must be measured on a disjoint split from any new training data.
