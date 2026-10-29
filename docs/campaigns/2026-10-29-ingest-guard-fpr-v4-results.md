# Results — IngestGuard / ConformalGuard FPR-v4 (ingest-domain FiQA recalibration)

Prereg: `docs/campaigns/2026-10-29-ingest-guard-fpr-v4-prereg.md`, merged in #251 (`be6382f`)
**before** any v4 run. Harness `crates/ccos-enterprise-docmemory/examples/ingest_guard_fpr_v4.rs`,
built and run once on `be6382f` + this PR's harness commit. Raw output:
`2026-10-29-ingest-guard-fpr-v4/raw.jsonl`. All SHA-256 pins (FiQA, SciFact, NFCorpus, deepset JSONL),
the model fingerprint `1a21468e…dfce8` and the tokenizer/model dim check matched. Score, model,
tokenizer identical to v3; no retraining.

## Verdict

- **FPR (Q1, α = 0.05): INCONCLUSIVE (non-degenerate).** Mean FiQA-test FPR over 20 seeds
  **0.050099** (sd 0.00215, se 0.00048). Not REFUTED (m − 1.729·se = 0.04927 ≤ α), but m > α by
  1.0·10⁻⁴, so the preregistered rule "CONFIRMED iff m ≤ α" is not met. This is the expected
  behaviour of a split-conformal guard (marginal guarantee ≈ α, sampling noise around it); the rule
  is applied as written. Degeneracy checks (a)–(g) all pass (57,595 distinct scores, finite
  threshold 0.2117, 1 tie, 1 at max, 1,408 benign flagged on seed 0, 0 docs with n ≤ 1).
  Secondary: α = 0.01 → 0.00999 CONFIRMED; α = 0.10 → 0.09984 CONFIRMED.
- **Detection (Q2): NON-TRIVIAL but weak.** Seed 0, α = 0.05: **65 / 263, TPR 0.247, CP95
  [0.196, 0.304]**; lower bound > 0.05. Mean TPR over seeds 0.247. Down from v3's 0.426 (the
  FiQA threshold 0.212 is ~3× the SciFact one 0.069). Far below "useful" 0.5.
- **Wiring gate: NOT met** (FPR not CONFIRMED). **Nothing wired; no product code/default changed.**
  superiority_claim = false.

## Numbers vs v3

| Item | v3 (SciFact-calibrated) | v4 (FiQA-calibrated) |
|---|---|---|
| Seed-0 threshold α=0.05 | 0.0685 | 0.2117 |
| Mean FPR on calibration domain (20 seeds) | 0.0465 (SciFact) CONFIRMED | 0.0501 (FiQA) INCONCLUSIVE |
| Seed-0 FPR calib domain | 122/2,607 = 0.047 | 1,408/28,691 = 0.049, CP95 [0.047, 0.052] |
| Seed-0 TPR deepset inj. | 0.426 [0.365, 0.488] | 0.247 [0.196, 0.304] |
| α = 0.01 / 0.10 mean FPR | 0.0089 / 0.0969 | 0.0100 / 0.0998 |
| α = 0.01 / 0.10 mean TPR | 0.369 / 0.456 (seed 0) | 0.188 / 0.323 |
| FiQA FPR | 0.281 (drift) | in-domain (above) |
| SciFact FPR | in-domain | 0.0004 (2/5,183) |
| NFCorpus FPR | 0.037 | 0.0003 (1/3,633) |
| deepset label 0 FPR | 0.231 | **0.105** (42/399), CP95 [0.077, 0.140] |

Reproduction check (prereg §5): v3 seed-0 SciFact threshold on FiQA gives 16,161/57,600 = 0.281 and
112/263 injections — v3 reproduced exactly.

FiQA: 57,600 docs (38 blank excluded), n min/median/max 7 / 617 / 20,046, Spearman ρ(s, n) = 0.050.
Split seed 0: n_cal 28,909 / n_test 28,691; cal/test disjointness asserted for every seed.

Chat arm (descriptive, calibrated on deepset label 0 halves, ~198/201): α = 0.05 mean FPR 0.047,
mean TPR 0.179 (seed-0 threshold 0.361); α = 0.01 → 0.008 / 0.035; α = 0.10 → 0.087 / 0.227.

## Interpretation (exploratory, not preregistered)

- Recalibration works as conformal theory predicts: FPR ≈ α in-domain at every α, and the guard
  becomes very conservative on scientific text. The cost is detection: TPR roughly halves, because
  benign FiQA forum text scores much more injection-like than SciFact under this model.
- Short chat text remains the weak spot: even with FiQA calibration, benign deepset prompts are
  flagged at 10.5 % (≈ 2× α); calibrating on chat itself controls FPR but drops TPR to ~0.18.
- Conclusion: the current hashing NB detector + v3 score does not separate injections from
  informal benign text well enough to be a useful ingest guard; the limiting factor is the model,
  not the calibration.

## Wiring decision

Gate not met → **not wired**. Rebuild path unchanged, guard remains off by default.

## Deviations

None in protocol. Harness written while #251 CI ran (built, not executed); first and only run after
merge. Unused `raw_margin` helper removed before the run (no semantic effect).

## Limitations

As prereg §8: deepset labels as-is; FiQA assumed injection-free (not relabelled); leakage check only
against the in-repo trainer corpus; guarantee is marginal and only for FiQA-exchangeable data.

## Next steps (each needs its own prereg)

- Retrain / replace the detector on a larger, domain-diverse benign + injection corpus, evaluated on
  disjoint splits (the bottleneck identified here).
- Optionally, a prereg with a finite-sample-aware FPR rule (e.g. upper CP bound on pooled FPR) —
  must be fixed before any new run, not applied retroactively to v4.
