# Results — IngestGuard / ConformalGuard FPR-v3 (length-normalised margin)

Prereg: `docs/campaigns/2026-10-29-ingest-guard-fpr-v3-prereg.md`, merged in #249 (`8723d78`)
**before** any v3 run. Harness `crates/ccos-enterprise-docmemory/examples/ingest_guard_fpr_v3.rs`,
built and run once on `8723d78` + this PR's harness commit. Raw output:
`2026-10-29-ingest-guard-fpr-v3/raw.jsonl`. All SHA-256 pins (SciFact, NFCorpus, FiQA, deepset JSONL),
the model fingerprint and the tokenizer/model dim check matched.

Score: `s = (margin − prior_margin) / max(1, n)`, `n = HashingTokenizer::new().features(defang(doc)).len()`,
higher = more injection-like.

## Verdict

- **FPR (Q1, α = 0.05): CONFIRMED, non-degenerate.** Mean FPR over 20 seeds **0.0465** (sd 0.0048,
  se 0.0011). Checks (a)–(g) all pass: 5,183 distinct SciFact scores, finite seed-0 threshold
  **0.06853**, 1 tie at threshold, 1 at benign max, threshold < max score, 122 benign flagged on seed 0
  (not vacuous), 0 SciFact docs with n ≤ 1 (min n = 258). α = 0.01 → 0.0089, α = 0.10 → 0.0969:
  CONFIRMED.
- **Detection (Q2): NON-TRIVIAL.** Seed 0, α = 0.05: **112 / 263 flagged, TPR = 0.426, CP95
  [0.365, 0.488]**; lower bound 0.365 > 0.05. Mean TPR over 20 seeds 0.426. α = 0.01 → seed-0 TPR
  0.369; α = 0.10 → 0.456. Below the descriptive "useful" mark of 0.5.
- **Gate (prereg §7): met on SciFact.** See "Wiring decision" below.

## Numbers

| Item | Value |
|---|---|
| SciFact docs (blank) | 5,183 (0); seed 0 n_cal 2,576 / n_test 2,607 |
| SciFact s min / median / max | −0.450 / −0.032 / 0.272 |
| SciFact n min / median / max | 258 / 1,638 / 11,701 |
| Injections included (leak-excluded, blank) | 263 (0, 0) |
| Injection s min / median / max | −0.900 / 0.015 / 1.174 |
| Injection n min / median / max | 12 / 143 / 5,336 |
| Spearman ρ(s, n) SciFact / injections | −0.154 / −0.147 |
| Threshold seed 0, α = 0.01 / 0.05 / 0.10 | 0.1200 / 0.0685 / 0.0440 |
| Seed 0 α=0.05 FPR | 122 / 2,607 = 0.0468, CP95 [0.039, 0.056] |
| Seed 0 α=0.05 TPR | 112 / 263 = 0.426, CP95 [0.365, 0.488] |
| Reference: v2 raw margin, seed 0 α=0.05 | 16 / 263 (= v2 result reproduced) |
| Shift NFCorpus (3,633) | FPR 0.037 (no guarantee) |
| Shift FiQA (57,600; 38 blank) | FPR **0.281**, CP95 [0.277, 0.284] (no guarantee; ~5.6× α) |
| Shift deepset label 0 (399) | FPR **0.231**, CP95 [0.190, 0.275] (no guarantee; ~4.6× α) |

## Interpretation (exploratory, not preregistered)

- Length normalisation removes most of the v2 failure: TPR goes 0.061 → 0.426 at the same α on the same
  split, and ρ(s, n) is weak (≈ −0.15) on both sets.
- **Domain drift is much worse than v2.** FiQA FPR 0.137 → 0.281; short benign chat prompts (deepset
  label 0) 0.000 → 0.231. The prereg §8 risk materialised: the per-feature mean is higher-variance /
  shifted on short or informal text, and a SciFact-calibrated threshold does not transfer. On the
  deepset set itself, the guard flags 42.6 % of injections vs 23.1 % of benign prompts — real but
  modest discrimination in-domain for injections.
- Detection may still partly reflect domain (scientific vs chat) rather than injection-ness.

## Wiring decision

The preregistered gate is met, which *permits* opt-in, default-off wiring. **This PR does not wire
the guard into rebuild.** Reason: the only guarantee is for SciFact-like text; on two of three
out-of-domain benign sets the false-alarm rate is 4.6–5.6× α, so any deployment would need
calibration on the tenant's own benign ingest corpus first. Wiring (opt-in, default off,
calibrate-on-own-corpus documented) is left as a separate decision. No product default changed.

## Deviations

None. Harness written while #249 CI ran; first and only run after merge. A later `cargo fmt`-only commit (whitespace, no semantic change) was made for CI; not re-run. The descriptive v2-reference
line (prereg §6) is computed by direct `ConformalGuard::flags`, not via `insert_document`.

## Limitations

As prereg §8: benign/injection domain and length mismatch; deepset labels as-is; leakage check only
against the in-repo trainer corpus; benign corpora assumed injection-free; guarantees hold only for
exchangeable (SciFact) data.

## Next steps (each needs its own prereg)

- Calibrate on a benign set matching the ingest domain (e.g. FiQA or chat) and re-measure FPR/TPR there.
- Retrained detector on a larger corpus, evaluated on a disjoint split.
