# Results — IngestGuard / ConformalGuard false-alarm rate (FPR-v1)

Prereg: `docs/campaigns/2026-10-29-ingest-guard-fpr-v1-prereg.md`, merged in #245 (`c5c5c4f`)
**before** any run. Harness: `crates/ccos-enterprise-docmemory/examples/ingest_guard_fpr.rs`, built
from `c5c5c4f` + this PR's harness commit. Raw output (one JSON line per split):
`2026-10-29-ingest-guard-fpr-v1/raw.jsonl`. All three corpus SHA-256 matched the prereg.

## Verdict

- **Rule verdict (§7, primary α = 0.05): CONFIRMED** — mean FPR over 20 seeds = **0.000** ≤ 0.05
  (sd 0; every split 0 / ~2,600). Same at α = 0.01 and 0.10.
- **Substantive verdict: VACUOUS / NEGATIVE for the scorer.** The conformal threshold is **exactly
  1.0 on all 60 (seed, α) splits**, because **1,176 / 5,183 (22.7 %)** benign SciFact abstracts get
  injection probability saturated at `1.0` (f32). Since `flags` is strict `score > threshold` and
  a probability cannot exceed 1.0, the calibrated guard **can never flag any document**, benign or
  malicious. FPR ≤ α holds trivially; the guarantee is real but buys nothing.
- The prereg's degeneracy check (≥ 100 distinct scores; observed 2,300) did not anticipate
  saturation at the top of the scale. Reported here as a gap in the prereg, not used to change the
  rule verdict.

## Numbers

| Item | Value |
|---|---|
| Scorer | Core `shared_detector()` injection probability on `defang(title\n\ntext)` |
| Model fingerprint | `1a21468ef60e681eaffc91bbfa92b94e77d10ca5dd11a5400e9a53586d4dfce8` |
| SciFact docs (blank) | 5,183 (0) |
| Seed 0 split | n_cal 2,576 / n_test 2,607 |
| Threshold (all 60 splits) | 1.0 |
| Seed 0 α=0.05 flagged / FPR / CP95 | 0 / 0.000 / [0, 0.00141] |
| Mean FPR, 20 seeds, α ∈ {0.01, 0.05, 0.10} | 0.000 (sd 0) |
| Score min / median / max | 0.0 / 2.4e-23 / 1.0 |
| Benign scores == 1.0 | 1,176 (22.7 %) |
| Shift NFCorpus (3,633), seed-0 guard | 0 flagged, CP95 hi 0.00101 (no guarantee applies) |
| Shift FiQA (57,600; 38 blank skipped) | 0 flagged, CP95 hi 0.000064 (no guarantee applies) |

Exploratory, **not preregistered**: under the legacy hard cut `is_injection(text, 0.5)`,
**1,489 / 5,183 (28.7 %)** benign SciFact abstracts would be refused. The ad-hoc cut is far worse
than α; the calibrated cut is safe only because it is inert.

## Deviations

- The `meta` line gained two descriptive counts (`scores_eq_1`, `scores_ge_0_5`) after the first
  run, to explain the threshold = 1.0 observation. The primary computation was not changed; the
  re-run produced identical split/summary/shift lines.

## Consequences / decision

- `IngestGuard` stays **off by default** on ingest and is **not** wired into the server rebuild
  (#237): wiring an inert guard would add a code path with zero effect and a misleading
  "calibrated" label. No product default changed in this PR; retrieval (DocumentMemory, stdio+HTTP,
  dense/fused opt-in) untouched.
- The open item "FPR ≤ α measured" is closed **for this scorer**; the open item "usable calibrated
  ingest guard" is **not** closed.

## Limitations

- Benign = public BEIR corpora, assumed injection-free (not audited per doc). Model training data
  not re-audited for BEIR overlap.
- Detection rate on injections not measured (out of scope; and with threshold 1.0 it is 0 by
  construction).
- Exchangeability holds only for SciFact-like ingest; shift probes are descriptive.

## Roadmap (each needs its own prereg)

1. Non-saturating nonconformity score: use the injection–benign **logit margin**
   (`Explanation::margin`, already in Core) instead of the f32 probability, so ties at 1.0 vanish.
2. Re-run FPR-v1 protocol with that score (FPR-v2) **plus** a paired detection measurement on a
   held-out injection set disjoint from the model's training data.
3. Only if FPR-v2 CONFIRMED with non-trivial detection: opt-in guard on server rebuild, default off.
