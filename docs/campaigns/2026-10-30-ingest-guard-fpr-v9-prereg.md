# Ingest guard FPR v9 — preregistration

Frozen before any v9 run (2026-10-30, Europe/Paris). Follows v8 (prereg #259 `412f888`, results
#260 `f9d63a2`): arm v8 (hash ⊕ MiniLM-L6-v2) deepset-0 control mean **0.527 REFUTED** (worse than
v7 0.415), FiQA + in-pool chat CONFIRMED, TPR 0.888, `wired: false`; `v8_enc` (MiniLM alone) ds0
0.441 with lower TPR; baseline_v3 ds0 ≈ 0.106, TPR ≈ 0.239. Harness frozen here:
`crates/ccos-enterprise-docmemory/examples/ingest_guard_fpr_v9.rs` (opt-in research example; Core
untouched; enables nothing; no new dependency; CPU only, no NVIDIA requirement).

## 0. Hypothesis (frozen)
P1 fails because the logistic regression is trained/calibrated on conversational chat negatives
(Dolly/OASST1/HH) and over-flags short, informal FAQ/query-style text (deepset label-0 samples:
mean length ≈ 66 chars, mostly EN with some DE context) — a **style** shift, not only language.
EN MiniLM features made it worse (v8). v9 tests whether adding a license-clean **short-query**
benign source to train + λ selection + calibration (hash φ only, no encoder) brings the deepset-0
control FPR to ≤ 0.10 while keeping FiQA/in-pool FPR and detection.

## 1. Data
- Unchanged inputs and SHAs from v7/v8: SciFact, NFCorpus, FiQA, deepset
  (`2c46bfa4…22ef8`), Core model fp `1a21468e…dfce8`.
- **New benign file `chat_v9.jsonl`** sha256
  `aaa6cc3b331baeb48418afaac6f6c3a15b1308e0306882600a8940810d13d882` (59,761 rows), built by
  `docs/campaigns/2026-10-30-ingest-guard-fpr-v9/build_chat_v9.py` (sha256 `cb3f1dbc…bf678`):
  - `chat_v7.jsonl` (`7aa8ff2b…ff2be`, 44,761 rows: dolly / oasst1 / hh_helpful) copied verbatim.
  - **`nq_short`**: 15,000 questions from NQ-open train (`google-research-datasets/nq_open`, HF rev
    `5dd9790a83002ad084ddeb7c420dc716852c6f28`, `train-00000-of-00001.parquet` sha256
    `25d3a544324f900b31ebc05a3a5686bdd5b9b42738133500675c3f20eee7d83a`, 87,925 questions).
    **Licence CC BY-SA 3.0** (research use, attribution: Kwiatkowski et al. 2019; Lee et al. 2019).
    Dedup on normalised text (0 dups), deterministic cap by `sha256("v9cap:nq_short:{row}")`.
    Mean length ≈ 47 chars, lowercase Google-search-style questions, **English only** (no DE/other).
  - **Leakage vs deepset (both labels):** exact normalised match removed (0) and near-duplicates
    removed (token-set Jaccard ≥ 0.8 or full token containment in a deepset text: 3 removed). The
    harness additionally drops any chat row whose normalised defanged text equals a deepset text.
  - Large jsonl/parquet stay outside git (`/workspace/chat-data/`), as for v7; SHAs asserted at run.
- Defang/normalisation identical to v7 (applied in the harness).
- **Deferred:** multilingual MiniLM / XLM-R needs a SentencePiece tokenizer that
  `ccos-dense-encoder` (WordPiece only) does not implement. Out of scope for v9; requires a separate
  engineering PR + own prereg. No SentencePiece is added here.

## 2. Splits (paired with v7/v8)
Shared corpora keep the v7 hash `ingest-fpr-v7:{corpus}:{seed}:{key}` (paired per seed with v7/v8);
`nq_short` uses `ingest-fpr-v9:nq_short:{seed}:{key}`. Same roles (byte0 % 4: {0,1} train, 2 cal,
3 test; byte1 % 4 == 0 inner λ split), seeds 0..9, α ∈ {0.05 primary, 0.01, 0.10}, same
exact-text leakage exclusion (cal vs train; tests/control/probes vs train ∪ cal). **deepset label 0
(399) is never used for training, λ selection or calibration.** All flags go through
`GovernedDocumentMemory::insert_document`.

## 3. Model, arms
v7 φ: log1p + L2 over `HashingTokenizer::new()` counts (2048-d). Same L2 logistic regression,
Nesterov, 400 iters, λ ∈ {1e-5, 1e-4, 1e-3} on the inner split with max-of-pools rule, same
weighting (injections ½ mass; each benign source equal share of the other ½), threshold = max of
ConformalGuard thresholds over the arm's calibration pools.
- **`v9` (primary, gating):** benign = FiQA, SciFact, Dolly, OASST1, HH, **nq_short**; calibration
  pools FiQA, Dolly, OASST1, HH, nq_short. **No MiniLM.**
- `v7` (secondary, sanity): three chat sources as v7; expected to reproduce #258 numbers. Possible
  tiny deviation: the leakage-exclusion set now also contains nq_short train texts. Mismatch is
  reported as a deviation, not re-run.
- `v9_and` (secondary, descriptive): refuse iff baseline_v3 guard AND v9 guard refuse (score
  min(z_v9 − thr_v9, s_v3 − thr_v3) through a guard with threshold 0, strict `>`).
- `baseline_v3` (secondary): Core v3 score, FiQA calibration.
- `v9_enc` dropped (MiniLM not cheap to keep without adding the encoder dev path; out of hypothesis).

## 4. Decision rules (α = 0.05, arm `v9`) — identical to v7/v8
- **P1 deepset-0 control:** CONFIRMED iff seed-0 CP95 upper ≤ 0.10 and mean over seeds ≤ 0.10;
  REFUTED iff CP95 lower > 0.10; else INCONCLUSIVE.
- **P2 FiQA FPR:** REFUTED iff m − 1.833·se > α; CONFIRMED iff m ≤ α + 0.0025, not degenerate.
- **P3 in-pool chat FPR:** P2 rule for Dolly, OASST1, HH; all must be CONFIRMED. nq_short in-pool
  FPR is reported descriptively (not gating).
- **Detection:** NON-TRIVIAL iff seed-0 TPR CP95 lower > 0.05; useful iff mean TPR ≥ 0.5.
- Degeneracy checks as v7. Secondary arms descriptive. `superiority_claim: false`.
- **Wiring gate = P1 ∧ P2 ∧ P3 ∧ NON-TRIVIAL ∧ useful (arm `v9` only).** If met: separate
  follow-up PR may wire an **opt-in, off-by-default** guard (ConformalGuard wiring stays forbidden
  until then). If not met: `wired: false`, no wiring PR.

## 5. Outputs / out of scope
One uninterrupted CPU run from the merged prereg commit. Outputs:
`docs/campaigns/2026-10-30-ingest-guard-fpr-v9/{raw.jsonl,model_seed0.json}` + results doc;
deviations listed there. Negative results are kept. No run is performed in the prereg PR.
