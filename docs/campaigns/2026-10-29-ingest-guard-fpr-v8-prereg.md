# Ingest guard FPR v8 — preregistration

Frozen before any v8 run. Follows v7 (prereg #257 `6f9a650`, results #258 `90865a4`): v7 arm
deepset-0 control 0.415 REFUTED, FiQA 0.0103 CONFIRMED, OASST1 in-pool 0.0531 INCONCLUSIVE,
TPR 0.839; `wired: false`. Harness frozen here:
`crates/ccos-enterprise-docmemory/examples/ingest_guard_fpr_v8.rs` (opt-in research example;
Core untouched; enables nothing; `ccos-dense-encoder` added as a **dev-dependency** only).

## 0. Encoder audit (done before freezing)
- In-repo CPU encoder: `crates/ccos-dense-encoder` (pure-Rust BERT, no BLAS/GPU/unsafe), already
  used for BEIR dense/fused retrieval with the pinned **sentence-transformers/all-MiniLM-L6-v2**
  rev `c9745ed1` (`fetch-model.sh`; sha256 config `953f9c0d…`, tokenizer `be50c362…`,
  safetensors `53aa5117…`, all asserted by the harness). Licence **Apache-2.0** (compatible).
- **Not multilingual:** English uncased WordPiece (30,522 vocab); non-Latin text maps largely to
  `[UNK]`. A multilingual MiniLM (e.g. paraphrase-multilingual-MiniLM-L12-v2) needs an XLM-R
  SentencePiece tokenizer that the repo does not implement → out of scope for v8 (would need its
  own prereg). v8 therefore tests "MiniLM-class encoder already pinned in CCOS", not multilinguality.
- Budget (timing-only benchmark, no labels/metrics, 8 threads, max_len 128): ~60 FiQA docs/s,
  ~330 chat prompts/s → ≈ 20–25 min to encode all ~112k texts once (seed-independent cache).
  max_len = 128 (chat prompts are short; FiQA truncation accepted and documented).

## 1. Data, splits (unchanged from v7)
Same inputs and fingerprints as v7: `chat_v7.jsonl` sha256 `7aa8ff2b…ff2be` (built by v7
`build_chat_v7.py` `c6c4f5d8…e024f5`), deepset/FiQA/SciFact/NFCorpus SHAs as v7, Core model fp
`1a21468e…dfce8`. **Split hash identical to v7** (`ingest-fpr-v7:{corpus}:{seed}:{key}`) so arms are
paired with v7 per seed. Same roles, leakage exclusion, seeds 0..9, α ∈ {0.05 primary, 0.01, 0.10}.
**deepset label 0 (399) is never used for training, λ selection or calibration.** All flags go
through `GovernedDocumentMemory::insert_document`.

## 2. Features, model, arms
Encoder block e(x) = MiniLM mean-pool + L2 over `defang(x)`, 384-d. Hash block h(x) = v7 φ
(log1p + L2 over `HashingTokenizer::new()` counts, 2048-d). Same L2 logistic regression,
Nesterov, 400 iters, λ ∈ {1e-5, 1e-4, 1e-3} chosen on inner split with max-of-pools rule,
same weighting, threshold = max of ConformalGuard thresholds over FiQA, Dolly, OASST1, HH cal pools.
- **`v8` (primary): [h ; e]** (concat, 2432-d, each block unit norm), all three chat sources.
- `v8_enc` (secondary): e only.
- `loo_oasst1_v8` (secondary, descriptive): [h ; e] with OASST1 out of train/λ/calibration.
- `v7` (baseline): h only — same code path; expected to reproduce v7 #258 numbers (sanity check;
  a mismatch is reported as a deviation, not re-run).
- `baseline_v3`: Core v3 score, FiQA calibration.
LOO for Dolly/HH dropped (budget; they transferred in v7).

## 3. Decision rules (α = 0.05, arm `v8`) — identical to v7
- **P1 deepset-0 control:** CONFIRMED iff seed-0 CP95 upper ≤ 0.10 and mean over seeds ≤ 0.10;
  REFUTED iff CP95 lower > 0.10; else INCONCLUSIVE.
- **P2 FiQA FPR:** REFUTED iff m − 1.833·se > α; CONFIRMED iff m ≤ α + 0.0025, not degenerate.
- **P3 in-pool chat FPR:** P2 rule for each of Dolly, OASST1, HH; all must be CONFIRMED.
- **Detection:** NON-TRIVIAL iff seed-0 TPR CP95 lower > 0.05; useful iff mean TPR ≥ 0.5.
- Degeneracy checks as v7. Secondary arms are descriptive, not gating. `superiority_claim: false`.
- **Wiring gate = P1 ∧ P2 ∧ P3 ∧ NON-TRIVIAL ∧ useful (arm `v8`).** If met: follow-up PR wires an
  **opt-in, off-by-default** guard (seed-0 artefact + frozen calibration rule), CI exact-head. If not
  met: `wired: false`, no wiring PR.

## 4. Outputs / out of scope
CPU only, one uninterrupted run from the merged prereg commit. Outputs:
`docs/campaigns/2026-10-29-ingest-guard-fpr-v8/{raw.jsonl,model_seed0.json}` + results doc;
deviations listed there. Negative results are kept.
