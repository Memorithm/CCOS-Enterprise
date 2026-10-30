# Ingest guard FPR v11 — preregistration

Frozen before any v11 run (2026-10-30, Europe/Paris), from `main` `a628b1e` (#266: in-crate
SentencePiece Unigram tokenizer + multilingual MiniLM-L12-v2 in `ccos-dense-encoder`). Follows
v10 (#265 `21895ee`): hash ⊕ scalars deepset-0 control 0.384 **REFUTED**, OASST1 P3 **REFUTED**,
TPR 0.844, `wired: false`. deepset-0 FPR has plateaued across v7–v10 (≈ 0.38–0.53); v8 with the
**English** MiniLM-L6 made it worse (0.527). deepset label 0 is ≈ 37 % German.

Harness frozen here: `crates/ccos-enterprise-docmemory/examples/ingest_guard_fpr_v11.rs` (opt-in
research example; dev-dependency on `ccos-dense-encoder` only; **Core untouched**; enables nothing;
CPU only, no NVIDIA/GPU requirement). **No run is performed in this PR.**

## 0. Hypothesis (frozen)
Multilingual MiniLM-L12 (Unigram/XLM-R vocabulary) sentence features, concatenated with the v7/v9
hash features (and, secondarily, alone), reduce the deepset-0 control FPR to ≤ 0.10 while keeping
FiQA and in-pool chat FPR controlled and TPR ≥ 0.5 — because DE/non-EN deepset-0 texts were poorly
represented by EN WordPiece/hash-only decision boundaries.

## 1. Data (unchanged from v9/v10, SHAs asserted by the harness)
- SciFact `dec31c81…1ac6`, NFCorpus `10cc83ef…991f`, FiQA `ff593e4d…6517`, deepset
  `2c46bfa4…22ef8`, Core model fingerprint `1a21468e…dfce8`.
- `chat_v9.jsonl` `aaa6cc3b331baeb48418afaac6f6c3a15b1308e0306882600a8940810d13d882` (59,761 rows:
  dolly / oasst1 / hh_helpful / nq_short), same deepset-overlap exclusion as v9.
- **Encoder** `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2` rev
  `e8f8c211226b894fcb81acc59f3b34ba3efd5f42` (Apache-2.0), fetched by `fetch-model-multilingual.sh`
  to `/workspace/models/paraphrase-multilingual-MiniLM-L12-v2`. Asserted sha256:
  - `config.json` `6300193cb75e01cf80c96decef7187dfb33094d97cc1490b7ead6ff134476e4e`
  - `tokenizer.json` `2c3387be76557bd40970cec13153b3bbf80407865484b209e655e5e4729076b8`
  - `model.safetensors` `eaa086f0ffee582aeb45b36e34cdd1fe2d6de2bef61f8a559a1bbc9bd955917b`
  - plus `sentence_bert_config.json` `max_seq_length == 128` (`MULTILINGUAL_MAX_LEN`) and tokenizer
    variant `Unigram` asserted. Loaded with `BertSentenceEncoder::load_auto`, 8 threads.

## 2. Splits (paired with v7–v10)
Identical to v9: hash `ingest-fpr-v7:{corpus}:{seed}:{key}` for shared corpora,
`ingest-fpr-v9:nq_short:{seed}:{key}` for nq_short; byte0 % 4 {0,1} train, 2 cal, 3 test; byte1 %
4 == 0 inner λ split; seeds 0..9; α ∈ {0.05 primary, 0.01, 0.10}; same exact-text leakage
exclusion. **deepset label 0 (399) is never used for training, λ selection or calibration.** All
flags go through `GovernedDocumentMemory::insert_document`.

## 3. Features, model, arms
- h = v7 φ: log1p + L2 over `HashingTokenizer::new()` counts on `defang(x)` (2048-d, unit norm).
- e = multilingual MiniLM-L12 `encode(defang(x))`: mean-pool + L2 (384-d, unit norm), max_len 128.
- Embeddings computed **once per unique defanged text** before the seed loop (seed-independent
  in-memory cache, as v8 encoded once); no on-disk cache.
- Same L2 logistic regression as v9 (Nesterov, 400 iters, λ ∈ {1e-5, 1e-4, 1e-3} on the inner split
  with the max-of-pools rule; injections ½ mass, each benign source equal share of the other ½).
  Weight vector dimension 2432 for every arm (hash-only arm has zero encoder features, so its
  encoder weights stay 0 and it is numerically the v9 model).
- Benign train sources for every logistic arm: FiQA, SciFact, Dolly, OASST1, HH, nq_short.
  Calibration pools (threshold = max of ConformalGuard thresholds): FiQA, Dolly, OASST1, HH,
  nq_short — the v9 pool set.
- **`v11` (primary, gating):** [h ; e] (2432-d).
- `v11_enc` (secondary): e only.
- `v9` (sanity): h only; expected to reproduce #263 v9 numbers (any mismatch reported as a
  deviation, not re-run).
- `v11_and` (descriptive): refuse iff baseline_v3 AND v11 refuse (min(z_v11 − thr_v11, s_v3 −
  thr_v3) through a threshold-0 guard, strict `>`).
- `baseline_v3`: Core v3 score, FiQA calibration.

## 4. Decision rules (α = 0.05, arm `v11`) — identical to v9/v10
- **P1 deepset-0 control:** CONFIRMED iff seed-0 CP95 upper ≤ 0.10 and mean over seeds ≤ 0.10;
  REFUTED iff CP95 lower > 0.10; else INCONCLUSIVE.
- **P2 FiQA FPR:** REFUTED iff m − 1.833·se > α; CONFIRMED iff m ≤ α + 0.0025, not degenerate.
- **P3 in-pool chat FPR:** P2 rule for Dolly, OASST1, HH; all CONFIRMED. nq_short descriptive.
- **Detection:** NON-TRIVIAL iff seed-0 TPR CP95 lower > 0.05; useful iff mean TPR ≥ 0.5.
- Degeneracy checks as v9. Secondary arms descriptive. `superiority_claim: false`.
- **Wiring gate = P1 ∧ P2 ∧ P3 ∧ NON-TRIVIAL ∧ useful (arm `v11` only).** If met, a separate
  follow-up PR may wire an **opt-in, off-by-default** guard. If not met: `wired: false`, no wiring
  PR. **The product default stays off in all cases.**

## 5. Compute budget (honest estimate, not a measurement of this campaign)
- Texts to encode ≈ 127k rows (FiQA 57.6k, chat_v9 59.8k, SciFact 5.2k, NFCorpus 3.6k, deepset
  ~0.66k, Core OOD literals), fewer after per-text dedup.
- Measured in #266: ≈ 46 docs/s at 8 threads (CPU). ⇒ ≈ 45 min if that rate holds; long FiQA /
  NFCorpus documents are truncated to 128 tokens but still cost more than short chat rows, so plan
  **45 min – 2 h** for encoding (v8 with the 6-layer EN model took 2162 s for ~111k texts; L12 has
  twice the layers).
- Training: 3 logistic arms × (3 λ + 1 refit) × 10 seeds on dense 384-d + sparse hash rows; plus
  insert-path scoring for 5 arms × 3 α. Estimate **1–3 h**. Total wall budget **≈ 2–5 h**; the run
  is declared failed (reported, not silently re-run) if it exceeds 10 h.
- Peak memory dominated by the f32 embedding cache + three f64 sparse copies (~1–2 GB).

## 6. Outputs / out of scope
One uninterrupted CPU run from the merged prereg commit:
`cargo run --release -p ccos-enterprise-docmemory --example ingest_guard_fpr_v11 -- <scifact>
<nfcorpus> <fiqa> <deepset.jsonl> <chat_v9.jsonl> <minilm-dir> <out-model.json>` →
`docs/campaigns/2026-10-30-ingest-guard-fpr-v11/{raw.jsonl,model_seed0.json}` + results doc;
deviations listed there. Negative results are kept. Not in scope: any guard wiring, any Core
change, GPU execution, new datasets.
