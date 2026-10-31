# Ingest guard FPR v14 — preregistration

Frozen before any v14 run (2026-10-31, Europe/Paris), from `main` `4673a26` (#278), after FPR-v13
results (#276, `a55d61f`): primary `v13` (multilingual MiniLM-L12 encoder only, six benign pools incl.
`oasst1_de`) deepset-0 control mean **0.178**, seed-0 75/399 CP95 [0.151, 0.230] → P1 **REFUTED**;
P2/P3 CONFIRMED; TPR 0.716 (NON-TRIVIAL, useful); `wired: false`.

Harness frozen here: `crates/ccos-enterprise-docmemory/examples/ingest_guard_fpr_v14.rs` (opt-in
research example, **Core untouched**, enables nothing). It is the v13 harness with **one change: the
arm order / which arm is primary** (plus renames). Same data, same features, same optimiser, same
gates. **No run is performed in this PR.**

## 0. Hypothesis (frozen)
**Hash-only features trained and calibrated on the six benign pools (FiQA + dolly, oasst1,
hh_helpful, nq_short, oasst1_de) bring the deepset-0 control FPR to ≤ 0.10 at α = 0.05**, with P2
(FiQA) and P3 (Dolly, OASST1, HH) CONFIRMED and TPR NON-TRIVIAL and useful (≥ 0.5).

Provenance and honesty note: in v13 the hash-only arm `v13_hash` showed a deepset-0 mean of **0.121**
(vs ≈ 0.400 for the v9 hash arm without `oasst1_de`; `v13_cat` ≈ 0.216). That number was a
**descriptive secondary arm** and is **not** evidence for this hypothesis: v13's rules forbid post-hoc
promotion of secondary arms. v14 is the **first preregistration in which hash-only is the primary
gating arm**; only the v14 run decides. Note that 0.121 > 0.10 already, so the most likely outcome
is P1 INCONCLUSIVE or REFUTED.

Expected failure modes (reported, not fixed post hoc): the hash arm stays above 0.10 (as 0.121
suggests); the hash model overfits German orthography/surface tokens of `oasst1_de` and does not
generalise to deepset-0; hash features lose TPR (especially English injections) so the arm becomes
not useful; P2/P3 calibration is noisier for the hash arm.

## 1. Data (unchanged vs v13)
Reuses `chat_v13.jsonl` exactly (sha256 `14de7a08656d90ba21320408b356178a746a9478a76234bce88cbc066b03762a`,
asserted by the harness; vendored gzip in `docs/campaigns/2026-10-30-ingest-guard-fpr-v13/inputs/`).
Same SciFact, NFCorpus, FiQA, deepset SHAs. **No new download.** Split hash tags unchanged
(`oasst1_de` keeps `ingest-fpr-v13`; others v7/v9), so every split is identical to v13 per seed.
`nq_short` and `oasst1_de` in-pool FPR remain descriptive. **deepset label 0 (399) is never used for
training, λ selection or calibration.** All flags go through `GovernedDocumentMemory::insert_document`.

## 2. Unchanged from v13
Core fingerprint `1a21468e…dfce8`, hash φ (`HashingTokenizer`, block `F_HASH`, identical to `v9_hash`
/ `v13_hash`), encoder paraphrase-multilingual-MiniLM-L12-v2 rev `e8f8c211…5f42` and file SHAs,
seeds 0..9, α ∈ {0.05 primary, 0.01, 0.10}, λ grid {1e-5, 1e-4, 1e-3}, 400 Nesterov iterations,
`weighted` six-source benign share, max-of-pools calibration, leakage exclusions, degeneracy checks.

## 3. Execution: CUDA only (frozen, as v13)
The gating arm does not need the encoder, but the sanity arms `v14_enc` / `v14_cat` do and the
harness is kept byte-for-byte consistent with v13, so:
- Build `--features gpu-cuda`, `CCOS_ENCODER_BACKEND=cuda`. The harness **exits with code 3 before
  reading any data** without the feature, without the variable, or if the encoder does not load on
  CUDA. No CPU fallback; a CUDA error panics. Hosted CI only compiles the CPU build.
- Run on the Jetson Thor runner under `thor_gpu_guard.py` (scirust SHA pinned in the workflow),
  exclusive GPU (`concurrency: thor-gpu-dense-encoder`). Packed encode (#275) is on `main`.
- Precondition: `dense-encoder-cuda-thor.yml` parity probe green on the same host (`CUDA_MIN_COS =
  0.999`); output copied into the results doc. `meta.encoder.backend = "cuda"`.

## 4. Arms
- **`v14` (primary, gating):** hash features only, six benign pools.
- `v14_enc` (sanity/reference): encoder only = the v13 primary configuration (should reproduce v13).
- `v14_cat` (sanity): [hash ; encoder], same pools (should reproduce `v13_cat`).
- `v14_and` (descriptive): refuse iff baseline_v3 AND v14 refuse.
- `baseline_v3`: Core v3 score, FiQA calibration.
- Reference (not re-run): v13 results #276.

## 5. Decision rules (α = 0.05, arm `v14`), identical to v9–v13
- **P1 deepset-0 control:** CONFIRMED iff seed-0 CP95 upper ≤ 0.10 and mean over seeds ≤ 0.10;
  REFUTED iff CP95 lower > 0.10; else INCONCLUSIVE.
- **P2 FiQA FPR:** REFUTED iff m − 1.833·se > α; CONFIRMED iff m ≤ α + 0.0025, not degenerate.
- **P3 in-pool chat FPR:** P2 rule for Dolly, OASST1, HH; all CONFIRMED. `nq_short`, `oasst1_de`
  descriptive.
- **Detection:** NON-TRIVIAL iff seed-0 TPR CP95 lower > 0.05; useful iff mean TPR ≥ 0.5.
- **Wiring gate = P1 ∧ P2 ∧ P3 ∧ NON-TRIVIAL ∧ useful (arm `v14` only).** If met, a separate PR may
  wire an opt-in, off-by-default guard. Otherwise `wired: false`. Product default stays off.
  `superiority_claim: false`. Sanity arms and other α are never promoted post hoc.

## 6. Run command and outputs
```bash
CCOS_ENCODER_BACKEND=cuda python3 thor_gpu_guard.py -- \
  cargo run --release --locked -p ccos-enterprise-docmemory --features gpu-cuda \
  --example ingest_guard_fpr_v14 -- <scifact> <nfcorpus> <fiqa> <deepset.jsonl> \
  <chat_v13.jsonl> <paraphrase-multilingual-MiniLM-L12-v2 dir> <out-model.json>
```
Via the manual workflow `.github/workflows/fpr-v14-campaign-thor.yml` (added in this PR; it only
runs the frozen harness). One uninterrupted run from the merged prereg commit →
`docs/campaigns/2026-10-31-ingest-guard-fpr-v14/{raw.jsonl,model_seed0.json}` + results doc
(separate PR). Declared failed (reported, not silently re-run) beyond 10 h. Negative results are kept.
`model_seed0.json` holds the primary (hash) arm's weights.
