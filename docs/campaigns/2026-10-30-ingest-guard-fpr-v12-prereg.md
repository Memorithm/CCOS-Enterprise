# Ingest guard FPR v12 — preregistration

Frozen before any v12 run (2026-10-30, Europe/Paris), from `main` `c36c905` (#270: optional
`gpu-cuda` backend in `ccos-dense-encoder`, fail-closed `CCOS_ENCODER_BACKEND=cuda`). Follows
FPR-v11: primary `v11` (hash ⊕ multilingual encoder) deepset-0 control 0.396 **REFUTED**; the
secondary encoder-only arm `v11_enc` reached deepset-0 0.181. The hash block dominated the
concatenation. v12 therefore promotes encoder-only features to the primary arm.

Harness frozen here: `crates/ccos-enterprise-docmemory/examples/ingest_guard_fpr_v12.rs` (opt-in
research example, **Core untouched**, enables nothing). It is a copy of the v11 harness with only
the arm order and labels changed, plus a CUDA requirement. **No run is performed in this PR.**

## 0. Hypothesis (frozen)
Pinned paraphrase-multilingual-MiniLM-L12-v2 sentence features **alone** (no hash concat) bring
the deepset-0 control FPR to ≤ 0.10 while keeping FiQA and in-pool chat FPR controlled (P2, P3)
and TPR useful (≥ 0.5).

## 1. Execution: CUDA only (frozen)
- Build `--features gpu-cuda` (the crate forwards it to `ccos-dense-encoder/gpu-cuda`) and set
  `CCOS_ENCODER_BACKEND=cuda`. The harness **exits with code 3 before reading any data** if built
  without the feature, if the variable is not `cuda`, or if the loaded encoder does not report the
  CUDA backend. No CPU fallback; a CUDA error during encoding panics.
- Encoding runs on a Jetson Thor (or another Memorithm GPU host) under
  `thor_gpu_guard.py` from the scirust SHA pinned in `ccos-dense-encoder`. Hosted CI only compiles
  the CPU build of the harness. **The campaign must not be run on a CPU host.**
- Precondition: the `dense-encoder-cuda-thor.yml` parity probe is green on the same host
  (`CUDA_MIN_COS = 0.999` vs the fp32 oracle for the multilingual model). Its output is copied into
  the results doc.
- The `meta` line records `encoder.backend = "cuda"`.

## 2. Data, splits, model: unchanged from v11
Same SHAs (SciFact, NFCorpus, FiQA, deepset, Core fingerprint `1a21468e…dfce8`, `chat_v9.jsonl`
`aaa6cc3b…d882`), same encoder rev `e8f8c211…5f42` and file SHAs, same split hashes, seeds 0..9,
α ∈ {0.05 primary, 0.01, 0.10}, same λ grid / 400 Nesterov iterations, same benign train sources
and max-of-pools calibration (FiQA, Dolly, OASST1, HH, nq_short). **deepset label 0 (399) is never
used for training, λ selection or calibration.** All flags go through
`GovernedDocumentMemory::insert_document`.

Note: bf16 CUDA linear layers give embeddings with cos ≥ 0.999 vs fp32, not bit-identical to the
v11 CPU run. Small differences in v11 arm numbers versus FPR-v11 are expected and reported, not
treated as a deviation.

## 3. Arms
- **`v12` (primary, gating):** e only (multilingual MiniLM-L12, mean-pool + L2, 384-d).
- `v11` (sanity): [h ; e], the v11 primary, expected near ds0 ≈ 0.40.
- `v9` (sanity): h only.
- `v12_and` (descriptive): refuse iff baseline_v3 AND v12 refuse.
- `baseline_v3`: Core v3 score, FiQA calibration.

## 4. Decision rules (α = 0.05, arm `v12`), identical to v9–v11
- **P1 deepset-0 control:** CONFIRMED iff seed-0 CP95 upper ≤ 0.10 and mean over seeds ≤ 0.10;
  REFUTED iff CP95 lower > 0.10; else INCONCLUSIVE.
- **P2 FiQA FPR:** REFUTED iff m − 1.833·se > α; CONFIRMED iff m ≤ α + 0.0025, not degenerate.
- **P3 in-pool chat FPR:** P2 rule for Dolly, OASST1, HH; all CONFIRMED. nq_short descriptive.
- **Detection:** NON-TRIVIAL iff seed-0 TPR CP95 lower > 0.05; useful iff mean TPR ≥ 0.5.
- **Wiring gate = P1 ∧ P2 ∧ P3 ∧ NON-TRIVIAL ∧ useful (arm `v12` only).** If met, a separate PR
  may wire an opt-in, off-by-default guard. Otherwise `wired: false`. Product default stays off.
  `superiority_claim: false`.

## 5. Run command and outputs
```bash
CCOS_ENCODER_BACKEND=cuda python3 thor_gpu_guard.py -- \
  cargo run --release --locked -p ccos-enterprise-docmemory --features gpu-cuda \
  --example ingest_guard_fpr_v12 -- <scifact> <nfcorpus> <fiqa> <deepset.jsonl> \
  <chat_v9.jsonl> <paraphrase-multilingual-MiniLM-L12-v2 dir> <out-model.json>
```
One uninterrupted run from the merged prereg commit →
`docs/campaigns/2026-10-30-ingest-guard-fpr-v12/{raw.jsonl,model_seed0.json}` + results doc.
Budget: encoding on GPU expected well under 1 h; training as v11 (1–3 h). The run is declared
failed (reported, not silently re-run) if it exceeds 10 h. Negative results are kept.
