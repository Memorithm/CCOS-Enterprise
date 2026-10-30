# Ingest guard FPR v13 — preregistration

Frozen before any v13 run (2026-10-30, Europe/Paris), from `main` `f8a7efb` (#273, FPR-v12 results).
FPR-v12: primary `v12` (multilingual MiniLM-L12 encoder only) deepset-0 control mean 0.181, seed-0
75/399 CP95 [0.151, 0.230] → P1 **REFUTED**; P2/P3 CONFIRMED; TPR 0.735 (NON-TRIVIAL, useful);
`wired: false`.

Harness frozen here: `crates/ccos-enterprise-docmemory/examples/ingest_guard_fpr_v13.rs` (opt-in
research example, **Core untouched**, enables nothing). It is the v12 harness with **one data
change** (a fifth benign chat source) plus arm renames. **No run is performed in this PR.**

## 0. Hypothesis (frozen)
deepset label 0 is ~37 % German, while the benign training/calibration pools are almost entirely
English: in `chat_v9.jsonl` the only German benign text is 568 / 14,999 OASST1 prompts (3.8 % of one
of five benign sources, i.e. < 1 % of benign training mass). German benign text therefore sits far
from the benign mass in encoder space and is flagged. **Adding German benign instructions as their
own equal-weight benign source (training + max-of-pools calibration) lowers the deepset-0 control FPR
of the encoder-only arm to ≤ 0.10** while P2 (FiQA) and P3 (Dolly, OASST1, HH) stay CONFIRMED and TPR
stays useful (≥ 0.5). This is the smallest change suggested by #273 "Next steps"; the encoder,
features, optimiser and gates are unchanged.

Expected failure modes (reported, not fixed post hoc): the source is small (669 texts → ~167 per
quarter split), so its calibration quantile is noisy; or the German benign/injection boundary is not
learnable from 669 texts and TPR on German injections drops instead.

## 1. Data change (the only change vs v12)
New source `oasst1_de`, built deterministically by
`docs/campaigns/2026-10-30-ingest-guard-fpr-v13/build_chat_v13.py`:

| Source | License | Pinned input | Rows |
|---|---|---|---|
| `oasst1_de`: OASST1 prompter turns with `lang == "de"`, not deleted, `review_result` true (same filter as v7), **excluding** the 568 message_ids already in the `oasst1` pool | Apache-2.0 (OpenAssistant/oasst1) | `2023-04-12_oasst_ready.messages.jsonl.gz` sha256 `286a6e9a5a413b3272ae9c0b5a20d327983dea1c24342ae28cb244a6da65185c` (already pinned since v7) | 669 |

Builder statistics: 1,246 German prompter turns; 568 already in `oasst1`; 3 duplicates (also deduped
against every chat_v9 text); 0 deepset exact and 6 deepset near-duplicates removed (token Jaccard ≥ 0.8
or containment, either deepset label — same rule as v9 `nq_short`); kept 669, mean length 121 chars.
Output `chat_v13.jsonl` = `chat_v9.jsonl` bytes verbatim + 669 `oasst1_de` rows, sha256
`14de7a08656d90ba21320408b356178a746a9478a76234bce88cbc066b03762a` (asserted by the harness;
vendored gzip in `docs/campaigns/2026-10-30-ingest-guard-fpr-v13/inputs/`). No new external download,
no machine translation, no unlicensed data.

`oasst1_de` split hash tag `ingest-fpr-v13` (other sources keep their v7/v9 tags, so their splits are
identical to v12). It gets its own equal benign share in training (`weighted`: six benign sources
incl. FiQA) and joins the max-of-pools calibration. Its in-pool FPR is **descriptive** (like
`nq_short`); P3 still gates Dolly, OASST1, HH only.

**deepset label 0 (399) is never used for training, λ selection or calibration.** All flags go through
`GovernedDocumentMemory::insert_document`.

## 2. Unchanged from v12
Same SciFact, NFCorpus, FiQA, deepset SHAs, Core fingerprint `1a21468e…dfce8`, encoder
paraphrase-multilingual-MiniLM-L12-v2 rev `e8f8c211…5f42` and file SHAs, seeds 0..9,
α ∈ {0.05 primary, 0.01, 0.10}, λ grid {1e-5, 1e-4, 1e-3}, 400 Nesterov iterations, leakage
exclusions, degeneracy checks.

## 3. Execution: CUDA only (frozen)
- Build `--features gpu-cuda`, `CCOS_ENCODER_BACKEND=cuda`. The harness **exits with code 3 before
  reading any data** without the feature, without the variable, or if the encoder does not load on
  CUDA. No CPU fallback; a CUDA error panics. Hosted CI only compiles the CPU build.
- Run on the Jetson Thor runner under `thor_gpu_guard.py` (scirust SHA pinned in the workflow),
  exclusive GPU (`concurrency: thor-gpu-dense-encoder`).
- Precondition: `dense-encoder-cuda-thor.yml` parity probe green on the same host (`CUDA_MIN_COS =
  0.999`); output copied into the results doc. `meta.encoder.backend = "cuda"`.

## 4. Arms
- **`v13` (primary, gating):** encoder only (multilingual MiniLM-L12, mean-pool + L2, 384-d), six
  benign pools.
- `v13_cat` (sanity): [hash ; encoder], same pools.
- `v13_hash` (sanity): hash only, same pools.
- `v13_and` (descriptive): refuse iff baseline_v3 AND v13 refuse.
- `baseline_v3`: Core v3 score, FiQA calibration (unaffected by the data change; should reproduce v12).
- Reference (not re-run): v12 primary from #273.

## 5. Decision rules (α = 0.05, arm `v13`), identical to v9–v12
- **P1 deepset-0 control:** CONFIRMED iff seed-0 CP95 upper ≤ 0.10 and mean over seeds ≤ 0.10;
  REFUTED iff CP95 lower > 0.10; else INCONCLUSIVE.
- **P2 FiQA FPR:** REFUTED iff m − 1.833·se > α; CONFIRMED iff m ≤ α + 0.0025, not degenerate.
- **P3 in-pool chat FPR:** P2 rule for Dolly, OASST1, HH; all CONFIRMED. `nq_short`, `oasst1_de`
  descriptive.
- **Detection:** NON-TRIVIAL iff seed-0 TPR CP95 lower > 0.05; useful iff mean TPR ≥ 0.5.
- **Wiring gate = P1 ∧ P2 ∧ P3 ∧ NON-TRIVIAL ∧ useful (arm `v13` only).** If met, a separate PR may
  wire an opt-in, off-by-default guard. Otherwise `wired: false`. Product default stays off.
  `superiority_claim: false`. Secondary arms and other α are never promoted post hoc.

## 6. Run command and outputs
```bash
CCOS_ENCODER_BACKEND=cuda python3 thor_gpu_guard.py -- \
  cargo run --release --locked -p ccos-enterprise-docmemory --features gpu-cuda \
  --example ingest_guard_fpr_v13 -- <scifact> <nfcorpus> <fiqa> <deepset.jsonl> \
  <chat_v13.jsonl> <paraphrase-multilingual-MiniLM-L12-v2 dir> <out-model.json>
```
Via the manual workflow `.github/workflows/fpr-v13-campaign-thor.yml` (added in this PR; it only
runs the frozen harness). One uninterrupted run from the merged prereg commit →
`docs/campaigns/2026-10-30-ingest-guard-fpr-v13/{raw.jsonl,model_seed0.json}` + results doc.
Budget: encoding ≈ 2 h on the current serial CUDA path (v12: 6,999 s), training as v12; declared
failed (reported, not silently re-run) beyond 10 h. Negative results are kept.
