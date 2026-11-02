# RAG E2E campaign inputs (2026-11-02) — skeleton, no results

Prereg: `../2026-11-02-rag-e2e-prereg.md`. `superiority_claim: false`. Nothing here is a measurement.

- `generator-prompt.v1.txt` — byte-exact freeze of `PROMPT` in `scripts/rag-e2e-generate.py`;
  `prompt_sha256 = sha256:9203b6c60ecb8f168a84613be557e7aa79ef7338ee068e0fc0e44cd7996c2746`
  (asserted by `scripts/test-rag-e2e-pins.py`).
- `manifest.skeleton.json` — real (non-smoke) scope, five families, Hub revision + tokenizer pins.
  Every `PENDING` / `0` / `-1` / empty field is unfilled on purpose; the readiness gate fails closed (39 errors today).
- `scripts/rag-e2e-pin-generator.py` + `.github/workflows/rag-e2e-pins-thor.yml` — download the pinned
  revision on Thor, compute `weights_sha256` (sha256 over sorted `"<shard sha256>  <name>"` lines), verify
  tokenizer/prompt against prereg, run readiness, upload the artifact. No arm runs.

## Remaining blockers before readiness can pass (true, not code-solvable tonight)
1. Dataset: choose corpus/queries/qrels, provenance (origin, license, split author) and a training-overlap audit;
   inventory must pass `scripts/check-rag-dataset-inventory.py`.
2. Run the five arms on a declared host: runner code SHA, command, wall/RSS/restart/cost, results path+sha256.
3. Blind adjudication (`scripts/rag-e2e-adjudicate.py`) → judgments path+sha256.
4. `weights_sha256` from the Thor workflow (not checked by the readiness gate itself — reviewers must check it).
