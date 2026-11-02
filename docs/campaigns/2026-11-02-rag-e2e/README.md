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

## Ranking adapter (each arm -> common ranking JSONL)
`scripts/rag-e2e-rank-adapter.py --format trec|beir --run <arm output> --queries Q --corpus C --protocol-sha256 P --k 10`
reads the same TREC run / BEIR `{qid:{docid:score}}` shapes used by the BEIR v3/v5 runs and writes
`{"query_id","protocol_sha256","ranking"}` rows (score desc, doc_id asc ties; missing queries -> empty
ranking; unknown query/doc ids or non-finite scores fail closed) for `rag-e2e-generate.py --retrieval`.

## SQuAD 2.0 inventory (checkable; contamination audit PENDING)
`scripts/rag-e2e-squad-inventory.py --train train-v2.0.json --dev dev-v2.0.json --out inventory.jsonl --provenance-out prov.json`
(document = paragraph, family = article; dev articles -> test, train articles -> dev iff
`sha256(title) % 10 == 0`, else train). Local run on the pinned files (dev sha256 matches prereg Pins;
train `sha256:68dcfbb9…de002`) passes `check-rag-dataset-inventory.py`: documents train 16,935 / dev 2,094 /
test 1,204; families 388 / 54 / 35; 6 exact-duplicate train paragraphs dropped (counted);
`inventory_sha256 = sha256:9a5c8e0e74c5a814755acff4e20545752a9346b7857797ea75a0e2cb8286dbd9`.
The 4.9 MB inventory is regenerable and not committed; `squad-provenance.stub.json` records the output.
`training_overlap_audit_sha256` stays **PENDING** — no contamination audit was performed.

## Triggering the Thor pins workflow (manual, not run by this PR)
`gh workflow run rag-e2e-pins-thor.yml -R Memorithm/CCOS-Enterprise -f cache_dir=/opt/ccos/models/hf`
(runner labels `self-hosted, Linux, ARM64, jetson-thor, internal`; downloads ~15 GB of weights; runs no arm).

## Remaining blockers before readiness can pass (true, not code-solvable tonight)
1. Dataset: SQuAD inventory now passes the checker (above); still missing the training-overlap audit and
   the corpus/queries/qrels JSONL export in campaign schema.
2. Run the five arms on a declared host: runner code SHA, command, wall/RSS/restart/cost, results path+sha256.
3. Blind adjudication (`scripts/rag-e2e-adjudicate.py`) → judgments path+sha256.
4. `weights_sha256` from the Thor workflow (not checked by the readiness gate itself — reviewers must check it).

## SQuAD export and overlap audit
- `scripts/rag-e2e-squad-export.py --train train-v2.0.json --dev dev-v2.0.json --out-dir OUT` writes `corpus.jsonl` (20233 docs, all splits), `queries.jsonl` (11873 test questions, 5928 answerable), `qrels.jsonl`; hashes in `squad-export-stats.json` (JSONL not committed).
- `scripts/rag-e2e-overlap-audit.py` fails closed: without training 13-gram indexes for both generator and judge it writes `overlap-audit.pending.json` (status PENDING) and exits 2. Training corpora of the pinned models are unpublished, so `training_overlap_audit_sha256` stays PENDING and readiness stays closed.

## Thor generator pins (recorded 2026-11-02)
Source: Thor run https://github.com/Memorithm/CCOS-Enterprise/actions/runs/41535764724 (pin step output),
`Qwen/Qwen2.5-7B-Instruct` @ `a09a35458c702b33eeacc393d103063234e8bc28`, prompt `generator-prompt.v1.txt`.
- `weights_sha256 = sha256:016771b384d7f005d173cf0067d3e4b8802f5e249beb5670dfed0b0c9936c6d6`
- `tokenizer_sha256 = sha256:c0382117ea329cdf097041132f6d735924b697924d6f6fc3945713e96ce87539` (matches existing pin)
- `prompt_sha256 = sha256:9203b6c60ecb8f168a84613be557e7aa79ef7338ee068e0fc0e44cd7996c2746` (matches existing pin)

The run's job conclusion was `failure` solely because the readiness step's expected FAIL (gate is
fail-closed while arms/hardware/audit are PENDING) tripped `bash -e` before artifact upload; fixed by #290.
Readiness remains **FAIL/closed**; no arm results or hardware measurements exist yet;
`training_overlap_audit_sha256` stays **PENDING**.

## Retrieval arms -> rankings (tooling only, no run yet)
Prior BEIR v3/v5 outputs are BEIR-corpus metrics (no per-query runs, different corpora), so **no
existing ranking is reusable** for SQuAD. New: `crates/ccos-dense-encoder/examples/rag_e2e_arm_runs.rs`
ranks **all** export queries (incl. unanswerable) at depth 100 and writes `lexical|dense|hybrid|ccos.trec`
(same frozen configs as BEIR v3/v5: BM25 1.2/0.75, MiniLM exact, RRF k=60, `DocumentMemory` fused α=0.5).
`.github/workflows/rag-e2e-arms-thor.yml` (manual) verifies the pinned SQuAD SHA-256, exports, ranks on
the Thor CUDA encoder, adapts with `rag-e2e-rank-adapter.py --k 10` and uploads TREC + ranking JSONL +
`SHA256SUMS.txt` (code SHA, protocol sha256). It scores nothing and fills no manifest field.

`gh workflow run rag-e2e-arms-thor.yml -R Memorithm/CCOS-Enterprise -f minilm_dir=/opt/ccos/models/all-MiniLM-L6-v2`

Still blocked: `reranked` (primary baseline) needs a cross-encoder runner for
`cross-encoder/ms-marco-MiniLM-L6-v2` @ `233902d2` (none in repo); generation needs a pinned Qwen backend
module for `rag-e2e-generate.py --backend` (none in repo); MiniLM dir must exist on Thor;
overlap audit PENDING; readiness stays closed.
