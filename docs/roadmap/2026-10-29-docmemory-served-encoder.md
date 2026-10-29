# 2026-10-29 — Injectable dense encoder for served `memory.document_recall`

## What changed
- New `ccos_enterprise_mcp::document_ranking` module: `DocumentRankingMode` (lexical / dense /
  fused{alpha, pool}), `DocumentRanker` (lexical default, or a shared `Encoder` + label),
  `ServedDocumentMemory` (recall + honest response annotation).
- Every response states `ranking: lexical_bm25 | dense | fused`; fused adds `ranking_alpha`,
  `ranking_pool`; dense/fused add `ranking_encoder` (operator label).
- Server env (stdio binary):
  - `CCOS_ENTERPRISE_DOCUMENT_RANKING` = `lexical` (default) | `dense` | `fused`
  - `CCOS_ENTERPRISE_DOCUMENT_ENCODER_DIR` — pinned sentence-transformers directory
    (e.g. all-MiniLM-L6-v2), loaded by the pure-Rust CPU `ccos-dense-encoder`. No GPU/CUDA.
  - `CCOS_ENTERPRISE_DOCUMENT_ENCODER_LABEL` (default: directory name)
  - `CCOS_ENTERPRISE_DOCUMENT_FUSED_ALPHA` (default 0.5, in [0,1]), `..._FUSED_POOL` (default 100)
- Fail-closed boot: dense/fused without governed provider, without encoder dir, or with a model
  that fails to load is refused; encoder/alpha/pool knobs without the matching mode are refused.
- Governance unchanged: tenant isolation and `admit_governed_recall` apply to all ranking modes.

## Tests
- Lexical default is byte-for-byte the shipped behaviour (no regression).
- Deterministic mock `ConceptEncoder` exercises dense and fused through governed admission,
  quarantine filtering and cross-tenant refusal — this is what CI runs.
- Real MiniLM: `#[ignore]` test `real_stdio_serves_fused_minilm_when_configured`, run with
  `CCOS_TEST_MINILM_DIR=/path/to/all-MiniLM-L6-v2 cargo test -- --ignored`. Not in CI (model weight).

## Non-claims
- No retrieval-quality (BEIR) metric is claimed for the server; campaign numbers stay in the
  campaign docs. No SML-GENIUS / Core product contract touched.

## Remaining
- HTTP gateway (only stdio serves the tool).
- False-alarm guard for dense recall (score floor / abstention when no lexical support).
- Incremental index rebuild (still O(assets) at boot and per generation; dense re-encodes all).
