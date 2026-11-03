# Retrieval rankings pins (recorded 2026-11-03) — inputs only, no results

Source: Thor run https://github.com/Memorithm/CCOS-Enterprise/actions/runs/41547494628 (`rag-e2e-arms-thor.yml`,
SUCCESS), artifact `rag-e2e-arm-rankings` (id 13189583633), `code_sha=5f7a5cc43720bcbe3b60b790f7535764d5782843`,
`protocol_sha256=sha256:366f96d4218efab5eabb6d8f7ae85587d3cfd36c04b2324a1a9de45a80fd419d`.
Log: `docs=20233 queries=11873 arms=["lexical","dense","hybrid","ccos"] (reranked: not emitted)`, wall 832.7 s.
`export-stats.json` is identical (canonical JSON) to the committed `squad-export-stats.json`.

| file | sha256 |
|---|---|
| ccos.ranking.jsonl | 09df27e9ad125448d5bb6be176c889cb7478b238f12e052505eaf8cbbfc5a27e |
| ccos.trec | 21b88aa70759fdb6da03768000a7602d96b911d51da25988f6119e5eb714c184 |
| dense.ranking.jsonl | 6fc28838d7a78f939109307efa38f55d8a1ec2f6e29e2b4c8eddf717dd338f4f |
| dense.trec | 8b269151afbb13bdaffaa48a87182a53d1799c00bb543f0536fd0594c3e8463a |
| hybrid.ranking.jsonl | c691dd5fad2a2020b0313a6ae6e19b3a9103a46c45535eca2a207562e944e260 |
| hybrid.trec | 9aad3a489f30c66603e19af427252cf19eeafad096c2b3c015f7990c7f866bff |
| lexical.ranking.jsonl | a7e8eff8caf2df0ffe550e7ff200bcb3b46667b520a1cd4276fe1d44bdc1b859 |
| lexical.trec | f99f9fd76f4715ff5f1d27e9d71c3b00f194c93cdc6c6a17066db5e876f43bff |
| export-stats.json | 52f65d698c324f1fa1871e2f4ae8836c557241e277f1e3dde433ea4499ec3b35 |
| runs-log.txt | 5d9d307e1171e1074f5acc661665f3e071475d3392bac43466cd654febd6bbeb |

`rankings-pins.sha256` (machine-checkable, ranking JSONL only) is verified by `rag-e2e-generate-thor.yml`.
These are retrieval inputs. No retrieval metric, generation result or judgment is recorded here; arm
result hashes in the manifest stay unfilled, readiness stays **FAIL/closed**, contamination audit **PENDING**.

## Arm mapping vs prereg (honest)
- `ccos` **is** the CCOS `DocumentMemory` arm: `DocumentMemory` with `RankMode::Fused { alpha: 0.5 (frozen v3), pool }`
  over the MiniLM encoder (`crates/ccos-dense-encoder/examples/rag_e2e_arm_runs.rs`). No separate
  DocumentMemory arm is missing; `dense` is also `DocumentMemory` but in `RankMode::Dense`.
- `lexical` = BM25 (k1 1.2, b 0.75); `hybrid` = RRF k=60 of lexical+dense.
- `reranked` (primary baseline, `cross-encoder/ms-marco-MiniLM-L6-v2` @ `233902d2`) is **not produced**: no runner.
