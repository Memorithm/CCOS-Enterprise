# Strict BEIR input contract

This repair implements the parser portion of Memorithm/CCOS-Enterprise#149 in
CCOS-Core first. It carries forward Enterprise PR #134's strict qrels behavior
and additionally validates corpus and queries before constructing any index.

## Accepted population

`corpus.jsonl` and `queries.jsonl` contain one JSON object per line. `_id` and
`text` are required strings. The corpus `title` is optional: absence means an
empty title; an explicitly null or non-string title is invalid. Additional
metadata is permitted and is not indexed. Duplicate authoritative fields inside
one JSON object are rejected by typed deserialization.

IDs are unique within each file, non-empty and free of surrounding whitespace
and control characters. They remain opaque and case-sensitive: URLs, Unicode,
slashes and punctuation are not coerced into a filename alphabet. Documents
retain input order and the existing `title + " " + text` representation. A
present empty body is accepted for a non-blank title. An entirely blank document
or query is rejected. Blank lines, malformed JSON and empty files are rejected,
not silently skipped. CRLF and a final complete line without a newline work.

`qrels/test.tsv` requires the exact header `query-id\tcorpus-id\tscore` and three
fields per data row. Every query/document reference must exist, even when its
score is non-positive. Scores must parse as finite f64 numbers; duplicate
judgments of any sign are errors. Positive gains are retained unchanged;
non-positive judgments are counted explicitly. At least one positively judged
query is required. Only positively judged queries are evaluated, as in the
previous Enterprise harness; this repair does not redefine the evaluation set
or the metric formulas for already-valid inputs.

Failures report a path and, for row errors, a one-based source line. File-open
errors retain the I/O diagnostic. The importer returns no partial dataset. The
caller finishes all imports before constructing BM25, TF-IDF or LSA. This is
prevalidation, not a bound on total dataset RAM or a claim about index quality.

## Validation

```bash
cargo test -p ccos-core --example beir_eval --locked
cargo run -p ccos-core --example beir_eval -- data/beir/scifact --validate-only
cargo test -p ccos-core --features llm --lib eval::tests --locked
```

Validation-only prints import counts and exits without index construction or
quality measurements. Successful imports report zero rejected rows; invalid
inputs abort at the first error instead of publishing a partial population.
The dedicated CI checks real binary exit codes and absence of ranking output
on invalid fixtures, as well as parser tests and explicitly enabled LLM tests.

BM25 k1/b, dimensions, LSA rank, retrieval depth, RRF and metric implementations
are unchanged. No new dataset score, neural encoder comparison, real-model
answer-quality result or tokenizer-accuracy claim is made.

## Sources and lineage

- BEIR maintainers, custom dataset format (Nandan Thakur, 29 June 2022), consulted
  15 September 2026: https://github.com/beir-cellar/beir/wiki/Load-your-custom-dataset
- Strict qrels predecessor: Memorithm/CCOS-Enterprise#134, incorporated in
  Enterprise `519519c8d2a26b83bba5231227d9ba549322a14a`.
- Follow-up scope: https://github.com/Memorithm/CCOS-Enterprise/issues/149

Enterprise synchronization must name the exact reviewed upstream commit and
copy only the benchmark/import contract slice. Its licensing-only marker is
not evidence of a full functional Core synchronization.
