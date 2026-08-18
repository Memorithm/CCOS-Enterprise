# CCOS Enterprise Knowledge Plane — source-span parsing

Status: **P1c parsing foundation**.

The parser's main contract is provenance, not convenience: every emitted unit
carries a `ByteSpan` into the immutable raw artifact. Normalized content is what
later extraction consumes, but `bytes:start-end` is what an assertion can cite.

```text
RawArtifact -----------------------------┐
  immutable bytes                        |
  raw SHA-256                            |
      |                                  |
      +--> normalize()                   |
      |       |                          |
      |       v                          |
      |   normalized representation      |
      |                                  |
      +--> parse framing ----------------+
              |
              v
          ParsedUnit
          normalized_text
          content_hash
          raw_span ----------> original raw bytes
```

## P1c units

- `text/plain`: logical line units;
- `text/markdown`: logical line units;
- `application/json`: one canonical document unit;
- `application/x-ndjson`: one unit for each non-blank JSON record;
- `text/csv`: RFC-4180-style **record framing** with quoted newlines kept inside
  their record. Field typing/header interpretation is deliberately later work.

For line-oriented formats, CRLF, LF and lone CR are recognized as source line
terminators. The raw span excludes the terminator and an initial UTF-8 BOM, so
it points at semantic source bytes. For CSV, line endings inside quoted fields
are content and do not terminate a record.

## Fail-closed rules

- parsing always invokes the P1b integrity/normalization gate first;
- raw and normalized record counts must agree for formats where normalization
  should preserve framing;
- unterminated CSV quotes are rejected;
- normalized text must remain UTF-8;
- no parser operation directly mutates canonical knowledge.

## Why spans precede extraction

Entity/relation extraction must never create an assertion that can only say
"the model saw this somewhere in normalized text." A future extractor should
produce evidence locators from `ParsedUnit::raw_span`, allowing audit to read
the exact original bytes that justified the assertion.

The next layer can now implement deterministic structural extraction and
chunking over `ParsedUnit` values while preserving source provenance.
