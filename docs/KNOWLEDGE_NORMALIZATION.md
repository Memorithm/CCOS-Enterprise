# CCOS Enterprise Knowledge Plane — deterministic normalization

Status: **P1b normalization foundation**.

Normalization consumes `RawArtifact` values from `ccos-enterprise-ingest`. It is
strictly a derived representation: it does not register a new source, replace
raw evidence, assert knowledge, or change authority class.

```text
immutable RawArtifact
  raw SHA-256 ------------------------------┐
      |                                     |
      v                                     |
normalize()                                 |
      |                                     |
      v                                     |
NormalizedArtifact                         |
  input_content_hash  <---------------------┘
  output_content_hash
  algorithm + contract version
```

## Integrity gate

Before transforming anything, the normalizer recomputes SHA-256 over the raw
bytes and compares it with the hash declared by `RawArtifact`. A mismatch fails
closed. This means callers cannot construct a `RawArtifact`, mutate its bytes,
and retain an earlier trusted hash through normalization.

## P1b algorithms

### `text-v1`

Used for plain text, Markdown and CSV at this stage:

- validates UTF-8;
- removes one UTF-8 BOM at byte zero;
- maps CRLF and lone CR to LF;
- otherwise preserves characters and trailing-newline semantics.

CSV is **not parsed yet**. P1b only gives its textual bytes a stable line-ending
representation.

### `json-canonical-v1`

- applies `text-v1` input handling;
- parses one JSON value;
- emits no insignificant whitespace;
- sorts object keys lexicographically at every nesting level;
- preserves array order and JSON values.

The emitter sorts keys explicitly instead of relying on the backing map chosen
by `serde_json`, so enabling a future map-order feature cannot silently alter
CCOS canonicalization.

### `ndjson-canonical-v1`

- applies `text-v1` line-ending handling;
- parses each non-blank line independently;
- canonicalizes each JSON value with the same key-sorting emitter;
- preserves record order, blank-line positions and whether the source had a
  trailing line break.

## Provenance rule

`NormalizationManifest::input_content_hash` remains the hash carried by the
source/evidence record. `output_content_hash` identifies only the derived
normalized representation. Later parsers and extractors may consume the latter,
but semantic assertions must still trace back through the manifest to immutable
raw evidence.

The next P1 slice is deterministic structured parsing with source-span locators;
that span mapping is required before extraction so normalized text never severs
traceability to the original bytes.
