# CCOS Enterprise Knowledge Plane — ingestion contract

Status: **P1a local-source foundation**. This document describes the shipped
`ccos-enterprise-ingest` boundary. It does not claim that parsing, entity
extraction, database/cloud connectors, streaming ingestion, or automatic entity
resolution exist yet.

## Authority boundary

Ingestion is not a second write path into the Knowledge Plane.

```text
filesystem bytes
      |
      v
LocalTreeSource
      |
      v
RawArtifact
  source id + virtual URI + SHA-256 + tenant
      |
      +--> SourceRecord
      +--> EvidenceRecord
                  |
                  v
          KnowledgeOp journal
                  |
                  v
          canonical KnowledgeState
```

`RawArtifact` never becomes a `Fact`, `Entity` or `Relation` automatically.
Those semantic assertions still require an explicit journal operation and must
cite evidence. This preserves P0's rule that observations and later LLM output
cannot silently become authoritative facts.

## Stable identity

Absolute host paths are intentionally excluded from canonical identity. A local
source is configured with a namespace such as `company-data`; a file
`reports/2026.json` is exposed as:

```text
fs://company-data/reports/2026.json
```

Its `SourceId` is derived from the namespace plus root-relative path. Mounting
the same dataset under a different host directory therefore does not change
source identity. The bytes themselves are independently SHA-256 hashed, so a
content change is observable without changing the logical source ID.

Whole-artifact evidence IDs bind tenant + source ID + content hash. Two versions
of one logical source therefore produce different evidence IDs.

## P1a accepted file types

The local source currently enumerates only:

- `.txt` → `text/plain`
- `.md`, `.markdown` → `text/markdown`
- `.json` → `application/json`
- `.jsonl`, `.ndjson` → `application/x-ndjson`
- `.csv` → `text/csv`

P1a preserves the original bytes. Parsing and normalization are deliberately a
separate stage so evidence always remains anchored to immutable source bytes.

## Security and resource bounds

The local source is read-only and has no network dependency. It:

- rejects a symlink as the configured root;
- never follows symlink entries during enumeration;
- canonicalizes a file again during fetch and refuses paths outside the root;
- accepts only UTF-8 relative paths for canonical locators;
- enforces maximum file count, per-artifact bytes and total enumerated bytes;
- re-enforces the per-artifact byte limit while reading, so a file that grows
  after enumeration cannot bypass the bound;
- percent-encodes virtual locators rather than inserting raw path characters.

There remains an ordinary filesystem TOCTOU window between metadata checks and
`open`; later hardening can add platform-specific descriptor-relative open APIs
without changing the canonical ingestion contract.

## Next P1 slices

After this contract is green, the next isolated changes should add deterministic
normalization/parsing for text/JSON/JSONL/CSV, then repository ingestion and
incremental checkpoints. Network/database/cloud connectors remain later work and
must pass through Enterprise policy before they are exposed.
