# CCOS Enterprise Knowledge Plane — deterministic structural extraction

Status: **P2a structural extraction foundation**.

P2a deliberately does less than a generic NER/LLM extraction stack: it extracts
only structure the source format already states. That makes the first extraction
path deterministic and prevents model guesses from entering the canonical graph
before the authority and entity-resolution contracts exist.

## Boundary

```text
RawArtifact
    |
    v
parse() ---- raw ByteSpan
    |
    v
structural extract
    |
    v
RecordCandidate
  AssertionKind::Observation
  deterministic CandidateId
  structured attributes
  fine-grained EvidenceRecord
    |
    X  no automatic canonical promotion
    |
    +--> later entity-resolution / policy gate
```

Every P2a candidate is hard-coded as `AssertionKind::Observation`. The crate has
no dependency on the canonical journal/store and therefore cannot mutate
`KnowledgeState` by itself.

## Current deterministic extraction

### JSON

A top-level object becomes one record candidate. A top-level array is accepted
only when every member is an object; each object becomes one distinct candidate.
Scalar attributes retain their JSON types. Nested arrays/objects are preserved
as recursively key-sorted canonical JSON strings.

### NDJSON

Each parsed JSON-object record becomes one candidate. Each candidate receives a
separate evidence ID derived from tenant, source ID, raw content hash and the
record's raw byte-span locator.

### CSV

The first record is interpreted as a header. P2a:

- parses quoted fields and doubled quote escapes;
- preserves normalized newlines inside quoted fields;
- rejects quotes in unquoted fields and characters after a closing quote;
- rejects empty or duplicate headers;
- requires every data record to match header width.

Headers are trimmed before becoming attribute keys. Field values otherwise stay
strings. Schema typing belongs to the later ontology/schema layer.

### Plain text / Markdown

No record candidates are invented. Deterministic structural extraction has no
basis for claiming that a sentence names an entity or relation. A later explicit
NER/model path may create model-labelled observations with model/prompt
provenance, but never authoritative facts by default.

## Identity and evidence

`CandidateId` binds tenant + source + raw content hash + parsed unit + record
index + unit content hash. A changed source version therefore produces new
observation candidate identities.

Fine-grained `EvidenceRecord` IDs bind tenant + source + raw hash +
`bytes:start-end`. Extraction consumers can register that evidence through the
P0 journal, then deliberately create an Observation. The conformance suite
exercises exactly that route; extraction itself never calls the store.

Next: entity-resolution candidates and reversible merge proposals. Canonical
entity merges must remain separate journaled decisions, never side effects of
this extraction crate.
