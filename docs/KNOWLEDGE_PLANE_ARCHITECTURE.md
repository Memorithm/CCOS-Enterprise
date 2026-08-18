# CCOS Enterprise Knowledge Plane — P0 architecture

Status: **P0 foundation**. This document describes the invariants implemented by
`ccos-enterprise-knowledge-model`, `ccos-enterprise-knowledge`, and
`ccos-enterprise-knowledge-store`. It does not claim that ingestion, ontology,
reasoning, external graph stores, REST, or MCP knowledge tools exist yet.

## Product boundary

The Knowledge Plane is an Enterprise capability. It is not part of `ccos-core`
and it does not weaken Core's deterministic/replay boundary. P0 is not exposed
through the Enterprise gateway yet; adding an MCP/API surface is a later,
explicit allowlist change.

```text
external sources
      |
      v
KnowledgeOp journal  <---- canonical authority
      |
      v
KnowledgeState
      |
      +---- future graph/RDF/vector projections (rebuildable)
      |
      +---- future context candidates
                     |
                     v
                 CCOS Core
             causal/token paging
                     |
                     v
                   agent
```

## P0 invariants

1. **Tenant scope is structural.** Every source, evidence item, entity, fact,
   relation, conflict and operation carries the canonical Enterprise `TenantId`.
   Lookups never fall back to another tenant. A reference that exists only in a
   different tenant is reported exactly like an absent reference so its
   existence is not leaked.
2. **The journal is the mutation boundary.** `KnowledgeState::apply` accepts a
   dense monotonically increasing sequence. Gaps and repeats are refused before
   state changes. `KnowledgeStore` validates a whole batch before writing any
   bytes, appends JSONL, flushes and `sync_data`s before the in-memory state is
   advanced.
3. **Replay is deterministic.** Canonical collections are `BTreeMap`/`BTreeSet`
   backed and the state exposes a SHA-256 canonical hash. The same journal must
   produce the same hash. Store restart rebuilds state from the journal only.
4. **Bi-temporal facts are explicit.** Valid time is a half-open world-time
   interval. Transaction time is the journal sequence at which a fact was
   asserted or invalidated; replay ordering never depends on wall-clock time.
5. **Contradictions are preserved.** Competing current facts for the same
   `(subject, predicate)` over overlapping valid time are kept and grouped in a
   deterministic `ConflictRecord`. Nothing silently overwrites another fact.
6. **Provenance is mandatory for assertions.** Entities, facts and relations
   require evidence; evidence must resolve to a registered source inside the
   same tenant. `fact_provenance` traces a fact back to evidence and sources.
7. **Authority is typed.** `AssertionKind` distinguishes authoritative data,
   observations, deterministic inferences and LLM outputs. P0 does not promote
   one class into another automatically.
8. **External stores will be projections.** A future Neo4j/RDF/vector backend
   may accelerate queries, but it must be reconstructible from the canonical
   journal/state and must never become the source of truth.
9. **Corruption fails closed.** A malformed complete journal line is refused.
   The only recoverable framing damage is an unterminated final fragment left by
   a crash; it is ignored and its byte count is reported. The store is
   single-writer through an OS lock, so two cached sequence counters cannot race.

## P0 event vocabulary

- `RegisterSource`
- `AddEvidence`
- `AddEntity`
- `AssertFact`
- `InvalidateFact`
- `AssertRelation`
- `InvalidateRelation`
- `ResolveConflict`

Later phases may add ingestion checkpoints, entity merges, ontology/rule
changes, inferences and decision records. Those additions must remain explicit
journal operations rather than hidden mutations.

## Transaction and valid time

A fact may remain queryable historically after invalidation. For a fact asserted
at journal sequence 3 and invalidated at sequence 8:

```text
transaction sequence 0..2 : absent
transaction sequence 3..7 : current
transaction sequence 8..  : historical, not current
```

The separate `ValidityInterval` answers when the fact was true in the source
world. `facts_at(tenant, valid_time, transaction_sequence)` requires both axes
to match.

## Conflict semantics

P0 detects conflicts only for competing **fact objects** with the same subject
and predicate whose valid-time intervals overlap. The conflict ID is derived
from tenant + subject + predicate, so replay does not invent new IDs.

Resolution is explicit and journaled. Adding a new competing assertion to a
previously resolved conflict re-opens that conflict because the earlier
resolution did not evaluate the new evidence.

## Durable journal semantics

`knowledge.jsonl` is authoritative. `KnowledgeStore::open` takes an OS-backed
single-writer lock and replays every complete line before accepting writes.
`append` first applies the entire proposed batch to a cloned state; therefore a
bad second operation cannot leave a valid first operation buffered on disk.
Only after validation does the batch become JSONL, get flushed and `sync_data`d,
and replace the live in-memory state.

An unterminated final fragment is treated as a crash tail and reported through
`Loaded::torn_tail`. Any malformed newline-terminated record is corruption and
startup fails closed.

## Security posture

P0 deliberately has no connector/network code and no gateway exposure. It also
returns `UnknownEvidence`/`UnknownEntity` inside the caller's tenant partition
instead of searching other partitions, preventing existence disclosure across
tenants.

The next implementation gate is a dedicated Knowledge conformance suite that
rebuilds canonical state from disk and exercises tenant/provenance/conflict
invariants before any enterprise connector or graph database is introduced.
