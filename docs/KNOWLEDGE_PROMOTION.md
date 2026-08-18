# CCOS Enterprise Knowledge Plane — canonical promotion

Status: **P4b schema-gated typed Observation promotion**.

P4b promotes a resolved proposal into the canonical event-sourced Knowledge Plane. It does **not** promote authority: generated entities and facts remain `AssertionKind::Observation`.

```text
EntityProposal
      |
      v
Ontology::validate_proposal
      |
      +-- violations --> no plan / no KnowledgeOp
      |
      v
PromotionPlan
      |
      +-- typed canonical literals
      +-- deterministic fact IDs
      +-- ontology version + fingerprint binding
      +-- deterministic plan hash
      |
      v
Vec<KnowledgeOp>
      |
      v
KnowledgeState::apply / durable journal
```

## Authority boundary

`ccos-enterprise-promotion` has no alternate state writer. `PromotionPlan::operations()` only returns ordinary canonical `KnowledgeOp` values. The existing journal remains the sole mutation path and performs the same tenant, evidence, entity, temporal and contradiction checks as any other write.

A valid ontology report therefore means only **schema-conformant Observation**. It is not permission to create an `Authoritative` fact. Authority elevation remains a later governed operation.

## Typed literals

P4b extends the canonical model without removing the legacy `FactObject::Literal(String)` variant. New schema-gated facts use:

- `Null`;
- `Bool(bool)`;
- `Number(CanonicalNumber)`;
- `String(String)`;
- `Json(CanonicalJson)`.

`CanonicalNumber` is normalized through JSON-number semantics. `CanonicalJson` recursively sorts object keys and emits a whitespace-free representation. Both values can be revalidated when a journal entry is replayed, preventing alternate lexical spellings from changing canonical hashes.

## Deduplication and contradictions

For one proposal, identical `(predicate, typed value)` assertions from multiple candidates become one fact with the union of their evidence IDs. Distinct typed values remain distinct facts. If their valid-time intervals overlap, the existing P0 contradiction machinery creates/reopens a conflict set; P4b never chooses a winner.

## Deterministic identity

Each generated fact ID binds:

- tenant;
- entity ID;
- predicate;
- typed value and type tag;
- valid-time interval;
- sorted evidence IDs;
- ontology fingerprint.

The promotion-plan hash additionally binds the promotion contract version and ordered fact IDs. Reordering input `FactProposal` values does not change the plan.

## Out of scope

P4b does not implement ontology migrations, RDF/JSON-LD, OWL, SHACL, SKOS, inference, authority elevation, MCP/REST exposure or direct store mutations. Ontology version migration is the next isolated slice so it can be reviewed and tested independently.
