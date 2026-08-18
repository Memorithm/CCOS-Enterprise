# CCOS Enterprise Knowledge Plane — entity resolution proposals

Status: **P2b exact-key resolution foundation**.

P2b introduces deterministic entity identity without pretending that exact-key
matching is the final entity-resolution system. It is deliberately a proposal
layer between structural extraction and canonical mutation.

```text
RecordCandidate(s)
      |
      v
ResolutionSchema
  entity type
  exact identity fields
  explicit normalization policy
      |
      v
EntityProposal
  deterministic EntityId
  contributing CandidateIds
  union of EvidenceIds
  label candidates
  typed FactProposals
      |
      X no automatic canonical merge
      |
      +--> entity_observation() only if labels do not conflict
```

## Identity contract

An entity ID hashes:

- tenant;
- entity type;
- sorted identity-field names;
- type-tagged normalized identity values.

Source ID is deliberately excluded. Two independent sources with the same
explicit business key can therefore resolve to one proposal. Tenant is included,
so the same business key in another tenant resolves to a different identity.

Identity-field order in configuration cannot change the ID because fields are
stored in a `BTreeSet`. Hash components are length-prefixed instead of separated
by an escapable delimiter.

## Explicit normalization

The schema chooses one policy:

- `Exact`;
- `Trim`;
- `TrimAsciiCaseFold`.

There is no hidden fuzzy matching. Null and nested JSON values are refused as
identity keys in P2b. Boolean and numeric scalar keys are type-tagged.

## No silent merge decisions

Combining candidates does not write to the Knowledge journal. The proposal
retains every contributing candidate/evidence ID and every typed fact proposal.
Input order is normalized, so swapping source order produces the same resolution
batch.

A configured label field is collected from all candidates. If two sources give
different labels, `entity_observation()` returns `LabelConflict` instead of
choosing one. When materialization is possible, the entity is always
`AssertionKind::Observation`.

## Facts are proposals, not facts yet

P2b intentionally keeps `ExtractedValue` typing in `FactProposal` rather than
flattening booleans/numbers/null/nested JSON into `FactObject::Literal(String)`.
The ontology/schema phase must decide the canonical datatype mapping first.
This avoids creating an irreversible weak literal model just to complete entity
resolution quickly.

Next: blocking/candidate matching and reversible merge decisions, followed by
ontology-aware promotion of typed fact proposals into journaled facts.
