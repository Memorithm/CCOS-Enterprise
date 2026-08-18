# CCOS Enterprise Knowledge Plane — ontology migrations

Status: **P4c deterministic lossless migration contract**.

P4c migrates unresolved/resolved Knowledge proposals between two exact ontology snapshots. It deliberately does not rewrite canonical journal history. A migrated proposal must pass the target ontology and may then enter the normal P4b promotion gate.

## Supported transformations

The first contract is intentionally restricted to bijective renames:

- entity type rename;
- property rename.

No value is discarded or coerced. Property deletion, optional-to-required default injection and datatype changes are excluded because they cannot generally be reversed without additional evidence or an explicit value-conversion contract.

## Endpoint binding

Every `OntologyMigration` records:

- tenant;
- source version and fingerprint;
- target version and fingerprint;
- ordered migration steps;
- deterministic migration hash.

`apply` refuses a different source/target ontology even if version labels happen to match. Source proposals are validated before transformation and target proposals are validated afterwards.

## Collision policy

Renaming a property fails closed if the destination property already exists on the same proposal. P4c never chooses which value to keep and never silently deduplicates two differently named source fields.

## Reversibility

`inverse()` reverses step order and inverts every rename. Conformance requires:

```text
proposal_v1
  -> migrate(v1, v2)
  -> proposal_v2
  -> inverse(v2, v1)
  -> proposal_v1 bit-for-bit at the Rust value level
```

This property is the reason the first migration vocabulary is deliberately narrow.

## Audit receipt

A successful migration returns a `MigrationReceipt` binding:

- migration ID and hash;
- tenant;
- source/target versions and fingerprints;
- deterministic before/after proposal hashes.

The receipt is metadata for later provenance/audit integration. It is not itself canonical authority.

## Registry

`MigrationRegistry` is tenant-scoped and keyed by exact `(source fingerprint, target fingerprint)`. A second migration for the same route is rejected rather than silently replacing the first definition.

## Out of scope

P4c does not mutate `KnowledgeState`, change assertion authority, perform fuzzy schema mapping, coerce datatypes, delete information, inject defaults, or automatically chain migrations. Those capabilities require separate explicit contracts and tests.
