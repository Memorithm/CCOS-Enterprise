# CCOS Enterprise Knowledge Plane — ontology schema foundation

Status: **P4a deterministic validation layer**.

P4a does not yet implement RDF, OWL, SHACL or SKOS. It establishes the contract those standards must map onto: tenant-scoped versioned schemas, deterministic fingerprints, typed properties, required properties and fail-closed validation of resolved observation proposals.

```text
RecordCandidate
      |
      v
EntityProposal
      |
      v
Ontology::validate_proposal
      |
      +-- violations --> no promotion
      |
      +-- valid ------> still Observation; later governed fact promotion
```

## Schema model

An `Ontology` owns one tenant and a non-empty version. It contains ordered `EntitySchema` definitions. Each entity schema defines:

- entity type;
- named properties;
- `ValueType` (`null`, `bool`, `number`, `string`, `json`);
- whether each property is required;
- whether undeclared properties are allowed.

Duplicate entity types and duplicate property declarations fail at schema construction.

## Validation

P4a reports all deterministic violations it can establish in one pass:

- tenant mismatch;
- unknown entity type;
- missing entity evidence;
- conflicting labels;
- missing required property;
- undeclared property when extras are disabled;
- property type mismatch;
- fact proposal referring to a candidate/evidence item not owned by the entity proposal.

Violations are ordered, so identical input produces an identical report. Cross-tenant input stops before entity-schema lookup, avoiding information leakage about another tenant's ontology.

## Fingerprint

`Ontology::fingerprint()` hashes contract version, tenant, ontology version, ordered entity types and ordered property declarations using length-prefixed components. Construction/insertion order therefore cannot change the fingerprint.

## Authority boundary

A valid report does **not** make a proposal authoritative and does not write to the Knowledge journal. P4a only proves conformance to a declared schema. A later policy-governed promotion operation must remain explicit and event-sourced.

Next P4 slices: datatype-rich canonical facts, ontology migration/version events, then RDF/JSON-LD and SHACL interoperability mapped onto this internal contract.
