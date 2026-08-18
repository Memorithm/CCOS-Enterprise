# CCOS Enterprise Knowledge Plane — semantic interoperability

Status: **P4d deterministic RDF / JSON-LD / SHACL Core projection**.

P4d provides a standards-oriented interchange surface for ontology schemas and validated Knowledge proposals. It is deliberately a projection layer: the CCOS event journal and ontology validator remain canonical authority.

## Supported outputs

### RDF N-Triples

`RdfDocument::to_ntriples()` emits a deterministic, sorted N-Triples representation of:

- ontology entity classes;
- ontology properties, domains and ranges;
- validated entity proposals;
- tenant-scoped entity IRIs;
- typed string, boolean, numeric, JSON and null values.

The implementation uses a conservative RDF subset and does not rely on a graph-database or RDF library.

### JSON-LD 1.1 node objects

`proposal_json_ld()` emits one deterministic JSON-LD node object containing:

- `@context` with JSON-LD 1.1 version;
- `@id` bound to tenant + canonical entity ID;
- `@type` bound to the ontology entity class;
- property arrays with deterministic ordering;
- JSON literals represented with `@type: "@json"`.

The JSON-LD export is an interchange projection. It is not a second canonical serialization for replay.

### SHACL Core shapes projection

`ontology_schema_shacl()` maps the constraints that currently have direct, unambiguous SHACL Core equivalents:

- `sh:NodeShape`;
- `sh:targetClass`;
- `sh:property` / `sh:PropertyShape`;
- `sh:path`;
- `sh:datatype`;
- `sh:minCount 1` for required properties.

`allow_extra_properties = false` is intentionally **not** emitted as `sh:closed true` in P4d. Correct closed-shape RDF validation also needs an ignored-property policy for RDF metadata such as `rdf:type`; pretending otherwise would make the projection stricter than the CCOS schema contract.

## Validation boundary

Proposal export always calls the native `Ontology::validate_proposal()` first. A foreign-tenant, mistyped or otherwise invalid proposal is refused before RDF or JSON-LD is created.

Semantic formats therefore do not become an alternate admission path into canonical Knowledge.

## Determinism

- RDF triples are held in ordered sets and serialized in stable order;
- SHACL property-shape blank-node identifiers are derived deterministically from entity type + property;
- JSON-LD object keys and repeated property values are emitted in deterministic canonical order;
- tenant and entity identifiers are percent-encoded into stable IRIs.

## Datatype notes

Strings map to XML Schema `string`; booleans to `boolean`; numeric proposal values currently map to XML Schema `double` in RDF. JSON and null use CCOS namespace-specific RDF datatypes because P4d does not claim a generic RDF datatype contract for arbitrary JSON/null values. JSON-LD JSON values use the JSON-LD 1.1 `@json` type marker.

## Explicit non-goals

P4d is **not** a full semantic-web engine. It does not yet provide:

- arbitrary RDF/Turtle/JSON-LD import;
- an external SHACL validation engine;
- complete SHACL Core/SHACL-SPARQL coverage;
- OWL semantics or OWL reasoning;
- SKOS concept-scheme management;
- SPARQL query execution;
- RDF canonicalization as the CCOS event-log format.

Those capabilities require separate contracts so standards compliance, determinism and authority boundaries can be tested independently.
