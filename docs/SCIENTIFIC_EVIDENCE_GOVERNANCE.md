# Scientific evidence governance boundary

Status: normative integration contract for importing scientific/research observations into CCOS Enterprise. This document does not grant any new execution authority.

Audited CCOS head: `b078339c6fa4420e80402f9166f791ce7db97876` (`main`).

Upstream research inputs considered by this contract include SciRust benchmark/evidence records and FLAT-ATTENTION research artifacts. Their scientific classification, reproducibility metadata, benchmark values, semantic identities, or negative-result status are observations. They are never CCOS authorization decisions by themselves.

## Core invariant

The admissible control flow is:

```text
external scientific/research artifact
-> provenance-preserving CCOS evidence observation
-> tenant/space/loadout governance
-> explicit trust / retention / promotion policy
-> explicit CCOS decision / approval policy
-> authorized action, if any
```

The following shortcut is prohibited:

```text
scientific label, benchmark value, similarity score, or model output
-> direct authorization / policy bypass / causal authority
```

This boundary applies equally to positive, negative, inconclusive, exact, approximate, empirical, phenomenological and speculative evidence.

## Existing CCOS ownership remains authoritative

At the audited head:

- `ccos-enterprise-memory` owns memory spaces, tenant-scoped loadouts, evidence lineage, retention/trust metadata and governed memory provider contracts.
- `MemoryStratum::Evidence` is the appropriate first landing stratum for imported research observations. Higher strata (`Episode`, `Context`, `Pattern`) require governed derivation rather than relabelling an external result.
- `MemoryEvidenceRef` is an opaque reference to immutable source evidence and intentionally assigns no authority to the reference syntax.
- `GovernedMemoryObservation` preserves asset identity and source space while its similarity remains a retrieval signal only.
- `ccos-enterprise-octasoma` is an implementation adapter. Its similarity/ranking results are evidence for retrieval relevance, not authorization or causal truth.
- `ccos-enterprise-policy`, `ccos-enterprise-decision`, approval, governance, tenancy and execution remain separate owners of policy, authorization and action.

No scientific integration may collapse those layers.

## Import contract

An imported scientific artifact should be materialized as a governed evidence asset with at least:

1. a stable `MemoryAssetId` chosen by CCOS integration code;
2. an explicit tenant and `MemorySpace`;
3. `MemoryStratum::Evidence` at initial ingestion;
4. `MemoryLineage::root(...)` containing one or more immutable `MemoryEvidenceRef` values;
5. a payload preserving the upstream scientific classification and statement without rewriting them into CCOS permissions;
6. enough immutable provenance to identify the producing repository/artifact/commit/run/configuration when available.

If an upstream record is later synthesized into CCOS context or pattern memory, the derived asset must keep parent lineage to the original governed evidence asset. Promotion does not erase a negative or inconclusive source result.

## Scientific classification is descriptive, not authoritative

SciRust/FLAT evidence metadata may describe distinctions such as:

- exact mathematical result;
- numerical approximation;
- empirical validation;
- phenomenological model;
- speculative model;
- rejection criterion;
- support, rejection, inconclusive, or not-applicable disposition.

CCOS may use these labels as policy inputs, filters, audit attributes or ranking features. It must not interpret any one label as a built-in authorization level.

Examples:

- `exact mathematical result` does **not** imply permission to deploy code;
- `empirical validation` does **not** bypass human approval or tenant policy;
- `supports` does **not** mean `allow`;
- `rejects` is retained as first-class evidence and does not authorize destructive action;
- `speculative model` may be stored and retrieved without being promoted to trusted operational policy.

## OctaSoma boundary

OctaSoma candidate generation, shortlist order and similarity are retrieval mechanics only.

A high similarity score must never:

- grant access to an excluded memory space;
- cross a tenant boundary;
- promote evidence automatically;
- override trust/retention metadata;
- satisfy an approval requirement;
- select an execution capability;
- be treated as causal proof.

Likewise, a low similarity score must not delete or invalidate a governed evidence asset. Retrieval rank and scientific validity are distinct dimensions.

## Negative-result retention

Negative evidence is a required part of the governed record, not garbage to discard.

When an upstream experiment falsifies or rejects a candidate hypothesis, CCOS should preserve:

- the original claim/statement;
- the evidence kind;
- the rejection/inconclusive disposition;
- immutable provenance to the executed artifact;
- any declared approximation/budget semantics relevant to interpretation.

A downstream memory compaction/promotion process must not silently transform `rejects` into `supports`, nor omit the disposition merely because the result is inconvenient.

## Approximation and resource budgets

Approximation is semantic metadata; resource budgets are operational policy. They are not interchangeable.

For example, bounded history, sampling, compression, approximate retrieval or reduced candidate sets must remain explicitly classified where their upstream contract requires it. CCOS may impose additional memory/context budgets, but exhausting a CCOS budget must produce an explicit bounded/truncated/rejected policy outcome rather than pretending the original scientific evidence changed.

## Decision and approval boundary

Any operational use of imported scientific evidence must still pass the normal CCOS decision path.

A future adapter may expose a typed observation such as:

```text
ScientificEvidenceObservation {
    source_ref,
    source_kind,
    disposition,
    statement,
    semantic_identity?,
    approximation_class?,
}
```

but this type must live on the observation/evidence side of the architecture. It must not implement or imply an authorization trait, approval token, execution capability or tenant escalation.

Policy code may explicitly decide how such an observation contributes to a decision. That policy must be reviewable, testable and auditable independently from the scientific producer.

## Cross-project responsibility split

### SciRust

Owns generic scientific/numerical mechanisms and evidence classification produced by its computations. It must not encode CCOS enterprise authorization semantics.

### FLAT-ATTENTION

Owns attention semantic identities, correctness oracles, approximation classification and executed performance/quality evidence for attention experiments. A fast candidate is not thereby an enterprise policy decision.

### CCOS Enterprise

Owns tenant isolation, governed memory, trust, retention, promotion, policy, decision, approval and execution authority. It consumes upstream research as observations with provenance.

## Qualification requirements for a future code adapter

Before implementing an executable SciRust/FLAT -> CCOS adapter, require tests proving at least:

- imported records enter as `MemoryStratum::Evidence`;
- immutable source provenance is mandatory;
- tenant and `MemorySpace` are explicit and validated;
- negative/inconclusive dispositions round-trip unchanged;
- retrieval similarity cannot alter authorization state;
- excluded memory spaces never participate in recall;
- promotion requires governed lineage rather than relabelling;
- no imported field can directly create an approval or execution capability;
- malformed/unknown scientific metadata fails closed or is retained as opaque evidence according to an explicit versioning rule;
- repeated ingestion behavior for the same immutable source is deterministic and auditable.

## Non-goals

This contract does not:

- introduce a second memory engine;
- replace OctaSoma;
- move SciRust numerical code into CCOS;
- move FLAT attention math into CCOS;
- treat scientific evidence classification as RBAC;
- define causal truth from semantic similarity;
- auto-promote research results into policy;
- bypass existing tenant, approval, retention or execution controls.
