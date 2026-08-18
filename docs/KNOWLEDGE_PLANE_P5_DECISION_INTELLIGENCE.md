# Knowledge Plane P5 — Decision Intelligence

P5 adds accountable decision records above the canonical Knowledge Plane. It does **not** add model chain-of-thought, autonomous self-modification, or a second source of truth.

## Product boundary

A decision records:

- tenant and authenticated actor;
- the question and selected action/result;
- a compact operator-visible rationale;
- facts, relations, evidence and rules actually used;
- explicit earlier decisions used as precedents;
- the exact canonical Knowledge Plane sequence and SHA-256 hash seen at admission;
- an optional immutable outcome, itself anchored to a canonical Knowledge snapshot.

The canonical Knowledge Plane remains authoritative. Graph/vector/RDF backends remain rebuildable projections. Decision Intelligence never bypasses Enterprise identity, tenant isolation, policy, quotas, gateway or audit boundaries.

## Determinism

`ccos-enterprise-decision` is BTree-backed and integer-ranked. It contains no LLM call, embedding model, vector database, wall-clock ordering or floating-point similarity score.

A decision journal is dense and monotonically sequenced. The same admitted journal replays to the same canonical SHA-256 state hash.

## Fail-closed admission

A new decision is refused when:

- its Knowledge anchor is not the exact supplied canonical state;
- its actor identifier is non-canonical;
- it has no accountable basis;
- any cited fact/relation/evidence is absent from the tenant partition;
- any cited fact or relation is invalidated in the anchored snapshot;
- any cited precedent is absent from the same tenant's already-recorded decisions.

Because precedents must already exist, precedent edges form a DAG by construction. Cross-tenant precedent existence is never consulted.

## Decision queries

P5 exposes four deterministic views:

1. **Precedent search** — integer-only overlap across facts, relations, rules and ASCII-normalized accountable text, with stable DecisionId tie-breaking.
2. **Causal ancestry** — bounded breadth-first traversal over explicit precedent edges.
3. **Impact analysis** — bounded reverse traversal showing all dependent decisions and the transitive knowledge/rule footprint that would need review if an earlier decision changed.
4. **Regulatory trail** — canonical JSON containing a decision, all explicit precedent ancestors, Knowledge anchors and recorded outcomes in deterministic decision-journal order.

These are explanations of recorded system decisions, not hidden model reasoning.

## Outcome semantics

An outcome is append-only. Once present it cannot be replaced. If a decision is later reversed or superseded, that is represented by a new decision citing the previous one as a precedent. This preserves replay, auditability and regulatory chronology.

## Next integration

The next layer should expose these operations through a governed Enterprise adapter/API only after RBAC, policy and audit contracts are pinned. P5 intentionally lands the deterministic domain contract and conformance tests first so transport cannot define semantics by accident.
