# CCOS Enterprise Knowledge Plane — canonical graph view

Status: **P3a bounded graph-query foundation**.

The Knowledge Graph is not a new database. `ccos-enterprise-kg` is a read-only,
bounded view over the canonical P0 `KnowledgeState`.

```text
KnowledgeOp journal
      |
      v
canonical KnowledgeState  <---- authority
      |
      v
GraphView
  outgoing / incoming
  shortest_path
  descendants / ancestors
      |
      +---- future rebuildable external graph projection
```

This keeps the architectural invariant established in P0: Neo4j, RDF stores,
Apache AGE, etc. may later accelerate queries, but deleting one of those
projections must not delete knowledge.

## Temporal semantics

A `GraphView` chooses a **valid time** and exposes only relations whose valid-time
interval contains that time and that are current in the supplied canonical
snapshot.

For historical **transaction time**, callers first reconstruct the required
snapshot with `KnowledgeState::replay_at(...)`, then create a graph view over
that snapshot. P3a deliberately does not invent a second entity transaction-time
index inside the graph layer.

## Tenant boundary

A graph view is created for exactly one canonical `TenantId`. It receives only
that `TenantKnowledge` partition. Entity and relation lookup never scans another
tenant, so same-named entity IDs in two tenants remain structurally isolated.

## Bounded queries

Every view receives `GraphLimits`:

- maximum traversal depth;
- maximum visited nodes;
- maximum returned results.

Bounds fail closed instead of silently truncating graph semantics. A caller can
therefore distinguish "no path" from "query exceeded its resource contract."
The initial defaults are conservative and are not an Enterprise policy bypass;
a later gateway/API must clamp caller-requested limits against tenant policy.

## Determinism

Relations are sourced from ordered canonical maps and query results are
explicitly sorted. Shortest path uses breadth-first traversal with stable
neighbor order, so equal-length alternatives select the same path on replay.

## P3a API

- `entity` / `entity_count`;
- `outgoing` / `incoming`, optionally filtered by relation name;
- outgoing `shortest_path`;
- bounded `descendants` / `ancestors`.

The next P3 slices can add graph statistics and rebuildable projection traits.
They must not add a mutation path around `KnowledgeOp`.
