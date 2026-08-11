# OctaSoma integration in CCOS Enterprise

Status: implementation contract for the dedicated Enterprise adapter.

## Role

OctaSoma is the semantic/episodic memory engine used by CCOS Enterprise. It is not part of `ccos-core`, does not become a causal authority, and is never exposed as a raw `octa.*` MCP namespace to Enterprise clients.

Enterprise owns authentication, RBAC, tenant isolation, quotas, retention policy, audit and restore policy. OctaSoma owns semantic indexing, high-dimensional precision retrieval and the Spatial/Fractal Lens.

## Dependency direction

```text
CCOS Enterprise
  -> ccos-enterprise-octasoma
       -> OctaSoma
            -> targeted SciRust crates

ccos-core  (no OctaSoma dependency)
```

The adapter is the only supported direct Enterprise dependency on OctaSoma. No dependency may point back from OctaSoma or SciRust into CCOS Enterprise.

## Tenant isolation

The initial adapter keeps one independent OctaSoma `HybridMemory` per `TenantId`. A query is therefore structurally tenant-scoped before semantic retrieval runs; two tenants never share one candidate pool or payload arena.

The adapter accepts `TenantScope<...>` values from `ccos-enterprise-tenancy` and returns owned observations. This deliberately prevents a caller from retaining references into another tenant's underlying memory instance.

## Authority boundary

A retrieval result is an **observation**, not an authorization or causal fact. Similarity scores may guide recall and ranking but may not bypass:

- authentication or RBAC;
- Enterprise policy and quota gates;
- CCOS hard causal/state transitions;
- audit and governance requirements.

## Quotas

The adapter enforces a hard per-tenant item capacity before insertion. A rejected write must not mutate the underlying OctaSoma index. Higher-level byte/token/storage budgets remain Enterprise policy concerns and may wrap this primitive quota.

## Persistence

The first adapter slice is intentionally in-memory. Production persistence will bind to OctaSoma's immutable-generation store once the v0.5 transactional persistence contract lands. Enterprise must not wrap the legacy two-file non-transactional `HybridMemory::save_dir` as if it were a governed durable store.

## MCP / gateway

Enterprise clients continue to enter through `ccos-enterprise-gateway`. The raw `octasoma-mcp` server remains a development/research surface; `octa.*` stays outside the Enterprise exposed namespace.

## Determinism

The default adapter uses OctaSoma's scalar deterministic precision path. SIMD/GPU are not enabled by the Enterprise adapter until their tolerance and replay contracts are explicitly represented in policy and audit metadata.
