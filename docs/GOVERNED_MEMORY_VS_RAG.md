# Governed memory and retrieval-augmented generation

Retrieval and governance answer different questions. A retrieval score orders
candidates; it does not establish their authorization, provenance, validity or
truth. CCOS combines retrieval with explicit governance checks. This is a
composition contract, not evidence that CCOS outperforms modern RAG systems.
Other retrieval systems must not be assumed to lack access control, persistence,
provenance or temporal filtering merely because they use RAG.

## Implemented library composition

`assemble_served_governed_context` composes the following library operations:

1. narrow an explicit `MemoryLoadoutPlan` to bootstrap-enabled spaces;
2. request bounded, tenant-scoped provider recall;
3. check asset identity, memory space, active lineage and the selected trust policy;
4. assemble an item- and payload-byte-bounded context.

`assemble_attested_served_context` additionally attaches categorical eligibility
metadata using a `GovernedMemoryProjection`. Attestation rechecks the exact space
as well as identity, active lineage and recall-eligible trust. Its output includes
parent identities and evidence references. A missing join fails closed.

These are library seams. They do not perform authentication or
`Deployment::admit` themselves. The stdio server is not made operationally
complete merely by exporting these functions. Issue #135 tracks actual server
wiring and protocol/restart conformance. Issue #136 tracks the governance
projection prerequisite.

## Projection guarantees and operating assumptions

`save_governed_memory_projection` validates the entire projection before writing.
It writes an exclusively created temporary file, syncs its contents, replaces the
fixed destination filename, and propagates parent-directory synchronization
errors. A failure after replacement means publication may already be visible:
callers must reload or stop, not assume rollback. Unix temporary files are created
with mode `0600`.

The encoded projection contains tenant, asset descriptors, explicit lineage
states, trust metadata and loadout bindings. It contains no embeddings or provider
index. Restore uses validating constructors and requires exactly one state for
every asset. Duplicate/unknown states and active children of inactive parents are
rejected. Unknown wire fields and duplicate lineage references are refused.
The encoded file has a 16 MiB limit; loading reads at most that limit plus one byte
before rejecting oversized input. This bounds the input bytes, not the total
allocation or CPU cost of reconstruction.

Served callers must load with `Some(expected_tenant)`. `None` is only suitable for
inspection/import before selecting a tenant. The destination directory must be
controlled by the deployment. Governance writers must be serialized externally:
atomic replacement is not a multi-writer transaction, an authenticated journal,
or protection against rollback to an older valid snapshot. A missing projection
must not silently create authority state for a served request.

Memory-space labels, asset IDs and evidence references retain their existing
opaque-data contracts. They are not filesystem paths; the projection uses fixed
filenames and JSON encoding instead of joining those values to a root. Tenant
path validation remains a separate tenancy boundary.

## What is not established

An attestation is not an unforgeable admission token. It does not bind the returned
payload cryptographically to its evidence, authenticate a snapshot version, prove
that a reference resolves, or guarantee a generated answer is true. `Verified` is
a categorical asset state under a policy, not a universal truth certificate.
The public raw-observation assembly API remains available. A future sealed
admission result should bind tenant, space, asset, content digest and snapshot
generation before entering a served response.

Item/payload-byte limits are not exact model-token limits. Final prompt framing,
metadata, tokenizer version and output reserves require separate accounting.
A reconstruction test or injected I/O failure is not a physical power-cut test.
No physical purge, encryption of this JSON file, distributed consistency, measured
latency target or end-to-end RAG superiority is claimed by this slice.

## Evidence required to close the vertical slice

Exercise the real binary through its authenticated MCP protocol: authorized
write/import, durable projection and provider reconstruction, admitted recall,
sourced response, invalidation, restart and replay. Negative cases must cover
cross-tenant and cross-space access, missing trust, stale/invalidated assets,
quarantine, corrupted state and uncertain publication. Compare quality only with
shared generators, equivalent rights and budgets, versioned data and held-out
evaluation; retain unfavorable results as well as favorable ones.
