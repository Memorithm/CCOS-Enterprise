# Governed memory and retrieval-augmented generation

Status reconciled with merged PRs #152–#163 and the A09 workload, 2026-09-19.
The objective is measurable improvement over strong RAG reference systems.
Similarity orders candidates; it does not establish authorization, provenance,
validity or truth. RAG reference systems may themselves implement governance.

## Implemented served path

The actual stdio server exposes `memory.context`, `memory.evidence.write` and `memory.purge`
through authenticated `Deployment::admit`, quota/audit and the existing durable
execution/effect/settlement lifecycle. #135 and #136 are closed; they no longer
describe missing server wiring. Writes fix tenant space, Evidence stratum and
Unverified trust server-side. They cannot choose their own authority or promote
themselves into the default VerifiedOnly served context.

Physical purge requires its own permission, invalidates the complete descendant
closure, rebuilds the provider without the purged payloads/vectors and removes
retired generation files. Reserved inactive IDs and a durable floor prevent
resurrection within the retained tenant root. See [A10](GOVERNED_PHYSICAL_PURGE.md)
for crash recovery, backup boundaries and residual metadata.

`ProviderGenerationStore` owns the cooperating-writer lock and selects immutable
provider and governance artifacts through one selector published last. Startup
validates the selected generation and reconstructs OctaSoma through the governed
adapter. Succeeded write receipts are checked before settlement; an ambiguous
Started write is refused on restart. See the
[recovery contract](GOVERNED_PROVIDER_RECOVERY_CONTRACT.md).

PR #163 replaced raw governed-context assembly with opaque admitted observations.
They bind the expected tenant, canonical projection version and SHA-256, exact
payload SHA-256, asset, space, lineage and trust eligibility. Assembly rejects a
different projection. The A09 immutable snapshot caches validated canonical bytes
and their fingerprint within an owned, non-mutable generation; asset eligibility
and payload checks still run on each query. APIs taking an independently supplied
mutable projection continue to validate and fingerprint it on each call.

## Authority and remaining provenance boundary

Attestation reports what was admitted and under which snapshot. Its hash is not a
signature, a proof that a statement is true, or proof that a MemoryEvidenceRef
resolves to an EvidenceRecord and an immutable SourceRecord. The evidence/source
join and content-hash/citation validation require their own qualified resolver.
The categorical Verified label is not a universal truth certificate.

The served authority is owned by a generation store, not supplied by the calling
agent. Low-level projection save/load helpers remain available for explicitly
controlled import/inspection; they are not an alternate authorization front door.
Tenant IDs and reference labels are opaque data rather than arbitrary paths.

## Scale and resource accounting

A09 provides a reproducible subprocess workload for 1k/10k/100k assets per tenant,
one and four concurrent tenants, signed identity admission, governed recall,
context assembly and attestation. It records raw latencies, empirical p50/p95/p99,
per-tenant and aggregate throughput, process RSS/high-water RSS, generation bytes
and fresh-process recovery equality. See [A09](GOVERNED_MEMORY_BENCHMARK.md).

Hard maxima are 64 MiB per governance projection and 256 MiB per provider image,
with bounded records, raw vector bytes and payload bytes. These are input limits,
not a peak-RAM or latency guarantee. Tenant capacity is still explicitly configured.
The scale workload uses synthetic 32-dimensional vectors and 64-byte payloads;
it cannot establish quality, capacity for larger embedding models, or production
SLOs. Prompt framing, tokenizer version and output reserves need separate budgets.

## Fair comparison and claim boundaries

Use the same corpus/version, queries, held-out judgments, generator, access rights,
context/token budgets and hardware. Include lexical, dense, hybrid and reranked
systems; swap the same encoder into both CCOS and RAG arms. Record answers with
supporting citations, unsupported claims, abstentions and stale/deleted evidence
alongside retrieval metrics and operational costs. Preserve all adverse results.
See [the encoder decision](EMBEDDING_MODEL_DECISION.md).

No completed end-to-end RAG superiority result is claimed here. A09 is a synthetic
cost/recovery workload and excludes MCP transport, a text encoder and generation.
Normal process restart is not forced power loss. Physical purge, tenant KMS,
anti-rollback and distributed consistency must be assessed against their own
implemented contracts and tests; they do not follow from a selector or checksum.
