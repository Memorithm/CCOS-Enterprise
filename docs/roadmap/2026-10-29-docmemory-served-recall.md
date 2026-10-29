# DocumentMemory — served recall closed (2026-10-29)

Follow-up to #234 (`c8de0ea`), #235 (`8702a0b`), #236 (`d1912fe`).

## Closed

- **Index rebuild from governed assets.** `RecoveredGovernedMemory::rebuild_document_index`
  (provider adapter, `ccos-enterprise-octasoma`) fills a caller-supplied
  `GovernedDocumentMemory` (encoder injected by the caller; the server uses lexical-only BM25)
  from the verified recovery image of the selected generation. Indexed only: non-forgotten,
  lineage-`Active`, space bound by the governance loadout, non-blank UTF-8. Tenant and space come
  from the authority projection / canonical descriptor, never from the provider or the client.
  Returns counts only (`DocumentIndexRebuild`). Trust is still enforced at recall by
  `admit_governed_recall` (quarantined assets are indexed but never admitted).
- **Persistence decision.** No custom on-disk index dump. The durable source of truth is the
  provider generation already on disk (recovery image + governance); the index is a derived
  projection rebuilt at server boot and lazily when the generation changes (evidence write,
  purge, key rotation).
- **`memory.document_recall` reachable from `ccos-enterprise-mcp-server` (stdio).** Listed in
  `tools/list` and governed (`memory.read`) when `CCOS_ENTERPRISE_GOVERNED_MEMORY_ROOT` is set.
  Executes through the same seam as `memory.context`: authenticated identity and host-claim
  match, `Deployment::admit` (RBAC/tenancy/quota/replay), execution journal
  (ToolRequested → ToolStarted → ToolFinished), durable effect marker, governance persistence,
  settlement, rollback on failure. Trust policy fixed to `VerifiedOnly`; client arguments are
  closed (no tenant/space/policy).
- **Tests.** `crates/ccos-enterprise-mcp/tests/governed_document_recall_stdio.rs`: rebuild →
  recall (counts, admission, tenant mismatch refused); real stdio process lists and executes the
  tool, writes effect + journal, rejects widened arguments and foreign tenant, suppresses replay,
  and serves again after restart from the rebuilt index; no payload of non-admitted assets
  appears in responses.

## Remaining

- **False-alarm guard at served ingest.** `IngestGuard` exists (#234) but the served rebuild uses
  no guard; a calibrated scorer and its wiring (and what to do with refused assets at rebuild)
  are open.
- ~~**Embedding trait / dense ranking in the server.**~~ Done — see
  `2026-10-29-docmemory-served-encoder.md` (optional CPU encoder, lexical default).
- **HTTP gateway.** Only the stdio binary serves the tool; an HTTP front door is open.
- **Rebuild cost.** Rebuild is O(assets) at boot and per new generation; incremental update or a
  verified cached index is open if generation sizes require it. No measurements were taken.
