# Verified memory citations

`memory.context` can resolve admitted memory lineage through the existing
Knowledge Plane, using exact `MemoryEvidenceRef == EvidenceRecord.id` joins and
`EvidenceRecord.source == SourceRecord.id`. No prefix rewriting or similarity
join is permitted. All records and source reads belong to the admitted tenant.
`Deployment::admit` remains ahead of recall and source reads.

Configure both `CCOS_ENTERPRISE_EVIDENCE_KNOWLEDGE_ROOT` (an existing KnowledgeStore)
and `CCOS_ENTERPRISE_SOURCE_BLOBS_ROOT` (a trusted, tenant-specific directory),
alongside `CCOS_ENTERPRISE_GOVERNED_MEMORY_ROOT`. Supplying only one evidence root
fails startup. The operator provisions these paths; MCP callers cannot choose
them. Publish each complete original source under its lowercase SHA-256 hex
filename, without the `sha256:` prefix. Source locators are display metadata;
they never cause filesystem traversal or network fetching.

Startup takes the journal's shared lock, refuses an active writer, and performs
bounded, read-only replay (64 MiB input ceiling). A missing tenant, malformed
journal, symlink, or torn tail fails startup. Metadata is frozen until restart;
the shared lock is released after loading. This does not refresh with subsequent
journal appends. The operator must use cooperating writers and protect the
directories against hostile replacement, as for the provider generation store.

For each admitted asset, the resolver follows its current projection's lineage
and collects all direct and inherited references. An opaque context assembly
must match the exact canonical projection fingerprint. Every selected asset's
reference must resolve, or the entire request fails without returning partial
citations. Source and evidence hashes must both use canonical
`sha256:<64 lowercase hex>` and agree on the **whole original source**. The bytes
are read and hashed on every request, with only a per-request cache. The evidence
locator must be a canonical, nonempty, half-open `bytes:start-end` range within
that source. CRLF, BOM and binary bytes remain unchanged.

Each item's `citations` includes the exact evidence/source identities, declared
source locator, source content hash, byte range, exact `quote_bytes`, and quote
hash. `citation_status = content_hash_and_byte_span_verified` describes this
integrity check. Without the two configured roots, legacy contexts explicitly
return `citation_status = unresolved` and no citations; trust labels alone never
produce verified citations.

Limits per context: 64 distinct sources, 16 MiB per source, 64 MiB total source
input, 1,024 citations and 4,096 lineage visits. Repeated quotes are charged again.
`context_max_payload_bytes` covers selected memory payload plus quoted bytes;
insufficient remaining quote space refuses the request. `total_context_bytes`
reports that sum, not JSON wire overhead or token count. No truncation, automatic
fallback, or substitution of normalized text occurs.

A content hash proves integrity of the supplied source bytes. It does **not**
authenticate a declared URL, prove the source's claims, establish that a derived
payload is entailed by its cited text, or promote an observation to canonical
truth. SourceTrust and memory validation labels remain separate policy inputs.
Source blob storage and the Knowledge journal are outside provider envelope
encryption and physical purge; their retention must be governed separately.

Tests include inherited evidence, hash/tenant/projection mismatches, malformed
spans, binary quotes, resource ceilings, bounded journal replay and real stdio
citations, corruption refusal, budget refusal and restart. A09's published
measurements do not include this optional per-request source hashing path.
