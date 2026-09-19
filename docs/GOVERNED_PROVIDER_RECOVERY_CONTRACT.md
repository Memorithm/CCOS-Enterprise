# Governed provider recovery and generation publication

A07/A08 recovery and served writes (#152–#163), A09 bounded scale, and A10 physical purge. Issues #135/#136 were closed by the served paths.
This contract covers reconstructible provider data plus local generation
selection. It does not claim that arbitrary Core `memory.ingest` calls already
produce governed semantic records, nor does it create authority from retrieval
similarity. No Core or raw OctaSoma API is copied into another product.

## Recovery image contract

`RecoveryImage::capture` accepts the complete ordered source records and a
validated `GovernedMemoryProjection`, with explicit dimension, SimHash width,
seed and per-tenant capacity. It records the original finite f32 bit patterns,
opaque asset identities, binary payloads and logical-forget tombstones. Spaces
come from canonical descriptors. Exactly one record per descriptor and explicit
trust for each asset are required; stale/invalidated assets are retained, not
reactivated or silently dropped. Logically forgotten rows continue to consume capacity. A10 format-2 physical tombstones retain inactive identity metadata with empty vectors/payloads and do not consume provider capacity; format 1 remains readable.
The source order is retained because replay order is part of the input contract.

The image includes canonical governance bytes, format version and the exact
supported OctaSoma revision. Its SHA-256 receipt covers the entire encoded image.
`restore_governed_memory` requires that receipt, expected configuration and
current governance independently from the caller; it never obtains authority
by trusting the image's own labels. It validates all rows before constructing a
new real `EnterpriseOctaSoma`, then replays through the adapter's existing
insertion and forget methods. No partially reconstructed provider is returned.

The recovered wrapper exposes no mutable backend or governance state. Each
recall requires the caller's current authority, an explicit tenant/loadout and
bounded recall request. It checks exact governance equality and tenant before
provider access, limits requested spaces to configured spaces, then applies the
existing canonical-space/lineage/trust gate. Authentication, RBAC, runtime
budget admission, context budgets and served settlement remain separate gates.

`encode_governed_memory_projection` is the shared validating encoding used by
projection persistence and provider generation binding.
`decode_governed_memory_projection` validates bounded canonical bytes through
the same typed constructors and requires an independently supplied expected
tenant. The governance version-1 wire format itself remains unchanged.

## Generation selector v2

`ProviderGenerationStore` now supports two selector generations:

- selector **v1** remains readable for existing deployments and binds the
  provider image to the separately owned `GovernedMemoryStore`;
- selector **v2** is emitted by new initialization and by `advance`.

A v2 generation consists of three durable objects under one provider root:

1. an immutable canonical governance artifact in `governance-generations/`;
2. an immutable provider recovery image in `provider-generations/`;
3. `provider-current.json`, containing the tenant, generation number, exact
   canonical filenames, SHA-256 receipts and recovery configuration.

The governance and provider files are created and synchronized before the
selector is published. The selector is the only authority pointer and is
published last via one rename followed by directory synchronization. Files that
exist but are not named by the selector are inert orphan artifacts and are never
selected implicitly.

`ProviderGenerationStore::advance(self, authority, config, records)` consumes
the current owner. It writes generation `n+1`, then replaces the selector and
reopens from durable bytes. Because the receiver is consumed, any failure means
the caller no longer possesses an owner that can continue serving potentially
uncertain in-memory state. If publication stops before selector replacement, the
previous selector remains authoritative and can be reopened. A failure after a
rename is an explicit reopen/recovery boundary, not a successful rollback.

The selector never accepts arbitrary generation paths: provider and governance
filenames are derived from the selected numeric generation and compared exactly.
Tenant identity is independently supplied at open. Version-2 governance bytes
are digest-checked before typed decode; provider image digest/configuration and
exact governance are revalidated again during provider reconstruction.

## Storage and error contract

Recovery images and immutable governance artifacts use create-new semantics.
Existing paths, dangling symlinks or non-directory generation roots are not
silently replaced. Files are synchronized before their parent directory.
Selector temporary files are created exclusively. Normal Unix rename semantics
provide one local pointer switch; an unsupported platform replacement failure
leaves the old selector in place and fails closed.

Restore reads at most 256 MiB + 1 byte and rejects oversized input. Limits also
cover 131,072 records/capacity, dimension 8,192, SimHash width 4,096, 32 MiB of
projector coefficients, 32 MiB of raw vectors and 16 MiB of payloads. Canonical
governance retains its 64 MiB wire bound. Archive input and selectors
use deny-unknown-fields decoding; malformed shapes, duplicate keys, unknown
assets, incomplete populations, nonfinite vectors, invalid digests and
unsupported revisions fail closed.

This protocol is **not** a distributed transaction, KMS layer, monotonic counter,
power-cut qualification or anti-rollback mechanism. An attacker able to replace
both older immutable artifacts and the trusted selector can still restore an
older valid generation unless a higher-level admitted monotonic receipt prevents
it.

## Validation commands

```bash
cargo +1.89.0 test -p ccos-enterprise-memory --locked
cargo +1.89.0 test -p ccos-enterprise-octasoma --test generation_selector --locked
cargo +1.89.0 test -p ccos-enterprise-octasoma recovery --locked
cargo +1.89.0 test -p ccos-enterprise-mcp --test governed_context_stdio --locked
cargo +1.89.0 clippy -p ccos-enterprise-memory -p ccos-enterprise-octasoma -p ccos-enterprise-mcp --all-targets --locked -- -D warnings
```

Generation-selector regressions cover v2 initialization/reopen, v1 read
compatibility, provider/governance path traversal refusal, generation 0→1
advancement, inert orphan artifacts, tenant mismatch and failure before selector
publication preserving the previous authority. Recovery tests separately cover
binary bytes/f32 bits/order/tombstones, changed authority/configuration,
read/sync errors and fresh-process provider reconstruction. The real MCP stdio
regression verifies that the selected provider generation still composes with
the authenticated governed-context path delivered by #155.

## Served mutation and purge status

PR #159 connected `memory.evidence.write` to the authenticated admission,
execution/effect/quota/audit lifecycle, closing #136. Inputs remain explicit
asset/evidence/embedding/payload tuples; the server fixes tenant space, direct
Evidence stratum and Unverified trust. Succeeded generation receipts are checked
on restart before settlement. Ambiguous Started effects require reconciliation.
Core ingest does not fabricate embeddings or promote semantic truth.

A10 adds independently authorized `memory.purge`, durable intent, physical
compaction and a retained local purge floor. The floor additionally constrains
selector opens and ordinary generation advancement; an older selector cannot
resurrect purged identities while the latest floor remains. Reopening pending
physical intents rolls forward before serving. See the complete
[purge contract](GOVERNED_PHYSICAL_PURGE.md), including real process-kill tests
and the separate MCP settlement boundary.

Explicitly encrypted roots use [tenant envelope KMS](TENANT_ENVELOPE_KMS.md)
for images, governance, selector and purge metadata; plaintext roots remain an
explicit separate mode. External monotonic rollback protection, backup-wide
erasure and physical power-loss qualification remain separate work.
A09 measures the bounded plaintext synthetic pipeline and normal reconstruction;
it does not establish retrieval-quality superiority over RAG. No Core source
change or Enterprise dependency backflow is introduced by these mechanisms.
