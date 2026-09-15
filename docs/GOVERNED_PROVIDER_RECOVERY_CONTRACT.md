# Governed provider recovery images

Incremental A07/A08 recovery work after #152, for #135/#136. This is a
reconstructible provider data artifact, not complete authenticated MCP serving.
The existing governance owner remains authoritative. No Core or raw OctaSoma
API is copied into another product.

## What this implements

`RecoveryImage::capture` accepts the complete ordered source records and a
validated `GovernedMemoryProjection`, with explicit dimension, SimHash width,
seed and per-tenant capacity. It records the original finite f32 bit patterns,
opaque asset identities, binary payloads and logical-forget tombstones. Spaces
come from canonical descriptors. Exactly one record per descriptor and explicit
trust for each asset are required; stale/invalidated assets are retained, not
reactivated or silently dropped. Forgotten rows continue to consume capacity.
The source order is retained because replay order is part of the input contract.

The artifact includes canonical governance bytes, format version and the exact
supported OctaSoma revision. Its SHA-256 receipt covers the entire encoded image.
`restore_governed_memory` requires that receipt, expected configuration and
current governance independently from the caller; it never obtains authority
by trusting the snapshot's own labels. It validates all rows before constructing
a new real `EnterpriseOctaSoma`, then replays through the adapter's existing
insertion and forget methods. No partially reconstructed provider is returned.

The recovered wrapper exposes no mutable backend or governance state. Each
recall requires the caller's current authority, an explicit tenant/loadout and
bounded recall request. It checks exact governance equality and tenant before
provider access, limits requested spaces to configured spaces, then applies the
existing canonical-space/lineage/trust gate. The caller must select the proper
bootstrap/on-demand subset and still pass authentication, RBAC and budget
admission first. Existing memory assembly and attestation accept the results.

`encode_governed_memory_projection` is the shared validating encoding used by
existing governance save and image binding. The governance version-1 wire format
is unchanged; its exact bytes are regression-tested against on-disk persistence.

## Storage and error contract

`write_new` creates a new generation file only, in an already-existing trusted
parent directory, with Unix mode 0600. It refuses existing files and dangling
symlinks, synchronizes the file and parent, and propagates errors. A failed call
may have left a partial or complete file: no served generation pointer may be
advanced after an error. This API intentionally does not replace a previous
snapshot or implement the caller's atomic generation selector.

Restore reads at most 64 MiB + 1 byte and rejects oversized input. Limits also
cover 16,384 records/capacity, dimension 8,192, SimHash width 4,096, 32 MiB of
projector coefficients, 32 MiB of raw vectors and 16 MiB of payloads. These are
input/resource policy bounds, not a guarantee on total heap or replay latency.
The canonical governance encoder retains its existing 16 MiB wire bound and
validation allocations. Archive input uses typed deny-unknown-fields decoding;
malformed shapes, duplicate keys, unknown assets, incomplete populations,
nonfinite vectors and unsupported revisions fail closed.

## Validation commands

```bash
cargo +1.89.0 test -p ccos-enterprise-octasoma --lib recovery::tests --locked
cargo +1.89.0 test -p ccos-enterprise-octasoma --doc --locked
cargo +1.89.0 clippy -p ccos-enterprise-memory -p ccos-enterprise-octasoma --all-targets --locked -- -D warnings
```

Tests compare original versus reconstructed real-provider results, preserve
binary bytes/f32 bits/order/tombstones, reject changed authority or configuration,
exercise read/sync errors and immutable file creation, and start a fresh child
process that loads the persisted image and rebuilds its own provider. This is
normal-process reconstruction, not forced termination or a power-cut experiment.
No measured retrieval-quality or large-scale performance result is claimed.

## Still required for the served vertical slice

1. Capture records from the authoritative accepted-write lifecycle. This API is
   not an exporter from arbitrary live indexes; supplied records must be complete
   and correspond to the intended source generation. Capture does not verify
   truth, source resolution, or historical insertion success.
2. Persist the expected receipt/configuration and select provider/governance
   generations through the existing durable request/effect/settlement boundary.
3. Wire actual authenticated stdio requests and prove restart/replay under the
   real server's permissions, quotas, audit and invalidation lifecycle.

A matching digest is integrity relative to a trusted receipt, not a signature,
anti-rollback protection or proof of truth. Replaying an older image together
with its older authority remains possible outside a monotonic admitted lifecycle.
Images contain plaintext payloads and embeddings, not encryption or physical
purge. Backend revisions fail closed; changing the dependency pin requires an
explicit migration/compatibility decision rather than automatic acceptance.

The reusable consumer contract benefits the future SoulSystem integration, but
SoulSystem must not create authority locally or gain access to raw adapter state.
No unreviewed cross-repository integration is included.

Sources: Memorithm/CCOS-Enterprise revision
1a02ce6da6aca55c56d52ceaa8f3333282d35e32 (15 September 2026), projection owner,
OctaSoma adapter and ecosystem roadmap. Rust standard-library docs consulted
15 September 2026: https://doc.rust-lang.org/std/fs/struct.OpenOptions.html#method.create_new
and https://doc.rust-lang.org/std/io/trait.Read.html#method.take.
