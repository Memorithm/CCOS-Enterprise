# Governed physical purge and compaction (A10)

`memory.purge` removes one asset and every derived descendant from the managed
provider's vectors and payloads. It rebuilds the actual OctaSoma index through
the governed adapter, retires all other provider/governance generation files,
and reserves the purged identities in inactive lineage metadata. A successful
receipt is issued after cleanup, directory synchronization and durable purge
floor publication. Similarity and trust labels play no role in this decision.

## Authority and scope

The served tool passes through signed identity, `Deployment::admit`, tenant
authorization, quotas, execution journal, effect receipt and audit settlement.
It requires the independent `memory.purge` permission. The normal stdio bootstrap
role has read/write permissions and **does not acquire purge permission**.
An operator must explicitly grant that permission through the deployment's
governance administration. The only client argument is `asset_id`; tenant,
descendant closure, generation and storage paths are server-owned.

Library calls accept an already-admitted tenant. Possessing a `TenantId` is not
authentication. Consumers must preserve the front door when composing the API.

This operation covers the configured provider generation root and the newly
reconstructed live adapter. It does not erase source documents, Core workspaces,
external copies or backups, independent duplicate assets, swap, storage-device
remanence or retained process dumps. Opaque IDs, evidence references, trust and
lineage metadata remain; callers must not put secret source content in IDs.
Filesystem unlink and index reconstruction are not a forensic secure-erase claim.

## Publication and crash recovery

The exclusive generation lock is held throughout each transition:

1. `prepare_purge` validates the tenant/root asset and constructs an inactive
   lineage closure, exact next population and image digest without I/O.
2. `provider-purge-intent.json` durably binds the tenant, base generation/digest,
   next generation/digest, root asset and cumulative tombstone set.
3. Canonical governance and provider image are written and synchronized, then
   `provider-current.json` switches to that exact next generation.
4. Every other canonical file in both generation directories is unlinked and
   those directories synchronized, including unselected orphan generations.
5. `provider-purge-floor.json` records the cumulative reserved IDs and minimum
   generation. Only after it is durable is the intent removed and the root synced.

An error consumes the old owner. Reopening with a pending intent either replays
the exact recorded transition or refuses; it never returns the old serving state.
If the selector still names the verified base, only the intent's next-generation
orphans can be replaced. Torn output is regenerated from that base and compared
with the intent digest. If the selector names the verified target, cleanup is
resumed idempotently. Any other generation/digest/tenant combination fails closed.
Unknown files or symlinks encountered during cleanup are refused, not traversed.

Version-1 recovery images remain readable. Version 2 permits a physical tombstone
encoded as forgotten=true with empty embedding and payload, only for inactive
governance. Tombstones are never inserted into OctaSoma and release provider
capacity. Metadata remains bounded by the separate record/projection limits.
Ordinary generation advancement cannot add, drop, reactivate or rewrite purged
identities; only the purge transition may extend the tombstone set. Accepted
evidence writes reject reuse of any reserved ID.

## Non-resurrection boundary

The retained floor rejects an older selector even when an operator restores its
older, internally valid artifacts. Missing floors beside a tombstoned image are
refused. Backups must preserve the latest floor and reconcile it before serving
restored data. Replacing the **entire** root, including both intent and floor,
with an older backup is outside this local proof: an external monotonic authority
or key-retirement service is needed to prevent that rollback. Hashes alone do
not provide it. No physical power-cut or malicious-filesystem guarantee is made.

The MCP effect protocol remains conservative: a Succeeded purge receipt is
revalidated against generation, digest, purged root and tombstone count before
settlement. An ambiguous Started effect still requires operator reconciliation;
startup does not invent a success or automatically repeat the admitted request.
Opening the provider independently completes a recorded physical intent, but
does not itself settle the MCP quota/audit record.

## Executable qualification

The provider tests kill a separate process at durable intent, complete artifacts,
selector switch, partial cleanup and floor publication. Reopen must finish the
purge, remove retired generations, preserve surviving payloads and refuse purged
identities. A torn unselected image is also injected before recovery. Additional
tests cover old-artifact restoration under a retained floor, missing floor,
active-tombstone refusal, tenant mismatch, reserved IDs and reclaimed capacity.

The real stdio tests exercise permission denial, explicit grant, purge, replay
suppression, restart, empty governed context, rejected ID reuse, and validated
Succeeded receipt settlement. The provider CI matrix runs the purge and stdio
regressions on Rust 1.89 and stable.

```sh
cargo test -p ccos-enterprise-octasoma --lib generation::purge::tests --locked
cargo test -p ccos-enterprise-mcp --test governed_evidence_stdio --locked
```
