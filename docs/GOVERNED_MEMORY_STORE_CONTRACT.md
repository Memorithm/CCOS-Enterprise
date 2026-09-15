# Governed memory projection owner

Scope: an incremental #136 prerequisite for #135. This is a single-host
cooperating-writer contract, not completion of the served MCP vertical slice.
The version-1 JSON projection, existing trust policy and Core lineage are unchanged.

## Ownership and startup

`GovernedMemoryStore::open(root, expected_tenant)` requires an existing valid
projection and an explicit validated tenant. It does not provision authority on
missing state. It acquires an exclusive OS file lock before reading and retains
that lock until drop. The lock lives in a separate `.governed-memory.lock` file,
not the atomically replaced JSON inode. The lock file is never removed on drop.
A second cooperating owner receives `AlreadyOpen` without blocking indefinitely.

`initialize(root, initial_projection)` is a separate provisioning operation. It
requires a valid explicit projection and refuses any existing projection-path
entry, including corrupt JSON and dangling symlinks. It must not be invoked as
an automatic fallback after an `open` error. Initial directories use the existing
synced-creation helper. Roots are canonicalized once so later CWD changes cannot
redirect publication. Unix newly created lock files have mode 0600.

The directory and lock file must remain controlled by the deployment. All writers
must cooperate with this owner. The older low-level save/load APIs remain for
compatibility and offline migration: mixing direct saves with a live owner is
unsupported. Advisory locks are not protection from a hostile filesystem writer,
root-directory replacement, another host ignoring locks, or restore of an older
valid snapshot. No distributed or anti-rollback guarantee is made.

## Reads and writes

`projection_for(expected_tenant)` exposes a shared borrow, never mutable state.
The argument must come from the caller's admitted request. The equality check
is not authentication or RBAC. A held borrow prevents replacement through safe
Rust while the borrowed projection is used. Cloning a projection is still
possible: it is not a sealed authority token and must not be cached as one.

`replace(candidate)` validates tenant equality and reconstructs all domain objects
through the same wire/constructor checks as restore, including the 16 MiB encoded
limit. Validation errors preserve both the acknowledged in-memory state and the
file. Once publication starts, the in-memory projection is removed until the
synced write/rename/directory-sync succeeds. Any publication error poisons the
owner: reads and further replacements return `RecoveryRequired`.

An error after rename is neither rollback nor a durable-success acknowledgment.
Recovery is explicit: drop the owner, reconcile the surrounding request/effect
state, then reopen the projection. Open syncs the visible file and parent before
exposing restored governance. It does not replay or retry the failed application
request. A fresh process reconstructs inactive/stale states without reactivation.

## MCP-facing composition

`assemble_stored_governed_context` obtains the acknowledged projection for the
expected request tenant before calling any semantic provider. It then reuses
`assemble_attested_served_context`: bounded loadout recall, exact canonical-space
admission, lineage/trust filtering, bounded assembly and eligibility metadata.
A tenant mismatch or poisoned owner fails before provider access.

This function is exported but is not yet wired into the real stdio tool route.
The caller still owes `Deployment::admit`, authorization, quota reservation,
audit/effect settlement, a durable/reconstructible provider, and real protocol
and restart tests. #135/#136 are intentionally not closed by this slice.

## Validation commands

```bash
cargo +1.89.0 test -p ccos-enterprise-memory projection::store::tests --locked
cargo +1.89.0 test -p ccos-enterprise-mcp --test stored_context_lifecycle --locked
cargo +1.89.0 test -p ccos-enterprise-memory --doc --locked
cargo +stable test -p ccos-enterprise-memory -p ccos-enterprise-mcp --all-features --locked
```

Tests cover missing/corrupt state, explicit creation, duplicate owners, tenant
mismatch, invalid candidates, persistent invalidation, errors before/after
publication and rejection before provider dispatch. A subprocess test actually
opens the store in another process: it refuses ownership while the parent holds
the lock, then reconstructs invalidated state after the owner is dropped. This
is process-level store qualification, not a restart of the real MCP binary or a
physical power-cut experiment. No quality, capacity or latency result is claimed.

## Sources and cross-project relevance

- Existing projection and recall implementation: Memorithm/CCOS-Enterprise,
  baseline `72e22014c6711cb85fd31b4fb3d087477f50bd0f`, reviewed 15 September 2026.
- Follow-up requirements: issues #135/#136 and `docs/AUDIT_2026-09-14.md`.
- Rust standard library, `File::try_lock` and lock lifetime, consulted
  15 September 2026: https://doc.rust-lang.org/std/fs/struct.File.html#method.try_lock

SoulSystem remains a planned consumer through the Enterprise front door; this
store must not be copied into CCOS-Core or treated as a SoulSystem permission
bypass. A later provider-reconstruction tranche will exercise the real governed
OctaSoma adapter. No other repository is modified on that assumption.
