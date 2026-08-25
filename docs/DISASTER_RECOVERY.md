# Disaster Recovery

RPO/RTO are deployment contracts, not marketing numbers: they are recorded
per tenant in the backup policy.

1. Detect (health gate / audit anomaly).
2. Freeze writes for the affected tenant scope.
3. Restore latest manifest passing all gates (BACKUP_AND_RESTORE.md).
4. Replay journal tail beyond the snapshot (Core replay — deterministic).
5. Verify integrity end-to-end before unfreezing.
Every step is journaled; recovery is itself auditable.

## Enterprise governance store: fail-closed durability contract

`ccos-enterprise-store` backs every governed decision (budget charges,
replay suppression, audit) with `audit.jsonl`, `governance.jsonl` and
`deployment.json` under the state directory. Its guarantees, and what they
mean during recovery:

- **Durable appends.** Every append is validated whole, written once, and
  `sync_data`d before the caller is told it happened. A newly created
  journal file has its *directory entry* fsynced too, so a power failure
  cannot silently remove a trail whose bytes were all acknowledged.
- **A failed append poisons the handle.** If an append hits an IO error
  partway through (`ENOSPC`, `EIO`), the partial bytes are rolled back
  best-effort and the `Store` refuses every further append with
  `StoreError::Poisoned` until it is **reopened**. Reopening recomputes the
  sequence from disk; retrying on the poisoned handle would reuse sequence
  numbers and permanently brick the journal.
- **Restore refuses a journal short of the snapshot watermark**
  (`RestoreError::JournalDiscontinuity`). The watermark asserts that every
  decision before it is folded into the snapshot's ledgers; a truncated or
  deleted journal cannot account for those decisions. Restoring anyway
  would reissue their sequence numbers and skip their costs — quota
  accounting resetting through data loss. Recovery from this state is an
  explicit operator act: repair the journal from backup or verify the loss
  before restoring.
- **Restore refuses a self-contradictory governance slice**: ordinals must
  be dense from zero and anchors non-regressing
  (`RestoreError::GovernanceDiscontinuity` /
  `GovernanceAnchorRegression`).
- **Torn tails stay the one crash-repairable case**: only an unsynced final
  partial line is discarded and reported (`Loaded::torn_tail`); corruption
  anywhere else is refused, never silently trimmed.
- **Startup cost is bounded by rotation, not by lifetime.** The MCP server
  seals the live decision journal into an immutable
  `audit.through-<last>.jsonl` segment once it passes 128 MiB, anchored to a
  durable snapshot of the same watermark. Startup replays segments plus the
  short live tail; a missing or torn segment is refused, never skipped.
  Operators can also run `Store::compact(&snapshot)` manually at any quiet
  moment — it moves nothing unless the snapshot watermark equals the durable
  journal end.

The composed product path (`ccos-enterprise-mcp-server`) persists after
every governed call and fails closed ("Enterprise durable state
unavailable") rather than serving from memory when any of these refusals
fire.
