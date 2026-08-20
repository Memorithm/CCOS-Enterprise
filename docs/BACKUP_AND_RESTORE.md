# Backup and Restore

- Unit: `BackupManifest` (tenant, time, digest, segments, schema version).
- Restore gates fail closed: malformed digest, non-canonical tenant, empty
  backup, schema zero, and snapshots newer than the build are refused.
- New backups use manifest schema v2. The manifest digest is domain-separated
  SHA-256 over sorted, framed `(segment name, byte length, content digest)`
  rows, so names, lengths, and bytes are authenticated. Schema v1 remains
  readable only for compatibility with existing backups.
- Publication uses immutable generations. A complete generation is validated
  and verified before the small durable `current` pointer is atomically
  updated; creating a new backup never mutates the last known-good generation.
- Restore verifies the exact source bytes, writes them into private staging,
  and verifies the completed staging tree again.
- Disaster recovery remains write-frozen while it replays the journal tail into
  private staging, reseals that replayed state, and performs end-to-end
  verification. Only a verified candidate is promoted through the atomic live
  pointer; failed replay or verification leaves the public live state
  unpublished/unchanged and the tenant frozen.
- A historical mutable `live` directory is refused fail-closed and must be
  migrated offline before the atomic live-pointer layout is used.
- Procedure: snapshot → sealed manifest/generation → off-host copy → verify →
  private stage → replay → reseal → end-to-end verify → atomic live promotion
  → unfreeze.
