# Backup and Restore

- Unit: `BackupManifest` (tenant, time, digest, segments, schema version).
- Restore gates: malformed digest refused; empty backup refused; snapshot
  schema newer than the build refused (forward-incompatible by default).
- Digest = sha256 over concatenated segment digests (lowercase hex).
- Procedure: snapshot → seal envelope → manifest → off-host copy.
  Restore verifies the manifest BEFORE any byte is applied.
