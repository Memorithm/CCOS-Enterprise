# Disaster Recovery

RPO/RTO are deployment contracts, not marketing numbers: they are recorded
per tenant in the backup policy.

1. Detect (health gate / audit anomaly).
2. Freeze writes for the affected tenant scope.
3. Restore latest manifest passing all gates (BACKUP_AND_RESTORE.md).
4. Replay journal tail beyond the snapshot (Core replay — deterministic).
5. Verify integrity end-to-end before unfreezing.
Every step is journaled; recovery is itself auditable.
