//! # CCOS Enterprise — Backup & Restore
//!
//! Tenant-scoped backup manifests (docs/BACKUP_AND_RESTORE.md,
//! docs/DISASTER_RECOVERY.md). Foundation slice: the manifest type and its
//! integrity rule — a backup that cannot verify its digest is not a backup.

use serde::{Deserialize, Serialize};

/// One restorable unit: a tenant's sealed snapshot set at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub tenant: String,
    pub created_unix: u64,
    /// sha256 (lowercase hex) over the concatenated segment digests.
    pub digest: String,
    pub segments: u32,
    /// Schema version of the enclosed snapshots (restore-time gate).
    pub schema_version: u32,
}

impl BackupManifest {
    /// Restore gate: refuse a manifest whose digest is malformed, whose
    /// segment count is zero, or whose schema is newer than this build.
    pub fn restorable_by(&self, build_schema: u32) -> Result<(), String> {
        let hex_ok = self.digest.len() == 64
            && self
                .digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
        if !hex_ok {
            return Err("manifest digest is not lowercase 64-hex".into());
        }
        if self.segments == 0 {
            return Err("manifest has no segments".into());
        }
        if self.schema_version > build_schema {
            return Err(format!(
                "snapshot schema v{} is newer than this build (v{})",
                self.schema_version, build_schema
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_gates() {
        let ok = BackupManifest {
            tenant: "acme".into(),
            created_unix: 1,
            digest: "a".repeat(64),
            segments: 3,
            schema_version: 1,
        };
        assert!(ok.restorable_by(1).is_ok());
        assert!(ok.restorable_by(0).is_err(), "newer snapshot than build");
        let mut bad = ok.clone();
        bad.digest = "ZZ".repeat(32);
        assert!(bad.restorable_by(1).is_err(), "malformed digest refused");
        let mut empty = ok;
        empty.segments = 0;
        assert!(empty.restorable_by(1).is_err(), "empty backup refused");
    }
}
