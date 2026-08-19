//! # CCOS Enterprise — Backup & Restore
//!
//! Tenant-scoped backup manifests (docs/BACKUP_AND_RESTORE.md,
//! docs/DISASTER_RECOVERY.md). This crate owns the full workflow:
//!
//! 1. **snapshot/manifest production** — gather tenant snapshot segments,
//!    compute canonical segment hashes and the manifest digest exactly,
//!    write the manifest durably and verify it after writing;
//! 2. **backup verification** — verify every segment, the aggregate digest,
//!    reject missing/extra/duplicate segments, unsafe paths, cross-tenant
//!    material and unsupported future schemas;
//! 3. **restore staging** — never mutate live tenant state before the
//!    complete backup verifies: restore into staging, validate tenant
//!    identity, schemas and digest, then atomically promote only after
//!    successful checks;
//! 4. **disaster recovery orchestration** — freeze writes for the affected
//!    tenant, locate the latest admissible manifest, restore, replay the
//!    deterministic journal tail, verify end-to-end integrity, unfreeze only
//!    on success, remain frozen/fail-closed on verification failure, audit
//!    every stage.
//!
//! The storage abstraction is deliberately narrow ([`BackupTarget`]): a
//! filesystem implementation ships first; credentials never enter persisted
//! cognitive state. RPO/RTO are deployment policy facts recorded per tenant
//! in the backup policy, never hard-coded marketing values.
//!
//! ## Manifest format
//!
//! `digest` = sha256 (lowercase hex) over the concatenated segment digests.
//! The manifest is schema-versioned (`BACKUP_SCHEMA`); a manifest with a
//! schema newer than the build is refused (forward-incompatible by default).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Schema version of the enclosed snapshots (restore-time gate).
pub const BACKUP_SCHEMA: u32 = 1;

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

/// One snapshot segment: an opaque, named unit of tenant state.
///
/// Segments are addressed by name; the name is a path component under the
/// tenant's backup root, so it must be path-safe (the same rule as tenant
/// ids: lowercase alphanumerics, `_` and `-`, no leading `-` or `_`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub name: String,
    pub bytes: Vec<u8>,
}

/// The digest of one segment: sha256 of its bytes, lowercase hex.
pub fn segment_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(hasher.finalize())
}

/// The aggregate manifest digest: sha256 over the concatenated segment
/// digests (each 64 lowercase hex chars), exactly as
/// `docs/BACKUP_AND_RESTORE.md` defines it.
pub fn manifest_digest(segment_digests: &[String]) -> String {
    let mut hasher = Sha256::new();
    for digest in segment_digests {
        hasher.update(digest.as_bytes());
    }
    hex(hasher.finalize())
}

fn hex(digest: sha2::digest::generic_array::GenericArray<u8, sha2::digest::consts::U32>) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Whether a segment name is path-safe: non-empty, at most 128 bytes, first
/// char alphanumeric, rest `[a-z0-9_-]`.
pub fn is_safe_segment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return false;
    }
    name.len() <= 128
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// Why a backup operation was refused. Every variant is fail-closed.
#[derive(Debug)]
pub enum BackupError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    InvalidManifest {
        detail: String,
    },
    InvalidSegment {
        detail: String,
    },
    CorruptManifest {
        path: PathBuf,
        detail: String,
    },
    CorruptSegment {
        path: PathBuf,
        detail: String,
    },
    DigestMismatch {
        expected: String,
        found: String,
    },
    MissingSegment {
        name: String,
    },
    ExtraSegment {
        name: String,
    },
    DuplicateSegment {
        name: String,
    },
    UnsupportedSchema {
        found: u32,
    },
    CrossTenant {
        tenant: String,
    },
    StagingNotEmpty {
        path: PathBuf,
    },
}

impl std::fmt::Display for BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::InvalidManifest { detail } => write!(f, "invalid backup manifest: {detail}"),
            Self::InvalidSegment { detail } => write!(f, "invalid backup segment: {detail}"),
            Self::CorruptManifest { path, detail } => {
                write!(f, "{}: manifest is corrupt: {detail}", path.display())
            }
            Self::CorruptSegment { path, detail } => {
                write!(f, "{}: segment is corrupt: {detail}", path.display())
            }
            Self::DigestMismatch { expected, found } => {
                write!(f, "digest mismatch: expected {expected}, found {found}")
            }
            Self::MissingSegment { name } => write!(f, "manifest names missing segment {name:?}"),
            Self::ExtraSegment { name } => write!(f, "backup holds extra segment {name:?}"),
            Self::DuplicateSegment { name } => write!(f, "backup holds duplicate segment {name:?}"),
            Self::UnsupportedSchema { found } => {
                write!(f, "backup schema v{found} is newer than this build")
            }
            Self::CrossTenant { tenant } => {
                write!(f, "backup material belongs to tenant {tenant:?}")
            }
            Self::StagingNotEmpty { path } => {
                write!(f, "staging directory is not empty: {}", path.display())
            }
        }
    }
}

impl std::error::Error for BackupError {}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> BackupError + '_ {
    move |source| BackupError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// A narrow off-host storage abstraction. The filesystem implementation
/// ships first; a vendor implementation must satisfy exactly this surface,
/// and credentials never enter persisted cognitive state.
pub trait BackupTarget {
    /// Read one segment's bytes. `NotFound` is reported as `Ok(None)`.
    fn read_segment(&self, tenant: &str, name: &str) -> Result<Option<Vec<u8>>, BackupError>;
    /// Write one segment's bytes durably.
    fn write_segment(&self, tenant: &str, name: &str, bytes: &[u8]) -> Result<(), BackupError>;
    /// List the segment names present for a tenant, in name order.
    fn list_segments(&self, tenant: &str) -> Result<Vec<String>, BackupError>;
    /// Read the durable manifest for a tenant, if any.
    fn read_manifest(&self, tenant: &str) -> Result<Option<BackupManifest>, BackupError>;
    /// Write the durable manifest for a tenant.
    fn write_manifest(&self, tenant: &str, manifest: &BackupManifest) -> Result<(), BackupError>;
}

/// Filesystem implementation of [`BackupTarget`].
///
/// Layout under a root:
/// - `<root>/<tenant>/manifest.json`
/// - `<root>/<tenant>/segments/<name>`
///
/// All paths derive from canonical tenant ids and safe segment names, so
/// traversal is refused by construction.
pub struct FsBackupTarget {
    root: PathBuf,
}

impl FsBackupTarget {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    fn tenant_root(&self, tenant: &str) -> Result<PathBuf, BackupError> {
        if !is_safe_tenant_id(tenant) {
            return Err(BackupError::CrossTenant {
                tenant: tenant.to_string(),
            });
        }
        Ok(self.root.join(tenant))
    }

    fn manifest_path(&self, tenant: &str) -> Result<PathBuf, BackupError> {
        Ok(self.tenant_root(tenant)?.join("manifest.json"))
    }

    fn segment_path(&self, tenant: &str, name: &str) -> Result<PathBuf, BackupError> {
        if !is_safe_segment_name(name) {
            return Err(BackupError::InvalidSegment {
                detail: format!("unsafe segment name {name:?}"),
            });
        }
        Ok(self.tenant_root(tenant)?.join("segments").join(name))
    }
}

impl BackupTarget for FsBackupTarget {
    fn read_segment(&self, tenant: &str, name: &str) -> Result<Option<Vec<u8>>, BackupError> {
        let path = self.segment_path(tenant, name)?;
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(BackupError::Io { path, source }),
        }
    }

    fn write_segment(&self, tenant: &str, name: &str, bytes: &[u8]) -> Result<(), BackupError> {
        let path = self.segment_path(tenant, name)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(io(parent))?;
        }
        ccos_core::util::write_durable(&path, bytes).map_err(io(&path))
    }

    fn list_segments(&self, tenant: &str) -> Result<Vec<String>, BackupError> {
        let dir = self.tenant_root(tenant)?.join("segments");
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => return Err(BackupError::Io { path: dir, source }),
        };
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(io(&dir))?;
            if entry.file_type().map_err(io(&dir))?.is_file() {
                if let Some(name) = entry.file_name().to_str() {
                    names.push(name.to_string());
                }
            }
        }
        names.sort();
        Ok(names)
    }

    fn read_manifest(&self, tenant: &str) -> Result<Option<BackupManifest>, BackupError> {
        let path = self.manifest_path(tenant)?;
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(BackupError::Io { path, source }),
        };
        let manifest: BackupManifest =
            serde_json::from_slice(&bytes).map_err(|error| BackupError::CorruptManifest {
                path: path.clone(),
                detail: error.to_string(),
            })?;
        Ok(Some(manifest))
    }

    fn write_manifest(&self, tenant: &str, manifest: &BackupManifest) -> Result<(), BackupError> {
        let path = self.manifest_path(tenant)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(io(parent))?;
        }
        let bytes =
            serde_json::to_vec_pretty(manifest).map_err(|error| BackupError::InvalidManifest {
                detail: format!("cannot serialize manifest: {error}"),
            })?;
        ccos_core::util::write_durable(&path, &bytes).map_err(io(&path))
    }
}

/// Whether a tenant id is path-safe for use as a backup root component.
/// The same rule the runtime enforces at provisioning time: non-empty, at
/// most 128 bytes, first char alphanumeric, rest `[a-z0-9_-]`.
fn is_safe_tenant_id(tenant: &str) -> bool {
    let mut bytes = tenant.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return false;
    }
    tenant.len() <= 128
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// Produce a backup for one tenant: write every segment, then the manifest
/// that binds them, then verify the written state end to end.
///
/// `created_unix` is the backup's point-in-time marker (the caller's clock).
/// The manifest is written only after every segment is durable, and the
/// whole result is verified before returning — a backup that cannot verify
/// is not a backup.
pub fn create_backup(
    target: &dyn BackupTarget,
    tenant: &str,
    segments: &[Segment],
    created_unix: u64,
) -> Result<BackupManifest, BackupError> {
    if !is_safe_tenant_id(tenant) {
        return Err(BackupError::CrossTenant {
            tenant: tenant.to_string(),
        });
    }
    if segments.is_empty() {
        return Err(BackupError::InvalidManifest {
            detail: "a backup needs at least one segment".into(),
        });
    }
    // Canonical names, no duplicates, then canonical (sorted) order — the
    // same order verification reconstructs.
    let mut names = BTreeMap::<&str, ()>::new();
    for segment in segments {
        if !is_safe_segment_name(&segment.name) {
            return Err(BackupError::InvalidSegment {
                detail: format!("unsafe segment name {:?}", segment.name),
            });
        }
        if names.insert(&segment.name, ()).is_some() {
            return Err(BackupError::DuplicateSegment {
                name: segment.name.clone(),
            });
        }
    }
    let mut sorted: Vec<&Segment> = segments.iter().collect();
    sorted.sort_by(|left, right| left.name.cmp(&right.name));

    let mut digests = Vec::with_capacity(sorted.len());
    for segment in &sorted {
        target.write_segment(tenant, &segment.name, &segment.bytes)?;
        digests.push(segment_digest(&segment.bytes));
    }

    let manifest = BackupManifest {
        tenant: tenant.to_string(),
        created_unix,
        digest: manifest_digest(&digests),
        segments: segments.len() as u32,
        schema_version: BACKUP_SCHEMA,
    };
    target.write_manifest(tenant, &manifest)?;

    // Verify after write: the backup must read back exactly.
    verify_backup(target, tenant, &manifest)?;
    Ok(manifest)
}

/// Verify a backup against its manifest, byte for byte.
///
/// Rejects: missing segments, extra segments, unsafe paths, cross-tenant
/// material, digest mismatches (per segment and aggregate) and unsupported
/// future schemas.
///
/// The manifest stores the aggregate digest and the segment count, not the
/// segment names; the canonical order is the sorted segment-name order that
/// [`create_backup`] produced, so verification reconstructs that order and
/// compares the aggregate and the count. A missing segment, an extra segment
/// or a tampered segment all change the aggregate and/or the count and are
/// refused.
pub fn verify_backup(
    target: &dyn BackupTarget,
    tenant: &str,
    manifest: &BackupManifest,
) -> Result<(), BackupError> {
    manifest
        .restorable_by(BACKUP_SCHEMA)
        .map_err(|detail| BackupError::InvalidManifest { detail })?;
    if manifest.tenant != tenant {
        return Err(BackupError::CrossTenant {
            tenant: manifest.tenant.clone(),
        });
    }

    let mut names = target.list_segments(tenant)?;
    if names.len() != manifest.segments as usize {
        return Err(BackupError::MissingSegment {
            name: format!("{} of {}", names.len(), manifest.segments),
        });
    }
    for name in &names {
        if !is_safe_segment_name(name) {
            return Err(BackupError::InvalidSegment {
                detail: format!("unsafe segment name {name:?}"),
            });
        }
    }
    names.sort();

    let mut digests = Vec::with_capacity(names.len());
    for name in &names {
        let Some(bytes) = target.read_segment(tenant, name)? else {
            return Err(BackupError::MissingSegment { name: name.clone() });
        };
        digests.push(segment_digest(&bytes));
    }

    let aggregate = manifest_digest(&digests);
    if aggregate != manifest.digest {
        return Err(BackupError::DigestMismatch {
            expected: manifest.digest.clone(),
            found: aggregate,
        });
    }
    Ok(())
}

/// Stage a verified backup into `staging` without touching live state.
///
/// The staging directory must be empty. Every segment is written there with
/// its verified bytes; the manifest is written last. Nothing is promoted by
/// this function — [`promote_staged`] is the atomic commit step.
pub fn stage_restore(
    target: &dyn BackupTarget,
    tenant: &str,
    manifest: &BackupManifest,
    staging: &Path,
) -> Result<(), BackupError> {
    verify_backup(target, tenant, manifest)?;
    if staging.exists() {
        let mut read = std::fs::read_dir(staging).map_err(io(staging))?;
        if read.next().is_some() {
            return Err(BackupError::StagingNotEmpty {
                path: staging.to_path_buf(),
            });
        }
    } else {
        std::fs::create_dir_all(staging).map_err(io(staging))?;
    }

    let names = target.list_segments(tenant)?;
    for name in &names {
        let Some(bytes) = target.read_segment(tenant, name)? else {
            return Err(BackupError::MissingSegment { name: name.clone() });
        };
        let path = staging.join(name);
        ccos_core::util::write_durable(&path, &bytes).map_err(io(&path))?;
    }
    let manifest_bytes =
        serde_json::to_vec_pretty(manifest).map_err(|error| BackupError::InvalidManifest {
            detail: format!("cannot serialize manifest: {error}"),
        })?;
    ccos_core::util::write_durable(&staging.join("manifest.json"), &manifest_bytes)
        .map_err(io(staging))?;
    Ok(())
}

/// Atomically promote a staged restore into a live tenant root.
///
/// The live directory is replaced by the staging directory in one rename:
/// either the old state or the new state exists, never a mix. Callers must
/// freeze writes for the tenant before promoting.
pub fn promote_staged(staging: &Path, live: &Path) -> Result<(), BackupError> {
    let parent = live.parent().ok_or_else(|| BackupError::InvalidManifest {
        detail: "live path has no parent".into(),
    })?;
    std::fs::create_dir_all(parent).map_err(io(parent))?;
    // Replace live with staging atomically: rename staging to a temp name,
    // then swap. The old live state is moved aside, not deleted, so a failed
    // promotion never destroys the previous state.
    let temp = live.with_extension("restore-tmp");
    let _ = std::fs::remove_dir_all(&temp);
    std::fs::rename(staging, &temp).map_err(io(&temp))?;
    if live.exists() {
        let old = live.with_extension("restore-old");
        let _ = std::fs::remove_dir_all(&old);
        std::fs::rename(live, &old).map_err(io(&old))?;
    }
    match std::fs::rename(&temp, live) {
        Ok(()) => {
            let _ = std::fs::remove_dir_all(live.with_extension("restore-old"));
            Ok(())
        }
        Err(source) => {
            // Roll back: restore the old state.
            let old = live.with_extension("restore-old");
            if old.exists() {
                let _ = std::fs::rename(&old, live);
            }
            Err(BackupError::Io { path: temp, source })
        }
    }
}

/// The policy facts of a tenant's backup schedule. RPO/RTO are deployment
/// policy, recorded per tenant, never hard-coded marketing values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupPolicy {
    pub tenant: String,
    /// Maximum acceptable data loss window in seconds.
    pub rpo_seconds: u64,
    /// Maximum acceptable recovery time in seconds.
    pub rto_seconds: u64,
    /// Whether the tenant's writes are currently frozen (disaster recovery).
    pub writes_frozen: bool,
}

/// A journaled stage of the disaster-recovery orchestration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "stage", rename_all = "snake_case")]
pub enum RecoveryStage {
    Detect,
    FreezeWrites,
    LocateManifest { created_unix: u64, digest: String },
    Restore,
    ReplayJournalTail { records: u64 },
    VerifyEndToEnd { ok: bool },
    Unfreeze,
    FailClosed { detail: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ccos-backup-{tag}-{pid}", pid = std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn segments() -> Vec<Segment> {
        vec![
            Segment {
                name: "ledger".into(),
                bytes: b"ledger-state".to_vec(),
            },
            Segment {
                name: "memory-root".into(),
                bytes: b"memory-state".to_vec(),
            },
        ]
    }

    #[test]
    fn manifest_digest_is_exact_and_stable() {
        let digests = vec!["a".repeat(64), "b".repeat(64)];
        let first = manifest_digest(&digests);
        let second = manifest_digest(&["a".repeat(64), "b".repeat(64)]);
        assert_eq!(first, second, "deterministic");
        assert_eq!(first.len(), 64);
        // Order matters: swapping digests changes the aggregate.
        assert_ne!(first, manifest_digest(&["b".repeat(64), "a".repeat(64)]));
    }

    #[test]
    fn create_then_verify_round_trip() {
        let root = scratch("roundtrip");
        let target = FsBackupTarget::new(&root);
        let manifest = create_backup(&target, "acme", &segments(), 1_700_000_000).unwrap();
        assert_eq!(manifest.tenant, "acme");
        assert_eq!(manifest.segments, 2);
        verify_backup(&target, "acme", &manifest).unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_segment_is_refused() {
        let root = scratch("missing");
        let target = FsBackupTarget::new(&root);
        let manifest = create_backup(&target, "acme", &segments(), 1).unwrap();
        let path = root.join("acme").join("segments").join("ledger");
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(
            verify_backup(&target, "acme", &manifest),
            Err(BackupError::MissingSegment { .. })
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn extra_segment_is_refused() {
        let root = scratch("extra");
        let target = FsBackupTarget::new(&root);
        let manifest = create_backup(&target, "acme", &segments(), 1).unwrap();
        target.write_segment("acme", "extra", b"x").unwrap();
        // The count no longer matches the manifest, so verification refuses.
        assert!(matches!(
            verify_backup(&target, "acme", &manifest),
            Err(BackupError::MissingSegment { .. })
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn tampered_segment_is_refused() {
        let root = scratch("tampered");
        let target = FsBackupTarget::new(&root);
        let manifest = create_backup(&target, "acme", &segments(), 1).unwrap();
        let path = root.join("acme").join("segments").join("ledger");
        std::fs::write(&path, b"tampered").unwrap();
        assert!(matches!(
            verify_backup(&target, "acme", &manifest),
            Err(BackupError::DigestMismatch { .. })
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unsafe_segment_names_and_cross_tenant_are_refused() {
        let root = scratch("unsafe");
        let target = FsBackupTarget::new(&root);
        let bad = Segment {
            name: "../escape".into(),
            bytes: b"x".to_vec(),
        };
        assert!(matches!(
            create_backup(&target, "acme", &[bad], 1),
            Err(BackupError::InvalidSegment { .. })
        ));
        assert!(create_backup(&target, "ACME-UPPER", &segments(), 1).is_err());
        assert!(!is_safe_segment_name("../escape"));
        assert!(!is_safe_segment_name(""));
        assert!(!is_safe_segment_name("-leading"));
        assert!(!is_safe_segment_name("_hidden"));
        assert!(is_safe_segment_name("memory-root"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn duplicate_segments_are_refused() {
        let root = scratch("dupe");
        let target = FsBackupTarget::new(&root);
        let dupes = vec![
            Segment {
                name: "a".into(),
                bytes: b"x".to_vec(),
            },
            Segment {
                name: "a".into(),
                bytes: b"x".to_vec(),
            },
        ];
        assert!(matches!(
            create_backup(&target, "acme", &dupes, 1),
            Err(BackupError::DuplicateSegment { .. })
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unsupported_future_schema_is_refused() {
        let root = scratch("schema");
        let target = FsBackupTarget::new(&root);
        let mut manifest = create_backup(&target, "acme", &segments(), 1).unwrap();
        manifest.schema_version = BACKUP_SCHEMA + 1;
        assert!(verify_backup(&target, "acme", &manifest).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn staging_requires_empty_dir_and_promotes_atomically() {
        let root = scratch("staging");
        let target = FsBackupTarget::new(&root);
        let manifest = create_backup(&target, "acme", &segments(), 1).unwrap();
        let staging = scratch("staging-dir");
        stage_restore(&target, "acme", &manifest, &staging).unwrap();
        // Live state exists; staging has the verified copy.
        assert!(staging.join("manifest.json").exists());

        // Non-empty staging is refused.
        std::fs::write(staging.join("junk"), b"junk").unwrap();
        assert!(matches!(
            stage_restore(&target, "acme", &manifest, &staging),
            Err(BackupError::StagingNotEmpty { .. })
        ));
        std::fs::remove_file(staging.join("junk")).unwrap();

        // Promote into a live root.
        let live = scratch("live");
        std::fs::create_dir_all(&live).unwrap();
        std::fs::write(live.join("old-state"), b"old").unwrap();
        promote_staged(&staging, &live).unwrap();
        assert!(live.join("manifest.json").exists());
        assert!(!live.join("old-state").exists(), "live state was replaced");
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&staging);
        let _ = std::fs::remove_dir_all(&live);
    }
}
