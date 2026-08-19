//! # CCOS Enterprise — Backup & Restore
//!
//! Tenant-scoped backup/restore with immutable backup generations and
//! crash-safe publication. A new backup never overwrites the generation named
//! by the current manifest. Production writes a complete generation, verifies
//! it, then atomically publishes a small `current` pointer. Restore follows the
//! same principle: stage and verify exact bytes, move them into an immutable
//! live generation, then atomically replace a symlink pointer. There is no
//! interval in a normal promotion where the public `live` path is absent.
//!
//! Schema v2 authenticates each segment's **name, length and content digest**.
//! Schema v1 remains readable for compatibility with existing manifests, but
//! new backups are always v2.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Latest manifest schema this build can restore.
pub const BACKUP_SCHEMA: u32 = 2;
const CURRENT_FILE: &str = "current";
const GENERATIONS_DIR: &str = "generations";
const MANIFEST_FILE: &str = "manifest.json";
const SEGMENTS_DIR: &str = "segments";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupManifest {
    pub tenant: String,
    pub created_unix: u64,
    /// v1: sha256 over concatenated content digests.
    /// v2: domain-separated sha256 over framed `(name, length, digest)` rows.
    pub digest: String,
    pub segments: u32,
    pub schema_version: u32,
}

impl BackupManifest {
    pub fn restorable_by(&self, build_schema: u32) -> Result<(), String> {
        if self.digest.len() != 64
            || !self
                .digest
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err("manifest digest is not lowercase 64-hex".into());
        }
        if self.segments == 0 {
            return Err("manifest has no segments".into());
        }
        if self.schema_version == 0 || self.schema_version > build_schema {
            return Err(format!(
                "snapshot schema v{} is unsupported by this build (latest v{})",
                self.schema_version, build_schema
            ));
        }
        if !is_safe_tenant_id(&self.tenant) {
            return Err("manifest tenant is not canonical".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub name: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBackup {
    pub manifest: BackupManifest,
    pub segments: Vec<Segment>,
}

pub fn segment_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(hasher.finalize())
}

/// Legacy v1 aggregate retained as public API for old manifests/tests.
pub fn manifest_digest(segment_digests: &[String]) -> String {
    let mut hasher = Sha256::new();
    for digest in segment_digests {
        hasher.update(digest.as_bytes());
    }
    hex(hasher.finalize())
}

/// Schema-v2 digest. Rows must already be sorted by name.
pub fn manifest_digest_v2(segments: &[Segment]) -> String {
    let mut rows: Vec<&Segment> = segments.iter().collect();
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    let mut hasher = Sha256::new();
    framed(&mut hasher, b"ccos-enterprise-backup-manifest-v2");
    hasher.update((rows.len() as u64).to_be_bytes());
    for segment in rows {
        let digest = segment_digest(&segment.bytes);
        framed(&mut hasher, segment.name.as_bytes());
        hasher.update((segment.bytes.len() as u64).to_be_bytes());
        framed(&mut hasher, digest.as_bytes());
    }
    hex(hasher.finalize())
}

fn framed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn hex(digest: sha2::digest::generic_array::GenericArray<u8, sha2::digest::consts::U32>) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub fn is_safe_segment_name(name: &str) -> bool {
    canonical_component(name, 128)
}

fn is_safe_tenant_id(tenant: &str) -> bool {
    canonical_component(tenant, 128)
}

fn canonical_component(value: &str, max: usize) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    value.len() <= max
        && (first.is_ascii_lowercase() || first.is_ascii_digit())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

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
    UnsafeLiveLayout {
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
            Self::DigestMismatch { expected, found } => {
                write!(f, "digest mismatch: expected {expected}, found {found}")
            }
            Self::MissingSegment { name } => write!(f, "manifest names missing segment {name:?}"),
            Self::ExtraSegment { name } => write!(f, "backup holds extra segment {name:?}"),
            Self::DuplicateSegment { name } => write!(f, "backup holds duplicate segment {name:?}"),
            Self::UnsupportedSchema { found } => write!(f, "unsupported backup schema v{found}"),
            Self::CrossTenant { tenant } => write!(f, "backup material belongs to tenant {tenant:?}"),
            Self::StagingNotEmpty { path } => {
                write!(f, "staging directory is not empty: {}", path.display())
            }
            Self::UnsafeLiveLayout { path } => write!(
                f,
                "live path {} is a mutable directory; migrate it offline to the versioned pointer layout before atomic promotion",
                path.display()
            ),
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

/// A target publishes complete immutable generations. The only mutating
/// operation receives the complete manifest and segment set, so an
/// implementation cannot accidentally expose half a backup through this API.
pub trait BackupTarget {
    fn read_backup(&self, tenant: &str) -> Result<Option<StoredBackup>, BackupError>;
    fn publish_backup(
        &self,
        tenant: &str,
        manifest: &BackupManifest,
        segments: &[Segment],
    ) -> Result<(), BackupError>;

    fn read_segment(&self, tenant: &str, name: &str) -> Result<Option<Vec<u8>>, BackupError> {
        Ok(self
            .read_backup(tenant)?
            .and_then(|backup| backup.segments.into_iter().find(|s| s.name == name))
            .map(|segment| segment.bytes))
    }

    fn list_segments(&self, tenant: &str) -> Result<Vec<String>, BackupError> {
        let mut names = self
            .read_backup(tenant)?
            .map(|backup| {
                backup
                    .segments
                    .into_iter()
                    .map(|segment| segment.name)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        names.sort();
        Ok(names)
    }

    fn read_manifest(&self, tenant: &str) -> Result<Option<BackupManifest>, BackupError> {
        Ok(self.read_backup(tenant)?.map(|backup| backup.manifest))
    }
}

/// Filesystem target layout:
///
/// `<root>/<tenant>/generations/<generation>/{manifest.json,segments/*}`
/// `<root>/<tenant>/current`
///
/// A generation is immutable after its directory is published. `current` is a
/// small durable file changed atomically only after generation verification.
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

    fn generations_dir(&self, tenant: &str) -> Result<PathBuf, BackupError> {
        Ok(self.tenant_root(tenant)?.join(GENERATIONS_DIR))
    }

    fn current_path(&self, tenant: &str) -> Result<PathBuf, BackupError> {
        Ok(self.tenant_root(tenant)?.join(CURRENT_FILE))
    }

    fn read_current_generation(&self, tenant: &str) -> Result<Option<String>, BackupError> {
        let path = self.current_path(tenant)?;
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(BackupError::Io { path, source }),
        };
        let generation = std::str::from_utf8(&bytes)
            .map_err(|error| BackupError::CorruptManifest {
                path: path.clone(),
                detail: format!("current generation is not UTF-8: {error}"),
            })?
            .trim();
        if !canonical_component(generation, 160) {
            return Err(BackupError::CorruptManifest {
                path,
                detail: "current generation id is not canonical".into(),
            });
        }
        Ok(Some(generation.to_string()))
    }

    pub fn current_generation_dir(&self, tenant: &str) -> Result<Option<PathBuf>, BackupError> {
        Ok(self
            .read_current_generation(tenant)?
            .map(|generation| self.root.join(tenant).join(GENERATIONS_DIR).join(generation)))
    }

    fn generation_id(manifest: &BackupManifest) -> String {
        format!("g{}-{}", manifest.created_unix, manifest.digest)
    }

    fn read_generation_dir(path: &Path) -> Result<StoredBackup, BackupError> {
        let manifest_path = path.join(MANIFEST_FILE);
        let manifest_bytes = std::fs::read(&manifest_path).map_err(io(&manifest_path))?;
        let manifest: BackupManifest = serde_json::from_slice(&manifest_bytes).map_err(|error| {
            BackupError::CorruptManifest {
                path: manifest_path.clone(),
                detail: error.to_string(),
            }
        })?;
        let segments_path = path.join(SEGMENTS_DIR);
        let entries = std::fs::read_dir(&segments_path).map_err(io(&segments_path))?;
        let mut segments = Vec::new();
        for entry in entries {
            let entry = entry.map_err(io(&segments_path))?;
            let ty = entry.file_type().map_err(io(&segments_path))?;
            if !ty.is_file() {
                return Err(BackupError::InvalidSegment {
                    detail: format!("non-file entry in segments: {:?}", entry.file_name()),
                });
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| BackupError::InvalidSegment {
                    detail: "non-UTF-8 segment name".into(),
                })?;
            if !is_safe_segment_name(&name) {
                return Err(BackupError::InvalidSegment {
                    detail: format!("unsafe segment name {name:?}"),
                });
            }
            let bytes = std::fs::read(entry.path()).map_err(io(&entry.path()))?;
            segments.push(Segment { name, bytes });
        }
        segments.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(StoredBackup { manifest, segments })
    }

    fn write_generation_dir(
        path: &Path,
        manifest: &BackupManifest,
        segments: &[Segment],
    ) -> Result<(), BackupError> {
        std::fs::create_dir_all(path.join(SEGMENTS_DIR)).map_err(io(path))?;
        for segment in segments {
            let segment_path = path.join(SEGMENTS_DIR).join(&segment.name);
            ccos_core::util::write_durable(&segment_path, &segment.bytes).map_err(io(&segment_path))?;
        }
        let manifest_bytes = serde_json::to_vec_pretty(manifest).map_err(|error| {
            BackupError::InvalidManifest {
                detail: format!("cannot serialize manifest: {error}"),
            }
        })?;
        let manifest_path = path.join(MANIFEST_FILE);
        ccos_core::util::write_durable(&manifest_path, &manifest_bytes).map_err(io(&manifest_path))?;
        std::fs::File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(io(path))?;
        Ok(())
    }
}

impl BackupTarget for FsBackupTarget {
    fn read_backup(&self, tenant: &str) -> Result<Option<StoredBackup>, BackupError> {
        let Some(path) = self.current_generation_dir(tenant)? else {
            return Ok(None);
        };
        Ok(Some(Self::read_generation_dir(&path)?))
    }

    fn publish_backup(
        &self,
        tenant: &str,
        manifest: &BackupManifest,
        segments: &[Segment],
    ) -> Result<(), BackupError> {
        if manifest.tenant != tenant {
            return Err(BackupError::CrossTenant {
                tenant: manifest.tenant.clone(),
            });
        }
        let tenant_root = self.tenant_root(tenant)?;
        let generations = self.generations_dir(tenant)?;
        std::fs::create_dir_all(&generations).map_err(io(&generations))?;
        let generation = Self::generation_id(manifest);
        let final_dir = generations.join(&generation);
        let temp_dir = generations.join(format!("tmp-{generation}"));
        if temp_dir.exists() {
            std::fs::remove_dir_all(&temp_dir).map_err(io(&temp_dir))?;
        }
        Self::write_generation_dir(&temp_dir, manifest, segments)?;
        let staged = Self::read_generation_dir(&temp_dir)?;
        verify_stored(tenant, manifest, &staged)?;

        if final_dir.exists() {
            let existing = Self::read_generation_dir(&final_dir)?;
            verify_stored(tenant, manifest, &existing)?;
            if existing != staged {
                return Err(BackupError::InvalidManifest {
                    detail: "generation id collision with different bytes".into(),
                });
            }
            std::fs::remove_dir_all(&temp_dir).map_err(io(&temp_dir))?;
        } else {
            std::fs::rename(&temp_dir, &final_dir).map_err(io(&final_dir))?;
            std::fs::File::open(&generations)
                .and_then(|directory| directory.sync_all())
                .map_err(io(&generations))?;
        }

        std::fs::create_dir_all(&tenant_root).map_err(io(&tenant_root))?;
        let current = self.current_path(tenant)?;
        ccos_core::util::write_durable(&current, format!("{generation}\n").as_bytes())
            .map_err(io(&current))?;
        Ok(())
    }
}

fn validate_segments(segments: &[Segment]) -> Result<(), BackupError> {
    if segments.is_empty() {
        return Err(BackupError::InvalidManifest {
            detail: "a backup needs at least one segment".into(),
        });
    }
    if segments.len() > u32::MAX as usize {
        return Err(BackupError::InvalidManifest {
            detail: "too many segments".into(),
        });
    }
    let mut names = BTreeSet::new();
    for segment in segments {
        if !is_safe_segment_name(&segment.name) {
            return Err(BackupError::InvalidSegment {
                detail: format!("unsafe segment name {:?}", segment.name),
            });
        }
        if !names.insert(segment.name.as_str()) {
            return Err(BackupError::DuplicateSegment {
                name: segment.name.clone(),
            });
        }
    }
    Ok(())
}

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
    validate_segments(segments)?;
    let manifest = BackupManifest {
        tenant: tenant.to_string(),
        created_unix,
        digest: manifest_digest_v2(segments),
        segments: segments.len() as u32,
        schema_version: BACKUP_SCHEMA,
    };
    target.publish_backup(tenant, &manifest, segments)?;
    verify_backup(target, tenant, &manifest)?;
    Ok(manifest)
}

fn verify_stored(
    tenant: &str,
    expected: &BackupManifest,
    stored: &StoredBackup,
) -> Result<(), BackupError> {
    expected
        .restorable_by(BACKUP_SCHEMA)
        .map_err(|detail| BackupError::InvalidManifest { detail })?;
    stored
        .manifest
        .restorable_by(BACKUP_SCHEMA)
        .map_err(|detail| BackupError::InvalidManifest { detail })?;
    if expected.tenant != tenant || stored.manifest.tenant != tenant {
        return Err(BackupError::CrossTenant {
            tenant: stored.manifest.tenant.clone(),
        });
    }
    if &stored.manifest != expected {
        return Err(BackupError::InvalidManifest {
            detail: "published manifest differs from requested manifest".into(),
        });
    }
    validate_segments(&stored.segments)?;
    if stored.segments.len() != expected.segments as usize {
        return Err(BackupError::MissingSegment {
            name: format!("{} of {}", stored.segments.len(), expected.segments),
        });
    }
    let found = match expected.schema_version {
        1 => {
            let mut rows: Vec<&Segment> = stored.segments.iter().collect();
            rows.sort_by(|a, b| a.name.cmp(&b.name));
            manifest_digest(
                &rows
                    .into_iter()
                    .map(|segment| segment_digest(&segment.bytes))
                    .collect::<Vec<_>>(),
            )
        }
        2 => manifest_digest_v2(&stored.segments),
        found => return Err(BackupError::UnsupportedSchema { found }),
    };
    if found != expected.digest {
        return Err(BackupError::DigestMismatch {
            expected: expected.digest.clone(),
            found,
        });
    }
    Ok(())
}

pub fn verify_backup(
    target: &dyn BackupTarget,
    tenant: &str,
    manifest: &BackupManifest,
) -> Result<(), BackupError> {
    let stored = target
        .read_backup(tenant)?
        .ok_or_else(|| BackupError::MissingSegment {
            name: "backup generation".into(),
        })?;
    verify_stored(tenant, manifest, &stored)
}

/// Restore uses one target snapshot: the exact bytes verified are the bytes
/// written to staging. The completed staging tree is then read back and
/// verified again before it becomes eligible for promotion.
pub fn stage_restore(
    target: &dyn BackupTarget,
    tenant: &str,
    manifest: &BackupManifest,
    staging: &Path,
) -> Result<(), BackupError> {
    let stored = target
        .read_backup(tenant)?
        .ok_or_else(|| BackupError::MissingSegment {
            name: "backup generation".into(),
        })?;
    verify_stored(tenant, manifest, &stored)?;

    if staging.exists() {
        if std::fs::read_dir(staging).map_err(io(staging))?.next().is_some() {
            return Err(BackupError::StagingNotEmpty {
                path: staging.to_path_buf(),
            });
        }
    } else {
        std::fs::create_dir_all(staging).map_err(io(staging))?;
    }
    std::fs::create_dir_all(staging.join(SEGMENTS_DIR)).map_err(io(staging))?;
    for segment in &stored.segments {
        let path = staging.join(SEGMENTS_DIR).join(&segment.name);
        ccos_core::util::write_durable(&path, &segment.bytes).map_err(io(&path))?;
    }
    let manifest_bytes = serde_json::to_vec_pretty(manifest).map_err(|error| {
        BackupError::InvalidManifest {
            detail: format!("cannot serialize manifest: {error}"),
        }
    })?;
    let manifest_path = staging.join(MANIFEST_FILE);
    ccos_core::util::write_durable(&manifest_path, &manifest_bytes).map_err(io(&manifest_path))?;
    std::fs::File::open(staging)
        .and_then(|directory| directory.sync_all())
        .map_err(io(staging))?;

    let staged = FsBackupTarget::read_generation_dir(staging)?;
    verify_stored(tenant, manifest, &staged)?;
    Ok(())
}

fn live_generations_dir(live: &Path) -> Result<PathBuf, BackupError> {
    let parent = live.parent().ok_or_else(|| BackupError::InvalidManifest {
        detail: "live path has no parent".into(),
    })?;
    let name = live
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| BackupError::InvalidManifest {
            detail: "live path has no UTF-8 basename".into(),
        })?;
    if !canonical_component(name, 128) {
        return Err(BackupError::InvalidManifest {
            detail: "live basename is not canonical".into(),
        });
    }
    Ok(parent.join(format!(".{name}-restore-generations")))
}

/// Promote by immutable generation + atomic symlink replacement.
///
/// If `live` already exists it must itself be a symlink produced by this
/// mechanism. A historical mutable directory is refused rather than moved
/// aside online; migrate that legacy layout while the tenant is offline once,
/// then every later switch is a single atomic rename of a symlink.
pub fn promote_staged(staging: &Path, live: &Path) -> Result<(), BackupError> {
    let staged = FsBackupTarget::read_generation_dir(staging)?;
    verify_stored(&staged.manifest.tenant, &staged.manifest, &staged)?;

    if live.exists() || std::fs::symlink_metadata(live).is_ok() {
        let metadata = std::fs::symlink_metadata(live).map_err(io(live))?;
        if !metadata.file_type().is_symlink() {
            return Err(BackupError::UnsafeLiveLayout {
                path: live.to_path_buf(),
            });
        }
    }

    let parent = live.parent().ok_or_else(|| BackupError::InvalidManifest {
        detail: "live path has no parent".into(),
    })?;
    std::fs::create_dir_all(parent).map_err(io(parent))?;
    let generations = live_generations_dir(live)?;
    std::fs::create_dir_all(&generations).map_err(io(&generations))?;
    let generation = FsBackupTarget::generation_id(&staged.manifest);
    let final_dir = generations.join(&generation);
    if final_dir.exists() {
        let existing = FsBackupTarget::read_generation_dir(&final_dir)?;
        verify_stored(&staged.manifest.tenant, &staged.manifest, &existing)?;
        if existing != staged {
            return Err(BackupError::InvalidManifest {
                detail: "live generation id collision with different bytes".into(),
            });
        }
        std::fs::remove_dir_all(staging).map_err(io(staging))?;
    } else {
        std::fs::rename(staging, &final_dir).map_err(io(&final_dir))?;
        std::fs::File::open(&generations)
            .and_then(|directory| directory.sync_all())
            .map_err(io(&generations))?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let live_name = live.file_name().and_then(|v| v.to_str()).unwrap_or("live");
        let next = parent.join(format!(".{live_name}.next-{}", std::process::id()));
        let _ = std::fs::remove_file(&next);
        // Relative target keeps the pointer valid if the whole parent tree is moved.
        let generation_dir_name = generations
            .file_name()
            .ok_or_else(|| BackupError::InvalidManifest {
                detail: "generation directory has no basename".into(),
            })?;
        let relative = PathBuf::from(generation_dir_name).join(&generation);
        symlink(&relative, &next).map_err(io(&next))?;
        std::fs::rename(&next, live).map_err(io(live))?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(io(parent))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = final_dir;
        Err(BackupError::InvalidManifest {
            detail: "atomic live generation switching is currently supported on Unix deployments only"
                .into(),
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupPolicy {
    pub tenant: String,
    pub rpo_seconds: u64,
    pub rto_seconds: u64,
    /// Runtime freeze state. Recovery sets this before restore and clears it
    /// only after replay and end-to-end verification both succeed.
    pub writes_frozen: bool,
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryOutcome {
    pub tenant: String,
    pub stages: Vec<RecoveryStage>,
    pub at_unix: u64,
    pub recovered: bool,
}

/// Recovery owns the ordering and freeze state. The replay callback performs
/// the actual deterministic journal-tail replay and returns the number of
/// records applied; the verification callback runs against the atomically
/// switched live path. Any error leaves `policy.writes_frozen == true`.
#[allow(clippy::too_many_arguments)]
pub fn run_disaster_recovery(
    tenant: &str,
    policy: &mut BackupPolicy,
    target: &dyn BackupTarget,
    staging: &Path,
    live: &Path,
    now: u64,
    replay_tail: &dyn Fn(&Path) -> Result<u64, String>,
    verify_live: &dyn Fn(&Path) -> Result<(), String>,
) -> RecoveryOutcome {
    let mut stages = vec![RecoveryStage::Detect];
    let failed = |stages: Vec<RecoveryStage>| RecoveryOutcome {
        tenant: tenant.to_string(),
        stages,
        at_unix: now,
        recovered: false,
    };
    if policy.tenant != tenant {
        stages.push(RecoveryStage::FailClosed {
            detail: "policy belongs to a different tenant".into(),
        });
        return failed(stages);
    }

    policy.writes_frozen = true;
    stages.push(RecoveryStage::FreezeWrites);

    let manifest = match target.read_manifest(tenant) {
        Ok(Some(manifest)) => match verify_backup(target, tenant, &manifest) {
            Ok(()) => {
                stages.push(RecoveryStage::LocateManifest {
                    created_unix: manifest.created_unix,
                    digest: manifest.digest.clone(),
                });
                manifest
            }
            Err(error) => {
                stages.push(RecoveryStage::FailClosed {
                    detail: format!("latest manifest fails verification: {error}"),
                });
                return failed(stages);
            }
        },
        Ok(None) => {
            stages.push(RecoveryStage::FailClosed {
                detail: "no backup manifest exists for this tenant".into(),
            });
            return failed(stages);
        }
        Err(error) => {
            stages.push(RecoveryStage::FailClosed {
                detail: format!("cannot read backup manifest: {error}"),
            });
            return failed(stages);
        }
    };

    stages.push(RecoveryStage::Restore);
    if let Err(error) = stage_restore(target, tenant, &manifest, staging) {
        stages.push(RecoveryStage::FailClosed {
            detail: format!("staging failed: {error}"),
        });
        return failed(stages);
    }
    if let Err(error) = promote_staged(staging, live) {
        stages.push(RecoveryStage::FailClosed {
            detail: format!("promotion failed: {error}"),
        });
        return failed(stages);
    }

    let replayed = match replay_tail(live) {
        Ok(records) => records,
        Err(error) => {
            stages.push(RecoveryStage::FailClosed {
                detail: format!("journal replay failed: {error}"),
            });
            return failed(stages);
        }
    };
    stages.push(RecoveryStage::ReplayJournalTail { records: replayed });

    match verify_live(live) {
        Ok(()) => stages.push(RecoveryStage::VerifyEndToEnd { ok: true }),
        Err(error) => {
            stages.push(RecoveryStage::VerifyEndToEnd { ok: false });
            stages.push(RecoveryStage::FailClosed {
                detail: format!("end-to-end verification failed: {error}"),
            });
            return failed(stages);
        }
    }

    policy.writes_frozen = false;
    stages.push(RecoveryStage::Unfreeze);
    RecoveryOutcome {
        tenant: tenant.to_string(),
        stages,
        at_unix: now,
        recovered: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ccos-backup-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn segments(version: u8) -> Vec<Segment> {
        vec![
            Segment {
                name: "ledger".into(),
                bytes: format!("ledger-v{version}").into_bytes(),
            },
            Segment {
                name: "memory-root".into(),
                bytes: format!("memory-v{version}").into_bytes(),
            },
        ]
    }

    #[test]
    fn v2_digest_authenticates_names_lengths_and_bytes() {
        let a = vec![Segment {
            name: "ledger".into(),
            bytes: b"same".to_vec(),
        }];
        let b = vec![Segment {
            name: "renamed".into(),
            bytes: b"same".to_vec(),
        }];
        assert_ne!(manifest_digest_v2(&a), manifest_digest_v2(&b));
        let c = vec![Segment {
            name: "ledger".into(),
            bytes: b"different".to_vec(),
        }];
        assert_ne!(manifest_digest_v2(&a), manifest_digest_v2(&c));
    }

    #[test]
    fn publishing_new_generation_never_overwrites_last_good() {
        let root = scratch("generation");
        let target = FsBackupTarget::new(&root);
        let first = create_backup(&target, "acme", &segments(1), 1).unwrap();
        let first_dir = target.current_generation_dir("acme").unwrap().unwrap();
        let first_bytes = std::fs::read(first_dir.join(SEGMENTS_DIR).join("ledger")).unwrap();
        let second = create_backup(&target, "acme", &segments(2), 2).unwrap();
        assert_ne!(first.digest, second.digest);
        assert_eq!(
            std::fs::read(first_dir.join(SEGMENTS_DIR).join("ledger")).unwrap(),
            first_bytes,
            "old generation was mutated"
        );
        assert_eq!(target.read_segment("acme", "ledger").unwrap().unwrap(), b"ledger-v2");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rename_attack_is_detected() {
        let root = scratch("rename");
        let target = FsBackupTarget::new(&root);
        let manifest = create_backup(&target, "acme", &segments(1), 1).unwrap();
        let dir = target.current_generation_dir("acme").unwrap().unwrap();
        std::fs::rename(
            dir.join(SEGMENTS_DIR).join("ledger"),
            dir.join(SEGMENTS_DIR).join("ledger-renamed"),
        )
        .unwrap();
        assert!(matches!(
            verify_backup(&target, "acme", &manifest),
            Err(BackupError::DigestMismatch { .. })
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn stage_uses_and_reverifies_exact_snapshot_bytes() {
        let root = scratch("stage");
        let target = FsBackupTarget::new(&root);
        let manifest = create_backup(&target, "acme", &segments(1), 1).unwrap();
        let staging = scratch("stage-tree");
        stage_restore(&target, "acme", &manifest, &staging).unwrap();
        let staged = FsBackupTarget::read_generation_dir(&staging).unwrap();
        verify_stored("acme", &manifest, &staged).unwrap();
        assert_eq!(
            std::fs::read(staging.join(SEGMENTS_DIR).join("ledger")).unwrap(),
            b"ledger-v1"
        );
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(staging);
    }

    #[test]
    #[cfg(unix)]
    fn promotion_switches_symlink_atomically_and_preserves_old_generation() {
        let root = scratch("promote-source");
        let target = FsBackupTarget::new(&root);
        let first = create_backup(&target, "acme", &segments(1), 1).unwrap();
        let parent = scratch("live-parent");
        std::fs::create_dir_all(&parent).unwrap();
        let live = parent.join("live");

        let staging1 = parent.join("stage1");
        stage_restore(&target, "acme", &first, &staging1).unwrap();
        promote_staged(&staging1, &live).unwrap();
        assert!(std::fs::symlink_metadata(&live).unwrap().file_type().is_symlink());
        assert_eq!(
            std::fs::read(live.join(SEGMENTS_DIR).join("ledger")).unwrap(),
            b"ledger-v1"
        );
        let old_target = std::fs::read_link(&live).unwrap();

        let second = create_backup(&target, "acme", &segments(2), 2).unwrap();
        let staging2 = parent.join("stage2");
        stage_restore(&target, "acme", &second, &staging2).unwrap();
        promote_staged(&staging2, &live).unwrap();
        let new_target = std::fs::read_link(&live).unwrap();
        assert_ne!(old_target, new_target);
        assert!(parent.join(old_target).exists(), "old live generation was deleted");
        assert_eq!(
            std::fs::read(live.join(SEGMENTS_DIR).join("ledger")).unwrap(),
            b"ledger-v2"
        );
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(parent);
    }

    #[test]
    #[cfg(unix)]
    fn mutable_live_directory_is_refused_not_moved_aside() {
        let root = scratch("legacy-source");
        let target = FsBackupTarget::new(&root);
        let manifest = create_backup(&target, "acme", &segments(1), 1).unwrap();
        let parent = scratch("legacy-live-parent");
        std::fs::create_dir_all(&parent).unwrap();
        let live = parent.join("live");
        std::fs::create_dir_all(&live).unwrap();
        std::fs::write(live.join("old"), b"must remain").unwrap();
        let staging = parent.join("stage");
        stage_restore(&target, "acme", &manifest, &staging).unwrap();
        assert!(matches!(
            promote_staged(&staging, &live),
            Err(BackupError::UnsafeLiveLayout { .. })
        ));
        assert_eq!(std::fs::read(live.join("old")).unwrap(), b"must remain");
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(parent);
    }

    #[test]
    #[cfg(unix)]
    fn disaster_recovery_executes_replay_and_unfreezes_only_after_verification() {
        let root = scratch("dr");
        let target = FsBackupTarget::new(&root);
        let manifest = create_backup(&target, "acme", &segments(1), 1).unwrap();
        let parent = scratch("dr-parent");
        std::fs::create_dir_all(&parent).unwrap();
        let staging = parent.join("stage");
        let live = parent.join("live");
        let mut policy = BackupPolicy {
            tenant: "acme".into(),
            rpo_seconds: 300,
            rto_seconds: 600,
            writes_frozen: false,
        };
        let outcome = run_disaster_recovery(
            "acme",
            &mut policy,
            &target,
            &staging,
            &live,
            100,
            &|path| {
                assert!(path.exists());
                Ok(7)
            },
            &|path| {
                let bytes = std::fs::read(path.join(SEGMENTS_DIR).join("ledger"))
                    .map_err(|error| error.to_string())?;
                (bytes == b"ledger-v1")
                    .then_some(())
                    .ok_or_else(|| "wrong live bytes".to_string())
            },
        );
        assert!(outcome.recovered);
        assert!(!policy.writes_frozen);
        assert_eq!(
            outcome.stages,
            vec![
                RecoveryStage::Detect,
                RecoveryStage::FreezeWrites,
                RecoveryStage::LocateManifest {
                    created_unix: manifest.created_unix,
                    digest: manifest.digest,
                },
                RecoveryStage::Restore,
                RecoveryStage::ReplayJournalTail { records: 7 },
                RecoveryStage::VerifyEndToEnd { ok: true },
                RecoveryStage::Unfreeze,
            ]
        );
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(parent);
    }

    #[test]
    #[cfg(unix)]
    fn recovery_failure_remains_frozen() {
        let root = scratch("dr-fail");
        let target = FsBackupTarget::new(&root);
        create_backup(&target, "acme", &segments(1), 1).unwrap();
        let parent = scratch("dr-fail-parent");
        std::fs::create_dir_all(&parent).unwrap();
        let mut policy = BackupPolicy {
            tenant: "acme".into(),
            rpo_seconds: 300,
            rto_seconds: 600,
            writes_frozen: false,
        };
        let outcome = run_disaster_recovery(
            "acme",
            &mut policy,
            &target,
            &parent.join("stage"),
            &parent.join("live"),
            100,
            &|_| Err("replay failed".into()),
            &|_| Ok(()),
        );
        assert!(!outcome.recovered);
        assert!(policy.writes_frozen);
        assert!(!outcome
            .stages
            .iter()
            .any(|stage| matches!(stage, RecoveryStage::Unfreeze)));
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(parent);
    }
}
