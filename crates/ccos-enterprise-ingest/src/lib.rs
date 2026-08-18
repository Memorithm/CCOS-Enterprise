//! Deterministic ingestion boundary for the CCOS Enterprise Knowledge Plane.
//!
//! P1a intentionally starts with local, read-only sources. The crate has no network
//! dependency and never mutates canonical knowledge. It turns source bytes into a
//! tenant-scoped [`RawArtifact`] carrying a stable virtual locator and SHA-256 digest;
//! callers must still submit the derived source/evidence records through the P0 journal.
//!
//! Absolute host paths are deliberately not used as canonical locators or identifiers.
//! A configured source namespace plus a root-relative UTF-8 path defines identity, so the
//! same dataset mounted at different host paths yields the same source IDs.

#![forbid(unsafe_code)]

use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Take};
use std::path::{Component, Path, PathBuf};

use ccos_enterprise_knowledge_model::{
    EvidenceId, EvidenceRecord, SourceId, SourceRecord, SourceTrust, TenantId,
};
use sha2::{Digest, Sha256};

pub const INGESTION_CONTRACT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestLimits {
    pub max_files: usize,
    pub max_artifact_bytes: u64,
    pub max_total_bytes: u64,
}

impl Default for IngestLimits {
    fn default() -> Self {
        Self {
            max_files: 10_000,
            max_artifact_bytes: 16 * 1024 * 1024,
            max_total_bytes: 512 * 1024 * 1024,
        }
    }
}

impl IngestLimits {
    fn validate(self) -> Result<Self, IngestError> {
        if self.max_files == 0 || self.max_artifact_bytes == 0 || self.max_total_bytes == 0 {
            return Err(IngestError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDescriptor {
    tenant: TenantId,
    source_id: SourceId,
    virtual_uri: String,
    media_type: &'static str,
    byte_len: u64,
    local_path: PathBuf,
}

impl SourceDescriptor {
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub fn source_id(&self) -> &SourceId {
        &self.source_id
    }

    pub fn virtual_uri(&self) -> &str {
        &self.virtual_uri
    }

    pub fn media_type(&self) -> &'static str {
        self.media_type
    }

    pub fn byte_len(&self) -> u64 {
        self.byte_len
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawArtifact {
    pub tenant: TenantId,
    pub source_id: SourceId,
    pub virtual_uri: String,
    pub media_type: String,
    pub content_hash: String,
    pub bytes: Vec<u8>,
}

impl RawArtifact {
    pub fn source_record(&self, trust: SourceTrust) -> SourceRecord {
        SourceRecord {
            id: self.source_id.clone(),
            tenant: self.tenant.clone(),
            locator: self.virtual_uri.clone(),
            content_hash: Some(self.content_hash.clone()),
            trust,
        }
    }

    /// Evidence for the whole immutable byte artifact. Fine-grained parsers can later
    /// create additional evidence records whose locators point into this same source.
    pub fn whole_artifact_evidence(&self) -> EvidenceRecord {
        let mut hasher = Sha256::new();
        hasher.update(self.tenant.0.as_bytes());
        hasher.update([0]);
        hasher.update(self.source_id.as_str().as_bytes());
        hasher.update([0]);
        hasher.update(self.content_hash.as_bytes());
        let digest = hasher.finalize();
        EvidenceRecord {
            id: EvidenceId::new(format!("evidence:artifact:{}", hex_lower(&digest))),
            tenant: self.tenant.clone(),
            source: self.source_id.clone(),
            locator: Some(format!("bytes:0-{}", self.bytes.len())),
            content_hash: Some(self.content_hash.clone()),
        }
    }
}

pub trait KnowledgeSource {
    type Descriptor;

    fn enumerate(&self) -> Result<Vec<Self::Descriptor>, IngestError>;
    fn fetch(&self, descriptor: &Self::Descriptor) -> Result<RawArtifact, IngestError>;
}

#[derive(Debug)]
pub enum IngestError {
    InvalidNamespace,
    InvalidLimits,
    RootIsSymlink(PathBuf),
    RootNotDirectory(PathBuf),
    NonUtf8Path(PathBuf),
    EscapesRoot(PathBuf),
    TooManyFiles {
        limit: usize,
    },
    ArtifactTooLarge {
        path: String,
        limit: u64,
        observed: u64,
    },
    TotalTooLarge {
        limit: u64,
        observed: u64,
    },
    DescriptorMismatch,
    UnsupportedFile(PathBuf),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl fmt::Display for IngestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNamespace => {
                f.write_str("source namespace must be a non-empty [A-Za-z0-9._-] identifier")
            }
            Self::InvalidLimits => f.write_str("ingestion limits must all be greater than zero"),
            Self::RootIsSymlink(path) => {
                write!(f, "ingestion root is a symlink: {}", path.display())
            }
            Self::RootNotDirectory(path) => {
                write!(f, "ingestion root is not a directory: {}", path.display())
            }
            Self::NonUtf8Path(path) => {
                write!(f, "source path is not valid UTF-8: {}", path.display())
            }
            Self::EscapesRoot(path) => {
                write!(f, "source path escapes configured root: {}", path.display())
            }
            Self::TooManyFiles { limit } => {
                write!(f, "source contains more than {limit} accepted files")
            }
            Self::ArtifactTooLarge {
                path,
                limit,
                observed,
            } => write!(
                f,
                "artifact {path} is {observed} bytes, over {limit}-byte limit"
            ),
            Self::TotalTooLarge { limit, observed } => write!(
                f,
                "enumerated source is {observed} bytes, over {limit}-byte limit"
            ),
            Self::DescriptorMismatch => {
                f.write_str("descriptor does not belong to this source instance")
            }
            Self::UnsupportedFile(path) => {
                write!(f, "unsupported local source file: {}", path.display())
            }
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
        }
    }
}

impl std::error::Error for IngestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> IngestError + '_ {
    move |source| IngestError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Read-only local tree source. Symlinks are never followed and unsupported file types
/// are ignored during enumeration. Accepted P1a formats remain raw bytes; parsing and
/// normalization are separate phases and cannot silently rewrite source evidence.
pub struct LocalTreeSource {
    tenant: TenantId,
    namespace: String,
    root: PathBuf,
    limits: IngestLimits,
}

impl LocalTreeSource {
    pub fn new(
        tenant: TenantId,
        namespace: impl Into<String>,
        root: impl AsRef<Path>,
        limits: IngestLimits,
    ) -> Result<Self, IngestError> {
        let namespace = namespace.into();
        if namespace.is_empty()
            || !namespace
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(IngestError::InvalidNamespace);
        }
        let limits = limits.validate()?;
        let requested = root.as_ref();
        let metadata = fs::symlink_metadata(requested).map_err(io(requested))?;
        if metadata.file_type().is_symlink() {
            return Err(IngestError::RootIsSymlink(requested.to_path_buf()));
        }
        if !metadata.is_dir() {
            return Err(IngestError::RootNotDirectory(requested.to_path_buf()));
        }
        let root = fs::canonicalize(requested).map_err(io(requested))?;
        Ok(Self {
            tenant,
            namespace,
            root,
            limits,
        })
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn descriptor(&self, path: PathBuf, byte_len: u64) -> Result<SourceDescriptor, IngestError> {
        let relative = path
            .strip_prefix(&self.root)
            .map_err(|_| IngestError::EscapesRoot(path.clone()))?;
        let relative = portable_relative_path(relative)?;
        let media_type =
            media_type_for(&path).ok_or_else(|| IngestError::UnsupportedFile(path.clone()))?;
        let virtual_uri = format!("fs://{}/{}", self.namespace, percent_encode_path(&relative));
        let mut hasher = Sha256::new();
        hasher.update(self.namespace.as_bytes());
        hasher.update([0]);
        hasher.update(relative.as_bytes());
        let digest = hasher.finalize();
        Ok(SourceDescriptor {
            tenant: self.tenant.clone(),
            source_id: SourceId::new(format!("source:fs:{}", hex_lower(&digest))),
            virtual_uri,
            media_type,
            byte_len,
            local_path: path,
        })
    }

    fn walk(
        &self,
        directory: &Path,
        accepted: &mut Vec<(PathBuf, u64)>,
    ) -> Result<(), IngestError> {
        let mut entries = fs::read_dir(directory)
            .map_err(io(directory))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(io(directory))?;
        entries.sort_by_key(|entry| entry.path());

        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(io(&path))?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                self.walk(&path, accepted)?;
                continue;
            }
            if !metadata.is_file() || media_type_for(&path).is_none() {
                continue;
            }
            if accepted.len() == self.limits.max_files {
                return Err(IngestError::TooManyFiles {
                    limit: self.limits.max_files,
                });
            }
            if metadata.len() > self.limits.max_artifact_bytes {
                let relative = path
                    .strip_prefix(&self.root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned();
                return Err(IngestError::ArtifactTooLarge {
                    path: relative,
                    limit: self.limits.max_artifact_bytes,
                    observed: metadata.len(),
                });
            }
            accepted.push((path, metadata.len()));
        }
        Ok(())
    }
}

impl KnowledgeSource for LocalTreeSource {
    type Descriptor = SourceDescriptor;

    fn enumerate(&self) -> Result<Vec<Self::Descriptor>, IngestError> {
        let mut files = Vec::new();
        self.walk(&self.root, &mut files)?;
        files.sort_by(|left, right| left.0.cmp(&right.0));

        let mut total = 0_u64;
        let mut descriptors = Vec::with_capacity(files.len());
        for (path, len) in files {
            total = total.saturating_add(len);
            if total > self.limits.max_total_bytes {
                return Err(IngestError::TotalTooLarge {
                    limit: self.limits.max_total_bytes,
                    observed: total,
                });
            }
            descriptors.push(self.descriptor(path, len)?);
        }
        descriptors.sort_by(|left, right| left.virtual_uri.cmp(&right.virtual_uri));
        Ok(descriptors)
    }

    fn fetch(&self, descriptor: &Self::Descriptor) -> Result<RawArtifact, IngestError> {
        if descriptor.tenant != self.tenant
            || !descriptor
                .virtual_uri
                .starts_with(&format!("fs://{}/", self.namespace))
        {
            return Err(IngestError::DescriptorMismatch);
        }

        let metadata =
            fs::symlink_metadata(&descriptor.local_path).map_err(io(&descriptor.local_path))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(IngestError::DescriptorMismatch);
        }
        let canonical =
            fs::canonicalize(&descriptor.local_path).map_err(io(&descriptor.local_path))?;
        if !canonical.starts_with(&self.root) {
            return Err(IngestError::EscapesRoot(canonical));
        }
        let media_type = media_type_for(&canonical)
            .ok_or_else(|| IngestError::UnsupportedFile(canonical.clone()))?;
        if media_type != descriptor.media_type {
            return Err(IngestError::DescriptorMismatch);
        }

        let file = File::open(&canonical).map_err(io(&canonical))?;
        let mut reader: Take<File> = file.take(self.limits.max_artifact_bytes.saturating_add(1));
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).map_err(io(&canonical))?;
        if bytes.len() as u64 > self.limits.max_artifact_bytes {
            return Err(IngestError::ArtifactTooLarge {
                path: descriptor.virtual_uri.clone(),
                limit: self.limits.max_artifact_bytes,
                observed: bytes.len() as u64,
            });
        }

        let digest = Sha256::digest(&bytes);
        Ok(RawArtifact {
            tenant: self.tenant.clone(),
            source_id: descriptor.source_id.clone(),
            virtual_uri: descriptor.virtual_uri.clone(),
            media_type: media_type.to_owned(),
            content_hash: format!("sha256:{}", hex_lower(&digest)),
            bytes,
        })
    }
}

fn portable_relative_path(path: &Path) -> Result<String, IngestError> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => {
                let value = value
                    .to_str()
                    .ok_or_else(|| IngestError::NonUtf8Path(path.to_path_buf()))?;
                parts.push(value);
            }
            Component::CurDir => {}
            _ => return Err(IngestError::EscapesRoot(path.to_path_buf())),
        }
    }
    if parts.is_empty() {
        return Err(IngestError::UnsupportedFile(path.to_path_buf()));
    }
    Ok(parts.join("/"))
}

fn media_type_for(path: &Path) -> Option<&'static str> {
    let extension = path.extension()?.to_str()?.to_ascii_lowercase();
    match extension.as_str() {
        "txt" => Some("text/plain"),
        "md" | "markdown" => Some("text/markdown"),
        "json" => Some("application/json"),
        "jsonl" | "ndjson" => Some("application/x-ndjson"),
        "csv" => Some("text/csv"),
        _ => None,
    }
}

fn percent_encode_path(path: &str) -> String {
    let mut output = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
            output.push(byte as char);
        } else {
            output.push('%');
            output.push(hex_digit(byte >> 4));
            output.push(hex_digit(byte & 0x0f));
        }
    }
    output
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + value - 10) as char,
        _ => unreachable!(),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(hex_digit(byte >> 4));
        output.push(hex_digit(byte & 0x0f));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let ordinal = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("ccos-ingest-{}-{ordinal}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn source(root: &Path) -> LocalTreeSource {
        LocalTreeSource::new(
            TenantId("acme".into()),
            "docs",
            root,
            IngestLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn enumeration_is_sorted_and_uses_virtual_not_host_paths() {
        let dir = TestDir::new();
        fs::create_dir_all(dir.0.join("nested")).unwrap();
        fs::write(dir.0.join("z.txt"), b"z").unwrap();
        fs::write(dir.0.join("nested/a.md"), b"a").unwrap();
        fs::write(dir.0.join("ignored.bin"), b"x").unwrap();

        let descriptors = source(&dir.0).enumerate().unwrap();
        let uris: Vec<_> = descriptors
            .iter()
            .map(SourceDescriptor::virtual_uri)
            .collect();
        assert_eq!(uris, vec!["fs://docs/nested/a.md", "fs://docs/z.txt"]);
        assert!(uris
            .iter()
            .all(|uri| !uri.contains(dir.0.to_string_lossy().as_ref())));
    }

    #[test]
    fn source_identity_is_stable_across_mount_points() {
        let left = TestDir::new();
        let right = TestDir::new();
        fs::write(left.0.join("same.json"), br#"{"a":1}"#).unwrap();
        fs::write(right.0.join("same.json"), br#"{"a":2}"#).unwrap();
        let left_id = source(&left.0).enumerate().unwrap()[0].source_id().clone();
        let right_id = source(&right.0).enumerate().unwrap()[0].source_id().clone();
        assert_eq!(
            left_id, right_id,
            "identity is namespace + relative path, not host path or content"
        );
    }

    #[test]
    fn content_hash_and_whole_artifact_evidence_are_bound_to_bytes() {
        let dir = TestDir::new();
        fs::write(dir.0.join("a.txt"), b"alpha").unwrap();
        let source = source(&dir.0);
        let descriptor = source.enumerate().unwrap().remove(0);
        let first = source.fetch(&descriptor).unwrap();
        let first_evidence = first.whole_artifact_evidence();

        fs::write(dir.0.join("a.txt"), b"beta").unwrap();
        let second = source.fetch(&descriptor).unwrap();
        let second_evidence = second.whole_artifact_evidence();
        assert_ne!(first.content_hash, second.content_hash);
        assert_ne!(first_evidence.id, second_evidence.id);
        assert_eq!(first.source_id, second.source_id);
    }

    #[test]
    fn artifact_limit_is_enforced_during_fetch_not_only_enumeration() {
        let dir = TestDir::new();
        fs::write(dir.0.join("grow.txt"), b"ok").unwrap();
        let source = LocalTreeSource::new(
            TenantId("acme".into()),
            "docs",
            &dir.0,
            IngestLimits {
                max_files: 4,
                max_artifact_bytes: 4,
                max_total_bytes: 100,
            },
        )
        .unwrap();
        let descriptor = source.enumerate().unwrap().remove(0);
        fs::write(dir.0.join("grow.txt"), b"too-large").unwrap();
        assert!(matches!(
            source.fetch(&descriptor),
            Err(IngestError::ArtifactTooLarge { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_not_followed() {
        use std::os::unix::fs::symlink;

        let dir = TestDir::new();
        fs::write(dir.0.join("real.txt"), b"real").unwrap();
        symlink(dir.0.join("real.txt"), dir.0.join("alias.txt")).unwrap();
        let descriptors = source(&dir.0).enumerate().unwrap();
        assert_eq!(descriptors.len(), 1);
        assert_eq!(descriptors[0].virtual_uri(), "fs://docs/real.txt");
    }

    #[test]
    fn knowledge_records_preserve_tenant_hash_and_locator() {
        let dir = TestDir::new();
        fs::write(dir.0.join("fact.json"), br#"{"ceo":"Alice"}"#).unwrap();
        let source = source(&dir.0);
        let descriptor = source.enumerate().unwrap().remove(0);
        let artifact = source.fetch(&descriptor).unwrap();
        let record = artifact.source_record(SourceTrust::External);
        let evidence = artifact.whole_artifact_evidence();
        assert_eq!(record.tenant, TenantId("acme".into()));
        assert_eq!(record.locator, "fs://docs/fact.json");
        assert_eq!(
            record.content_hash.as_deref(),
            Some(artifact.content_hash.as_str())
        );
        assert_eq!(evidence.source, record.id);
        assert_eq!(evidence.content_hash, record.content_hash);
    }
}
