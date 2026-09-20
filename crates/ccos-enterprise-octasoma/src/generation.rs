//! Trusted selector for reconstructed governed provider generations.
//!
//! Version 1 selectors bound a provider image to a separately mutable
//! `GovernedMemoryStore`. Version 2 instead publishes two immutable generation
//! artifacts — canonical governance bytes and the provider recovery image — and
//! makes them authoritative together by atomically replacing one small selector.
//! The selector is always published last, so unreferenced artifacts are inert.
//!
//! Version 1 remains readable for existing deployments. New initialization and
//! generation advancement emit version 2 only. `advance` consumes the current
//! owner: if publication becomes uncertain the caller cannot keep serving the
//! old in-memory owner and must explicitly reopen the durable selector.

use ccos_enterprise_envelope::{EnvelopeCipher, EnvelopeError};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ccos_enterprise_memory::{
    decode_governed_memory_projection, encode_governed_memory_projection, GovernedMemoryProjection,
    GovernedMemoryProjectionError, GovernedMemoryStore, GovernedMemoryStoreError,
    MAX_GOVERNED_MEMORY_PROJECTION_BYTES,
};
use ccos_enterprise_tenancy::TenantId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::recovery::{
    restore_governed_memory, RecoveredGovernedMemory, RecoveryConfig, RecoveryError, RecoveryImage,
    RecoveryRecord,
};

const LEGACY_GENERATION_SELECTOR_VERSION: u32 = 1;
pub const GENERATION_SELECTOR_VERSION: u32 = 2;
/// Legacy v1 mutable governance directory. Version 2 does not write here.
pub const GOVERNANCE_DIR: &str = "governance";
pub const PROVIDER_GENERATIONS_DIR: &str = "provider-generations";
pub const GOVERNANCE_GENERATIONS_DIR: &str = "governance-generations";
pub const PROVIDER_SELECTOR_FILE: &str = "provider-current.json";
const PROVIDER_LOCK_FILE: &str = ".provider-generation.lock";
const MAX_SELECTOR_BYTES: usize = 64 * 1024;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[path = "purge.rs"]
mod purge;
pub use purge::{PreparedPurge, PurgeReceipt};
#[path = "encrypted_artifacts.rs"]
mod encrypted_artifacts;
pub use encrypted_artifacts::EncryptionRotationReceipt;
use encrypted_artifacts::{
    encode_artifact, new_artifact, new_or_exact_artifact, read_artifact, resume_rotation,
};

#[derive(Debug)]
pub enum ProviderGenerationError {
    Io { path: PathBuf, source: io::Error },
    Json(serde_json::Error),
    Projection(GovernedMemoryProjectionError),
    Governance(GovernedMemoryStoreError),
    Recovery(RecoveryError),
    Encryption(EnvelopeError),
    AlreadyOpen { path: PathBuf },
    AlreadyInitialized { path: PathBuf },
    MissingSelector { path: PathBuf },
    Invalid(&'static str),
    TenantMismatch,
    GovernanceMismatch,
    GenerationOverflow,
}

impl std::fmt::Display for ProviderGenerationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "provider generation {path:?}: {source}"),
            Self::Json(error) => write!(f, "provider generation selector JSON: {error}"),
            Self::Projection(error) => write!(f, "provider generation projection: {error}"),
            Self::Governance(error) => write!(f, "provider generation governance: {error}"),
            Self::Recovery(error) => write!(f, "provider generation recovery: {error}"),
            Self::Encryption(error) => write!(f, "{error}"),
            Self::AlreadyOpen { path } => write!(f, "provider generation already owned: {path:?}"),
            Self::AlreadyInitialized { path } => {
                write!(f, "provider generation already initialized: {path:?}")
            }
            Self::MissingSelector { path } => {
                write!(f, "provider generation selector required: {path:?}")
            }
            Self::Invalid(detail) => write!(f, "invalid provider generation: {detail}"),
            Self::TenantMismatch => {
                f.write_str("provider generation belongs to a different tenant")
            }
            Self::GovernanceMismatch => {
                f.write_str("provider generation selector does not match its governance")
            }
            Self::GenerationOverflow => f.write_str("provider generation counter overflow"),
        }
    }
}

impl std::error::Error for ProviderGenerationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json(error) => Some(error),
            Self::Projection(error) => Some(error),
            Self::Governance(error) => Some(error),
            Self::Recovery(error) => Some(error),
            _ => None,
        }
    }
}

impl From<GovernedMemoryProjectionError> for ProviderGenerationError {
    fn from(value: GovernedMemoryProjectionError) -> Self {
        Self::Projection(value)
    }
}

impl From<GovernedMemoryStoreError> for ProviderGenerationError {
    fn from(value: GovernedMemoryStoreError) -> Self {
        Self::Governance(value)
    }
}

impl From<EnvelopeError> for ProviderGenerationError {
    fn from(error: EnvelopeError) -> Self {
        Self::Encryption(error)
    }
}

impl From<RecoveryError> for ProviderGenerationError {
    fn from(value: RecoveryError) -> Self {
        Self::Recovery(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSelector {
    version: u32,
    tenant: String,
    generation: u64,
    image_file: String,
    image_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    governance_file: Option<String>,
    governance_sha256: String,
    config: RecoveryConfig,
}

enum GenerationGovernance {
    Legacy(GovernedMemoryStore),
    Immutable(GovernedMemoryProjection),
}

/// Exclusive owner of one selected provider generation and its exact governance.
pub struct ProviderGenerationStore {
    root: PathBuf,
    tenant: TenantId,
    generation: u64,
    config: RecoveryConfig,
    governance: GenerationGovernance,
    recovered: RecoveredGovernedMemory,
    _lock: File,
    cipher: Option<Arc<EnvelopeCipher>>,
}

impl Drop for ProviderGenerationStore {
    fn drop(&mut self) {
        let _ = self._lock.unlock();
    }
}

impl ProviderGenerationStore {
    /// Provision generation zero from one complete authoritative record set.
    ///
    /// Both version-2 generation artifacts are immutable and durably written
    /// before `provider-current.json` is created. A failure may leave unreferenced
    /// artifacts, but they are never authoritative without the selector.
    pub fn initialize(
        root: impl AsRef<Path>,
        authority: GovernedMemoryProjection,
        config: RecoveryConfig,
        records: &[RecoveryRecord],
    ) -> Result<Self, ProviderGenerationError> {
        Self::initialize_with_cipher(root, authority, config, records, None)
    }

    pub fn initialize_encrypted(
        root: impl AsRef<Path>,
        authority: GovernedMemoryProjection,
        config: RecoveryConfig,
        records: &[RecoveryRecord],
        cipher: Arc<EnvelopeCipher>,
    ) -> Result<Self, ProviderGenerationError> {
        Self::initialize_with_cipher(root, authority, config, records, Some(cipher))
    }

    fn initialize_with_cipher(
        root: impl AsRef<Path>,
        authority: GovernedMemoryProjection,
        config: RecoveryConfig,
        records: &[RecoveryRecord],
        cipher: Option<Arc<EnvelopeCipher>>,
    ) -> Result<Self, ProviderGenerationError> {
        let tenant = authority.tenant.clone();
        validate_cipher(&tenant, cipher.as_deref())?;
        if records.iter().any(RecoveryRecord::is_physically_purged) {
            return Err(ProviderGenerationError::Invalid(
                "initialization cannot invent purge history",
            ));
        }
        validate_tenant(&tenant)?;
        let requested = root.as_ref();
        fs::create_dir_all(requested).map_err(|source| io_error(requested, source))?;
        let root = fs::canonicalize(requested).map_err(|source| io_error(requested, source))?;
        let lock = acquire_lock(&root)?;
        reject_existing(&root.join(PROVIDER_SELECTOR_FILE))?;

        let provider_generations = root.join(PROVIDER_GENERATIONS_DIR);
        create_exclusive_directory(&provider_generations)?;
        let governance_generations = root.join(GOVERNANCE_GENERATIONS_DIR);
        create_exclusive_directory(&governance_generations)?;
        sync_directory(&root)?;

        let governance_bytes = encode_governed_memory_projection(&authority)?;
        let current = decode_governed_memory_projection(&governance_bytes, &tenant)?;
        let image = RecoveryImage::capture(&current, config, records)?;
        let generation = 0;
        let governance_file = governance_generation_filename(generation);
        new_artifact(
            &root,
            cipher.as_deref(),
            &governance_generations.join(&governance_file),
            &governance_bytes,
            MAX_GOVERNED_MEMORY_PROJECTION_BYTES,
        )?;
        let image_file = provider_generation_filename(generation);
        new_artifact(
            &root,
            cipher.as_deref(),
            &provider_generations.join(&image_file),
            image.as_bytes(),
            crate::recovery::MAX_RECOVERY_IMAGE_BYTES,
        )?;
        let selector = WireSelector {
            version: GENERATION_SELECTOR_VERSION,
            tenant: tenant.as_str().to_string(),
            generation,
            image_file,
            image_sha256: hex_digest(image.digest()),
            governance_file: Some(governance_file),
            governance_sha256: sha256_hex(&governance_bytes),
            config,
        };
        publish_initial_selector(&root, &selector, cipher.as_deref())?;

        let lock_path = root.join(PROVIDER_LOCK_FILE);
        lock.unlock()
            .map_err(|source| io_error(&lock_path, source))?;
        drop(lock);
        Self::open_with_cipher(&root, tenant, cipher)
    }

    /// Open exactly the generation named by the trusted local selector.
    ///
    /// Before serving any visible selector, reopen synchronizes both the selector
    /// file and its containing directory. This closes an uncertain-publication
    /// window where a rename was visible but the directory sync previously failed:
    /// reopen either establishes durability or fails without returning an owner.
    pub fn open(
        root: impl AsRef<Path>,
        expected_tenant: TenantId,
    ) -> Result<Self, ProviderGenerationError> {
        Self::open_with_cipher(root, expected_tenant, None)
    }

    pub fn open_encrypted(
        root: impl AsRef<Path>,
        tenant: TenantId,
        cipher: Arc<EnvelopeCipher>,
    ) -> Result<Self, ProviderGenerationError> {
        Self::open_with_cipher(root, tenant, Some(cipher))
    }

    fn open_with_cipher(
        root: impl AsRef<Path>,
        expected_tenant: TenantId,
        cipher: Option<Arc<EnvelopeCipher>>,
    ) -> Result<Self, ProviderGenerationError> {
        validate_tenant(&expected_tenant)?;
        validate_cipher(&expected_tenant, cipher.as_deref())?;
        let requested = root.as_ref();
        let root = fs::canonicalize(requested).map_err(|source| io_error(requested, source))?;
        let lock = LockGuard::new(acquire_lock(&root)?);
        resume_rotation(&root, cipher.as_deref())?;
        sync_visible_selector(&root)?;
        let selector_bytes = read_artifact(
            &root,
            cipher.as_deref(),
            &root.join(PROVIDER_SELECTOR_FILE),
            MAX_SELECTOR_BYTES,
        )?;
        let selector: WireSelector =
            serde_json::from_slice(&selector_bytes).map_err(ProviderGenerationError::Json)?;
        validate_selector(&selector, &expected_tenant)?;
        let store = match selector.version {
            LEGACY_GENERATION_SELECTOR_VERSION => {
                if cipher.is_some() {
                    return Err(ProviderGenerationError::Invalid(
                        "encrypted legacy selectors are unsupported",
                    ));
                }
                Self::open_v1(root, lock, expected_tenant, selector)
            }
            GENERATION_SELECTOR_VERSION => {
                Self::open_v2(root, lock, expected_tenant, selector, cipher)
            }
            _ => Err(ProviderGenerationError::Invalid(
                "unsupported selector version",
            )),
        }?;
        store.recover_pending_purge()
    }

    fn open_v1(
        root: PathBuf,
        lock: LockGuard,
        expected_tenant: TenantId,
        selector: WireSelector,
    ) -> Result<Self, ProviderGenerationError> {
        if selector.governance_file.is_some() {
            return Err(ProviderGenerationError::Invalid(
                "legacy selector cannot name a governance generation",
            ));
        }
        let governance =
            GovernedMemoryStore::open(root.join(GOVERNANCE_DIR), expected_tenant.clone())?;
        let current = governance.projection_for(&expected_tenant)?;
        let expected_governance = sha256_hex(&encode_governed_memory_projection(current)?);
        if selector.governance_sha256 != expected_governance {
            return Err(ProviderGenerationError::GovernanceMismatch);
        }
        let recovered = open_provider_image(&root, &selector, current, None)?;
        Ok(Self {
            root,
            tenant: expected_tenant,
            generation: selector.generation,
            config: selector.config,
            governance: GenerationGovernance::Legacy(governance),
            recovered,
            _lock: lock.into_file(),
            cipher: None,
        })
    }

    fn open_v2(
        root: PathBuf,
        lock: LockGuard,
        expected_tenant: TenantId,
        selector: WireSelector,
        cipher: Option<Arc<EnvelopeCipher>>,
    ) -> Result<Self, ProviderGenerationError> {
        let expected_governance_file = governance_generation_filename(selector.generation);
        let governance_file =
            selector
                .governance_file
                .as_deref()
                .ok_or(ProviderGenerationError::Invalid(
                    "version-2 selector requires governance file",
                ))?;
        if governance_file != expected_governance_file {
            return Err(ProviderGenerationError::Invalid(
                "non-canonical governance filename",
            ));
        }
        let governance_path = root.join(GOVERNANCE_GENERATIONS_DIR).join(governance_file);
        let governance_bytes = read_artifact(
            &root,
            cipher.as_deref(),
            &governance_path,
            MAX_GOVERNED_MEMORY_PROJECTION_BYTES,
        )?;
        if sha256_hex(&governance_bytes) != selector.governance_sha256 {
            return Err(ProviderGenerationError::GovernanceMismatch);
        }
        let current = decode_governed_memory_projection(&governance_bytes, &expected_tenant)?;
        let recovered = open_provider_image(&root, &selector, &current, cipher.as_deref())?;
        Ok(Self {
            root,
            tenant: expected_tenant,
            generation: selector.generation,
            config: selector.config,
            governance: GenerationGovernance::Immutable(current),
            recovered,
            _lock: lock.into_file(),
            cipher,
        })
    }

    /// Publish one complete next generation and reopen it from durable bytes.
    ///
    /// The receiver is consumed. If any step fails, this owner is dropped and
    /// the caller must reopen the selector explicitly. Provider/governance files
    /// are immutable. A retry may reuse an orphan only when its bytes exactly
    /// match the generation that is being retried; any collision with different
    /// bytes fails closed. The selector replacement itself is one filesystem
    /// rename followed by directory sync; no anti-rollback, distributed-
    /// transaction, or broad physical power-loss guarantee is claimed.
    pub fn advance(
        self,
        authority: GovernedMemoryProjection,
        config: RecoveryConfig,
        records: &[RecoveryRecord],
    ) -> Result<Self, ProviderGenerationError> {
        self.validate_purge_transition(&authority, records)?;
        self.publish_generation(&authority, config, records)?;
        let root = self.root.clone();
        let tenant = self.tenant.clone();
        let cipher = self.cipher.clone();
        drop(self);
        Self::open_with_cipher(&root, tenant, cipher)
    }

    fn publish_generation(
        &self,
        authority: &GovernedMemoryProjection,
        config: RecoveryConfig,
        records: &[RecoveryRecord],
    ) -> Result<(), ProviderGenerationError> {
        let root = &self.root;
        let tenant = &self.tenant;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(ProviderGenerationError::GenerationOverflow)?;
        let governance_bytes = encode_governed_memory_projection(authority)?;
        let current = decode_governed_memory_projection(&governance_bytes, tenant)?;
        let image = RecoveryImage::capture(&current, config, records)?;

        let governance_generations = root.join(GOVERNANCE_GENERATIONS_DIR);
        ensure_directory(&governance_generations)?;
        let provider_generations = root.join(PROVIDER_GENERATIONS_DIR);
        ensure_directory(&provider_generations)?;

        let governance_file = governance_generation_filename(generation);
        new_or_exact_artifact(
            root,
            self.cipher.as_deref(),
            &governance_generations.join(&governance_file),
            &governance_bytes,
            MAX_GOVERNED_MEMORY_PROJECTION_BYTES,
        )?;
        let image_file = provider_generation_filename(generation);
        new_or_exact_artifact(
            root,
            self.cipher.as_deref(),
            &provider_generations.join(&image_file),
            image.as_bytes(),
            crate::recovery::MAX_RECOVERY_IMAGE_BYTES,
        )?;
        purge::checkpoint(root, "artifacts")?;
        let selector = WireSelector {
            version: GENERATION_SELECTOR_VERSION,
            tenant: tenant.as_str().to_string(),
            generation,
            image_file,
            image_sha256: hex_digest(image.digest()),
            governance_file: Some(governance_file),
            governance_sha256: sha256_hex(&governance_bytes),
            config,
        };
        replace_selector(root, &selector, self.cipher.as_deref())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn config(&self) -> RecoveryConfig {
        self.config
    }

    pub fn governance(&self) -> &GovernedMemoryProjection {
        match &self.governance {
            GenerationGovernance::Legacy(store) => store
                .projection_for(&self.tenant)
                .expect("legacy generation governance was validated when opened"),
            GenerationGovernance::Immutable(projection) => projection,
        }
    }

    pub fn recovered(&self) -> &RecoveredGovernedMemory {
        &self.recovered
    }
}

fn open_provider_image(
    root: &Path,
    selector: &WireSelector,
    current: &GovernedMemoryProjection,
    cipher: Option<&EnvelopeCipher>,
) -> Result<RecoveredGovernedMemory, ProviderGenerationError> {
    let expected_file = provider_generation_filename(selector.generation);
    if selector.image_file != expected_file {
        return Err(ProviderGenerationError::Invalid(
            "non-canonical image filename",
        ));
    }
    let digest = parse_digest(&selector.image_sha256)?;
    let image_path = root
        .join(PROVIDER_GENERATIONS_DIR)
        .join(&selector.image_file);
    if cipher.is_some() {
        let bytes = read_artifact(
            root,
            cipher,
            &image_path,
            crate::recovery::MAX_RECOVERY_IMAGE_BYTES,
        )?;
        return restore_governed_memory(bytes.as_slice(), digest, current, selector.config)
            .map_err(ProviderGenerationError::Recovery);
    }
    let image = File::open(&image_path).map_err(|source| io_error(&image_path, source))?;
    restore_governed_memory(image, digest, current, selector.config)
        .map_err(ProviderGenerationError::Recovery)
}

fn validate_tenant(tenant: &TenantId) -> Result<(), ProviderGenerationError> {
    if TenantId::validated(tenant.as_str()).as_ref() != Some(tenant) {
        return Err(ProviderGenerationError::Invalid("invalid tenant"));
    }
    Ok(())
}

fn reject_existing(path: &Path) -> Result<(), ProviderGenerationError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(ProviderGenerationError::AlreadyInitialized {
            path: path.to_path_buf(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error(path, source)),
    }
}

fn create_exclusive_directory(path: &Path) -> Result<(), ProviderGenerationError> {
    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            Err(ProviderGenerationError::AlreadyInitialized {
                path: path.to_path_buf(),
            })
        }
        Err(source) => Err(io_error(path, source)),
    }
}

fn ensure_directory(path: &Path) -> Result<(), ProviderGenerationError> {
    match fs::create_dir(path) {
        Ok(()) => sync_directory(path.parent().unwrap_or_else(|| Path::new("."))),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(ProviderGenerationError::Invalid(
                    "generation directory is not a real directory",
                ));
            }
            Ok(())
        }
        Err(source) => Err(io_error(path, source)),
    }
}

fn provider_generation_filename(generation: u64) -> String {
    format!("generation-{generation:020}.json")
}

fn governance_generation_filename(generation: u64) -> String {
    format!("generation-{generation:020}.governance.json")
}

struct LockGuard {
    file: Option<File>,
}

impl LockGuard {
    fn new(file: File) -> Self {
        Self { file: Some(file) }
    }

    fn into_file(mut self) -> File {
        self.file
            .take()
            .expect("provider lock guard consumed exactly once")
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = file.unlock();
        }
    }
}

fn acquire_lock(root: &Path) -> Result<File, ProviderGenerationError> {
    let path = root.join(PROVIDER_LOCK_FILE);
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options
        .open(&path)
        .map_err(|source| io_error(&path, source))?;
    lock.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => ProviderGenerationError::AlreadyOpen { path },
        TryLockError::Error(source) => io_error(&path, source),
    })?;
    Ok(lock)
}

fn sync_visible_selector(root: &Path) -> Result<(), ProviderGenerationError> {
    let path = root.join(PROVIDER_SELECTOR_FILE);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(ProviderGenerationError::MissingSelector { path });
        }
        Err(source) => return Err(io_error(&path, source)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ProviderGenerationError::Invalid(
            "selector is not a regular file",
        ));
    }
    File::open(&path)
        .and_then(|file| file.sync_all())
        .map_err(|source| io_error(&path, source))?;
    sync_directory(root)
}

fn read_bounded_file(
    path: &Path,
    max_bytes: usize,
    limit_message: &'static str,
) -> Result<Vec<u8>, ProviderGenerationError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if path
                .file_name()
                .is_some_and(|name| name == PROVIDER_SELECTOR_FILE)
            {
                return Err(ProviderGenerationError::MissingSelector {
                    path: path.to_path_buf(),
                });
            }
            return Err(io_error(path, error));
        }
        Err(source) => return Err(io_error(path, source)),
    };
    let mut bytes = Vec::new();
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    if bytes.len() > max_bytes {
        return Err(ProviderGenerationError::Invalid(limit_message));
    }
    Ok(bytes)
}

fn validate_selector(
    selector: &WireSelector,
    tenant: &TenantId,
) -> Result<(), ProviderGenerationError> {
    if selector.version != LEGACY_GENERATION_SELECTOR_VERSION
        && selector.version != GENERATION_SELECTOR_VERSION
    {
        return Err(ProviderGenerationError::Invalid(
            "unsupported selector version",
        ));
    }
    if selector.tenant != tenant.as_str() {
        return Err(ProviderGenerationError::TenantMismatch);
    }
    if !valid_hex_digest(&selector.governance_sha256) {
        return Err(ProviderGenerationError::Invalid(
            "invalid governance digest",
        ));
    }
    if !valid_hex_digest(&selector.image_sha256) {
        return Err(ProviderGenerationError::Invalid("invalid image digest"));
    }
    Ok(())
}

struct TemporarySelector(PathBuf);

impl Drop for TemporarySelector {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn publish_initial_selector(
    root: &Path,
    selector: &WireSelector,
    cipher: Option<&EnvelopeCipher>,
) -> Result<(), ProviderGenerationError> {
    let path = root.join(PROVIDER_SELECTOR_FILE);
    reject_existing(&path)?;
    write_selector(root, &path, selector, cipher)
}

fn replace_selector(
    root: &Path,
    selector: &WireSelector,
    cipher: Option<&EnvelopeCipher>,
) -> Result<(), ProviderGenerationError> {
    let path = root.join(PROVIDER_SELECTOR_FILE);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(ProviderGenerationError::Invalid(
                "selector is not a regular file",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(ProviderGenerationError::MissingSelector { path });
        }
        Err(source) => return Err(io_error(&path, source)),
    }
    write_selector(root, &path, selector, cipher)
}

fn write_selector(
    root: &Path,
    path: &Path,
    selector: &WireSelector,
    cipher: Option<&EnvelopeCipher>,
) -> Result<(), ProviderGenerationError> {
    let bytes = serde_json::to_vec_pretty(selector).map_err(ProviderGenerationError::Json)?;
    if bytes.len() > MAX_SELECTOR_BYTES {
        return Err(ProviderGenerationError::Invalid(
            "selector exceeds byte limit",
        ));
    }
    let bytes = encode_artifact(root, cipher, path, &bytes, MAX_SELECTOR_BYTES)?;
    let ordinal = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    let temp = root.join(format!(
        ".provider-current-{}-{ordinal}.tmp",
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp)
        .map_err(|source| io_error(&temp, source))?;
    let temporary = TemporarySelector(temp);
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| io_error(&temporary.0, source))?;
    drop(file);
    fs::rename(&temporary.0, path).map_err(|source| io_error(path, source))?;
    sync_directory(root)
}

fn write_new_bytes(path: &Path, bytes: &[u8]) -> Result<(), ProviderGenerationError> {
    let parent = path.parent().ok_or(ProviderGenerationError::Invalid(
        "generation artifact parent required",
    ))?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|source| io_error(path, source))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| io_error(path, source))?;
    sync_directory(parent)
}

fn write_new_or_verify_exact(path: &Path, bytes: &[u8]) -> Result<(), ProviderGenerationError> {
    let parent = path.parent().ok_or(ProviderGenerationError::Invalid(
        "generation artifact parent required",
    ))?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    match options.open(path) {
        Ok(mut file) => {
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|source| io_error(path, source))?;
            sync_directory(parent)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(ProviderGenerationError::Invalid(
                    "generation artifact is not a regular file",
                ));
            }
            let file = File::open(path).map_err(|source| io_error(path, source))?;
            let limit = bytes
                .len()
                .checked_add(1)
                .ok_or(ProviderGenerationError::Invalid(
                    "generation artifact size overflow",
                ))?;
            let mut existing = Vec::new();
            (&file)
                .take(limit as u64)
                .read_to_end(&mut existing)
                .map_err(|source| io_error(path, source))?;
            if existing != bytes {
                return Err(ProviderGenerationError::Invalid(
                    "generation artifact collision",
                ));
            }
            file.sync_all().map_err(|source| io_error(path, source))?;
            sync_directory(parent)
        }
        Err(source) => Err(io_error(path, source)),
    }
}

fn sync_directory(path: &Path) -> Result<(), ProviderGenerationError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|source| io_error(path, source))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_digest(Sha256::digest(bytes).into())
}

fn hex_digest(digest: [u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn valid_hex_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn parse_digest(value: &str) -> Result<[u8; 32], ProviderGenerationError> {
    if !valid_hex_digest(value) {
        return Err(ProviderGenerationError::Invalid("invalid image digest"));
    }
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| ProviderGenerationError::Invalid("invalid image digest"))?;
    }
    Ok(digest)
}

fn io_error(path: &Path, source: io::Error) -> ProviderGenerationError {
    ProviderGenerationError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn validate_cipher(
    tenant: &TenantId,
    cipher: Option<&EnvelopeCipher>,
) -> Result<(), ProviderGenerationError> {
    if cipher.is_some_and(|c| c.tenant() != tenant) {
        return Err(ProviderGenerationError::TenantMismatch);
    }
    Ok(())
}
