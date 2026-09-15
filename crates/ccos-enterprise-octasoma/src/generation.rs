//! Trusted selector for one reconstructed governed provider generation.
//!
//! The immutable recovery image remains data. This module stores the independent
//! receipt/configuration/tenant selection required to decide which image may be
//! served, then opens the existing `GovernedMemoryStore` and reconstructs the
//! actual `EnterpriseOctaSoma` through `recovery`.
//!
//! It is deliberately read-only after open. Accepted-write capture and generation
//! advancement require a separate crash-safe mutation protocol; callers must not
//! rewrite the selector behind a live owner.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ccos_enterprise_memory::{
    encode_governed_memory_projection, GovernedMemoryProjection, GovernedMemoryStore,
    GovernedMemoryStoreError,
};
use ccos_enterprise_tenancy::TenantId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::recovery::{
    restore_governed_memory, RecoveredGovernedMemory, RecoveryConfig, RecoveryError,
    RecoveryImage, RecoveryRecord,
};

pub const GENERATION_SELECTOR_VERSION: u32 = 1;
pub const GOVERNANCE_DIR: &str = "governance";
pub const PROVIDER_GENERATIONS_DIR: &str = "provider-generations";
pub const PROVIDER_SELECTOR_FILE: &str = "provider-current.json";
const PROVIDER_LOCK_FILE: &str = ".provider-generation.lock";
const MAX_SELECTOR_BYTES: usize = 64 * 1024;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub enum ProviderGenerationError {
    Io { path: PathBuf, source: io::Error },
    Json(serde_json::Error),
    Governance(GovernedMemoryStoreError),
    Recovery(RecoveryError),
    AlreadyOpen { path: PathBuf },
    AlreadyInitialized { path: PathBuf },
    MissingSelector { path: PathBuf },
    Invalid(&'static str),
    TenantMismatch,
    GovernanceMismatch,
}

impl std::fmt::Display for ProviderGenerationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "provider generation {path:?}: {source}"),
            Self::Json(error) => write!(f, "provider generation selector JSON: {error}"),
            Self::Governance(error) => write!(f, "provider generation governance: {error}"),
            Self::Recovery(error) => write!(f, "provider generation recovery: {error}"),
            Self::AlreadyOpen { path } => write!(f, "provider generation already owned: {path:?}"),
            Self::AlreadyInitialized { path } => write!(f, "provider generation already initialized: {path:?}"),
            Self::MissingSelector { path } => write!(f, "provider generation selector required: {path:?}"),
            Self::Invalid(detail) => write!(f, "invalid provider generation: {detail}"),
            Self::TenantMismatch => f.write_str("provider generation belongs to a different tenant"),
            Self::GovernanceMismatch => f.write_str("provider generation selector does not match current governance"),
        }
    }
}

impl std::error::Error for ProviderGenerationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json(error) => Some(error),
            Self::Governance(error) => Some(error),
            Self::Recovery(error) => Some(error),
            _ => None,
        }
    }
}

impl From<GovernedMemoryStoreError> for ProviderGenerationError {
    fn from(value: GovernedMemoryStoreError) -> Self {
        Self::Governance(value)
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
    governance_sha256: String,
    config: RecoveryConfig,
}

/// Exclusive read-only owner of one provider generation and its governance.
pub struct ProviderGenerationStore {
    root: PathBuf,
    tenant: TenantId,
    generation: u64,
    config: RecoveryConfig,
    governance: GovernedMemoryStore,
    recovered: RecoveredGovernedMemory,
    _lock: File,
}

impl Drop for ProviderGenerationStore {
    fn drop(&mut self) {
        let _ = self._lock.unlock();
    }
}

impl ProviderGenerationStore {
    /// Provision generation zero from a complete authoritative record set.
    ///
    /// Provisioning is explicit and refuses every existing selector entry. A
    /// failure may leave governance/image files that require operator recovery;
    /// it never treats partial state as initialized authority.
    pub fn initialize(
        root: impl AsRef<Path>,
        authority: GovernedMemoryProjection,
        config: RecoveryConfig,
        records: &[RecoveryRecord],
    ) -> Result<Self, ProviderGenerationError> {
        validate_tenant(&authority.tenant)?;
        let root = root.as_ref();
        fs::create_dir_all(root).map_err(|source| io_error(root, source))?;
        let root = fs::canonicalize(root).map_err(|source| io_error(root, source))?;
        let lock = acquire_lock(&root)?;
        let selector_path = root.join(PROVIDER_SELECTOR_FILE);
        match fs::symlink_metadata(&selector_path) {
            Ok(_) => return Err(ProviderGenerationError::AlreadyInitialized { path: selector_path }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error(&selector_path, source)),
        }

        let generations = root.join(PROVIDER_GENERATIONS_DIR);
        fs::create_dir(&generations).map_err(|source| io_error(&generations, source))?;
        sync_directory(&root)?;

        let governance = GovernedMemoryStore::initialize(root.join(GOVERNANCE_DIR), authority)?;
        let current = governance.projection_for(&governance.projection_for(&governance.projection_for(&tenant_from_store(&governance)?)?.tenant)?.tenant)?;
        let image = RecoveryImage::capture(current, config, records)?;
        let generation = 0;
        let image_file = generation_filename(generation);
        let image_path = generations.join(&image_file);
        image.write_new(&image_path)?;
        let governance_sha256 = sha256_hex(&encode_governed_memory_projection(current).map_err(|error| ProviderGenerationError::Invalid(Box::leak(error.to_string().into_boxed_str())))?);
        let selector = WireSelector {
            version: GENERATION_SELECTOR_VERSION,
            tenant: current.tenant.as_str().to_string(),
            generation,
            image_file,
            image_sha256: hex_digest(image.digest()),
            governance_sha256,
            config,
        };
        publish_selector(&root, &selector)?;
        drop(lock);
        Self::open(&root, current.tenant.clone())
    }

    /// Open exactly the generation named by the trusted local selector.
    pub fn open(
        root: impl AsRef<Path>,
        expected_tenant: TenantId,
    ) -> Result<Self, ProviderGenerationError> {
        validate_tenant(&expected_tenant)?;
        let root = fs::canonicalize(root.as_ref()).map_err(|source| io_error(root.as_ref(), source))?;
        let lock = acquire_lock(&root)?;
        let governance = GovernedMemoryStore::open(root.join(GOVERNANCE_DIR), expected_tenant.clone())?;
        let current = governance.projection_for(&expected_tenant)?;
        let selector_path = root.join(PROVIDER_SELECTOR_FILE);
        let selector = read_selector(&selector_path)?;
        validate_selector(&selector, &expected_tenant)?;

        let expected_governance = sha256_hex(
            &encode_governed_memory_projection(current)
                .map_err(|_| ProviderGenerationError::Invalid("cannot encode current governance"))?,
        );
        if selector.governance_sha256 != expected_governance {
            return Err(ProviderGenerationError::GovernanceMismatch);
        }

        let expected_file = generation_filename(selector.generation);
        if selector.image_file != expected_file {
            return Err(ProviderGenerationError::Invalid("non-canonical image filename"));
        }
        let digest = parse_digest(&selector.image_sha256)?;
        let image_path = root.join(PROVIDER_GENERATIONS_DIR).join(&selector.image_file);
        let image = File::open(&image_path).map_err(|source| io_error(&image_path, source))?;
        let recovered = restore_governed_memory(image, digest, current, selector.config)?;
        Ok(Self {
            root,
            tenant: expected_tenant,
            generation: selector.generation,
            config: selector.config,
            governance,
            recovered,
            _lock: lock,
        })
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
        self.governance
            .projection_for(&self.tenant)
            .expect("owned tenant was validated when the generation opened")
    }

    pub fn recovered(&self) -> &RecoveredGovernedMemory {
        &self.recovered
    }
}

fn tenant_from_store(store: &GovernedMemoryStore) -> Result<TenantId, ProviderGenerationError> {
    // The store API intentionally requires the expected tenant for reads, so
    // initialization keeps the projection tenant before calling this helper.
    // This function is unreachable in normal use and exists only to avoid
    // exposing mutable authority from the owner.
    Err(ProviderGenerationError::Invalid("tenant must be supplied explicitly"))
}

fn validate_tenant(tenant: &TenantId) -> Result<(), ProviderGenerationError> {
    if TenantId::validated(tenant.as_str()).as_ref() != Some(tenant) {
        return Err(ProviderGenerationError::Invalid("invalid tenant"));
    }
    Ok(())
}

fn generation_filename(generation: u64) -> String {
    format!("generation-{generation:020}.json")
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
    let lock = options.open(&path).map_err(|source| io_error(&path, source))?;
    lock.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => ProviderGenerationError::AlreadyOpen { path },
        TryLockError::Error(source) => io_error(&path, source),
    })?;
    Ok(lock)
}

fn read_selector(path: &Path) -> Result<WireSelector, ProviderGenerationError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(ProviderGenerationError::MissingSelector { path: path.to_path_buf() })
        }
        Err(source) => return Err(io_error(path, source)),
    };
    let mut bytes = Vec::new();
    file.take(MAX_SELECTOR_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    if bytes.len() > MAX_SELECTOR_BYTES {
        return Err(ProviderGenerationError::Invalid("selector exceeds byte limit"));
    }
    serde_json::from_slice(&bytes).map_err(ProviderGenerationError::Json)
}

fn validate_selector(
    selector: &WireSelector,
    tenant: &TenantId,
) -> Result<(), ProviderGenerationError> {
    if selector.version != GENERATION_SELECTOR_VERSION {
        return Err(ProviderGenerationError::Invalid("unsupported selector version"));
    }
    if selector.tenant != tenant.as_str() {
        return Err(ProviderGenerationError::TenantMismatch);
    }
    if selector.governance_sha256.len() != 64
        || !selector.governance_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ProviderGenerationError::Invalid("invalid governance digest"));
    }
    Ok(())
}

fn publish_selector(root: &Path, selector: &WireSelector) -> Result<(), ProviderGenerationError> {
    let path = root.join(PROVIDER_SELECTOR_FILE);
    let bytes = serde_json::to_vec_pretty(selector).map_err(ProviderGenerationError::Json)?;
    if bytes.len() > MAX_SELECTOR_BYTES {
        return Err(ProviderGenerationError::Invalid("selector exceeds byte limit"));
    }
    let ordinal = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    let temp = root.join(format!(".provider-current-{}-{ordinal}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp).map_err(|source| io_error(&temp, source))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| io_error(&temp, source))?;
    drop(file);
    fs::rename(&temp, &path).map_err(|source| io_error(&path, source))?;
    sync_directory(root)
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

fn parse_digest(value: &str) -> Result<[u8; 32], ProviderGenerationError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
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
