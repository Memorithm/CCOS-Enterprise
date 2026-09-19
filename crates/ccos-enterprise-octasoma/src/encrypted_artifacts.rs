//! Encryption is an explicit storage mode. Plaintext fallback is never allowed.
use super::*;
use ccos_enterprise_envelope::EnvelopeCipher;
use zeroize::Zeroizing;

const ROTATION_INTENT: &str = "provider-key-rotation-intent.json";

fn name<'a>(root: &Path, path: &'a Path) -> Result<&'a str, ProviderGenerationError> {
    path.strip_prefix(root)
        .ok()
        .and_then(Path::to_str)
        .ok_or(ProviderGenerationError::Invalid(
            "artifact outside tenant root",
        ))
}

pub(super) fn read_artifact(
    root: &Path,
    cipher: Option<&EnvelopeCipher>,
    path: &Path,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, ProviderGenerationError> {
    let encoded_limit = match cipher {
        Some(_) => EnvelopeCipher::encoded_limit(limit)?,
        None => limit,
    };
    let bytes = read_bounded_file(path, encoded_limit, "artifact exceeds byte limit")?;
    match cipher {
        Some(cipher) => Ok(cipher.open(name(root, path)?, &bytes, limit)?),
        None => Ok(Zeroizing::new(bytes)),
    }
}

pub(super) fn encode_artifact(
    root: &Path,
    cipher: Option<&EnvelopeCipher>,
    path: &Path,
    bytes: &[u8],
    limit: usize,
) -> Result<Vec<u8>, ProviderGenerationError> {
    match cipher {
        Some(cipher) => Ok(cipher.seal(name(root, path)?, bytes, limit)?),
        None if bytes.len() <= limit => Ok(bytes.to_vec()),
        None => Err(ProviderGenerationError::Invalid(
            "artifact exceeds byte limit",
        )),
    }
}

pub(super) fn new_artifact(
    root: &Path,
    cipher: Option<&EnvelopeCipher>,
    path: &Path,
    bytes: &[u8],
    limit: usize,
) -> Result<(), ProviderGenerationError> {
    let encoded = encode_artifact(root, cipher, path, bytes, limit)?;
    write_new_bytes(path, &encoded)
}

pub(super) fn new_or_exact_artifact(
    root: &Path,
    cipher: Option<&EnvelopeCipher>,
    path: &Path,
    bytes: &[u8],
    limit: usize,
) -> Result<(), ProviderGenerationError> {
    if cipher.is_none() {
        return write_new_or_verify_exact(path, bytes);
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(ProviderGenerationError::Invalid(
                    "encrypted artifact is not a regular file",
                ));
            }
            if read_artifact(root, cipher, path, limit)?.as_slice() != bytes {
                return Err(ProviderGenerationError::Invalid(
                    "generation artifact collision",
                ));
            }
            File::open(path)
                .and_then(|f| f.sync_all())
                .map_err(|e| io_error(path, e))?;
            sync_directory(
                path.parent()
                    .ok_or(ProviderGenerationError::Invalid("missing parent"))?,
            )
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            new_artifact(root, cipher, path, bytes, limit)
        }
        Err(e) => Err(io_error(path, e)),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RotationIntent {
    version: u32,
    tenant: String,
    key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionRotationReceipt {
    pub generation: u64,
    pub image_digest: [u8; 32],
    pub key_id: String,
}

impl ProviderGenerationStore {
    pub fn encryption_key_id(&self) -> Option<&str> {
        self.cipher.as_ref().map(|c| c.active_key())
    }

    /// Rewrap all managed artifacts to the independently configured active KEK.
    /// KMS key creation/retirement is an operator action, never an implicit side effect.
    pub fn rotate_encryption(
        self,
        admitted_tenant: &TenantId,
    ) -> Result<(Self, EncryptionRotationReceipt), ProviderGenerationError> {
        if self.tenant() != admitted_tenant {
            return Err(ProviderGenerationError::TenantMismatch);
        }
        let cipher = self
            .cipher
            .as_ref()
            .ok_or(ProviderGenerationError::Invalid(
                "encryption is not configured",
            ))?;
        let intent = RotationIntent {
            version: 1,
            tenant: self.tenant.as_str().into(),
            key_id: cipher.active_key().into(),
        };
        let path = self.root.join(ROTATION_INTENT);
        reject_existing(&path)?;
        let bytes = serde_json::to_vec(&intent).map_err(ProviderGenerationError::Json)?;
        let encoded = encode_artifact(&self.root, Some(cipher), &path, &bytes, MAX_SELECTOR_BYTES)?;
        atomic_raw(&path, &encoded)?;
        rotation_checkpoint(&self.root, "intent");
        resume_rotation(&self.root, self.cipher.as_deref())?;
        let root = self.root.clone();
        let tenant = self.tenant.clone();
        let cipher = self.cipher.clone();
        drop(self);
        let next = Self::open_with_cipher(root, tenant, cipher)?;
        let receipt = EncryptionRotationReceipt {
            generation: next.generation,
            image_digest: next.recovered.digest(),
            key_id: next.encryption_key_id().expect("encrypted owner").into(),
        };
        Ok((next, receipt))
    }

    pub fn matches_encryption_receipt(
        &self,
        receipt: &EncryptionRotationReceipt,
    ) -> Result<bool, ProviderGenerationError> {
        if self.generation != receipt.generation
            || self.recovered.digest() != receipt.image_digest
            || self.encryption_key_id() != Some(receipt.key_id.as_str())
        {
            return Ok(false);
        }
        let cipher = self
            .cipher
            .as_deref()
            .ok_or(ProviderGenerationError::Invalid("encryption required"))?;
        for (path, limit) in managed_artifacts(&self.root)? {
            let bytes = read_bounded_file(
                &path,
                EnvelopeCipher::encoded_limit(limit)?,
                "encrypted artifact exceeds limit",
            )?;
            if !cipher.uses_active_key(&bytes, limit)? {
                return Ok(false);
            }
            cipher.open(name(&self.root, &path)?, &bytes, limit)?;
        }
        Ok(true)
    }
}

pub(super) fn resume_rotation(
    root: &Path,
    cipher: Option<&EnvelopeCipher>,
) -> Result<(), ProviderGenerationError> {
    let path = root.join(ROTATION_INTENT);
    if !regular(&path)? {
        return Ok(());
    }
    let cipher = cipher.ok_or(ProviderGenerationError::Invalid(
        "pending encrypted rotation requires KMS",
    ))?;
    let bytes = read_artifact(root, Some(cipher), &path, MAX_SELECTOR_BYTES)?;
    let intent: RotationIntent =
        serde_json::from_slice(&bytes).map_err(ProviderGenerationError::Json)?;
    if intent.version != 1
        || intent.tenant != cipher.tenant().as_str()
        || intent.key_id != cipher.active_key()
    {
        return Err(ProviderGenerationError::Invalid(
            "rotation differs from configured tenant or active key",
        ));
    }
    for (artifact, limit) in managed_artifacts(root)? {
        let bytes = read_bounded_file(
            &artifact,
            EnvelopeCipher::encoded_limit(limit)?,
            "encrypted artifact exceeds limit",
        )?;
        let rewrapped = cipher.rewrap(name(root, &artifact)?, &bytes, limit)?;
        if rewrapped != bytes {
            atomic_raw(&artifact, &rewrapped)?;
        }
        rotation_checkpoint(root, "artifact");
    }
    // Crash leftovers contain envelopes too. Retire only our temporary names;
    // never traverse or remove unrelated files in a trusted tenant root.
    for directory in [
        root.to_path_buf(),
        root.join(PROVIDER_GENERATIONS_DIR),
        root.join(GOVERNANCE_GENERATIONS_DIR),
    ] {
        for entry in fs::read_dir(&directory).map_err(|e| io_error(&directory, e))? {
            let entry = entry.map_err(|e| io_error(&directory, e))?;
            if entry.file_name().to_str().is_some_and(temporary_name) {
                regular(&entry.path())?;
                fs::remove_file(entry.path()).map_err(|e| io_error(&entry.path(), e))?;
            }
        }
        sync_directory(&directory)?;
    }
    rotation_checkpoint(root, "complete");
    fs::remove_file(&path).map_err(|e| io_error(&path, e))?;
    sync_directory(root)
}

fn temporary_name(name: &str) -> bool {
    [
        ".envelope-",
        ".provider-current-",
        ".provider-purge-intent.json-",
        ".provider-purge-floor.json-",
    ]
    .iter()
    .any(|prefix| {
        name.strip_prefix(prefix)
            .and_then(|s| s.strip_suffix(".tmp"))
            .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit() || b == b'-'))
    })
}

fn managed_artifacts(root: &Path) -> Result<Vec<(PathBuf, usize)>, ProviderGenerationError> {
    let mut paths = vec![(root.join(PROVIDER_SELECTOR_FILE), MAX_SELECTOR_BYTES)];
    for name in ["provider-purge-intent.json", "provider-purge-floor.json"] {
        let path = root.join(name);
        if regular(&path)? {
            paths.push((path, MAX_GOVERNED_MEMORY_PROJECTION_BYTES));
        }
    }
    for (dir, governance, limit) in [
        (
            PROVIDER_GENERATIONS_DIR,
            false,
            crate::recovery::MAX_RECOVERY_IMAGE_BYTES,
        ),
        (
            GOVERNANCE_GENERATIONS_DIR,
            true,
            MAX_GOVERNED_MEMORY_PROJECTION_BYTES,
        ),
    ] {
        let dir = root.join(dir);
        ensure_directory(&dir)?;
        for entry in fs::read_dir(&dir).map_err(|e| io_error(&dir, e))? {
            let entry = entry.map_err(|e| io_error(&dir, e))?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(ProviderGenerationError::Invalid(
                "invalid artifact filename",
            ))?;
            if temporary_name(name) {
                continue;
            }
            if !purge::canonical_generation_name(name, governance) {
                return Err(ProviderGenerationError::Invalid(
                    "unexpected rotation artifact",
                ));
            }
            regular(&entry.path())?;
            paths.push((entry.path(), limit));
        }
    }
    for (path, _) in &paths {
        if !regular(path)? {
            return Err(ProviderGenerationError::Invalid(
                "missing rotation artifact",
            ));
        }
    }
    paths.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(paths)
}

fn regular(path: &Path) -> Result<bool, ProviderGenerationError> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_file() && !m.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(ProviderGenerationError::Invalid(
            "rotation artifact is not a regular file",
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io_error(path, e)),
    }
}

fn atomic_raw(path: &Path, bytes: &[u8]) -> Result<(), ProviderGenerationError> {
    regular(path)?;
    let parent = path
        .parent()
        .ok_or(ProviderGenerationError::Invalid("missing artifact parent"))?;
    let temp = TemporarySelector(parent.join(format!(
        ".envelope-{}-{}.tmp",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    )));
    write_new_bytes(&temp.0, bytes)?;
    fs::rename(&temp.0, path).map_err(|e| io_error(path, e))?;
    sync_directory(parent)
}

fn rotation_checkpoint(_root: &Path, _stage: &str) {
    #[cfg(test)]
    if std::env::var("CCOS_ROTATION_TEST_STAGE").as_deref() == Ok(_stage) {
        fs::write(_root.join("test-ready"), _stage).unwrap();
        loop {
            std::thread::park();
        }
    }
}

#[cfg(test)]
#[path = "encrypted_artifacts_tests.rs"]
mod tests;
