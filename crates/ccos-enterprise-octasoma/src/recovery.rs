//! Bounded, immutable recovery images for governed-only OctaSoma data.
//!
//! This is input replay, not serialization of opaque OctaSoma internals. The
//! caller supplies the complete ordered record set from an authoritative source.
//! It is not a checkpoint exporter for an arbitrary already-live adapter.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use ccos_enterprise_memory::{
    admit_governed_recall, encode_governed_memory_projection, BudgetedMemoryRecall,
    GovernedMemoryProjection, GovernedMemoryProjectionError, GovernedRecallGate,
    GovernedRecallGateError, GovernedRecallTrustPolicy, GovernedSemanticMemoryProviderExt,
    MemoryRecallBudgetError,
};
use ccos_enterprise_tenancy::TenantScope;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    EnterpriseMemoryError, EnterpriseOctaSoma, GovernedMemoryObservation, GovernedMemoryWrite,
    MemoryAssetId,
};

pub const MAX_RECOVERY_IMAGE_BYTES: usize = 64 * 1024 * 1024;
const MAX_RECORDS: usize = 16_384;
const MAX_VECTOR_BYTES: usize = 32 * 1024 * 1024;
const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
const MAX_PROJECTOR_BYTES: usize = 32 * 1024 * 1024;
const FORMAT_VERSION: u32 = 1;
// Deliberately fail closed across backend revisions; migration must be qualified.
const BACKEND_REVISION: &str = "2e2e0f1ed88d81675f301819529aeb3aa6053c72";

/// Exact replay configuration, also required independently by the restoring caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryConfig {
    pub dimension: usize,
    pub simhash_bits: usize,
    pub per_tenant_capacity: usize,
    pub seed: u64,
}

impl RecoveryConfig {
    fn validate(self) -> Result<(), RecoveryError> {
        if self.dimension == 0
            || self.dimension > 8192
            || self.simhash_bits == 0
            || self.simhash_bits > 4096
            || !self.simhash_bits.is_multiple_of(64)
            || self.per_tenant_capacity == 0
            || self.per_tenant_capacity > MAX_RECORDS
        {
            return Err(RecoveryError::Invalid("unsupported recovery configuration"));
        }
        let projector = self
            .dimension
            .checked_mul(self.simhash_bits)
            .and_then(|n| n.checked_mul(std::mem::size_of::<f32>()))
            .ok_or(RecoveryError::Limit("projector arithmetic"))?;
        if projector > MAX_PROJECTOR_BYTES {
            return Err(RecoveryError::Limit("projector bytes"));
        }
        Ok(())
    }
}

/// One original governed insertion, in original insertion order.
///
/// Space comes only from the canonical descriptor, never a provider label.
/// Forgotten rows retain payload and capacity consumption: omission would change
/// quota and could resurrect an asset after recovery. This is not physical purge.
#[derive(Debug, Clone, PartialEq)]
pub struct RecoveryRecord {
    pub asset_id: MemoryAssetId,
    pub embedding: Vec<f32>,
    pub payload: Vec<u8>,
    pub forgotten: bool,
}

#[derive(Debug)]
pub enum RecoveryError {
    Io { path: PathBuf, source: io::Error },
    Json(serde_json::Error),
    Projection(GovernedMemoryProjectionError),
    Provider(EnterpriseMemoryError),
    Budget(MemoryRecallBudgetError),
    Admission(GovernedRecallGateError),
    Invalid(&'static str),
    Limit(&'static str),
    DigestMismatch,
    GovernanceMismatch,
    ConfigurationMismatch,
    TenantMismatch,
}

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "recovery image {path:?}: {source}"),
            Self::Json(error) => write!(f, "recovery JSON: {error}"),
            Self::Projection(error) => write!(f, "recovery governance: {error}"),
            Self::Provider(error) => write!(f, "recovery provider: {error}"),
            Self::Budget(error) => write!(f, "recovery recall budget: {error}"),
            Self::Admission(error) => write!(f, "recovery admission: {error}"),
            Self::Invalid(detail) => write!(f, "invalid recovery image: {detail}"),
            Self::Limit(detail) => write!(f, "recovery resource limit: {detail}"),
            Self::DigestMismatch => {
                f.write_str("recovery image digest differs from expected receipt")
            }
            Self::GovernanceMismatch => {
                f.write_str("recovery image does not match current governance")
            }
            Self::ConfigurationMismatch => {
                f.write_str("recovery configuration differs from expected configuration")
            }
            Self::TenantMismatch => {
                f.write_str("recovery request tenant differs from authority tenant")
            }
        }
    }
}
impl std::error::Error for RecoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json(error) => Some(error),
            Self::Projection(error) => Some(error),
            Self::Provider(error) => Some(error),
            Self::Budget(error) => Some(error),
            Self::Admission(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireImage {
    version: u32,
    backend_revision: String,
    config: RecoveryConfig,
    // A JSON string preserves the projection's exact canonical bytes, avoiding
    // a Value intermediate that could collapse duplicate authoritative keys.
    governance: String,
    records: Vec<WireRecord>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRecord {
    asset_id: String,
    // Preserve every finite f32 bit pattern, including signed zero/subnormals.
    embedding_bits: Vec<u32>,
    payload: Vec<u8>,
    forgotten: bool,
}

/// Validated immutable bytes plus their SHA-256 receipt.
///
/// The receipt must be retained by the caller's trusted publication mechanism.
/// A hash delivered beside attacker-controlled bytes is not authentication.
pub struct RecoveryImage {
    bytes: Vec<u8>,
    digest: [u8; 32],
}

impl RecoveryImage {
    /// Encode a complete ordered input set tied to exact current authority.
    ///
    /// Every descriptor needs one record and explicit trust metadata. No rows are
    /// silently dropped, including inactive and logically forgotten assets.
    ///
    /// ```no_run
    /// # use ccos_enterprise_memory::GovernedMemoryProjection;
    /// # use ccos_enterprise_octasoma::recovery::{RecoveryImage, RecoveryRecord, RecoveryConfig};
    /// # fn example(authority: &GovernedMemoryProjection, rows: &[RecoveryRecord], config: RecoveryConfig) -> Result<(), Box<dyn std::error::Error>> {
    /// let image = RecoveryImage::capture(authority, config, rows)?;
    /// let expected_digest = image.digest();
    /// image.write_new("/srv/ccos/recovery/generation-001.json")?;
    /// # let _ = expected_digest;
    /// # Ok(()) }
    /// ```
    pub fn capture(
        authority: &GovernedMemoryProjection,
        config: RecoveryConfig,
        records: &[RecoveryRecord],
    ) -> Result<Self, RecoveryError> {
        config.validate()?;
        let governance =
            encode_governed_memory_projection(authority).map_err(RecoveryError::Projection)?;
        validate_records(authority, config, records)?;
        let wire = WireImage {
            version: FORMAT_VERSION,
            backend_revision: BACKEND_REVISION.into(),
            config,
            governance: String::from_utf8(governance)
                .map_err(|_| RecoveryError::Invalid("non-UTF8 governance"))?,
            records: records
                .iter()
                .map(|record| WireRecord {
                    asset_id: record.asset_id.as_str().into(),
                    embedding_bits: record
                        .embedding
                        .iter()
                        .map(|value| value.to_bits())
                        .collect(),
                    payload: record.payload.clone(),
                    forgotten: record.forgotten,
                })
                .collect(),
        };
        let mut output = LimitedOutput(Vec::new());
        serde_json::to_writer(&mut output, &wire).map_err(RecoveryError::Json)?;
        let bytes = output.0;
        let digest = Sha256::digest(&bytes).into();
        Ok(Self { bytes, digest })
    }

    /// Borrow the exact immutable bytes; storage must not rewrite their formatting.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Digest of the entire image, binding metadata, configuration and ordered rows.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Create a new immutable generation file and synchronize file plus directory.
    ///
    /// The parent must already exist in a trusted directory. Existing files and
    /// dangling symlinks are never replaced. After any I/O error the file may be
    /// absent, partial, or complete but not acknowledged: do not advance a served
    /// generation pointer. This is not a multi-file transaction or a KMS layer.
    pub fn write_new(&self, path: impl AsRef<Path>) -> Result<(), RecoveryError> {
        self.write_new_with(path.as_ref(), |parent| File::open(parent)?.sync_all())
    }

    fn write_new_with(
        &self,
        path: &Path,
        sync_parent: impl FnOnce(&Path) -> io::Result<()>,
    ) -> Result<(), RecoveryError> {
        let name = path
            .file_name()
            .ok_or(RecoveryError::Invalid("image filename required"))?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = fs::canonicalize(parent).map_err(|source| io_error(parent, source))?;
        let destination = parent.join(name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&destination)
            .map_err(|source| io_error(&destination, source))?;
        file.write_all(&self.bytes)
            .and_then(|()| file.sync_all())
            .map_err(|source| io_error(&destination, source))?;
        sync_parent(&parent).map_err(|source| io_error(&parent, source))?;
        Ok(())
    }
}

struct LimitedOutput(Vec<u8>);
impl Write for LimitedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_RECOVERY_IMAGE_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::other("recovery image byte limit exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Rebuilt governed indexes, paired with immutable exact authority.
///
/// No mutable backend or authority handle is exposed. Recall requires the caller
/// to supply current authority again, so an obsolete restored image fails rather
/// than silently recalling under a newer invalidation/loadout/trust snapshot.
pub struct RecoveredGovernedMemory {
    provider: EnterpriseOctaSoma,
    authority: GovernedMemoryProjection,
    canonical_governance: Vec<u8>,
    digest: [u8; 32],
    records: Vec<RecoveryRecord>,
}

impl RecoveredGovernedMemory {
    /// Receipt identifying the complete recovered input generation.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Count includes forgotten records, preserving append-only quota accounting.
    pub fn stored_records(&self) -> usize {
        self.provider.tenant_len(&self.authority.tenant)
    }

    /// Exact validated source rows reconstructed from the immutable recovery image.
    /// Kept crate-private so generation publication can derive a complete next input
    /// population without exposing an arbitrary live-index export API.
    pub(crate) fn source_records(&self) -> &[RecoveryRecord] {
        &self.records
    }

    /// Recall only after exact tenant, current-generation and loadout checks.
    ///
    /// This is not authentication. Supply authority from an acknowledged owner
    /// and a tenant from an admitted request. The supplied loadout must be a
    /// subset of that authority's configured spaces; the caller selects the
    /// appropriate bootstrap/on-demand mode before invoking this method.
    ///
    /// ```no_run
    /// # use ccos_enterprise_octasoma::recovery::RecoveredGovernedMemory;
    /// # use ccos_enterprise_memory::{GovernedMemoryProjection, BudgetedMemoryRecall, GovernedRecallTrustPolicy};
    /// # use ccos_enterprise_tenancy::TenantScope;
    /// # fn example(memory: &RecoveredGovernedMemory, current: &GovernedMemoryProjection, request: TenantScope<BudgetedMemoryRecall<'_>>) -> Result<(), Box<dyn std::error::Error>> {
    /// let observations = memory.recall(current, request, GovernedRecallTrustPolicy::VerifiedOnly)?;
    /// # let _ = observations;
    /// # Ok(()) }
    /// ```
    pub fn recall(
        &self,
        current: &GovernedMemoryProjection,
        request: TenantScope<BudgetedMemoryRecall<'_>>,
        policy: GovernedRecallTrustPolicy,
    ) -> Result<Vec<GovernedMemoryObservation>, RecoveryError> {
        if request.tenant != self.authority.tenant || current.tenant != self.authority.tenant {
            return Err(RecoveryError::TenantMismatch);
        }
        let current_bytes =
            encode_governed_memory_projection(current).map_err(RecoveryError::Projection)?;
        if current_bytes != self.canonical_governance {
            return Err(RecoveryError::GovernanceMismatch);
        }
        for space in request.inner.loadout.spaces() {
            if !current
                .loadout
                .bindings()
                .any(|binding| &binding.space == space)
            {
                return Err(RecoveryError::Invalid(
                    "requested space outside governance loadout",
                ));
            }
        }
        let observations = self
            .provider
            .recall_governed_bounded(request)
            .map_err(RecoveryError::Budget)?;
        admit_governed_recall(
            GovernedRecallGate {
                graph: &current.graph,
                trust: &current.trust,
                policy,
            },
            observations,
        )
        .map_err(RecoveryError::Admission)
    }
}

/// Verify one bounded input and reconstruct a fresh real OctaSoma provider.
///
/// Expected digest, configuration and authority are independent caller inputs,
/// not defaults extracted from the image. Complete input validation precedes
/// provider construction; no partial provider is returned after a replay error.
/// Read errors, missing bytes, unsupported versions and mismatched snapshots fail
/// closed. At most 64 MiB + 1 byte is read; total reconstruction RAM is larger.
///
/// ```no_run
/// # use ccos_enterprise_octasoma::recovery::{restore_governed_memory, RecoveryConfig};
/// # use ccos_enterprise_memory::GovernedMemoryProjection;
/// # fn example(expected: [u8;32], authority: &GovernedMemoryProjection, config: RecoveryConfig) -> Result<(), Box<dyn std::error::Error>> {
/// let file = std::fs::File::open("/srv/ccos/recovery/generation-001.json")?;
/// let rebuilt = restore_governed_memory(file, expected, authority, config)?;
/// assert_eq!(rebuilt.digest(), expected);
/// # Ok(()) }
/// ```
pub fn restore_governed_memory(
    reader: impl Read,
    expected_digest: [u8; 32],
    authority: &GovernedMemoryProjection,
    expected_config: RecoveryConfig,
) -> Result<RecoveredGovernedMemory, RecoveryError> {
    expected_config.validate()?;
    let canonical_governance =
        encode_governed_memory_projection(authority).map_err(RecoveryError::Projection)?;
    let mut bytes = Vec::new();
    reader
        .take(MAX_RECOVERY_IMAGE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(Path::new("<recovery reader>"), source))?;
    if bytes.len() > MAX_RECOVERY_IMAGE_BYTES {
        return Err(RecoveryError::Limit("image bytes"));
    }
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if digest != expected_digest {
        return Err(RecoveryError::DigestMismatch);
    }
    let wire: WireImage = serde_json::from_slice(&bytes).map_err(RecoveryError::Json)?;
    if wire.version != FORMAT_VERSION || wire.backend_revision != BACKEND_REVISION {
        return Err(RecoveryError::Invalid(
            "unsupported format or backend revision",
        ));
    }
    if wire.config != expected_config {
        return Err(RecoveryError::ConfigurationMismatch);
    }
    if wire.governance.as_bytes() != canonical_governance {
        return Err(RecoveryError::GovernanceMismatch);
    }
    let records = wire
        .records
        .into_iter()
        .map(|record| {
            Ok(RecoveryRecord {
                asset_id: MemoryAssetId::new(record.asset_id).map_err(RecoveryError::Provider)?,
                embedding: record
                    .embedding_bits
                    .into_iter()
                    .map(f32::from_bits)
                    .collect(),
                payload: record.payload,
                forgotten: record.forgotten,
            })
        })
        .collect::<Result<Vec<_>, RecoveryError>>()?;
    validate_records(authority, expected_config, &records)?;
    let mut provider = EnterpriseOctaSoma::new(
        expected_config.dimension,
        expected_config.simhash_bits,
        expected_config.per_tenant_capacity,
        expected_config.seed,
    )
    .map_err(RecoveryError::Provider)?;
    for record in &records {
        let descriptor = authority
            .graph
            .descriptor(&record.asset_id)
            .ok_or(RecoveryError::Invalid("record descriptor missing"))?;
        provider
            .insert_governed(TenantScope::new(
                authority.tenant.clone(),
                GovernedMemoryWrite {
                    asset_id: &record.asset_id,
                    space: &descriptor.space,
                    embedding: &record.embedding,
                    payload: &record.payload,
                },
            ))
            .map_err(RecoveryError::Provider)?;
        if record.forgotten {
            provider
                .forget_governed(TenantScope::new(authority.tenant.clone(), &record.asset_id))
                .map_err(RecoveryError::Provider)?;
        }
    }
    Ok(RecoveredGovernedMemory {
        provider,
        authority: authority.clone(),
        canonical_governance,
        digest,
        records,
    })
}

fn validate_records(
    authority: &GovernedMemoryProjection,
    config: RecoveryConfig,
    records: &[RecoveryRecord],
) -> Result<(), RecoveryError> {
    if records.len() > config.per_tenant_capacity || records.len() > MAX_RECORDS {
        return Err(RecoveryError::Limit("record count"));
    }
    if records.len() != authority.graph.len() {
        return Err(RecoveryError::Invalid("incomplete provider population"));
    }
    let mut ids = BTreeSet::new();
    let mut vector_bytes = 0usize;
    let mut payload_bytes = 0usize;
    for record in records {
        if !ids.insert(&record.asset_id) {
            return Err(RecoveryError::Invalid("duplicate provider asset"));
        }
        if authority.graph.descriptor(&record.asset_id).is_none() {
            return Err(RecoveryError::Invalid("unknown provider asset"));
        }
        if !authority.trust.contains_key(&record.asset_id) {
            return Err(RecoveryError::Invalid("missing explicit trust"));
        }
        if record.asset_id.as_str().len() > 4096 {
            return Err(RecoveryError::Limit("asset identifier bytes"));
        }
        crate::validate_embedding(&record.embedding, config.dimension)
            .map_err(RecoveryError::Provider)?;
        vector_bytes = vector_bytes
            .checked_add(
                record
                    .embedding
                    .len()
                    .checked_mul(4)
                    .ok_or(RecoveryError::Limit("vector arithmetic"))?,
            )
            .ok_or(RecoveryError::Limit("vector arithmetic"))?;
        payload_bytes = payload_bytes
            .checked_add(record.payload.len())
            .ok_or(RecoveryError::Limit("payload arithmetic"))?;
        if vector_bytes > MAX_VECTOR_BYTES || payload_bytes > MAX_PAYLOAD_BYTES {
            return Err(RecoveryError::Limit("aggregate vectors or payloads"));
        }
    }
    Ok(())
}

fn io_error(path: &Path, source: io::Error) -> RecoveryError {
    RecoveryError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;
