//! Irreversible, roll-forward physical compaction under the generation lock.
//! The local intent and floor are authority files in the trusted tenant root.
//! This is not protection against replacement of the entire root or external backups.

use super::*;
use ccos_enterprise_memory::{MemoryAssetId, MemoryAssetState};
use std::collections::BTreeSet;

const INTENT: &str = "provider-purge-intent.json";
const FLOOR: &str = "provider-purge-floor.json";
const MAX_PURGE_METADATA: usize = MAX_GOVERNED_MEMORY_PROJECTION_BYTES;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PurgeIntent {
    version: u32,
    tenant: String,
    base_generation: u64,
    base_digest: String,
    next_generation: u64,
    next_digest: String,
    root_asset: String,
    purged: BTreeSet<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PurgeFloor {
    version: u32,
    tenant: String,
    generation: u64,
    purged: BTreeSet<String>,
}

/// Side-effect-free purge preparation, bound to one exact selected generation.
pub struct PreparedPurge {
    intent: PurgeIntent,
    authority: GovernedMemoryProjection,
    records: Vec<RecoveryRecord>,
}

/// Returned only after physical cleanup and floor publication are durable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeReceipt {
    pub generation: u64,
    pub asset_id: MemoryAssetId,
    pub image_digest: [u8; 32],
    pub purged_assets: usize,
}

fn tombstones(records: &[RecoveryRecord]) -> BTreeSet<String> {
    records
        .iter()
        .filter(|r| r.is_physically_purged())
        .map(|r| r.asset_id.as_str().to_owned())
        .collect()
}

impl ProviderGenerationStore {
    /// The caller must obtain tenant authorization through Deployment::admit.
    /// Invalidates this asset and its entire lineage closure, then removes all
    /// corresponding vectors and payloads. Metadata IDs remain reserved forever.
    pub fn prepare_purge(
        &self,
        admitted_tenant: &TenantId,
        asset_id: MemoryAssetId,
    ) -> Result<PreparedPurge, ProviderGenerationError> {
        if admitted_tenant != self.tenant() {
            return Err(ProviderGenerationError::TenantMismatch);
        }
        let mut authority = self.governance().clone();
        let report = authority
            .graph
            .invalidate(&asset_id)
            .map_err(|_| ProviderGenerationError::Invalid("unknown purge asset"))?;
        let mut targets = report.stale_descendants;
        targets.insert(asset_id.clone());
        let records: Vec<_> = self
            .recovered()
            .source_records()
            .iter()
            .map(|row| {
                if targets.contains(&row.asset_id) {
                    RecoveryRecord::physical_tombstone(row.asset_id.clone())
                } else {
                    row.clone()
                }
            })
            .collect();
        let image = RecoveryImage::capture(&authority, self.config, &records)?;
        let intent = PurgeIntent {
            version: 1,
            tenant: self.tenant.as_str().into(),
            base_generation: self.generation,
            base_digest: hex_digest(self.recovered.digest()),
            next_generation: self
                .generation
                .checked_add(1)
                .ok_or(ProviderGenerationError::GenerationOverflow)?,
            next_digest: hex_digest(image.digest()),
            root_asset: asset_id.as_str().into(),
            purged: tombstones(&records),
        };
        Ok(PreparedPurge {
            intent,
            authority,
            records,
        })
    }

    /// After durable intent, every open rolls forward before returning an owner.
    /// The consumed owner cannot continue serving after uncertain publication.
    pub fn commit_prepared_purge(
        self,
        prepared: PreparedPurge,
    ) -> Result<(Self, PurgeReceipt), ProviderGenerationError> {
        let intent = &prepared.intent;
        if self.tenant.as_str() != intent.tenant
            || self.generation != intent.base_generation
            || hex_digest(self.recovered.digest()) != intent.base_digest
        {
            return Err(ProviderGenerationError::Invalid("stale purge preparation"));
        }
        reject_existing(&self.root.join(INTENT))?;
        write_metadata(&self.root, INTENT, intent, self.cipher.as_deref())?;
        checkpoint(&self.root, "intent")?;
        self.publish_generation(&prepared.authority, self.config, &prepared.records)?;
        checkpoint(&self.root, "selector")?;
        let root = self.root.clone();
        let tenant = self.tenant.clone();
        let asset_id = MemoryAssetId::new(intent.root_asset.clone())
            .map_err(|_| ProviderGenerationError::Invalid("invalid purge asset"))?;
        let cipher = self.cipher.clone();
        drop(self);
        let next = Self::open_with_cipher(root, tenant, cipher)?;
        let receipt = PurgeReceipt {
            generation: next.generation,
            asset_id,
            image_digest: next.recovered.digest(),
            purged_assets: intent.purged.len(),
        };
        Ok((next, receipt))
    }

    pub fn matches_purge_receipt(&self, receipt: &PurgeReceipt) -> bool {
        self.generation == receipt.generation
            && self.recovered.digest() == receipt.image_digest
            && self
                .recovered
                .source_records()
                .iter()
                .any(|r| r.asset_id == receipt.asset_id && r.is_physically_purged())
            && self
                .governance()
                .provenance
                .class(&receipt.asset_id)
                .is_some()
            && tombstones(self.recovered.source_records()).len() == receipt.purged_assets
    }

    pub(super) fn validate_purge_transition(
        &self,
        authority: &GovernedMemoryProjection,
        records: &[RecoveryRecord],
    ) -> Result<(), ProviderGenerationError> {
        let before = tombstones(self.recovered.source_records());
        if tombstones(records) != before
            || before.iter().any(|name| {
                let id = MemoryAssetId::new(name.clone()).expect("validated source ID");
                !matches!(
                    authority.graph.state(&id),
                    Some(MemoryAssetState::Stale | MemoryAssetState::Invalidated)
                ) || authority.graph.descriptor(&id) != self.governance().graph.descriptor(&id)
                    || authority.provenance.class(&id) != self.governance().provenance.class(&id)
            })
        {
            return Err(ProviderGenerationError::Invalid(
                "ordinary advance cannot change purge history",
            ));
        }
        Ok(())
    }

    pub(super) fn recover_pending_purge(self) -> Result<Self, ProviderGenerationError> {
        if !regular_file_exists(&self.root.join(INTENT))? {
            self.validate_floor(false)?;
            return Ok(self);
        }
        let intent: PurgeIntent = read_metadata(&self.root, INTENT, self.cipher.as_deref())?;
        if intent.version != 1
            || intent.tenant != self.tenant.as_str()
            || intent.base_generation.checked_add(1) != Some(intent.next_generation)
            || !valid_hex_digest(&intent.base_digest)
            || !valid_hex_digest(&intent.next_digest)
            || !intent.purged.contains(&intent.root_asset)
        {
            return Err(ProviderGenerationError::Invalid("invalid purge intent"));
        }
        if self.generation == intent.base_generation {
            self.validate_floor(false)?;
            if hex_digest(self.recovered.digest()) != intent.base_digest {
                return Err(ProviderGenerationError::Invalid(
                    "purge base digest mismatch",
                ));
            }
            let asset_id = MemoryAssetId::new(intent.root_asset.clone())
                .map_err(|_| ProviderGenerationError::Invalid("invalid purge asset"))?;
            let prepared = self.prepare_purge(&self.tenant, asset_id)?;
            if prepared.intent.next_digest != intent.next_digest
                || prepared.intent.purged != intent.purged
            {
                return Err(ProviderGenerationError::Invalid(
                    "purge replay differs from durable intent",
                ));
            }
            // Only the recorded next generation is repairable. The selected base
            // remains intact until both replacements have been synchronized.
            for (dir, file) in [
                (
                    PROVIDER_GENERATIONS_DIR,
                    provider_generation_filename(intent.next_generation),
                ),
                (
                    GOVERNANCE_GENERATIONS_DIR,
                    governance_generation_filename(intent.next_generation),
                ),
            ] {
                remove_regular_if_exists(&self.root.join(dir).join(file))?;
                sync_directory(&self.root.join(dir))?;
            }
            self.publish_generation(&prepared.authority, self.config, &prepared.records)?;
            let root = self.root.clone();
            let tenant = self.tenant.clone();
            let cipher = self.cipher.clone();
            drop(self);
            return Self::open_with_cipher(root, tenant, cipher);
        }
        if self.generation != intent.next_generation
            || hex_digest(self.recovered.digest()) != intent.next_digest
            || tombstones(self.recovered.source_records()) != intent.purged
        {
            return Err(ProviderGenerationError::Invalid(
                "selected generation contradicts purge intent",
            ));
        }
        self.validate_floor(true)?;
        for (dir, selected, governance) in [
            (
                PROVIDER_GENERATIONS_DIR,
                provider_generation_filename(self.generation),
                false,
            ),
            (
                GOVERNANCE_GENERATIONS_DIR,
                governance_generation_filename(self.generation),
                true,
            ),
        ] {
            let path = self.root.join(dir);
            ensure_directory(&path)?;
            for entry in fs::read_dir(&path).map_err(|source| io_error(&path, source))? {
                let entry = entry.map_err(|source| io_error(&path, source))?;
                let name = entry.file_name();
                let name = name
                    .to_str()
                    .ok_or(ProviderGenerationError::Invalid("non-UTF8 generation name"))?;
                if !canonical_generation_name(name, governance) {
                    return Err(ProviderGenerationError::Invalid(
                        "unexpected file in generation directory",
                    ));
                }
                regular_file_exists(&entry.path())?;
                if name != selected {
                    remove_regular_if_exists(&entry.path())?;
                    checkpoint(&self.root, "cleanup")?;
                }
            }
            sync_directory(&path)?;
        }
        // Version-1 mutable governance contains no payload/vector data, but keep
        // it outside the proof rather than deleting a directory with other owners.
        write_metadata(
            &self.root,
            FLOOR,
            &PurgeFloor {
                version: 1,
                tenant: self.tenant.as_str().into(),
                generation: self.generation,
                purged: intent.purged,
            },
            self.cipher.as_deref(),
        )?;
        checkpoint(&self.root, "floor")?;
        remove_regular_if_exists(&self.root.join(INTENT))?;
        sync_directory(&self.root)?;
        self.validate_floor(false)?;
        Ok(self)
    }

    fn validate_floor(&self, pending: bool) -> Result<(), ProviderGenerationError> {
        let purged = tombstones(self.recovered.source_records());
        if !regular_file_exists(&self.root.join(FLOOR))? {
            if !pending && !purged.is_empty() {
                return Err(ProviderGenerationError::Invalid("purge floor missing"));
            }
            return Ok(());
        }
        let floor: PurgeFloor = read_metadata(&self.root, FLOOR, self.cipher.as_deref())?;
        if floor.version != 1
            || floor.tenant != self.tenant.as_str()
            || floor.generation > self.generation
            || floor.purged.is_empty()
            || if pending {
                !floor.purged.is_subset(&purged)
            } else {
                floor.purged != purged
            }
        {
            return Err(ProviderGenerationError::Invalid("purge floor violation"));
        }
        Ok(())
    }
}

pub(super) fn canonical_generation_name(name: &str, governance: bool) -> bool {
    let suffix = if governance {
        ".governance.json"
    } else {
        ".json"
    };
    name.strip_prefix("generation-")
        .and_then(|s| s.strip_suffix(suffix))
        .is_some_and(|n| {
            n.len() == 20 && n.bytes().all(|b| b.is_ascii_digit()) && n.parse::<u64>().is_ok()
        })
}

fn regular_file_exists(path: &Path) -> Result<bool, ProviderGenerationError> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_file() && !m.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(ProviderGenerationError::Invalid(
            "purge file is not a regular file",
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io_error(path, e)),
    }
}

fn remove_regular_if_exists(path: &Path) -> Result<(), ProviderGenerationError> {
    if regular_file_exists(path)? {
        fs::remove_file(path).map_err(|e| io_error(path, e))?;
    }
    Ok(())
}

fn read_metadata<T: serde::de::DeserializeOwned>(
    root: &Path,
    name: &str,
    cipher: Option<&EnvelopeCipher>,
) -> Result<T, ProviderGenerationError> {
    let bytes = read_artifact(root, cipher, &root.join(name), MAX_PURGE_METADATA)?;
    serde_json::from_slice(&bytes).map_err(ProviderGenerationError::Json)
}

fn write_metadata(
    root: &Path,
    name: &str,
    value: &impl Serialize,
    cipher: Option<&EnvelopeCipher>,
) -> Result<(), ProviderGenerationError> {
    let bytes = serde_json::to_vec(value).map_err(ProviderGenerationError::Json)?;
    if bytes.len() > MAX_PURGE_METADATA {
        return Err(ProviderGenerationError::Invalid(
            "purge metadata exceeds byte limit",
        ));
    }
    let target = root.join(name);
    regular_file_exists(&target)?;
    let bytes = encode_artifact(root, cipher, &target, &bytes, MAX_PURGE_METADATA)?;
    let temp = TemporarySelector(root.join(format!(
        ".{name}-{}-{}.tmp",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    )));
    write_new_bytes(&temp.0, &bytes)?;
    fs::rename(&temp.0, &target).map_err(|e| io_error(&target, e))?;
    sync_directory(root)
}

pub(super) fn checkpoint(_root: &Path, _stage: &str) -> Result<(), ProviderGenerationError> {
    #[cfg(test)]
    if std::env::var("CCOS_PURGE_TEST_STAGE").as_deref() == Ok(_stage) {
        fs::write(_root.join("test-ready"), _stage).unwrap();
        loop {
            std::thread::park();
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "purge_tests.rs"]
mod tests;
