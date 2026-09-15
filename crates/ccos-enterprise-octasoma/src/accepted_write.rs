//! Write-side generation staging for accepted governed evidence.
//!
//! This module deliberately starts with the narrowest authoritative mutation:
//! one new tenant-wide root evidence asset. The caller supplies identity,
//! evidence reference, embedding and payload; space, stratum and trust are not
//! caller-controlled. New evidence is `Unverified` and therefore does not enter
//! the served `VerifiedOnly` context until an independent governance transition
//! promotes its trust state.

use ccos_enterprise_memory::{
    GovernedMemoryProjection, MemoryAssetDescriptor, MemoryAssetId, MemoryError,
    MemoryEvidenceRef, MemoryGraphError, MemoryLineage, MemorySpace, MemoryStratum,
    MemoryTrustMetadata, MemoryValidationState,
};

use crate::generation::{ProviderGenerationError, ProviderGenerationStore};
use crate::recovery::{RecoveryConfig, RecoveryRecord};

/// Complete semantic input for one already-admitted direct evidence write.
#[derive(Debug, Clone, PartialEq)]
pub struct AcceptedEvidenceWrite {
    pub asset_id: MemoryAssetId,
    pub evidence: MemoryEvidenceRef,
    pub embedding: Vec<f32>,
    pub payload: Vec<u8>,
}

/// Prepared next population, bound to the exact generation from which it arose.
///
/// Preparation is side-effect-free. The fields are private so callers cannot
/// substitute another authority, population or provider configuration before
/// committing it.
pub struct PreparedEvidenceGeneration {
    base_generation: u64,
    base_digest: [u8; 32],
    authority: GovernedMemoryProjection,
    config: RecoveryConfig,
    records: Vec<RecoveryRecord>,
    asset_id: MemoryAssetId,
}

/// Durable receipt returned only after the selector has advanced and the newly
/// selected generation has been reopened from disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceGenerationReceipt {
    pub generation: u64,
    pub asset_id: MemoryAssetId,
    pub image_digest: [u8; 32],
}

#[derive(Debug)]
pub enum AcceptedEvidenceWriteError {
    DuplicateAsset(MemoryAssetId),
    EmptyPayload,
    Memory(MemoryError),
    Lineage(MemoryGraphError),
    StalePreparation,
    Generation(ProviderGenerationError),
}

impl std::fmt::Display for AcceptedEvidenceWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateAsset(id) => {
                write!(f, "governed evidence asset already exists: {}", id.as_str())
            }
            Self::EmptyPayload => f.write_str("governed evidence payload must not be empty"),
            Self::Memory(error) => write!(f, "governed evidence input: {error}"),
            Self::Lineage(error) => write!(f, "governed evidence lineage: {error}"),
            Self::StalePreparation => {
                f.write_str("prepared evidence generation no longer matches selected provider state")
            }
            Self::Generation(error) => write!(f, "governed evidence generation: {error}"),
        }
    }
}

impl std::error::Error for AcceptedEvidenceWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Memory(error) => Some(error),
            Self::Lineage(error) => Some(error),
            Self::Generation(error) => Some(error),
            _ => None,
        }
    }
}

impl From<MemoryError> for AcceptedEvidenceWriteError {
    fn from(value: MemoryError) -> Self {
        Self::Memory(value)
    }
}

impl From<MemoryGraphError> for AcceptedEvidenceWriteError {
    fn from(value: MemoryGraphError) -> Self {
        Self::Lineage(value)
    }
}

impl From<ProviderGenerationError> for AcceptedEvidenceWriteError {
    fn from(value: ProviderGenerationError) -> Self {
        Self::Generation(value)
    }
}

impl ProviderGenerationStore {
    /// Validate one write and build the complete next generation in memory.
    ///
    /// No file or provider mutation occurs here. The descriptor space is always
    /// tenant-wide, the stratum is always direct Evidence and trust is always
    /// Unverified. An opaque evidence reference is provenance, not proof of
    /// truth or verification.
    pub fn prepare_unverified_evidence(
        &self,
        write: AcceptedEvidenceWrite,
    ) -> Result<PreparedEvidenceGeneration, AcceptedEvidenceWriteError> {
        if write.payload.is_empty() {
            return Err(AcceptedEvidenceWriteError::EmptyPayload);
        }
        if self.governance().graph.descriptor(&write.asset_id).is_some() {
            return Err(AcceptedEvidenceWriteError::DuplicateAsset(write.asset_id));
        }

        let mut authority = self.governance().clone();
        let descriptor = MemoryAssetDescriptor::new(
            write.asset_id.clone(),
            MemorySpace::Tenant,
            MemoryStratum::Evidence,
            MemoryLineage::root([write.evidence])?,
        )?;
        authority.graph.register(descriptor)?;
        if authority
            .trust
            .insert(write.asset_id.clone(), MemoryTrustMetadata::unverified(1))
            .is_some()
        {
            return Err(AcceptedEvidenceWriteError::DuplicateAsset(write.asset_id));
        }

        let mut records = self.recovered().source_records().to_vec();
        records.push(RecoveryRecord {
            asset_id: write.asset_id.clone(),
            embedding: write.embedding,
            payload: write.payload,
            forgotten: false,
        });

        Ok(PreparedEvidenceGeneration {
            base_generation: self.generation(),
            base_digest: self.recovered().digest(),
            authority,
            config: self.config(),
            records,
            asset_id: write.asset_id,
        })
    }

    /// Commit a previously prepared complete population as the next generation.
    ///
    /// The owner is consumed. A preparation from another generation or digest is
    /// refused before publication. Once `advance` begins, its existing selector-
    /// last protocol and uncertain-publication rules apply.
    pub fn commit_prepared_evidence(
        self,
        prepared: PreparedEvidenceGeneration,
    ) -> Result<(Self, EvidenceGenerationReceipt), AcceptedEvidenceWriteError> {
        if self.generation() != prepared.base_generation
            || self.recovered().digest() != prepared.base_digest
            || self.tenant() != &prepared.authority.tenant
        {
            return Err(AcceptedEvidenceWriteError::StalePreparation);
        }
        let asset_id = prepared.asset_id;
        let next = self.advance(prepared.authority, prepared.config, &prepared.records)?;
        let receipt = EvidenceGenerationReceipt {
            generation: next.generation(),
            asset_id,
            image_digest: next.recovered().digest(),
        };
        Ok((next, receipt))
    }

    /// Check a durable write receipt against the generation selected after a
    /// restart. The provider image digest binds the complete ordered population;
    /// the asset must also exist in both governance and the recovered source rows
    /// with the fixed Unverified state assigned by this write path.
    pub fn matches_evidence_receipt(&self, receipt: &EvidenceGenerationReceipt) -> bool {
        self.generation() == receipt.generation
            && self.recovered().digest() == receipt.image_digest
            && self
                .governance()
                .graph
                .descriptor(&receipt.asset_id)
                .is_some_and(|descriptor| {
                    descriptor.space == MemorySpace::Tenant
                        && descriptor.stratum == MemoryStratum::Evidence
                })
            && self
                .governance()
                .trust
                .get(&receipt.asset_id)
                .is_some_and(|trust| trust.state() == MemoryValidationState::Unverified)
            && self
                .recovered()
                .source_records()
                .iter()
                .any(|record| record.asset_id == receipt.asset_id && !record.forgotten)
    }
}
