//! Versioned scientific-evidence observations for governed CCOS memory.
//!
//! These types live strictly on the observation side of the CCOS architecture.
//! They preserve upstream scientific interpretation and immutable provenance,
//! but carry no capability, approval, resource lease, budget, or execution
//! authority.

use core::fmt;

use crate::{
    MemoryAssetDescriptor, MemoryAssetId, MemoryError, MemoryEvidenceRef, MemoryLineage,
    MemorySpace, MemoryStratum,
};

/// Version of the scientific-evidence observation contract.
pub const SCIENTIFIC_EVIDENCE_OBSERVATION_VERSION: u16 = 1;

/// Scientific classification preserved from an upstream research producer.
///
/// The variants are descriptive and deliberately non-ordinal. None grants CCOS
/// authorization or implies that an artifact may be executed or deployed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScientificEvidenceKind {
    /// Direct measurement or experiment against an external/real system.
    EmpiricalValidation,
    /// Computed result whose meaning depends on a declared approximation.
    NumericalApproximation,
    /// Result exact under its declared mathematical assumptions.
    ExactMathematicalResult,
    /// Model describing observed behavior without claiming fundamental truth.
    PhenomenologicalModel,
    /// Proposed model or mechanism not yet independently validated.
    SpeculativeModel,
    /// Criterion intended to reject or falsify a candidate claim/model.
    RejectionCriterion,
}

/// Outcome of one evidence item with respect to its stated claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScientificEvidenceDisposition {
    /// Evidence supports the stated claim under its declared conditions.
    Supports,
    /// Evidence rejects the stated claim/candidate under its declared conditions.
    Rejects,
    /// Evidence does not resolve the claim either way.
    Inconclusive,
    /// Support-versus-rejection does not apply to this evidence item.
    NotApplicable,
}

/// Provenance-preserving scientific observation suitable for CCOS evidence memory.
///
/// `source_ref` must identify immutable upstream evidence (for example a commit,
/// run, artifact digest, or signed observation). Optional semantic and
/// approximation labels are descriptive metadata only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScientificEvidenceObservation {
    source_ref: MemoryEvidenceRef,
    kind: ScientificEvidenceKind,
    disposition: ScientificEvidenceDisposition,
    statement: String,
    semantic_identity: Option<String>,
    approximation_class: Option<String>,
}

impl ScientificEvidenceObservation {
    /// Construct a version-1 scientific observation.
    ///
    /// # Errors
    ///
    /// Empty statements and empty optional metadata fail closed. The immutable
    /// source reference is already validated by [`MemoryEvidenceRef`].
    pub fn new(
        source_ref: MemoryEvidenceRef,
        kind: ScientificEvidenceKind,
        disposition: ScientificEvidenceDisposition,
        statement: impl Into<String>,
    ) -> Result<Self, ScientificEvidenceError> {
        let statement = statement.into();
        if statement.trim().is_empty() {
            return Err(ScientificEvidenceError::EmptyStatement);
        }
        Ok(Self {
            source_ref,
            kind,
            disposition,
            statement,
            semantic_identity: None,
            approximation_class: None,
        })
    }

    /// Attach an upstream semantic identity as descriptive provenance.
    ///
    /// # Errors
    ///
    /// Empty identities fail closed.
    pub fn with_semantic_identity(
        mut self,
        semantic_identity: impl Into<String>,
    ) -> Result<Self, ScientificEvidenceError> {
        let semantic_identity = semantic_identity.into();
        if semantic_identity.trim().is_empty() {
            return Err(ScientificEvidenceError::EmptySemanticIdentity);
        }
        self.semantic_identity = Some(semantic_identity);
        Ok(self)
    }

    /// Attach an explicit upstream approximation classification.
    ///
    /// # Errors
    ///
    /// Empty classifications fail closed.
    pub fn with_approximation_class(
        mut self,
        approximation_class: impl Into<String>,
    ) -> Result<Self, ScientificEvidenceError> {
        let approximation_class = approximation_class.into();
        if approximation_class.trim().is_empty() {
            return Err(ScientificEvidenceError::EmptyApproximationClass);
        }
        self.approximation_class = Some(approximation_class);
        Ok(self)
    }

    /// Immutable external source evidence reference.
    #[must_use]
    pub const fn source_ref(&self) -> &MemoryEvidenceRef {
        &self.source_ref
    }

    /// Preserved upstream evidence kind.
    #[must_use]
    pub const fn kind(&self) -> ScientificEvidenceKind {
        self.kind
    }

    /// Preserved upstream disposition, including negative/inconclusive results.
    #[must_use]
    pub const fn disposition(&self) -> ScientificEvidenceDisposition {
        self.disposition
    }

    /// Exact upstream claim/result statement supplied to the adapter.
    #[must_use]
    pub fn statement(&self) -> &str {
        &self.statement
    }

    /// Optional semantic identity supplied by the research producer.
    #[must_use]
    pub fn semantic_identity(&self) -> Option<&str> {
        self.semantic_identity.as_deref()
    }

    /// Optional explicit approximation classification.
    #[must_use]
    pub fn approximation_class(&self) -> Option<&str> {
        self.approximation_class.as_deref()
    }

    /// Build the governed CCOS descriptor for initial evidence ingestion.
    ///
    /// The stratum is always [`MemoryStratum::Evidence`] and lineage is always
    /// rooted in the immutable external source. No caller can relabel an import
    /// as `Episode`, `Context`, or `Pattern` through this adapter.
    ///
    /// # Errors
    ///
    /// Propagates existing CCOS memory identity/space/lineage validation errors.
    pub fn evidence_descriptor(
        &self,
        asset_id: MemoryAssetId,
        space: MemorySpace,
    ) -> Result<MemoryAssetDescriptor, MemoryError> {
        let lineage = MemoryLineage::root([self.source_ref.clone()])?;
        MemoryAssetDescriptor::new(asset_id, space, MemoryStratum::Evidence, lineage)
    }

    /// Deterministic versioned record suitable for evidence payloads and audit keys.
    ///
    /// This encoding is deliberately simple and local to version 1. It includes
    /// scientific/provenance metadata only and contains no authorization state.
    #[must_use]
    pub fn canonical_record(&self) -> String {
        let semantic = self.semantic_identity.as_deref().unwrap_or("-");
        let approximation = self.approximation_class.as_deref().unwrap_or("-");
        format!(
            "ccos-scientific-evidence-v{SCIENTIFIC_EVIDENCE_OBSERVATION_VERSION};source={};kind={};disposition={};statement_len={};statement={};semantic={semantic};approximation={approximation}",
            self.source_ref.as_str(),
            kind_tag(self.kind),
            disposition_tag(self.disposition),
            self.statement.len(),
            self.statement,
        )
    }

    /// Stable FNV-1a-64 fingerprint of [`Self::canonical_record`].
    ///
    /// This is a deterministic deduplication/audit aid, not a cryptographic
    /// digest and not an authorization token.
    #[must_use]
    pub fn stable_fingerprint(&self) -> u64 {
        fnv1a64(self.canonical_record().as_bytes())
    }
}

/// Fail-closed validation errors for scientific-observation metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScientificEvidenceError {
    /// Scientific statement was empty or whitespace-only.
    EmptyStatement,
    /// Optional semantic identity was empty or whitespace-only.
    EmptySemanticIdentity,
    /// Optional approximation classification was empty or whitespace-only.
    EmptyApproximationClass,
}

impl fmt::Display for ScientificEvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyStatement => {
                formatter.write_str("scientific evidence statement must not be empty")
            }
            Self::EmptySemanticIdentity => {
                formatter.write_str("scientific semantic identity must not be empty")
            }
            Self::EmptyApproximationClass => {
                formatter.write_str("scientific approximation class must not be empty")
            }
        }
    }
}

impl std::error::Error for ScientificEvidenceError {}

const fn kind_tag(kind: ScientificEvidenceKind) -> &'static str {
    match kind {
        ScientificEvidenceKind::EmpiricalValidation => "empirical_validation",
        ScientificEvidenceKind::NumericalApproximation => "numerical_approximation",
        ScientificEvidenceKind::ExactMathematicalResult => "exact_mathematical_result",
        ScientificEvidenceKind::PhenomenologicalModel => "phenomenological_model",
        ScientificEvidenceKind::SpeculativeModel => "speculative_model",
        ScientificEvidenceKind::RejectionCriterion => "rejection_criterion",
    }
}

const fn disposition_tag(disposition: ScientificEvidenceDisposition) -> &'static str {
    match disposition {
        ScientificEvidenceDisposition::Supports => "supports",
        ScientificEvidenceDisposition::Rejects => "rejects",
        ScientificEvidenceDisposition::Inconclusive => "inconclusive",
        ScientificEvidenceDisposition::NotApplicable => "not_applicable",
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(disposition: ScientificEvidenceDisposition) -> ScientificEvidenceObservation {
        ScientificEvidenceObservation::new(
            MemoryEvidenceRef::new("github:Memorithm/scirust@deadbeef#run-17").unwrap(),
            ScientificEvidenceKind::NumericalApproximation,
            disposition,
            "bounded history improves endpoint error over complete history",
        )
        .unwrap()
    }

    #[test]
    fn imported_observation_is_forced_into_root_evidence_stratum() {
        let observation = observation(ScientificEvidenceDisposition::Rejects);
        let descriptor = observation
            .evidence_descriptor(
                MemoryAssetId::new("memory:science:17").unwrap(),
                MemorySpace::project("attention-research").unwrap(),
            )
            .unwrap();

        assert_eq!(descriptor.stratum, MemoryStratum::Evidence);
        assert!(descriptor.lineage.is_root());
        assert_eq!(
            descriptor.lineage.evidence().collect::<Vec<_>>(),
            vec![observation.source_ref()]
        );
    }

    #[test]
    fn negative_and_inconclusive_results_remain_distinct_first_class_evidence() {
        let rejected = observation(ScientificEvidenceDisposition::Rejects);
        let inconclusive = observation(ScientificEvidenceDisposition::Inconclusive);

        assert_eq!(
            rejected.disposition(),
            ScientificEvidenceDisposition::Rejects
        );
        assert_eq!(
            inconclusive.disposition(),
            ScientificEvidenceDisposition::Inconclusive
        );
        assert_ne!(rejected.canonical_record(), inconclusive.canonical_record());
        assert_ne!(
            rejected.stable_fingerprint(),
            inconclusive.stable_fingerprint()
        );
    }

    #[test]
    fn scientific_metadata_is_descriptive_and_deterministic() {
        let first = observation(ScientificEvidenceDisposition::Supports)
            .with_semantic_identity("nonlocal-history-softmax@1")
            .unwrap()
            .with_approximation_class("windowed")
            .unwrap();
        let second = first.clone();

        assert_eq!(first.canonical_record(), second.canonical_record());
        assert_eq!(first.stable_fingerprint(), second.stable_fingerprint());
        let record = first.canonical_record();
        for forbidden in [
            "capability_token",
            "resource_lease",
            "resource_budget",
            "approval_token",
        ] {
            assert!(!record.contains(forbidden));
        }
    }

    #[test]
    fn malformed_observation_metadata_fails_closed() {
        let source = MemoryEvidenceRef::new("artifact:abc").unwrap();
        assert_eq!(
            ScientificEvidenceObservation::new(
                source.clone(),
                ScientificEvidenceKind::SpeculativeModel,
                ScientificEvidenceDisposition::Inconclusive,
                "  ",
            ),
            Err(ScientificEvidenceError::EmptyStatement)
        );
        assert_eq!(
            observation(ScientificEvidenceDisposition::Supports)
                .with_semantic_identity(" ")
                .unwrap_err(),
            ScientificEvidenceError::EmptySemanticIdentity
        );
        assert_eq!(
            observation(ScientificEvidenceDisposition::Supports)
                .with_approximation_class("")
                .unwrap_err(),
            ScientificEvidenceError::EmptyApproximationClass
        );
    }
}
