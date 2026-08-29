use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemoryValidationState {
    Unverified,
    Corroborated,
    Verified,
    Disputed,
    Quarantined,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryTrustMetadata {
    state: MemoryValidationState,
    source_count: u32,
    independent_source_count: u32,
    contradiction_count: u32,
    verification_refs: Vec<String>,
}

impl MemoryTrustMetadata {
    pub fn new(
        state: MemoryValidationState,
        source_count: u32,
        independent_source_count: u32,
        contradiction_count: u32,
        verification_refs: impl IntoIterator<Item = String>,
    ) -> Result<Self, MemoryTrustError> {
        if independent_source_count > source_count {
            return Err(MemoryTrustError::IndependentSourcesExceedSources { source_count, independent_source_count });
        }
        let mut verification_refs: Vec<_> = verification_refs.into_iter().collect();
        if verification_refs.iter().any(|value| value.trim().is_empty()) {
            return Err(MemoryTrustError::EmptyVerificationRef);
        }
        verification_refs.sort();
        verification_refs.dedup();
        match state {
            MemoryValidationState::Corroborated if independent_source_count < 2 => {
                return Err(MemoryTrustError::CorroborationRequiresIndependentSources);
            }
            MemoryValidationState::Verified if verification_refs.is_empty() => {
                return Err(MemoryTrustError::VerificationRequiresEvidence);
            }
            MemoryValidationState::Unverified | MemoryValidationState::Corroborated | MemoryValidationState::Verified if contradiction_count > 0 => {
                return Err(MemoryTrustError::ContradictionsRequireDisputedState);
            }
            _ => {}
        }
        Ok(Self { state, source_count, independent_source_count, contradiction_count, verification_refs })
    }

    pub fn unverified(source_count: u32) -> Self {
        Self { state: MemoryValidationState::Unverified, source_count, independent_source_count: source_count.min(1), contradiction_count: 0, verification_refs: Vec::new() }
    }

    pub const fn state(&self) -> MemoryValidationState { self.state }
    pub const fn source_count(&self) -> u32 { self.source_count }
    pub const fn independent_source_count(&self) -> u32 { self.independent_source_count }
    pub const fn contradiction_count(&self) -> u32 { self.contradiction_count }
    pub fn verification_refs(&self) -> impl Iterator<Item=&str> { self.verification_refs.iter().map(String::as_str) }
    pub const fn recall_eligible(&self) -> bool { !matches!(self.state, MemoryValidationState::Quarantined) }
    pub const fn promotion_eligible(&self) -> bool { matches!(self.state, MemoryValidationState::Verified) && self.contradiction_count == 0 }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryTrustError {
    IndependentSourcesExceedSources { source_count: u32, independent_source_count: u32 },
    EmptyVerificationRef,
    CorroborationRequiresIndependentSources,
    VerificationRequiresEvidence,
    ContradictionsRequireDisputedState,
}

impl fmt::Display for MemoryTrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IndependentSourcesExceedSources { source_count, independent_source_count } => write!(f, "independent source count {independent_source_count} exceeds total source count {source_count}"),
            Self::EmptyVerificationRef => write!(f, "memory verification references must not be empty"),
            Self::CorroborationRequiresIndependentSources => write!(f, "corroborated memory requires at least two independent sources"),
            Self::VerificationRequiresEvidence => write!(f, "verified memory requires at least one verification reference"),
            Self::ContradictionsRequireDisputedState => write!(f, "memory with known contradictions must use the disputed state"),
        }
    }
}
impl std::error::Error for MemoryTrustError {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_sources_cannot_exceed_total_sources() {
        assert!(matches!(MemoryTrustMetadata::new(MemoryValidationState::Unverified,1,2,0,Vec::<String>::new()), Err(MemoryTrustError::IndependentSourcesExceedSources { .. })));
    }
    #[test]
    fn corroboration_requires_real_independence() {
        assert_eq!(MemoryTrustMetadata::new(MemoryValidationState::Corroborated,3,1,0,Vec::<String>::new()), Err(MemoryTrustError::CorroborationRequiresIndependentSources));
    }
    #[test]
    fn verification_requires_evidence_and_deduplicates_refs() {
        assert_eq!(MemoryTrustMetadata::new(MemoryValidationState::Verified,1,1,0,Vec::<String>::new()), Err(MemoryTrustError::VerificationRequiresEvidence));
        let trust = MemoryTrustMetadata::new(MemoryValidationState::Verified,2,2,0,["proof:b".into(),"proof:a".into(),"proof:b".into()]).unwrap();
        assert_eq!(trust.verification_refs().collect::<Vec<_>>(), vec!["proof:a","proof:b"]);
        assert!(trust.promotion_eligible());
    }
    #[test]
    fn contradictions_cannot_hide_behind_positive_state() {
        assert_eq!(MemoryTrustMetadata::new(MemoryValidationState::Corroborated,3,3,1,Vec::<String>::new()), Err(MemoryTrustError::ContradictionsRequireDisputedState));
        let disputed = MemoryTrustMetadata::new(MemoryValidationState::Disputed,3,3,1,Vec::<String>::new()).unwrap();
        assert!(!disputed.promotion_eligible());
        assert!(disputed.recall_eligible());
    }
    #[test]
    fn quarantined_memory_is_not_recall_eligible() {
        let quarantined = MemoryTrustMetadata::new(MemoryValidationState::Quarantined,1,1,0,Vec::<String>::new()).unwrap();
        assert!(!quarantined.recall_eligible());
        assert!(!quarantined.promotion_eligible());
    }
}
