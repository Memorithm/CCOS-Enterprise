use std::fmt;

use crate::{
    MemoryAssetId, MemoryAssetState, MemoryLineageGraph, MemorySpace, MemoryStratum,
    MemoryTrustMetadata, MemoryValidationState,
};

/// A non-executable proposal that a governed memory pattern may be considered
/// by a downstream crystallization workflow.
///
/// Creating this value never publishes, activates, executes, or grants access
/// to a skill. It only records that the memory-side gates were satisfied at the
/// time of evaluation. Downstream proof, trial, policy, tenancy and activation
/// checks remain authoritative.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryPromotionCandidate {
    pub asset_id: MemoryAssetId,
    pub space: MemorySpace,
    pub validation_state: MemoryValidationState,
    pub verification_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryPromotionError {
    UnknownAsset(MemoryAssetId),
    AssetNotActive {
        asset_id: MemoryAssetId,
        state: MemoryAssetState,
    },
    NotPattern {
        asset_id: MemoryAssetId,
        stratum: MemoryStratum,
    },
    TrustNotEligible {
        asset_id: MemoryAssetId,
        state: MemoryValidationState,
        contradiction_count: u32,
    },
}

impl fmt::Display for MemoryPromotionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownAsset(id) => write!(f, "unknown memory asset: {}", id.as_str()),
            Self::AssetNotActive { asset_id, state } => write!(
                f,
                "memory asset {} is not active ({state:?})",
                asset_id.as_str()
            ),
            Self::NotPattern { asset_id, stratum } => write!(
                f,
                "memory asset {} is {stratum:?}, not a promotable pattern",
                asset_id.as_str()
            ),
            Self::TrustNotEligible {
                asset_id,
                state,
                contradiction_count,
            } => write!(
                f,
                "memory asset {} is not promotion-eligible (state {state:?}, contradictions {contradiction_count})",
                asset_id.as_str()
            ),
        }
    }
}

impl std::error::Error for MemoryPromotionError {}

/// Evaluate the memory-side promotion gates for one governed asset.
///
/// The order is fail-closed and deliberate: existence, lineage validity state,
/// semantic stratum, then trust evidence. No numeric confidence score is
/// invented and no downstream lifecycle transition is performed here.
pub fn evaluate_memory_promotion(
    graph: &MemoryLineageGraph,
    asset_id: &MemoryAssetId,
    trust: &MemoryTrustMetadata,
) -> Result<MemoryPromotionCandidate, MemoryPromotionError> {
    let descriptor = graph
        .descriptor(asset_id)
        .ok_or_else(|| MemoryPromotionError::UnknownAsset(asset_id.clone()))?;

    let state = graph
        .state(asset_id)
        .ok_or_else(|| MemoryPromotionError::UnknownAsset(asset_id.clone()))?;
    if state != MemoryAssetState::Active {
        return Err(MemoryPromotionError::AssetNotActive {
            asset_id: asset_id.clone(),
            state,
        });
    }

    if descriptor.stratum != MemoryStratum::Pattern {
        return Err(MemoryPromotionError::NotPattern {
            asset_id: asset_id.clone(),
            stratum: descriptor.stratum,
        });
    }

    if !trust.promotion_eligible() {
        return Err(MemoryPromotionError::TrustNotEligible {
            asset_id: asset_id.clone(),
            state: trust.state(),
            contradiction_count: trust.contradiction_count(),
        });
    }

    Ok(MemoryPromotionCandidate {
        asset_id: asset_id.clone(),
        space: descriptor.space.clone(),
        validation_state: trust.state(),
        verification_refs: trust.verification_refs().map(str::to_owned).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryAssetDescriptor, MemoryEvidenceRef, MemoryLineage};

    fn id(value: &str) -> MemoryAssetId {
        MemoryAssetId::new(value).unwrap()
    }

    fn evidence(value: &str) -> MemoryAssetDescriptor {
        MemoryAssetDescriptor::new(
            id(value),
            MemorySpace::Tenant,
            MemoryStratum::Evidence,
            MemoryLineage::root([MemoryEvidenceRef::new(format!("audit:{value}")).unwrap()])
                .unwrap(),
        )
        .unwrap()
    }

    fn derived(value: &str, stratum: MemoryStratum, parent: &str) -> MemoryAssetDescriptor {
        MemoryAssetDescriptor::new(
            id(value),
            MemorySpace::Tenant,
            stratum,
            MemoryLineage::derived([id(parent)], []).unwrap(),
        )
        .unwrap()
    }

    fn verified() -> MemoryTrustMetadata {
        MemoryTrustMetadata::new(
            MemoryValidationState::Verified,
            2,
            2,
            0,
            ["verify:2".into(), "verify:1".into()],
        )
        .unwrap()
    }

    fn pattern_graph() -> MemoryLineageGraph {
        let mut graph = MemoryLineageGraph::new();
        graph.register(evidence("e0")).unwrap();
        graph
            .register(derived("episode", MemoryStratum::Episode, "e0"))
            .unwrap();
        graph
            .register(derived("context", MemoryStratum::Context, "episode"))
            .unwrap();
        graph
            .register(derived("pattern", MemoryStratum::Pattern, "context"))
            .unwrap();
        graph
    }

    #[test]
    fn verified_active_pattern_becomes_candidate_only() {
        let graph = pattern_graph();
        let candidate = evaluate_memory_promotion(&graph, &id("pattern"), &verified()).unwrap();
        assert_eq!(candidate.asset_id, id("pattern"));
        assert_eq!(candidate.space, MemorySpace::Tenant);
        assert_eq!(candidate.validation_state, MemoryValidationState::Verified);
        assert_eq!(candidate.verification_refs, vec!["verify:1", "verify:2"]);
    }

    #[test]
    fn non_pattern_memory_cannot_be_promoted() {
        let graph = pattern_graph();
        assert_eq!(
            evaluate_memory_promotion(&graph, &id("context"), &verified()),
            Err(MemoryPromotionError::NotPattern {
                asset_id: id("context"),
                stratum: MemoryStratum::Context,
            })
        );
    }

    #[test]
    fn stale_pattern_cannot_be_promoted() {
        let mut graph = pattern_graph();
        graph.invalidate(&id("e0")).unwrap();
        assert_eq!(
            evaluate_memory_promotion(&graph, &id("pattern"), &verified()),
            Err(MemoryPromotionError::AssetNotActive {
                asset_id: id("pattern"),
                state: MemoryAssetState::Stale,
            })
        );
    }

    #[test]
    fn unverified_or_disputed_pattern_cannot_be_promoted() {
        let graph = pattern_graph();
        let unverified = MemoryTrustMetadata::unverified(1);
        assert!(matches!(
            evaluate_memory_promotion(&graph, &id("pattern"), &unverified),
            Err(MemoryPromotionError::TrustNotEligible {
                state: MemoryValidationState::Unverified,
                ..
            })
        ));

        let disputed = MemoryTrustMetadata::new(
            MemoryValidationState::Disputed,
            2,
            2,
            1,
            Vec::<String>::new(),
        )
        .unwrap();
        assert!(matches!(
            evaluate_memory_promotion(&graph, &id("pattern"), &disputed),
            Err(MemoryPromotionError::TrustNotEligible {
                state: MemoryValidationState::Disputed,
                contradiction_count: 1,
                ..
            })
        ));
    }

    #[test]
    fn unknown_asset_fails_closed() {
        let graph = MemoryLineageGraph::new();
        assert_eq!(
            evaluate_memory_promotion(&graph, &id("missing"), &verified()),
            Err(MemoryPromotionError::UnknownAsset(id("missing")))
        );
    }
}
