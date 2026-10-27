use std::collections::BTreeMap;
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
    /// No trust metadata is recorded for this asset in the supplied store.
    MissingTrust(MemoryAssetId),
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
            Self::MissingTrust(id) => {
                write!(f, "no trust metadata recorded for memory asset {}", id.as_str())
            }
        }
    }
}

impl std::error::Error for MemoryPromotionError {}

/// Evaluate promotion for `asset_id`, looking its trust metadata up **by the
/// same id** in `trust_store` (e.g. `MemoryProjection::trust`).
///
/// This is the recommended entry point: it makes it impossible to evaluate one
/// asset against another asset's trust evidence. A missing entry fails closed
/// with [`MemoryPromotionError::MissingTrust`], after the graph-side gates.
pub fn evaluate_memory_promotion_in(
    graph: &MemoryLineageGraph,
    asset_id: &MemoryAssetId,
    trust_store: &BTreeMap<MemoryAssetId, MemoryTrustMetadata>,
) -> Result<MemoryPromotionCandidate, MemoryPromotionError> {
    // Run graph gates first so error precedence matches `evaluate_memory_promotion`.
    let placeholder = MemoryTrustMetadata::unverified(0);
    match trust_store.get(asset_id) {
        Some(trust) => evaluate_memory_promotion(graph, asset_id, trust),
        None => match evaluate_memory_promotion(graph, asset_id, &placeholder) {
            Err(MemoryPromotionError::TrustNotEligible { .. }) => {
                Err(MemoryPromotionError::MissingTrust(asset_id.clone()))
            }
            Err(other) => Err(other),
            Ok(_) => Err(MemoryPromotionError::MissingTrust(asset_id.clone())),
        },
    }
}

/// Evaluate the memory-side promotion gates for one governed asset.
///
/// The order is fail-closed and deliberate: existence, lineage validity state,
/// semantic stratum, then trust evidence. No numeric confidence score is
/// invented and no downstream lifecycle transition is performed here.
///
/// **Caller contract (audit 2026-10-27):** `trust` is *not* bound to `asset_id`
/// by type or content; this function cannot detect trust metadata belonging to
/// a different asset. Callers must look `trust` up by the same `asset_id`.
/// Prefer [`evaluate_memory_promotion_in`], which performs the lookup itself.
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
    fn store_lookup_ignores_another_assets_trust() {
        let graph = pattern_graph();
        let mut store = BTreeMap::new();
        // Verified trust recorded for a *different* asset must not promote "pattern".
        store.insert(id("context"), verified());
        assert_eq!(
            evaluate_memory_promotion_in(&graph, &id("pattern"), &store),
            Err(MemoryPromotionError::MissingTrust(id("pattern")))
        );
        store.insert(id("pattern"), MemoryTrustMetadata::unverified(1));
        assert!(matches!(
            evaluate_memory_promotion_in(&graph, &id("pattern"), &store),
            Err(MemoryPromotionError::TrustNotEligible { .. })
        ));
        store.insert(id("pattern"), verified());
        assert_eq!(
            evaluate_memory_promotion_in(&graph, &id("pattern"), &store)
                .unwrap()
                .asset_id,
            id("pattern")
        );
    }

    #[test]
    fn store_lookup_keeps_graph_gate_precedence() {
        let graph = pattern_graph();
        let store = BTreeMap::new();
        assert!(matches!(
            evaluate_memory_promotion_in(&graph, &id("missing"), &store),
            Err(MemoryPromotionError::UnknownAsset(_))
        ));
        assert!(matches!(
            evaluate_memory_promotion_in(&graph, &id("context"), &store),
            Err(MemoryPromotionError::NotPattern { .. })
        ));
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
