use std::collections::BTreeMap;
use std::fmt;

use crate::{
    GovernedMemoryObservation, MemoryAssetId, MemoryAssetState, MemoryLineageGraph, MemorySpace,
    MemoryTrustMetadata, MemoryValidationState,
};

/// Minimum trust class required before a governed memory observation can be used.
///
/// This policy is an admission gate, never a ranking signal. Similarity does not
/// influence whether an asset satisfies governance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernedRecallTrustPolicy {
    /// Admit any active asset except one explicitly quarantined.
    AnyNonQuarantined,
    /// Require corroborated or verified evidence; disputed and unverified assets stay out.
    CorroboratedOrVerified,
    /// Admit only explicitly verified assets.
    VerifiedOnly,
}

/// Read-only governance state used to narrow identity-bearing recall results.
#[derive(Debug, Clone, Copy)]
pub struct GovernedRecallGate<'a> {
    pub graph: &'a MemoryLineageGraph,
    pub trust: &'a BTreeMap<MemoryAssetId, MemoryTrustMetadata>,
    pub policy: GovernedRecallTrustPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernedRecallGateError {
    ProviderReturnedUnknownAsset(MemoryAssetId),
    /// A provider must preserve the canonical space, even within one loadout.
    ProviderReturnedMismatchedSpace {
        asset_id: MemoryAssetId,
        expected: MemorySpace,
        observed: MemorySpace,
    },
    MissingTrustMetadata(MemoryAssetId),
}

impl fmt::Display for GovernedRecallGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProviderReturnedUnknownAsset(id) => write!(
                f,
                "governed memory provider returned unknown asset {}",
                id.as_str()
            ),
            Self::ProviderReturnedMismatchedSpace {
                asset_id,
                expected,
                observed,
            } => write!(
                f,
                "governed memory asset {} has space {observed:?}, expected {expected:?}",
                asset_id.as_str()
            ),
            Self::MissingTrustMetadata(id) => write!(
                f,
                "governed memory asset {} has no trust metadata",
                id.as_str()
            ),
        }
    }
}

impl std::error::Error for GovernedRecallGateError {}

/// Apply canonical space, lineage state and trust policy to provider results.
///
/// The function preserves provider order and only narrows the result set. Unknown
/// provider identities, mismatched canonical spaces and missing trust metadata
/// fail closed. Loadout membership alone does not prove an asset's space: the
/// descriptor check precedes inactive/trust filtering and applies to every
/// observation passed to this gate. No admitted prefix is returned on error.
///
/// This boundary does not authenticate a tenant or bind payload bytes to evidence.
/// Those remain separate request and content-integrity contracts.
pub fn admit_governed_recall(
    gate: GovernedRecallGate<'_>,
    observations: impl IntoIterator<Item = GovernedMemoryObservation>,
) -> Result<Vec<GovernedMemoryObservation>, GovernedRecallGateError> {
    let mut admitted = Vec::new();
    for observation in observations {
        let descriptor = gate
            .graph
            .descriptor(&observation.asset_id)
            .ok_or_else(|| {
                GovernedRecallGateError::ProviderReturnedUnknownAsset(observation.asset_id.clone())
            })?;
        if descriptor.space != observation.space {
            return Err(GovernedRecallGateError::ProviderReturnedMismatchedSpace {
                asset_id: observation.asset_id,
                expected: descriptor.space.clone(),
                observed: observation.space,
            });
        }
        let state = gate.graph.state(&observation.asset_id).ok_or_else(|| {
            GovernedRecallGateError::ProviderReturnedUnknownAsset(observation.asset_id.clone())
        })?;
        if state != MemoryAssetState::Active {
            continue;
        }

        let trust = gate.trust.get(&observation.asset_id).ok_or_else(|| {
            GovernedRecallGateError::MissingTrustMetadata(observation.asset_id.clone())
        })?;
        if !trust.recall_eligible() || !policy_allows(gate.policy, trust.state()) {
            continue;
        }
        admitted.push(observation);
    }
    Ok(admitted)
}

fn policy_allows(policy: GovernedRecallTrustPolicy, state: MemoryValidationState) -> bool {
    match policy {
        GovernedRecallTrustPolicy::AnyNonQuarantined => {
            !matches!(state, MemoryValidationState::Quarantined)
        }
        GovernedRecallTrustPolicy::CorroboratedOrVerified => matches!(
            state,
            MemoryValidationState::Corroborated | MemoryValidationState::Verified
        ),
        GovernedRecallTrustPolicy::VerifiedOnly => {
            matches!(state, MemoryValidationState::Verified)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MemoryAssetDescriptor, MemoryEvidenceRef, MemoryLineage, MemorySpace, MemoryStratum,
    };

    fn id(value: &str) -> MemoryAssetId {
        MemoryAssetId::new(value).unwrap()
    }

    fn descriptor(value: &str) -> MemoryAssetDescriptor {
        MemoryAssetDescriptor::new(
            id(value),
            MemorySpace::Tenant,
            MemoryStratum::Evidence,
            MemoryLineage::root([MemoryEvidenceRef::new(format!("audit:{value}")).unwrap()])
                .unwrap(),
        )
        .unwrap()
    }

    fn observation(value: &str, similarity: f32) -> GovernedMemoryObservation {
        GovernedMemoryObservation {
            asset_id: id(value),
            space: MemorySpace::Tenant,
            payload: value.as_bytes().to_vec(),
            similarity,
        }
    }

    fn verified() -> MemoryTrustMetadata {
        MemoryTrustMetadata::new(MemoryValidationState::Verified, 1, 1, 0, ["proof:1".into()])
            .unwrap()
    }

    #[test]
    fn unknown_provider_asset_fails_closed() {
        let graph = MemoryLineageGraph::new();
        let trust = BTreeMap::new();
        assert_eq!(
            admit_governed_recall(
                GovernedRecallGate {
                    graph: &graph,
                    trust: &trust,
                    policy: GovernedRecallTrustPolicy::AnyNonQuarantined,
                },
                [observation("missing", 1.0)],
            ),
            Err(GovernedRecallGateError::ProviderReturnedUnknownAsset(id(
                "missing"
            )))
        );
    }

    #[test]
    fn inactive_lineage_is_removed_before_context_use() {
        let mut graph = MemoryLineageGraph::new();
        graph.register(descriptor("expired")).unwrap();
        graph.invalidate(&id("expired")).unwrap();
        let trust = BTreeMap::from([(id("expired"), verified())]);

        let admitted = admit_governed_recall(
            GovernedRecallGate {
                graph: &graph,
                trust: &trust,
                policy: GovernedRecallTrustPolicy::VerifiedOnly,
            },
            [observation("expired", 1.0)],
        )
        .unwrap();
        assert!(admitted.is_empty());
    }

    #[test]
    fn missing_trust_metadata_fails_closed() {
        let mut graph = MemoryLineageGraph::new();
        graph.register(descriptor("known")).unwrap();
        let trust = BTreeMap::new();
        assert_eq!(
            admit_governed_recall(
                GovernedRecallGate {
                    graph: &graph,
                    trust: &trust,
                    policy: GovernedRecallTrustPolicy::AnyNonQuarantined,
                },
                [observation("known", 1.0)],
            ),
            Err(GovernedRecallGateError::MissingTrustMetadata(id("known")))
        );
    }

    #[test]
    fn quarantine_and_stricter_trust_policies_only_narrow_results() {
        let mut graph = MemoryLineageGraph::new();
        for value in ["unverified", "corroborated", "verified", "quarantined"] {
            graph.register(descriptor(value)).unwrap();
        }
        let trust = BTreeMap::from([
            (id("unverified"), MemoryTrustMetadata::unverified(1)),
            (
                id("corroborated"),
                MemoryTrustMetadata::new(
                    MemoryValidationState::Corroborated,
                    2,
                    2,
                    0,
                    Vec::<String>::new(),
                )
                .unwrap(),
            ),
            (id("verified"), verified()),
            (
                id("quarantined"),
                MemoryTrustMetadata::new(
                    MemoryValidationState::Quarantined,
                    1,
                    1,
                    0,
                    Vec::<String>::new(),
                )
                .unwrap(),
            ),
        ]);
        let source = [
            observation("unverified", 0.9),
            observation("corroborated", 0.8),
            observation("verified", 0.7),
            observation("quarantined", 1.0),
        ];

        let corroborated = admit_governed_recall(
            GovernedRecallGate {
                graph: &graph,
                trust: &trust,
                policy: GovernedRecallTrustPolicy::CorroboratedOrVerified,
            },
            source.clone(),
        )
        .unwrap();
        assert_eq!(
            corroborated
                .iter()
                .map(|item| item.asset_id.as_str())
                .collect::<Vec<_>>(),
            vec!["corroborated", "verified"]
        );

        let verified_only = admit_governed_recall(
            GovernedRecallGate {
                graph: &graph,
                trust: &trust,
                policy: GovernedRecallTrustPolicy::VerifiedOnly,
            },
            source,
        )
        .unwrap();
        assert_eq!(verified_only.len(), 1);
        assert_eq!(verified_only[0].asset_id.as_str(), "verified");
    }
}
