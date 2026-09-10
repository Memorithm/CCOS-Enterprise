//! Server-facing composition for governed semantic-memory context.
//!
//! This module owns no vector index and no durable governance state. It composes
//! the backend-neutral memory contracts so a served path can retrieve only from
//! an explicit bootstrap loadout, bound provider output, apply lineage/trust
//! admission, and assemble a bounded context without dropping `MemoryAssetId`.

use std::fmt;

use ccos_enterprise_memory::{
    admit_governed_recall, assemble_governed_bootstrap_context, BudgetedMemoryRecall,
    GovernedMemoryContextAssembly, GovernedRecallGate, GovernedRecallGateError,
    GovernedSemanticMemoryProvider, GovernedSemanticMemoryProviderExt, MemoryContextBudget,
    MemoryContextError, MemoryLoadoutPlan, MemoryLoadoutPlanError, MemoryRecallBudget,
    MemoryRecallBudgetError,
};
use ccos_enterprise_tenancy::{TenantId, TenantScope};

#[derive(Debug)]
pub enum ServedContextError {
    Loadout(MemoryLoadoutPlanError),
    NoBootstrapLoadout,
    Recall(MemoryRecallBudgetError),
    RecallAdmission(GovernedRecallGateError),
    Context(MemoryContextError),
}

impl fmt::Display for ServedContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Loadout(error) => write!(f, "invalid governed memory loadout: {error}"),
            Self::NoBootstrapLoadout => {
                f.write_str("governed memory loadout has no bootstrap-enabled space")
            }
            Self::Recall(error) => write!(f, "governed memory recall failed: {error}"),
            Self::RecallAdmission(error) => {
                write!(f, "governed memory recall admission failed: {error}")
            }
            Self::Context(error) => write!(f, "governed memory context assembly failed: {error}"),
        }
    }
}

impl std::error::Error for ServedContextError {}

impl From<MemoryLoadoutPlanError> for ServedContextError {
    fn from(value: MemoryLoadoutPlanError) -> Self {
        Self::Loadout(value)
    }
}

impl From<MemoryRecallBudgetError> for ServedContextError {
    fn from(value: MemoryRecallBudgetError) -> Self {
        Self::Recall(value)
    }
}

impl From<GovernedRecallGateError> for ServedContextError {
    fn from(value: GovernedRecallGateError) -> Self {
        Self::RecallAdmission(value)
    }
}

impl From<MemoryContextError> for ServedContextError {
    fn from(value: MemoryContextError) -> Self {
        Self::Context(value)
    }
}

/// Retrieve and assemble one governed bootstrap context for a served tenant.
///
/// Order is security-significant:
/// 1. narrow the configured plan to bootstrap-enabled spaces;
/// 2. bound and validate provider output;
/// 3. apply lineage and categorical trust admission;
/// 4. assemble the final item/byte-bounded context.
///
/// This function deliberately performs no RBAC or request admission itself. A
/// real MCP handler must first cross the existing `Deployment::admit` front door
/// and must supply durable/reconstructed lineage and trust state to `gate`.
pub fn assemble_served_governed_context<P: GovernedSemanticMemoryProvider + ?Sized>(
    provider: &P,
    tenant: TenantId,
    plan: &MemoryLoadoutPlan,
    gate: GovernedRecallGate<'_>,
    embedding: &[f32],
    recall_budget: MemoryRecallBudget,
    context_budget: MemoryContextBudget,
) -> Result<GovernedMemoryContextAssembly, ServedContextError> {
    let loadout = plan
        .bootstrap_loadout()?
        .ok_or(ServedContextError::NoBootstrapLoadout)?;
    let recalled = provider.recall_governed_bounded(TenantScope::new(
        tenant,
        BudgetedMemoryRecall {
            embedding,
            loadout: &loadout,
            budget: recall_budget,
        },
    ))?;
    let admitted = admit_governed_recall(gate, recalled)?;
    Ok(assemble_governed_bootstrap_context(
        plan,
        admitted,
        context_budget,
    )?)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use ccos_enterprise_memory::{
        GovernedMemoryObservation, GovernedMemoryWrite, GovernedRecallTrustPolicy,
        LoadoutMemoryQuery, MemoryAssetDescriptor, MemoryAssetId, MemoryError, MemoryEvidenceRef,
        MemoryLineage, MemoryLineageGraph, MemoryLoadoutBinding, MemorySpace, MemoryStratum,
        MemoryTrustMetadata, MemoryUsageMode, MemoryValidationState,
    };

    struct Provider {
        observations: Vec<GovernedMemoryObservation>,
    }

    impl GovernedSemanticMemoryProvider for Provider {
        fn insert_governed(
            &mut self,
            _scoped: TenantScope<GovernedMemoryWrite<'_>>,
        ) -> Result<(), MemoryError> {
            Ok(())
        }

        fn recall_governed(
            &self,
            scoped: TenantScope<LoadoutMemoryQuery<'_>>,
        ) -> Result<Vec<GovernedMemoryObservation>, MemoryError> {
            assert!(scoped
                .inner
                .loadout
                .spaces()
                .all(|space| space == &MemorySpace::Tenant));
            Ok(self.observations.clone())
        }
    }

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

    fn plan(usage: MemoryUsageMode) -> MemoryLoadoutPlan {
        MemoryLoadoutPlan::new(
            [MemoryLoadoutBinding::new(MemorySpace::Tenant, 100, usage).unwrap()],
        )
        .unwrap()
    }

    #[test]
    fn served_composition_filters_inactive_and_quarantined_assets() {
        let mut graph = MemoryLineageGraph::new();
        for value in ["active", "inactive", "quarantined"] {
            graph.register(descriptor(value)).unwrap();
        }
        graph.invalidate(&id("inactive")).unwrap();
        let trust = BTreeMap::from([
            (id("active"), verified()),
            (id("inactive"), verified()),
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
        let provider = Provider {
            observations: vec![
                observation("quarantined", 1.0),
                observation("inactive", 0.9),
                observation("active", 0.8),
            ],
        };
        let embedding = [1.0_f32, 0.0];
        let plan = plan(MemoryUsageMode::BootstrapAndOnDemand);
        let context = assemble_served_governed_context(
            &provider,
            ccos_enterprise_tenancy::TenantId("acme".into()),
            &plan,
            GovernedRecallGate {
                graph: &graph,
                trust: &trust,
                policy: GovernedRecallTrustPolicy::VerifiedOnly,
            },
            &embedding,
            MemoryRecallBudget::new(8, 16, 1024).unwrap(),
            MemoryContextBudget::new(8, 1024).unwrap(),
        )
        .unwrap();

        assert_eq!(context.len(), 1);
        assert_eq!(context.chunks()[0].asset_id.as_str(), "active");
        assert_eq!(context.chunks()[0].payload, b"active");
    }

    #[test]
    fn missing_governance_join_fails_closed() {
        let mut graph = MemoryLineageGraph::new();
        graph.register(descriptor("known")).unwrap();
        let provider = Provider {
            observations: vec![observation("known", 1.0)],
        };
        let trust = BTreeMap::new();
        let embedding = [1.0_f32, 0.0];
        let plan = plan(MemoryUsageMode::Bootstrap);
        assert!(matches!(
            assemble_served_governed_context(
                &provider,
                ccos_enterprise_tenancy::TenantId("acme".into()),
                &plan,
                GovernedRecallGate {
                    graph: &graph,
                    trust: &trust,
                    policy: GovernedRecallTrustPolicy::AnyNonQuarantined,
                },
                &embedding,
                MemoryRecallBudget::new(4, 8, 1024).unwrap(),
                MemoryContextBudget::new(4, 1024).unwrap(),
            ),
            Err(ServedContextError::RecallAdmission(
                GovernedRecallGateError::MissingTrustMetadata(asset)
            )) if asset.as_str() == "known"
        ));
    }

    #[test]
    fn on_demand_only_plan_cannot_be_promoted_to_bootstrap() {
        let graph = MemoryLineageGraph::new();
        let trust = BTreeMap::new();
        let provider = Provider {
            observations: Vec::new(),
        };
        let embedding = [1.0_f32, 0.0];
        let plan = plan(MemoryUsageMode::OnDemand);
        assert!(matches!(
            assemble_served_governed_context(
                &provider,
                ccos_enterprise_tenancy::TenantId("acme".into()),
                &plan,
                GovernedRecallGate {
                    graph: &graph,
                    trust: &trust,
                    policy: GovernedRecallTrustPolicy::VerifiedOnly,
                },
                &embedding,
                MemoryRecallBudget::new(4, 8, 1024).unwrap(),
                MemoryContextBudget::new(4, 1024).unwrap(),
            ),
            Err(ServedContextError::NoBootstrapLoadout)
        ));
    }
}
