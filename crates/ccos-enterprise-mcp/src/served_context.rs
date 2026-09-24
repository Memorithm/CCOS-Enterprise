//! Server-facing composition for governed semantic-memory context.
//!
//! This module owns no vector index and no durable governance state. It composes
//! the backend-neutral memory contracts so a served path can retrieve only from
//! an explicit bootstrap loadout, bound provider output, apply lineage/trust
//! admission, and assemble a bounded context without dropping `MemoryAssetId`.

use std::fmt;

use ccos_enterprise_memory::{
    admit_governed_recall, assemble_governed_bootstrap_context, attest_governed_context,
    validate_admitted_provenance, BudgetedMemoryRecall, GovernedMemoryContextAssembly,
    GovernedMemoryProjection, GovernedMemoryStore, GovernedMemoryStoreError, GovernedRecallGate,
    GovernedRecallGateError, GovernedRecallTrustPolicy, GovernedSemanticMemoryProvider,
    GovernedSemanticMemoryProviderExt, MemoryContextAttestation, MemoryContextBudget,
    MemoryContextError, MemoryError, MemoryLoadoutPlanError, MemoryRecallBudget,
    MemoryRecallBudgetError, ProvenanceRecallError, ProvenanceRecallPolicy,
};
use ccos_enterprise_tenancy::{TenantId, TenantScope};

#[derive(Debug)]
pub enum ServedContextError {
    Loadout(MemoryLoadoutPlanError),
    NoBootstrapLoadout,
    Recall(MemoryRecallBudgetError),
    RecallAdmission(GovernedRecallGateError),
    Context(MemoryContextError),
    Attestation(MemoryError),
    Provenance(ProvenanceRecallError),
    Store(GovernedMemoryStoreError),
}

impl fmt::Display for ServedContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(f, "governed memory owner unavailable: {error}"),
            Self::Loadout(error) => write!(f, "invalid governed memory loadout: {error}"),
            Self::NoBootstrapLoadout => {
                f.write_str("governed memory loadout has no bootstrap-enabled space")
            }
            Self::Recall(error) => write!(f, "governed memory recall failed: {error}"),
            Self::RecallAdmission(error) => {
                write!(f, "governed memory recall admission failed: {error}")
            }
            Self::Context(error) => write!(f, "governed memory context assembly failed: {error}"),
            Self::Attestation(error) => {
                write!(f, "governed memory context attestation failed: {error}")
            }
            Self::Provenance(error) => {
                write!(f, "governed memory provenance admission failed: {error}")
            }
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

impl From<ProvenanceRecallError> for ServedContextError {
    fn from(value: ProvenanceRecallError) -> Self {
        Self::Provenance(value)
    }
}

impl From<MemoryError> for ServedContextError {
    fn from(value: MemoryError) -> Self {
        Self::Attestation(value)
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
    expected_tenant: &TenantId,
    projection: &GovernedMemoryProjection,
    policy: GovernedRecallTrustPolicy,
    embedding: &[f32],
    recall_budget: MemoryRecallBudget,
    context_budget: MemoryContextBudget,
) -> Result<GovernedMemoryContextAssembly, ServedContextError> {
    if expected_tenant != &projection.tenant {
        return Err(ServedContextError::RecallAdmission(
            GovernedRecallGateError::TenantMismatch {
                expected: expected_tenant.as_str().to_string(),
                found: projection.tenant.as_str().to_string(),
            },
        ));
    }
    let loadout = projection
        .loadout
        .bootstrap_loadout()?
        .ok_or(ServedContextError::NoBootstrapLoadout)?;
    let recalled = provider.recall_governed_bounded(TenantScope::new(
        expected_tenant.clone(),
        BudgetedMemoryRecall {
            embedding,
            loadout: &loadout,
            budget: recall_budget,
        },
    ))?;
    let admitted = admit_governed_recall(
        GovernedRecallGate {
            expected_tenant,
            projection,
            policy,
        },
        recalled,
    )?;
    validate_admitted_provenance(
        &projection.provenance,
        &admitted,
        ProvenanceRecallPolicy::ObservedOrDerived,
    )?;
    Ok(assemble_governed_bootstrap_context(
        projection,
        admitted,
        context_budget,
    )?)
}

/// Assemble context from a reconstructed governance projection.
///
/// The projection is the durable authority for lineage, trust and loadout.
/// Provider similarity still cannot mint eligibility; each surviving chunk
/// carries an attestation that names why it was admitted.
pub fn assemble_attested_served_context<P: GovernedSemanticMemoryProvider + ?Sized>(
    provider: &P,
    projection: &GovernedMemoryProjection,
    policy: GovernedRecallTrustPolicy,
    embedding: &[f32],
    recall_budget: MemoryRecallBudget,
    context_budget: MemoryContextBudget,
) -> Result<(GovernedMemoryContextAssembly, Vec<MemoryContextAttestation>), ServedContextError> {
    let assembly = assemble_served_governed_context(
        provider,
        &projection.tenant,
        projection,
        policy,
        embedding,
        recall_budget,
        context_budget,
    )?;
    let attested = attest_governed_context(&assembly);
    Ok((assembly, attested))
}

impl From<GovernedMemoryStoreError> for ServedContextError {
    fn from(value: GovernedMemoryStoreError) -> Self {
        Self::Store(value)
    }
}

/// Assemble from the acknowledged state of an exclusively owned projection.
///
/// Check the admitted request tenant and owner health before any provider
/// call. Borrowing the store also prevents replacement while this synchronous
/// context assembly is in progress. This function does not authenticate,
/// reserve quota or settle the request; the real handler must still enter
/// through `Deployment::admit`. It does not reconstruct provider indexes.
///
/// ```no_run
/// # use ccos_enterprise_mcp::{assemble_stored_governed_context, ServedContextError};
/// # use ccos_enterprise_memory::{GovernedMemoryStore, GovernedSemanticMemoryProvider,
/// # GovernedRecallTrustPolicy, MemoryRecallBudget, MemoryContextBudget};
/// # use ccos_enterprise_tenancy::TenantId;
/// # fn example<P: GovernedSemanticMemoryProvider>(provider: &P, store: &GovernedMemoryStore, admitted_tenant: &TenantId) -> Result<(), ServedContextError> {
/// let (context, evidence) = assemble_stored_governed_context(
///     provider, store, admitted_tenant, GovernedRecallTrustPolicy::VerifiedOnly,
///     &[1.0, 0.0], MemoryRecallBudget::new(8, 16, 4096).unwrap(),
///     MemoryContextBudget::new(4, 2048).unwrap(),
/// )?;
/// assert_eq!(context.len(), evidence.len());
/// # Ok(()) }
/// ```
pub fn assemble_stored_governed_context<P: GovernedSemanticMemoryProvider + ?Sized>(
    provider: &P,
    store: &GovernedMemoryStore,
    expected_tenant: &TenantId,
    policy: GovernedRecallTrustPolicy,
    embedding: &[f32],
    recall_budget: MemoryRecallBudget,
    context_budget: MemoryContextBudget,
) -> Result<(GovernedMemoryContextAssembly, Vec<MemoryContextAttestation>), ServedContextError> {
    let projection = store.projection_for(expected_tenant)?;
    assemble_attested_served_context(
        provider,
        projection,
        policy,
        embedding,
        recall_budget,
        context_budget,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ccos_enterprise_memory::{
        GovernedMemoryObservation, GovernedMemoryWrite, LoadoutMemoryQuery, MemoryAssetDescriptor,
        MemoryAssetId, MemoryEvidenceRef, MemoryLineage, MemoryLineageGraph, MemoryLoadoutBinding,
        MemoryLoadoutPlan, MemorySpace, MemoryStratum, MemoryTrustMetadata, MemoryUsageMode,
        MemoryValidationState,
    };
    use std::collections::BTreeMap;

    struct Provider {
        observations: Vec<GovernedMemoryObservation>,
    }
    impl GovernedSemanticMemoryProvider for Provider {
        fn insert_governed(
            &mut self,
            _: TenantScope<GovernedMemoryWrite<'_>>,
        ) -> Result<(), MemoryError> {
            Ok(())
        }
        fn recall_governed(
            &self,
            scoped: TenantScope<LoadoutMemoryQuery<'_>>,
        ) -> Result<Vec<GovernedMemoryObservation>, MemoryError> {
            assert_eq!(scoped.tenant.as_str(), "acme");
            Ok(self.observations.clone())
        }
    }
    fn id(v: &str) -> MemoryAssetId {
        MemoryAssetId::new(v).unwrap()
    }
    fn projection(usage: MemoryUsageMode, trust: bool) -> GovernedMemoryProjection {
        let mut graph = MemoryLineageGraph::new();
        graph
            .register(
                MemoryAssetDescriptor::new(
                    id("known"),
                    MemorySpace::Tenant,
                    MemoryStratum::Evidence,
                    MemoryLineage::root([MemoryEvidenceRef::new("audit:known").unwrap()]).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        let trust = if trust {
            BTreeMap::from([(
                id("known"),
                MemoryTrustMetadata::new(
                    MemoryValidationState::Verified,
                    1,
                    1,
                    0,
                    ["proof:1".into()],
                )
                .unwrap(),
            )])
        } else {
            BTreeMap::new()
        };
        GovernedMemoryProjection::new(
            TenantId::new("acme").unwrap(),
            graph,
            trust,
            MemoryLoadoutPlan::new([
                MemoryLoadoutBinding::new(MemorySpace::Tenant, 100, usage).unwrap()
            ])
            .unwrap(),
        )
        .unwrap()
    }
    fn provider() -> Provider {
        Provider {
            observations: vec![GovernedMemoryObservation {
                asset_id: id("known"),
                space: MemorySpace::Tenant,
                payload: b"known".to_vec(),
                similarity: 0.8,
            }],
        }
    }
    #[test]
    fn served_context_is_bound_to_projection_and_payload() {
        let p = projection(MemoryUsageMode::BootstrapAndOnDemand, true);
        let c = assemble_served_governed_context(
            &provider(),
            &p.tenant,
            &p,
            GovernedRecallTrustPolicy::VerifiedOnly,
            &[1.0, 0.0],
            MemoryRecallBudget::new(4, 8, 1024).unwrap(),
            MemoryContextBudget::new(4, 1024).unwrap(),
        )
        .unwrap();
        assert_eq!(c.tenant(), &p.tenant);
        assert_eq!(c.chunks()[0].asset_id.as_str(), "known");
        assert_eq!(c.chunks()[0].payload, b"known");
        assert_eq!(
            attest_governed_context(&c)[0].projection_sha256,
            c.projection_sha256_hex()
        );
    }
    #[test]
    fn expected_tenant_mismatch_fails_before_provider_use() {
        let p = projection(MemoryUsageMode::Bootstrap, true);
        let other = TenantId::new("globex").unwrap();
        assert!(matches!(
            assemble_served_governed_context(
                &provider(),
                &other,
                &p,
                GovernedRecallTrustPolicy::VerifiedOnly,
                &[1.0, 0.0],
                MemoryRecallBudget::new(4, 8, 1024).unwrap(),
                MemoryContextBudget::new(4, 1024).unwrap()
            ),
            Err(ServedContextError::RecallAdmission(
                GovernedRecallGateError::TenantMismatch { .. }
            ))
        ));
    }
    #[test]
    fn missing_trust_and_on_demand_only_fail_closed() {
        let p = projection(MemoryUsageMode::Bootstrap, false);
        assert!(matches!(
            assemble_served_governed_context(
                &provider(),
                &p.tenant,
                &p,
                GovernedRecallTrustPolicy::AnyNonQuarantined,
                &[1.0, 0.0],
                MemoryRecallBudget::new(4, 8, 1024).unwrap(),
                MemoryContextBudget::new(4, 1024).unwrap()
            ),
            Err(ServedContextError::RecallAdmission(
                GovernedRecallGateError::MissingTrustMetadata(_)
            ))
        ));
        let p = projection(MemoryUsageMode::OnDemand, true);
        assert!(matches!(
            assemble_served_governed_context(
                &provider(),
                &p.tenant,
                &p,
                GovernedRecallTrustPolicy::VerifiedOnly,
                &[1.0, 0.0],
                MemoryRecallBudget::new(4, 8, 1024).unwrap(),
                MemoryContextBudget::new(4, 1024).unwrap()
            ),
            Err(ServedContextError::NoBootstrapLoadout)
        ));
    }
}
