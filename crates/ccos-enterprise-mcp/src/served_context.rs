//! Server-facing composition for governed semantic-memory context.
//!
//! This module owns no vector index and no durable governance state. It composes
//! the backend-neutral memory contracts so a served path can retrieve only from
//! an explicit bootstrap loadout, bound provider output, apply lineage/trust
//! admission, and assemble a bounded context without dropping `MemoryAssetId`.

use std::fmt;

use ccos_enterprise_memory::{
    admit_governed_recall, assemble_governed_bootstrap_context, attest_governed_context,
    BudgetedMemoryRecall, GovernedMemoryContextAssembly, GovernedMemoryProjection,
    GovernedRecallGate, GovernedRecallGateError, GovernedRecallTrustPolicy,
    GovernedSemanticMemoryProvider, GovernedSemanticMemoryProviderExt, MemoryContextAttestation,
    MemoryContextBudget, MemoryContextError, MemoryError, MemoryLoadoutPlan,
    MemoryLoadoutPlanError, MemoryRecallBudget, MemoryRecallBudgetError,
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
            Self::Attestation(error) => {
                write!(f, "governed memory context attestation failed: {error}")
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
        projection.tenant.clone(),
        &projection.loadout,
        GovernedRecallGate {
            graph: &projection.graph,
            trust: &projection.trust,
            policy,
        },
        embedding,
        recall_budget,
        context_budget,
    )?;
    let attested = attest_governed_context(&assembly, &projection.graph, &projection.trust)?;
    Ok((assembly, attested))
}
