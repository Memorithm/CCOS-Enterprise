//! Adversarial provider-composition tests, not a network exploit or server restart.

use std::collections::BTreeMap;

use ccos_enterprise_mcp::{
    assemble_attested_served_context, assemble_served_governed_context, ServedContextError,
};
use ccos_enterprise_memory::{
    admit_governed_recall, GovernedMemoryObservation, GovernedMemoryProjection,
    GovernedMemoryWrite, GovernedRecallGate, GovernedRecallGateError, GovernedRecallTrustPolicy,
    GovernedSemanticMemoryProvider, LoadoutMemoryQuery, MemoryAssetDescriptor, MemoryAssetId,
    MemoryContextBudget, MemoryError, MemoryEvidenceRef, MemoryLineage, MemoryLineageGraph,
    MemoryLoadoutBinding, MemoryLoadoutPlan, MemoryRecallBudget, MemorySpace, MemoryStratum,
    MemoryTrustMetadata, MemoryUsageMode,
};
use ccos_enterprise_tenancy::{TenantId, TenantScope};

fn id() -> MemoryAssetId {
    MemoryAssetId::new("asset:private").unwrap()
}

fn private_space() -> MemorySpace {
    MemorySpace::project("private").unwrap()
}

fn observation(space: MemorySpace) -> GovernedMemoryObservation {
    GovernedMemoryObservation {
        asset_id: id(),
        space,
        payload: b"evidence".to_vec(),
        similarity: 0.99,
    }
}

fn projection(include_private: bool) -> GovernedMemoryProjection {
    let mut graph = MemoryLineageGraph::new();
    graph
        .register(
            MemoryAssetDescriptor::new(
                id(),
                private_space(),
                MemoryStratum::Evidence,
                MemoryLineage::root([MemoryEvidenceRef::new("audit:private").unwrap()])
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    let mut bindings = vec![
        MemoryLoadoutBinding::new(MemorySpace::Tenant, 100, MemoryUsageMode::Bootstrap)
            .unwrap(),
    ];
    if include_private {
        bindings.push(
            MemoryLoadoutBinding::new(private_space(), 80, MemoryUsageMode::Bootstrap)
                .unwrap(),
        );
    }
    GovernedMemoryProjection::new(
        TenantId::validated("acme").unwrap(),
        graph,
        BTreeMap::from([(id(), MemoryTrustMetadata::unverified(1))]),
        MemoryLoadoutPlan::new(bindings).unwrap(),
    )
    .unwrap()
}

fn gate(projection: &GovernedMemoryProjection) -> GovernedRecallGate<'_> {
    GovernedRecallGate {
        graph: &projection.graph,
        trust: &projection.trust,
        policy: GovernedRecallTrustPolicy::AnyNonQuarantined,
    }
}

fn mismatch() -> GovernedRecallGateError {
    GovernedRecallGateError::ProviderReturnedMismatchedSpace {
        asset_id: id(),
        expected: private_space(),
        observed: MemorySpace::Tenant,
    }
}

struct Provider(Vec<GovernedMemoryObservation>);

impl GovernedSemanticMemoryProvider for Provider {
    fn insert_governed(
        &mut self,
        _scoped: TenantScope<GovernedMemoryWrite<'_>>,
    ) -> Result<(), MemoryError> {
        Err(MemoryError::InsertRejected)
    }

    fn recall_governed(
        &self,
        scoped: TenantScope<LoadoutMemoryQuery<'_>>,
    ) -> Result<Vec<GovernedMemoryObservation>, MemoryError> {
        assert_eq!(scoped.tenant.as_str(), "acme");
        Ok(self.0.clone())
    }
}

fn assert_both_refuse(projection: &GovernedMemoryProjection) {
    let provider = Provider(vec![observation(MemorySpace::Tenant)]);
    let plain = assemble_served_governed_context(
        &provider,
        projection.tenant.clone(),
        &projection.loadout,
        gate(projection),
        &[1.0, 0.0],
        MemoryRecallBudget::new(4, 8, 128).unwrap(),
        MemoryContextBudget::new(4, 128).unwrap(),
    );
    assert!(matches!(
        plain,
        Err(ServedContextError::RecallAdmission(error)) if error == mismatch()
    ));
    let attested = assemble_attested_served_context(
        &provider,
        projection,
        GovernedRecallTrustPolicy::AnyNonQuarantined,
        &[1.0, 0.0],
        MemoryRecallBudget::new(4, 8, 128).unwrap(),
        MemoryContextBudget::new(4, 128).unwrap(),
    );
    // Reject at the common gate, not only at the later attestation check.
    assert!(matches!(
        attested,
        Err(ServedContextError::RecallAdmission(error)) if error == mismatch()
    ));
}

#[test]
fn common_gate_rejects_provider_relabeling() {
    let projection = projection(false);
    assert_eq!(
        admit_governed_recall(gate(&projection), [observation(MemorySpace::Tenant)]),
        Err(mismatch())
    );
}

#[test]
fn mismatched_space_is_rejected_even_for_inactive_lineage() {
    let mut projection = projection(false);
    projection.graph.invalidate(&id()).unwrap();
    projection.trust.clear();
    assert_eq!(
        admit_governed_recall(gate(&projection), [observation(MemorySpace::Tenant)]),
        Err(mismatch())
    );
}

#[test]
fn space_check_precedes_missing_trust_and_stricter_policy() {
    let mut projection = projection(false);
    projection.trust.clear();
    for policy in [
        GovernedRecallTrustPolicy::AnyNonQuarantined,
        GovernedRecallTrustPolicy::CorroboratedOrVerified,
        GovernedRecallTrustPolicy::VerifiedOnly,
    ] {
        let mut gate = gate(&projection);
        gate.policy = policy;
        assert_eq!(
            admit_governed_recall(gate, [observation(MemorySpace::Tenant)]),
            Err(mismatch())
        );
    }
}

#[test]
fn gate_returns_no_partial_prefix_after_a_later_mismatch() {
    let projection = projection(true);
    assert_eq!(
        admit_governed_recall(
            gate(&projection),
            [observation(private_space()), observation(MemorySpace::Tenant)],
        ),
        Err(mismatch())
    );
}

#[test]
fn both_compositions_refuse_private_asset_labeled_as_tenant() {
    assert_both_refuse(&projection(false));
}

#[test]
fn authorizing_both_spaces_does_not_authorize_relabeling() {
    assert_both_refuse(&projection(true));
}

#[test]
fn matching_canonical_space_preserves_both_context_variants() {
    let projection = projection(true);
    let source = observation(private_space());
    let provider = Provider(vec![source.clone()]);
    let plain = assemble_served_governed_context(
        &provider,
        projection.tenant.clone(),
        &projection.loadout,
        gate(&projection),
        &[1.0, 0.0],
        MemoryRecallBudget::new(4, 8, 128).unwrap(),
        MemoryContextBudget::new(4, 128).unwrap(),
    )
    .unwrap();
    let (attested, evidence) = assemble_attested_served_context(
        &provider,
        &projection,
        GovernedRecallTrustPolicy::AnyNonQuarantined,
        &[1.0, 0.0],
        MemoryRecallBudget::new(4, 8, 128).unwrap(),
        MemoryContextBudget::new(4, 128).unwrap(),
    )
    .unwrap();
    assert_eq!(plain, attested);
    assert_eq!(plain.chunks(), &[source]);
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].asset_id, id());
    assert_eq!(evidence[0].evidence[0].as_str(), "audit:private");
}
