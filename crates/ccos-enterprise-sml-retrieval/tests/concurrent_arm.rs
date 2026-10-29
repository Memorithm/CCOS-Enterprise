#![cfg(feature = "concurrent-arm")]
//! Mock/oracle tests: the oracle returns a fixed, declared ranking. It is a contract
//! fixture, not a retriever, and its scores carry no performance meaning.

use std::collections::BTreeMap;

use ccos_enterprise_memory::{
    admit_governed_recall, GovernedMemoryProjection, GovernedRecallGate, GovernedRecallTrustPolicy,
    MemoryAssetDescriptor, MemoryAssetId, MemoryEvidenceRef, MemoryLineage, MemoryLineageGraph,
    MemoryLoadout, MemoryLoadoutBinding, MemoryLoadoutPlan, MemorySpace, MemoryStratum,
    MemoryTrustMetadata, MemoryUsageMode,
};
use ccos_enterprise_sml_retrieval::*;
use ccos_enterprise_tenancy::{TenantId, TenantScope};

fn t(s: &str) -> TenantId {
    TenantId::new(s).unwrap()
}
fn id(i: usize) -> MemoryAssetId {
    MemoryAssetId::new(format!("memory:asset:{i}")).unwrap()
}
fn cand(i: usize, space: MemorySpace, score: f32) -> SmlRetrievalCandidate {
    SmlRetrievalCandidate {
        asset_id: id(i),
        space,
        payload: format!("doc {i}").into_bytes(),
        score,
    }
}

/// Per-tenant fixed answers; records which tenant it was asked for.
struct Oracle {
    by_tenant: BTreeMap<String, Vec<SmlRetrievalCandidate>>,
    asked: Vec<String>,
}
impl SmlRetrievalAdapter for Oracle {
    fn backend_id(&self) -> &'static str {
        "oracle-fixture"
    }
    fn retrieve(
        &mut self,
        tenant: &TenantId,
        _r: SmlRetrievalRequest<'_>,
    ) -> Result<Vec<SmlRetrievalCandidate>, SmlRetrievalError> {
        self.asked.push(tenant.as_str().to_string());
        Ok(self
            .by_tenant
            .get(tenant.as_str())
            .cloned()
            .unwrap_or_default())
    }
}

fn oracle(c: Vec<SmlRetrievalCandidate>) -> GovernedSmlRetrieval<Oracle> {
    GovernedSmlRetrieval::new(Oracle {
        by_tenant: BTreeMap::from([
            ("acme".to_string(), c),
            (
                "other".to_string(),
                vec![cand(99, MemorySpace::Tenant, 9.0)],
            ),
        ]),
        asked: Vec::new(),
    })
}

fn recall(
    g: &mut GovernedSmlRetrieval<Oracle>,
    tenant: &str,
    text: &str,
    k: usize,
    lo: &MemoryLoadout,
) -> Result<Vec<ccos_enterprise_memory::GovernedMemoryObservation>, SmlRetrievalError> {
    g.recall(TenantScope::new(
        t(tenant),
        SmlRetrievalRequest {
            text,
            k,
            loadout: lo,
        },
    ))
}

#[test]
fn stable_order_score_desc_then_id_asc_and_truncation() {
    let lo = MemoryLoadout::tenant_only();
    let mut g = oracle(vec![
        cand(3, MemorySpace::Tenant, 0.2),
        cand(2, MemorySpace::Tenant, 0.9),
        cand(1, MemorySpace::Tenant, 0.9),
    ]);
    let out = recall(&mut g, "acme", "q", 2, &lo).unwrap();
    let ids: Vec<_> = out.iter().map(|o| o.asset_id.clone()).collect();
    assert_eq!(ids, vec![id(1), id(2)]);
    assert_eq!(out[0].similarity, 0.9);
    assert_eq!(g.arm_id(), SML_CONCURRENT_ARM_ID);
    assert_eq!(g.backend_id(), "oracle-fixture");
}

#[test]
fn tenant_isolation_backend_only_sees_scoped_tenant() {
    let lo = MemoryLoadout::tenant_only();
    let mut g = oracle(vec![cand(1, MemorySpace::Tenant, 0.5)]);
    let out = recall(&mut g, "acme", "q", 5, &lo).unwrap();
    assert!(out.iter().all(|o| o.asset_id != id(99)));
}

#[test]
fn fail_closed_on_space_outside_loadout_nan_and_duplicates() {
    let lo = MemoryLoadout::tenant_only();
    let proj = MemorySpace::project("p1").unwrap();
    let mut g = oracle(vec![cand(1, proj, 0.5)]);
    assert!(matches!(
        recall(&mut g, "acme", "q", 5, &lo),
        Err(SmlRetrievalError::SpaceOutsideLoadout(_))
    ));
    let mut g = oracle(vec![cand(1, MemorySpace::Tenant, f32::NAN)]);
    assert!(matches!(
        recall(&mut g, "acme", "q", 5, &lo),
        Err(SmlRetrievalError::NonFiniteScore(_))
    ));
    let mut g = oracle(vec![
        cand(1, MemorySpace::Tenant, 0.5),
        cand(1, MemorySpace::Tenant, 0.4),
    ]);
    assert!(matches!(
        recall(&mut g, "acme", "q", 5, &lo),
        Err(SmlRetrievalError::DuplicateAsset(_))
    ));
}

#[test]
fn empty_query_and_k_zero_do_not_reach_backend() {
    let lo = MemoryLoadout::tenant_only();
    let mut g = oracle(vec![cand(1, MemorySpace::Tenant, 0.5)]);
    assert_eq!(
        recall(&mut g, "acme", "  ", 5, &lo),
        Err(SmlRetrievalError::EmptyQuery)
    );
    assert!(recall(&mut g, "acme", "q", 0, &lo).unwrap().is_empty());
}

#[test]
fn unavailable_backend_is_an_error_not_empty_scores() {
    let lo = MemoryLoadout::tenant_only();
    let mut g = GovernedSmlRetrieval::new(UnavailableSmlRetrieval);
    let r = g.recall(TenantScope::new(
        t("acme"),
        SmlRetrievalRequest {
            text: "q",
            k: 3,
            loadout: &lo,
        },
    ));
    assert!(matches!(r, Err(SmlRetrievalError::BackendUnavailable(_))));
}

#[test]
fn output_passes_admit_governed_recall() {
    let mut graph = MemoryLineageGraph::new();
    let mut trust = BTreeMap::new();
    for i in 0..3 {
        graph
            .register(
                MemoryAssetDescriptor::new(
                    id(i),
                    MemorySpace::Tenant,
                    MemoryStratum::Evidence,
                    MemoryLineage::root([MemoryEvidenceRef::new(format!("artifact:{i}")).unwrap()])
                        .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        trust.insert(id(i), MemoryTrustMetadata::unverified(1));
    }
    let projection = GovernedMemoryProjection::new(
        t("acme"),
        graph,
        trust,
        MemoryLoadoutPlan::new([MemoryLoadoutBinding::new(
            MemorySpace::Tenant,
            1,
            MemoryUsageMode::Bootstrap,
        )
        .unwrap()])
        .unwrap(),
    )
    .unwrap();
    let lo = MemoryLoadout::tenant_only();
    let mut g = oracle(
        (0..3)
            .map(|i| cand(i, MemorySpace::Tenant, i as f32))
            .collect(),
    );
    let obs = recall(&mut g, "acme", "q", 3, &lo).unwrap();
    let tenant = t("acme");
    let admitted = admit_governed_recall(
        GovernedRecallGate {
            expected_tenant: &tenant,
            projection: &projection,
            policy: GovernedRecallTrustPolicy::AnyNonQuarantined,
        },
        obs,
    )
    .unwrap();
    assert_eq!(admitted.len(), 3);
}
