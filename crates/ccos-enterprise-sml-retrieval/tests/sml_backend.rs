//! Integration tests for the real SML-GENIUS sigpage-v0 backend. Contract checks only: these
//! assert ordering/governance behaviour on a toy corpus, not retrieval quality (NotBeirValidated).
#![cfg(feature = "sml-backend")]

use std::collections::BTreeMap;

use ccos_enterprise_memory::{
    admit_governed_recall, GovernedMemoryProjection, GovernedRecallGate, GovernedRecallTrustPolicy,
    MemoryAssetDescriptor, MemoryAssetId, MemoryEvidenceRef, MemoryLineage, MemoryLineageGraph,
    MemoryLoadout, MemoryLoadoutBinding, MemoryLoadoutPlan, MemorySpace, MemoryStratum,
    MemoryTrustMetadata, MemoryUsageMode,
};
use ccos_enterprise_sml_retrieval::*;
use ccos_enterprise_tenancy::{TenantId, TenantScope};

const DOCS: [&str; 3] = [
    "invoice payment terms net thirty days",
    "kubernetes cluster autoscaling node pools",
    "employee onboarding checklist laptop badge",
];

fn t(s: &str) -> TenantId {
    TenantId::new(s).unwrap()
}
fn id(i: usize) -> MemoryAssetId {
    MemoryAssetId::new(format!("memory:asset:{i}")).unwrap()
}

fn indexed() -> SmlSignaturePageAdapter {
    let mut a = SmlSignaturePageAdapter::new(7);
    for (i, d) in DOCS.iter().enumerate() {
        a.insert(
            &t("acme"),
            id(i),
            MemorySpace::Tenant,
            d,
            d.as_bytes().to_vec(),
        )
        .unwrap();
    }
    a.insert(
        &t("other"),
        id(99),
        MemorySpace::Tenant,
        "invoice payment terms net thirty days secret",
        b"other-secret".to_vec(),
    )
    .unwrap();
    a
}

fn recall(
    g: &mut GovernedSmlRetrieval<SmlSignaturePageAdapter>,
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
fn labels_arm_backend_and_non_beir_status() {
    let mut g = GovernedSmlRetrieval::new(indexed());
    assert_eq!(g.arm_id(), SML_CONCURRENT_ARM_ID);
    assert_eq!(g.backend_id(), "sml-icm-rank-sigpage-v0-experimental");
    let out = recall(
        &mut g,
        "acme",
        "invoice payment",
        3,
        &MemoryLoadout::tenant_only(),
    )
    .unwrap();
    assert!(!out.is_empty());
}

#[test]
fn adapter_reports_not_beir_validated() {
    let mut a = indexed();
    assert_eq!(a.validation_status(), SML_VALIDATION_STATUS);
    assert_eq!(a.last_validation_status(), None);
    let lo = MemoryLoadout::tenant_only();
    a.retrieve(
        &t("acme"),
        SmlRetrievalRequest {
            text: "invoice",
            k: 1,
            loadout: &lo,
        },
    )
    .unwrap();
    assert_eq!(a.last_validation_status(), Some("NotBeirValidated"));
}

#[test]
fn real_ranking_is_finite_ordered_and_truncated() {
    let mut g = GovernedSmlRetrieval::new(indexed());
    let out = recall(
        &mut g,
        "acme",
        "invoice payment terms",
        2,
        &MemoryLoadout::tenant_only(),
    )
    .unwrap();
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].asset_id, id(0));
    assert_eq!(out[0].payload, DOCS[0].as_bytes());
    assert!(out.iter().all(|o| o.similarity.is_finite()));
    assert!(out[0].similarity >= out[1].similarity);
}

#[test]
fn tenant_isolation() {
    let mut g = GovernedSmlRetrieval::new(indexed());
    let lo = MemoryLoadout::tenant_only();
    let out = recall(&mut g, "acme", "invoice secret", 10, &lo).unwrap();
    assert!(out.iter().all(|o| o.asset_id != id(99)));
    let out = recall(&mut g, "other", "invoice", 10, &lo).unwrap();
    assert_eq!(
        out.iter().map(|o| o.asset_id.clone()).collect::<Vec<_>>(),
        vec![id(99)]
    );
    assert!(recall(&mut g, "nobody", "invoice", 10, &lo)
        .unwrap()
        .is_empty());
}

#[test]
fn out_of_loadout_documents_are_excluded_not_leaked() {
    let mut a = indexed();
    a.insert(
        &t("acme"),
        id(7),
        MemorySpace::project("p1").unwrap(),
        "invoice payment terms net thirty days",
        b"project".to_vec(),
    )
    .unwrap();
    let mut g = GovernedSmlRetrieval::new(a);
    let out = recall(
        &mut g,
        "acme",
        "invoice payment",
        10,
        &MemoryLoadout::tenant_only(),
    )
    .unwrap();
    assert!(out.iter().all(|o| o.space == MemorySpace::Tenant));
}

#[test]
fn duplicates_and_empty_query_fail_closed() {
    let mut a = indexed();
    assert!(matches!(
        a.insert(&t("acme"), id(0), MemorySpace::Tenant, "x", vec![]),
        Err(SmlRetrievalError::DuplicateAsset(_))
    ));
    let mut g = GovernedSmlRetrieval::new(a);
    assert_eq!(
        recall(&mut g, "acme", "  ", 3, &MemoryLoadout::tenant_only()),
        Err(SmlRetrievalError::EmptyQuery)
    );
}

#[test]
fn sml_output_passes_admit_governed_recall() {
    let mut graph = MemoryLineageGraph::new();
    let mut trust = BTreeMap::new();
    for i in 0..DOCS.len() {
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
    let mut g = GovernedSmlRetrieval::new(indexed());
    let obs = recall(
        &mut g,
        "acme",
        "kubernetes node",
        3,
        &MemoryLoadout::tenant_only(),
    )
    .unwrap();
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
