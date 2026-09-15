//! Governance-owner integration, not a restart of the real MCP server.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use ccos_enterprise_mcp::{assemble_stored_governed_context, ServedContextError};
use ccos_enterprise_memory::{
    GovernedMemoryObservation, GovernedMemoryProjection, GovernedMemoryStore,
    GovernedMemoryStoreError, GovernedMemoryWrite, GovernedRecallTrustPolicy,
    GovernedSemanticMemoryProvider, LoadoutMemoryQuery, MemoryAssetDescriptor, MemoryAssetId,
    MemoryContextBudget, MemoryError, MemoryEvidenceRef, MemoryLineage, MemoryLineageGraph,
    MemoryLoadoutBinding, MemoryLoadoutPlan, MemoryRecallBudget, MemorySpace, MemoryStratum,
    MemoryTrustMetadata, MemoryUsageMode, GOVERNED_MEMORY_PROJECTION_FILE,
};
use ccos_enterprise_tenancy::{TenantId, TenantScope};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("ccos-stored-context-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Directory {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}
fn tenant() -> TenantId { TenantId::validated("acme").unwrap() }
fn asset() -> MemoryAssetId { MemoryAssetId::new("evidence").unwrap() }
fn projection() -> GovernedMemoryProjection {
    let mut graph = MemoryLineageGraph::new();
    graph.register(MemoryAssetDescriptor::new(asset(), MemorySpace::Tenant, MemoryStratum::Evidence,
        MemoryLineage::root([MemoryEvidenceRef::new("audit:evidence").unwrap()]).unwrap()).unwrap()).unwrap();
    GovernedMemoryProjection::new(tenant(), graph,
        BTreeMap::from([(asset(), MemoryTrustMetadata::unverified(1))]),
        MemoryLoadoutPlan::new([MemoryLoadoutBinding::new(MemorySpace::Tenant, 1, MemoryUsageMode::Bootstrap).unwrap()]).unwrap()).unwrap()
}
#[derive(Default)]
struct Provider { calls: AtomicUsize }
impl GovernedSemanticMemoryProvider for Provider {
    fn insert_governed(&mut self, _: TenantScope<GovernedMemoryWrite<'_>>) -> Result<(), MemoryError> {
        Err(MemoryError::InsertRejected)
    }
    fn recall_governed(&self, request: TenantScope<LoadoutMemoryQuery<'_>>) -> Result<Vec<GovernedMemoryObservation>, MemoryError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(request.tenant, tenant());
        Ok(vec![GovernedMemoryObservation { asset_id: asset(), space: MemorySpace::Tenant,
            payload: b"evidence payload".to_vec(), similarity: 0.99 }])
    }
}
fn recall(provider: &Provider, store: &GovernedMemoryStore, expected: &TenantId)
    -> Result<usize, ServedContextError> {
    let (assembly, attestations) = assemble_stored_governed_context(provider, store, expected,
        GovernedRecallTrustPolicy::AnyNonQuarantined, &[1.0, 0.0],
        MemoryRecallBudget::new(4, 8, 1024).unwrap(), MemoryContextBudget::new(4, 1024).unwrap())?;
    assert_eq!(assembly.len(), attestations.len());
    Ok(assembly.len())
}

#[test]
fn admitted_request_tenant_is_checked_before_provider_access() {
    let dir = Directory::new();
    let store = GovernedMemoryStore::initialize(&dir.0, projection()).unwrap();
    let provider = Provider::default();
    assert!(matches!(recall(&provider, &store, &TenantId::validated("other").unwrap()), Err(ServedContextError::Store(_))));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    assert_eq!(recall(&provider, &store, &tenant()).unwrap(), 1);
}

#[test]
fn reopened_governance_filters_invalidation_even_when_provider_still_recalls() {
    let dir = Directory::new();
    let mut store = GovernedMemoryStore::initialize(&dir.0, projection()).unwrap();
    let provider = Provider::default();
    assert_eq!(recall(&provider, &store, &tenant()).unwrap(), 1);
    let mut candidate = store.projection_for(&tenant()).unwrap().clone();
    candidate.graph.invalidate(&asset()).unwrap();
    store.replace(candidate).unwrap();
    assert_eq!(recall(&provider, &store, &tenant()).unwrap(), 0);
    drop(store);
    let reopened = GovernedMemoryStore::open(&dir.0, tenant()).unwrap();
    assert_eq!(recall(&provider, &reopened, &tenant()).unwrap(), 0);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 3);
}

#[test]
fn poisoned_governance_owner_never_calls_the_provider() {
    let dir = Directory::new();
    let mut store = GovernedMemoryStore::initialize(&dir.0, projection()).unwrap();
    // Inject a real publication failure: the destination is now a directory.
    // This mutation is test-only; deployments must control the directory.
    let path = dir.0.join(GOVERNED_MEMORY_PROJECTION_FILE);
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(store.replace(projection()).is_err());
    let provider = Provider::default();
    assert!(matches!(recall(&provider, &store, &tenant()),
        Err(ServedContextError::Store(GovernedMemoryStoreError::RecoveryRequired { .. }))));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
}
