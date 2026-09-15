//! Forced process termination releases ownership; this is not a power-cut test.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ccos_enterprise_memory::{
    GovernedMemoryProjection, GovernedMemoryStore, GovernedMemoryStoreError,
    MemoryAssetDescriptor, MemoryAssetId, MemoryAssetState, MemoryEvidenceRef,
    MemoryLineage, MemoryLineageGraph, MemoryLoadoutBinding, MemoryLoadoutPlan,
    MemorySpace, MemoryStratum, MemoryTrustMetadata, MemoryUsageMode,
};
use ccos_enterprise_tenancy::TenantId;

const CHILD_ROOT: &str = "CCOS_GOVERNANCE_TERMINATION_TEST_ROOT";
const READY: &str = "owner-ready";

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("ccos-owner-termination-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        // Never leak a test child if readiness or an assertion fails.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn tenant() -> TenantId {
    TenantId::validated("acme").unwrap()
}
fn asset() -> MemoryAssetId {
    MemoryAssetId::new("root").unwrap()
}
fn fixture() -> GovernedMemoryProjection {
    let mut graph = MemoryLineageGraph::new();
    graph.register(MemoryAssetDescriptor::new(
        asset(), MemorySpace::Tenant, MemoryStratum::Evidence,
        MemoryLineage::root([MemoryEvidenceRef::new("audit:root").unwrap()]).unwrap(),
    ).unwrap()).unwrap();
    GovernedMemoryProjection::new(
        tenant(), graph,
        BTreeMap::from([(asset(), MemoryTrustMetadata::unverified(1))]),
        MemoryLoadoutPlan::new([MemoryLoadoutBinding::new(
            MemorySpace::Tenant, 1, MemoryUsageMode::Bootstrap,
        ).unwrap()]).unwrap(),
    ).unwrap()
}

#[test]
fn holder_child() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let root = PathBuf::from(root);
    let mut store = GovernedMemoryStore::open(&root, tenant()).unwrap();
    let mut candidate = store.projection_for(&tenant()).unwrap().clone();
    candidate.graph.invalidate(&asset()).unwrap();
    store.replace(candidate).unwrap();
    fs::write(root.join(READY), b"acknowledged invalidation; owner still holds lock").unwrap();
    // The parent keeps this pipe open, then terminates us without running Drop.
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    panic!("holder must be terminated by the parent, not gracefully exited");
}

#[test]
fn forced_termination_releases_lock_and_preserves_acknowledged_invalidation() {
    let dir = Directory::new();
    drop(GovernedMemoryStore::initialize(&dir.0, fixture()).unwrap());
    let mut process = Process(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "holder_child", "--nocapture"])
        .env(CHILD_ROOT, &dir.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    while !dir.0.join(READY).try_exists().unwrap() {
        assert!(process.0.try_wait().unwrap().is_none(), "child exited before acquiring ownership");
        assert!(Instant::now() < deadline, "child never acknowledged its durable invalidation");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(matches!(
        GovernedMemoryStore::open(&dir.0, tenant()),
        Err(GovernedMemoryStoreError::AlreadyOpen { .. })
    ));
    process.0.kill().unwrap();
    assert!(!process.0.wait().unwrap().success());
    let reopened = GovernedMemoryStore::open(&dir.0, tenant()).unwrap();
    let projection = reopened.projection_for(&tenant()).unwrap();
    assert_eq!(projection.graph.state(&asset()), Some(MemoryAssetState::Invalidated));
    assert_eq!(projection.trust, fixture().trust);
    assert_eq!(projection.loadout, fixture().loadout);
}
