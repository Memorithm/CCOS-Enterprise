//! A09 subprocess workload. Invoke through scripts/bench-governed-memory.py.
//! Synthetic observations measure cost, never retrieval quality or truth.
use std::collections::BTreeMap;
use std::error::Error;
use std::path::Path;
use std::sync::{Barrier, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ccos_enterprise_auth::{
    issue_identity_token, AuthStrength, Authenticator, IdentityClaims, TokenAuthenticator,
    IDENTITY_TOKEN_VERSION,
};
use ccos_enterprise_memory::*;
use ccos_enterprise_provider_adapter::generation::ProviderGenerationStore;
use ccos_enterprise_provider_adapter::recovery::{RecoveryConfig, RecoveryRecord};
use ccos_enterprise_runtime::{request, Call, Deployment, TenantState};
use ccos_enterprise_tenancy::{TenantId, TenantScope};
use serde_json::json;
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
const DIMENSION: usize = 32;
const SEED: u64 = 20260919;

fn embedding(index: usize) -> Vec<f32> {
    let mut state = SEED.wrapping_add(index as u64);
    (0..DIMENSION)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state as u32) as f32 / u32::MAX as f32 - 0.5
        })
        .collect()
}

fn population(
    tenant: TenantId,
    count: usize,
) -> Result<(GovernedMemoryProjection, Vec<RecoveryRecord>)> {
    let mut graph = MemoryLineageGraph::new();
    let mut trust = BTreeMap::new();
    let mut records = Vec::with_capacity(count);
    for index in 0..count {
        let id = MemoryAssetId::new(format!("a{index:06}"))?;
        graph.register(MemoryAssetDescriptor::new(
            id.clone(),
            MemorySpace::Tenant,
            MemoryStratum::Evidence,
            MemoryLineage::root([MemoryEvidenceRef::new(format!("synthetic:{index}"))?])?,
        )?)?;
        trust.insert(id.clone(), MemoryTrustMetadata::unverified(1));
        let mut payload = format!("{}:{index:06}", tenant.as_str()).into_bytes();
        payload.resize(64, b' ');
        records.push(RecoveryRecord {
            asset_id: id,
            embedding: embedding(index),
            payload,
            forgotten: false,
        });
    }
    let plan = MemoryLoadoutPlan::new([MemoryLoadoutBinding::new(
        MemorySpace::Tenant,
        100,
        MemoryUsageMode::BootstrapAndOnDemand,
    )?])?;
    Ok((
        GovernedMemoryProjection::new(tenant, graph, trust, plan)?,
        records,
    ))
}

fn rss_kib(field: &str) -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix(field)?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 6 {
        return Err("usage: phase root assets_per_tenant tenants samples_per_tenant".into());
    }
    let phase = &args[1];
    let root = Path::new(&args[2]);
    let assets: usize = args[3].parse()?;
    let tenants: usize = args[4].parse()?;
    let samples: usize = args[5].parse()?;
    if assets == 0
        || assets > 100_000
        || tenants == 0
        || tenants > 16
        || samples == 0
        || samples > 100_000
    {
        return Err("benchmark arguments exceed explicit bounds".into());
    }
    let total_start = Instant::now();
    let mut stores = Vec::new();
    let mut recovery_ns = Vec::new();
    for index in 0..tenants {
        let tenant = TenantId::new(format!("t{index}")).ok_or("invalid benchmark tenant")?;
        let path = root.join(tenant.as_str());
        let start = Instant::now();
        let store = match phase.as_str() {
            "init" => {
                let (authority, records) = population(tenant, assets)?;
                ProviderGenerationStore::initialize(
                    path,
                    authority,
                    RecoveryConfig {
                        dimension: DIMENSION,
                        simhash_bits: 64,
                        per_tenant_capacity: assets,
                        seed: SEED,
                    },
                    &records,
                )?
            }
            "query" => ProviderGenerationStore::open(path, tenant)?,
            _ => return Err("unknown benchmark phase".into()),
        };
        if store.recovered().stored_records() != assets {
            return Err("population mismatch".into());
        }
        recovery_ns.push(start.elapsed().as_nanos() as u64);
        stores.push(store);
    }
    let ready_rss = rss_kib("VmRSS:");
    if phase == "init" {
        println!(
            "{}",
            json!({"phase":phase,"elapsed_ns":total_start.elapsed().as_nanos() as u64,
            "tenant_init_ns":recovery_ns,"rss_ready_kib":ready_rss,"peak_rss_kib":rss_kib("VmHWM:")})
        );
        return Ok(());
    }
    let mut deployment = Deployment::new();
    deployment
        .add_role("reader", &["memory.read"])
        .govern_tool("memory.recall", "memory.read");
    // Deterministic signing material is confined to this synthetic executable.
    let key = [47; 32];
    let signing = ed25519_dalek::SigningKey::from_bytes(&key);
    let mut verifier = TokenAuthenticator::new("a09", AuthStrength::Token);
    assert!(verifier.add_issuer("benchmark", signing.verifying_key()));
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut actors = Vec::new();
    for index in 0..tenants {
        let org = format!("org{index}");
        let mut tenant = TenantState::new(u64::MAX);
        tenant.allow_model("synthetic");
        assert!(deployment.add_tenant(&org, &format!("t{index}"), tenant));
        assert!(deployment.assign(&org, "reader", "reader"));
        let claims = IdentityClaims {
            version: IDENTITY_TOKEN_VERSION,
            jti: format!("actor{index}"),
            org,
            actor: "reader".into(),
            audience: "a09".into(),
            issued_at: now,
            expires_at: now + 3600,
            not_before: None,
        };
        let token = issue_identity_token(&key, "benchmark", &claims)?;
        actors.push(verifier.authenticate(&token, now)?);
    }
    // Negative control crosses the same front door before any provider access.
    if tenants > 1 {
        let req = request("t1", "reader", "memory.recall", "cross-tenant-probe");
        if deployment
            .admit(Call {
                actor: &actors[0],
                request: &req,
                model: "synthetic",
                cost_tokens: 1,
                variant: None,
                justification: None,
            })
            .is_forwarded()
        {
            return Err("cross-tenant negative control forwarded".into());
        }
    }
    let deployment = Mutex::new(deployment);
    let barrier = Barrier::new(tenants + 1);
    let (worker_results, wall_ns) = std::thread::scope(|scope| -> Result<_> {
        let handles: Vec<_> = stores.iter().zip(actors.iter()).map(|(store, actor)| {
            let deployment = &deployment;
            let barrier = &barrier;
            scope.spawn(move || -> Result<_> {
                let loadout = store.governance().loadout.bootstrap_loadout()?.ok_or("no loadout")?;
                let mut durations = Vec::with_capacity(samples);
                let mut digest = Sha256::new();
                barrier.wait();
                for index in 0..samples {
                    let query = embedding(index % assets);
                    let req = request(store.tenant().as_str(), "reader", "memory.recall", &format!("query-{index}"));
                    let start = Instant::now();
                    if !deployment.lock().map_err(|_| "admission lock poisoned")?.admit(Call {
                        actor, request: &req, model: "synthetic", cost_tokens: 1, variant: None, justification: None,
                    }).is_forwarded() { return Err("admission refused benchmark query".into()); }
                    let admitted = store.recovered().recall(store.governance(), TenantScope::new(
                        store.tenant().clone(), BudgetedMemoryRecall { embedding: &query, loadout: &loadout,
                            budget: MemoryRecallBudget::new(8, 64, 4096)? }),
                        GovernedRecallTrustPolicy::AnyNonQuarantined)?;
                    let context = assemble_governed_bootstrap_context(store.governance(), admitted,
                        MemoryContextBudget::new(8, 4096)?)?;
                    let attestations = attest_governed_context(&context);
                    durations.push(start.elapsed().as_nanos() as u64);
                    if context.is_empty() || attestations.len() != context.len() { return Err("empty/unattested context".into()); }
                    for chunk in context.chunks() {
                        if !chunk.payload.starts_with(store.tenant().as_str().as_bytes()) {
                            return Err("cross-tenant payload".into());
                        }
                        digest.update(chunk.asset_id.as_str().as_bytes());
                        digest.update(chunk.payload_sha256());
                    }
                }
                Ok(json!({"tenant":store.tenant().as_str(),"latency_ns":durations,
                    "result_sha256":hex(&digest.finalize()),"image_sha256":hex(&store.recovered().digest())}))
            })
        }).collect();
        let start = Instant::now();
        barrier.wait();
        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.join().map_err(|_| "benchmark thread panicked")??);
        }
        Ok((results, start.elapsed().as_nanos() as u64))
    })?;
    println!(
        "{}",
        json!({"phase":phase,"tenant_recovery_ns":recovery_ns,"workers":worker_results,
        "query_wall_ns":wall_ns,"rss_ready_kib":ready_rss,"peak_rss_kib":rss_kib("VmHWM:")})
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{}", json!({"status":"error","error":error.to_string()}));
        std::process::exit(1);
    }
}
