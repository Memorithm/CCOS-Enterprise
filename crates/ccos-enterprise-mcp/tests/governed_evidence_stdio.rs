use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use ccos_enterprise_auth::{issue_identity_token, IdentityClaims, IDENTITY_TOKEN_VERSION};
use ccos_enterprise_memory::{
    GovernedMemoryProjection, MemoryAssetDescriptor, MemoryAssetId, MemoryEvidenceRef,
    MemoryLineage, MemoryLineageGraph, MemoryLoadoutBinding, MemoryLoadoutPlan, MemorySpace,
    MemoryStratum, MemoryTrustMetadata, MemoryUsageMode, MemoryValidationState,
};
use ccos_enterprise_provider_adapter::accepted_write::AcceptedEvidenceWrite;
use ccos_enterprise_provider_adapter::generation::ProviderGenerationStore;
use ccos_enterprise_provider_adapter::recovery::{RecoveryConfig, RecoveryRecord};
use ccos_enterprise_tenancy::TenantId;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ccos-governed-evidence-stdio-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tenant() -> TenantId {
    TenantId::validated("acme").unwrap()
}
fn id(value: &str) -> MemoryAssetId {
    MemoryAssetId::new(value).unwrap()
}
fn evidence(value: &str) -> MemoryEvidenceRef {
    MemoryEvidenceRef::new(value).unwrap()
}
fn config() -> RecoveryConfig {
    RecoveryConfig {
        dimension: 2,
        simhash_bits: 64,
        per_tenant_capacity: 8,
        seed: 42,
    }
}

fn authority() -> GovernedMemoryProjection {
    let mut graph = MemoryLineageGraph::new();
    graph
        .register(
            MemoryAssetDescriptor::new(
                id("verified-root"),
                MemorySpace::Tenant,
                MemoryStratum::Evidence,
                MemoryLineage::root([evidence("audit:verified-root")]).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    GovernedMemoryProjection::new(
        tenant(),
        graph,
        BTreeMap::from([(
            id("verified-root"),
            MemoryTrustMetadata::new(
                MemoryValidationState::Verified,
                1,
                1,
                0,
                ["proof:verified-root".to_string()],
            )
            .unwrap(),
        )]),
        MemoryLoadoutPlan::new([MemoryLoadoutBinding::new(
            MemorySpace::Tenant,
            100,
            MemoryUsageMode::BootstrapAndOnDemand,
        )
        .unwrap()])
        .unwrap(),
    )
    .unwrap()
}

fn records() -> Vec<RecoveryRecord> {
    vec![RecoveryRecord {
        asset_id: id("verified-root"),
        embedding: vec![1.0, 0.0],
        payload: b"verified old evidence".to_vec(),
        forgotten: false,
    }]
}

fn write_input(asset: &str) -> AcceptedEvidenceWrite {
    AcceptedEvidenceWrite {
        asset_id: id(asset),
        evidence: evidence(&format!("audit:{asset}")),
        embedding: vec![0.0, 1.0],
        payload: format!("payload:{asset}").into_bytes(),
    }
}

fn token() -> (String, [u8; 32]) {
    let seed = [9u8; 32];
    let signing = SigningKey::from_bytes(&seed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = IdentityClaims {
        version: IDENTITY_TOKEN_VERSION,
        jti: format!("evidence-e2e-{}", NEXT.fetch_add(1, Ordering::Relaxed)),
        org: "memorithm".into(),
        actor: "alice".into(),
        audience: "evidence-test".into(),
        issued_at: now,
        expires_at: now + 600,
        not_before: None,
    };
    (
        issue_identity_token(&seed, "test-key", &claims).unwrap(),
        signing.verifying_key().to_bytes(),
    )
}

fn command(state: &Path, provider: &Path, token: &str, public_key: &[u8; 32]) -> Command {
    let binary = env!("CARGO_BIN_EXE_ccos-enterprise-mcp-server");
    let public_hex: String = public_key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let mut command = Command::new(binary);
    command
        .env("CCOS_ENTERPRISE_AUDIENCE", "evidence-test")
        .env("CCOS_ENTERPRISE_ISSUER_KID", "test-key")
        .env("CCOS_ENTERPRISE_ISSUER_PUBLIC_KEY_HEX", public_hex)
        .env("CCOS_ENTERPRISE_IDENTITY_TOKEN", token)
        .env("CCOS_ENTERPRISE_TENANT", "acme")
        .env("CCOS_ENTERPRISE_MODEL", "deepseek-harness")
        .env("CCOS_ENTERPRISE_TOKEN_BUDGET", "1000")
        .env("CCOS_ENTERPRISE_CALL_COST_TOKENS", "1")
        .env("CCOS_ENTERPRISE_STATE_DIR", state)
        .env("CCOS_ENTERPRISE_GOVERNED_MEMORY_ROOT", provider);
    command
}

struct ServerProcess {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}
impl ServerProcess {
    fn spawn(state: &Path, provider: &Path, token: &str, public_key: &[u8; 32]) -> Self {
        let mut child = command(state, provider, token, public_key)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            input,
            output,
        }
    }
    fn request(&mut self, value: Value) -> Value {
        writeln!(self.input, "{value}").unwrap();
        self.input.flush().unwrap();
        let mut line = String::new();
        self.output.read_line(&mut line).unwrap();
        assert!(!line.is_empty(), "server exited before response");
        serde_json::from_str(&line).unwrap()
    }
    fn stop(mut self) {
        let _ = self.child.kill();
        let status = self.child.wait().unwrap();
        assert!(!status.success());
    }
}

fn bootstrap_state(state: &Path, provider: &Path, token: &str, public: &[u8; 32]) {
    let output = command(state, provider, token, public)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "bootstrap failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn startup(state: &Path, provider: &Path, token: &str, public: &[u8; 32]) -> Output {
    command(state, provider, token, public)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

fn meta(id: u64, request_id: &str, attempt: &str) -> Value {
    json!({
        "tenant_id": "acme",
        "actor_id": "alice",
        "agent_id": "agent-1",
        "host": "deepseek-harness",
        "dsh_profile": "test",
        "dsh_session_id": "session-1",
        "request_id": request_id,
        "trace_id": "0123456789abcdef0123456789abcdef",
        "model": "deepseek-harness",
        "turn_id": "turn-1",
        "step_id": format!("step-{id}"),
        "execution_attempt_id": attempt
    })
}

fn write_call(id: u64, request_id: &str, attempt: &str, asset: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "memory.evidence.write",
            "arguments": {
                "asset_id": asset,
                "evidence_ref": format!("audit:{asset}"),
                "embedding": [0.0, 1.0],
                "payload_bytes": format!("payload:{asset}").into_bytes()
            },
            "_meta": { "ccos": meta(id, request_id, attempt) }
        }
    })
}

fn context_call(id: u64, request_id: &str, attempt: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "memory.context",
            "arguments": {
                "embedding": [0.0, 1.0],
                "recall_max_items": 8,
                "recall_max_shortlist": 8,
                "recall_max_payload_bytes": 4096,
                "context_max_items": 8,
                "context_max_payload_bytes": 4096
            },
            "_meta": { "ccos": meta(id, request_id, attempt) }
        }
    })
}

fn advance_offline(provider: &Path, asset: &str) -> ccos_enterprise_provider_adapter::accepted_write::EvidenceGenerationReceipt {
    let store = ProviderGenerationStore::open(provider, tenant()).unwrap();
    let prepared = store.prepare_unverified_evidence(write_input(asset)).unwrap();
    let (store, receipt) = store.commit_prepared_evidence(prepared).unwrap();
    assert_eq!(store.generation(), receipt.generation);
    drop(store);
    receipt
}

fn effect_path(state: &Path) -> PathBuf {
    state.join(".enterprise").join("effect.json")
}

fn digest_hex(digest: [u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_effect_fixture(
    state: &Path,
    effect_state: &str,
    receipt: Option<&ccos_enterprise_provider_adapter::accepted_write::EvidenceGenerationReceipt>,
) {
    let mut value = json!({
        "request_id": "offline-write",
        "tenant": "acme",
        "actor": "alice",
        "tool": "memory.evidence.write",
        "model": "deepseek-harness",
        "cost_tokens": 1,
        "state": effect_state,
        "output_sha256": "known-output"
    });
    if let Some(receipt) = receipt {
        value["governed_generation"] = json!(receipt.generation);
        value["governed_asset_id"] = json!(receipt.asset_id.as_str());
        value["governed_image_sha256"] = json!(digest_hex(receipt.image_digest));
    }
    std::fs::write(effect_path(state), serde_json::to_vec_pretty(&value).unwrap()).unwrap();
}

#[test]
fn real_stdio_write_advances_generation_and_restart_keeps_new_evidence_unverified() {
    let root = Directory::new();
    let provider = root.0.join("provider");
    let state = root.0.join("server");
    let store = ProviderGenerationStore::initialize(&provider, authority(), config(), &records()).unwrap();
    drop(store);
    let (token, public) = token();

    let mut server = ServerProcess::spawn(&state, &provider, &token, &public);
    let listed = server.request(json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":null}));
    assert!(listed["result"]["tools"].as_array().unwrap().iter().any(|tool| tool["name"] == "memory.evidence.write"));
    let written = server.request(write_call(2, "write-live", "attempt-write", "fresh-live"));
    assert!(written.get("error").is_none(), "{written}");
    assert_eq!(written["result"]["structuredContent"]["generation"], 1);
    assert_eq!(written["result"]["structuredContent"]["trust_state"], "unverified");
    let context = server.request(context_call(3, "context-live", "attempt-context"));
    let structured = &context["result"]["structuredContent"];
    assert_eq!(structured["generation"], 1);
    assert!(structured["items"].as_array().unwrap().iter().all(|item| item["asset_id"] != "fresh-live"));
    server.stop();

    let store = ProviderGenerationStore::open(&provider, tenant()).unwrap();
    assert_eq!(store.generation(), 1);
    assert_eq!(store.governance().trust[&id("fresh-live")].state(), MemoryValidationState::Unverified);
    drop(store);

    let mut restarted = ServerProcess::spawn(&state, &provider, &token, &public);
    let context = restarted.request(context_call(4, "context-restart", "attempt-restart"));
    assert_eq!(context["result"]["structuredContent"]["generation"], 1);
    assert!(context["result"]["structuredContent"]["items"].as_array().unwrap().iter().all(|item| item["asset_id"] != "fresh-live"));
    restarted.stop();
}

#[test]
fn published_generation_with_started_marker_fails_closed_on_restart() {
    let root = Directory::new();
    let provider = root.0.join("provider");
    let state = root.0.join("server");
    let store = ProviderGenerationStore::initialize(&provider, authority(), config(), &records()).unwrap();
    drop(store);
    let (token, public) = token();
    bootstrap_state(&state, &provider, &token, &public);
    let receipt = advance_offline(&provider, "fresh-unknown");
    assert_eq!(receipt.generation, 1);
    write_effect_fixture(&state, "started", None);

    let output = startup(&state, &provider, &token, &public);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("crossed the durable start boundary"), "{stderr}");
    let store = ProviderGenerationStore::open(&provider, tenant()).unwrap();
    assert_eq!(store.generation(), 1, "restart must not reexecute the write");
}

#[test]
fn succeeded_receipt_is_verified_then_settled_without_reexecuting_generation() {
    let root = Directory::new();
    let provider = root.0.join("provider");
    let state = root.0.join("server");
    let store = ProviderGenerationStore::initialize(&provider, authority(), config(), &records()).unwrap();
    drop(store);
    let (token, public) = token();
    bootstrap_state(&state, &provider, &token, &public);
    let receipt = advance_offline(&provider, "fresh-succeeded");
    write_effect_fixture(&state, "succeeded", Some(&receipt));

    let output = startup(&state, &provider, &token, &public);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let settled: Value = serde_json::from_slice(&std::fs::read(effect_path(&state)).unwrap()).unwrap();
    assert_eq!(settled["state"], "settled");
    assert_eq!(settled["governed_generation"], 1);
    let store = ProviderGenerationStore::open(&provider, tenant()).unwrap();
    assert_eq!(store.generation(), 1, "recovery must settle, not execute generation 2");
    assert!(store.matches_evidence_receipt(&receipt));
}
