use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use ccos_enterprise_auth::{issue_identity_token, IdentityClaims, IDENTITY_TOKEN_VERSION};
use ccos_enterprise_memory::{
    GovernedMemoryProjection, MemoryAssetDescriptor, MemoryAssetId, MemoryEvidenceRef,
    MemoryLineage, MemoryLineageGraph, MemoryLoadoutBinding, MemoryLoadoutPlan, MemorySpace,
    MemoryStratum, MemoryTrustMetadata, MemoryUsageMode, MemoryValidationState,
};
use ccos_enterprise_octasoma::generation::ProviderGenerationStore;
use ccos_enterprise_octasoma::recovery::{RecoveryConfig, RecoveryRecord};
use ccos_enterprise_tenancy::TenantId;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ccos-served-context-{}-{}",
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

fn id(value: &str) -> MemoryAssetId {
    MemoryAssetId::new(value).unwrap()
}

fn authority() -> GovernedMemoryProjection {
    let mut graph = MemoryLineageGraph::new();
    for name in ["active", "quarantined", "invalidated"] {
        graph
            .register(
                MemoryAssetDescriptor::new(
                    id(name),
                    MemorySpace::Tenant,
                    MemoryStratum::Evidence,
                    MemoryLineage::root([
                        MemoryEvidenceRef::new(format!("audit:{name}")).unwrap(),
                    ])
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
    }
    graph.invalidate(&id("invalidated")).unwrap();
    let verified = |name: &str| {
        (
            id(name),
            MemoryTrustMetadata::new(
                MemoryValidationState::Verified,
                1,
                1,
                0,
                [format!("proof:{name}")],
            )
            .unwrap(),
        )
    };
    let quarantined = (
        id("quarantined"),
        MemoryTrustMetadata::new(
            MemoryValidationState::Quarantined,
            1,
            1,
            1,
            ["proof:quarantine".to_string()],
        )
        .unwrap(),
    );
    GovernedMemoryProjection::new(
        TenantId::validated("acme").unwrap(),
        graph,
        BTreeMap::from([verified("active"), quarantined, verified("invalidated")]),
        MemoryLoadoutPlan::new([MemoryLoadoutBinding::new(
            MemorySpace::Tenant,
            100,
            MemoryUsageMode::Bootstrap,
        )
        .unwrap()])
        .unwrap(),
    )
    .unwrap()
}

fn records() -> Vec<RecoveryRecord> {
    ["active", "quarantined", "invalidated"]
        .into_iter()
        .map(|name| RecoveryRecord {
            asset_id: id(name),
            embedding: vec![1.0, 0.0],
            payload: name.as_bytes().to_vec(),
            forgotten: false,
        })
        .collect()
}

struct ServerProcess {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl ServerProcess {
    fn spawn(state: &Path, provider: &Path, token: &str, public_key: &[u8; 32]) -> Self {
        let binary = env!("CARGO_BIN_EXE_ccos-enterprise-mcp-server");
        let public_hex: String = public_key.iter().map(|byte| format!("{byte:02x}")).collect();
        let mut child = Command::new(binary)
            .env("CCOS_ENTERPRISE_AUDIENCE", "context-test")
            .env("CCOS_ENTERPRISE_ISSUER_KID", "test-key")
            .env("CCOS_ENTERPRISE_ISSUER_PUBLIC_KEY_HEX", public_hex)
            .env("CCOS_ENTERPRISE_IDENTITY_TOKEN", token)
            .env("CCOS_ENTERPRISE_TENANT", "acme")
            .env("CCOS_ENTERPRISE_MODEL", "deepseek-harness")
            .env("CCOS_ENTERPRISE_TOKEN_BUDGET", "1000")
            .env("CCOS_ENTERPRISE_CALL_COST_TOKENS", "1")
            .env("CCOS_ENTERPRISE_STATE_DIR", state)
            .env("CCOS_ENTERPRISE_GOVERNED_MEMORY_ROOT", provider)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        Self { child, input, output }
    }

    fn request(&mut self, value: Value) -> Value {
        writeln!(self.input, "{value}").unwrap();
        self.input.flush().unwrap();
        let mut line = String::new();
        self.output.read_line(&mut line).unwrap();
        assert!(!line.is_empty(), "server exited before producing a response");
        serde_json::from_str(&line).unwrap()
    }

    fn stop(mut self) {
        let _ = self.child.kill();
        let status = self.child.wait().unwrap();
        assert!(!status.success(), "kill is expected to terminate the test server");
    }
}

fn call(id: u64, request_id: &str, attempt: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "memory.context",
            "arguments": {
                "embedding": [1.0, 0.0],
                "recall_max_items": 8,
                "recall_max_shortlist": 8,
                "recall_max_payload_bytes": 4096,
                "context_max_items": 8,
                "context_max_payload_bytes": 4096
            },
            "_meta": { "ccos": {
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
            }}
        }
    })
}

fn assert_context(response: &Value) {
    assert!(response.get("error").is_none(), "{response}");
    let structured = &response["result"]["structuredContent"];
    assert_eq!(structured["trust_policy"], "verified_only");
    assert_eq!(structured["generation"], 0);
    let items = structured["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{structured}");
    assert_eq!(items[0]["asset_id"], "active");
    assert_eq!(items[0]["space"], "tenant");
    assert_eq!(items[0]["payload_bytes"], json!([97, 99, 116, 105, 118, 101]));
}

#[test]
fn real_stdio_serves_only_verified_active_context_and_recovers_after_process_death() {
    let root = Directory::new();
    let provider_root = root.0.join("provider");
    let state_root = root.0.join("server");
    let config = RecoveryConfig {
        dimension: 2,
        simhash_bits: 64,
        per_tenant_capacity: 8,
        seed: 42,
    };
    let store =
        ProviderGenerationStore::initialize(&provider_root, authority(), config, &records()).unwrap();
    drop(store);

    let signing = SigningKey::from_bytes(&[9u8; 32]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = IdentityClaims {
        version: IDENTITY_TOKEN_VERSION,
        jti: "context-e2e".into(),
        org: "memorithm".into(),
        actor: "alice".into(),
        audience: "context-test".into(),
        issued_at: now,
        expires_at: now + 600,
        not_before: None,
    };
    let token = issue_identity_token(&[9u8; 32], "test-key", &claims).unwrap();
    let public = signing.verifying_key().to_bytes();

    let mut first = ServerProcess::spawn(&state_root, &provider_root, &token, &public);
    let init = first.request(json!({
        "jsonrpc":"2.0", "id":1, "method":"initialize",
        "params":{"protocolVersion":"2024-11-05","capabilities":{}}
    }));
    assert_eq!(init["result"]["serverInfo"]["name"], "ccos-enterprise");
    let listed = first.request(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":null}));
    assert!(listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|tool| tool["name"] == "memory.context"));
    assert_context(&first.request(call(3, "context-request-1", "attempt-1")));
    first.stop();

    // The same persisted governance + selected provider generation is loaded by
    // a new OS process. A different request id proves this is not replay output.
    let mut second = ServerProcess::spawn(&state_root, &provider_root, &token, &public);
    assert_context(&second.request(call(4, "context-request-2", "attempt-2")));
    second.stop();
}
