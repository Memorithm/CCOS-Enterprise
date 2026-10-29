use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use ccos_enterprise_auth::{issue_identity_token, IdentityClaims, IDENTITY_TOKEN_VERSION};
use ccos_enterprise_ingest::doc_index::lexical_only_memory;
use ccos_enterprise_mcp::{recall_governed_documents, DocumentRecallError};
use ccos_enterprise_memory::{
    GovernedMemoryProjection, MemoryAssetDescriptor, MemoryAssetId, MemoryEvidenceRef,
    MemoryLineage, MemoryLineageGraph, MemoryLoadoutBinding, MemoryLoadoutPlan, MemorySpace,
    MemoryStratum, MemoryTrustMetadata, MemoryUsageMode, MemoryValidationState,
};
use ccos_enterprise_memory::{GovernedRecallTrustPolicy, MemoryContextBudget};
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
            "ccos-served-docrecall-{}-{}",
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
                    MemoryLineage::root([MemoryEvidenceRef::new(format!("audit:{name}")).unwrap()])
                        .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
    }
    graph
        .register(
            MemoryAssetDescriptor::new(
                id("offloadout"),
                MemorySpace::Project("p1".into()),
                MemoryStratum::Evidence,
                MemoryLineage::root([MemoryEvidenceRef::new("audit:offloadout").unwrap()]).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
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
        BTreeMap::from([
            verified("active"),
            quarantined,
            verified("invalidated"),
            verified("offloadout"),
        ]),
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

fn text(name: &str) -> String {
    format!("quarterly revenue report {name}")
}

fn records() -> Vec<RecoveryRecord> {
    ["active", "quarantined", "invalidated", "offloadout"]
        .into_iter()
        .map(|name| RecoveryRecord {
            asset_id: id(name),
            embedding: vec![1.0, 0.0],
            payload: text(name).into_bytes(),
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
        Self::spawn_with_evidence(state, provider, token, public_key, None)
    }

    fn spawn_with_evidence(
        state: &Path,
        provider: &Path,
        token: &str,
        public_key: &[u8; 32],
        roots: Option<(&Path, &Path)>,
    ) -> Self {
        let binary = env!("CARGO_BIN_EXE_ccos-enterprise-mcp-server");
        let public_hex: String = public_key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let mut command = Command::new(binary);
        command
            .env_remove("CCOS_ENTERPRISE_ENVELOPE_CONFIG")
            .env_remove("CCOS_ENTERPRISE_EVIDENCE_KNOWLEDGE_ROOT")
            .env_remove("CCOS_ENTERPRISE_SOURCE_BLOBS_ROOT");
        if let Some((knowledge, blobs)) = roots {
            command
                .env("CCOS_ENTERPRISE_EVIDENCE_KNOWLEDGE_ROOT", knowledge)
                .env("CCOS_ENTERPRISE_SOURCE_BLOBS_ROOT", blobs);
        }
        let mut child = command
            .env("CCOS_ENTERPRISE_AUDIENCE", "docrecall-test")
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
        assert!(
            !line.is_empty(),
            "server exited before producing a response"
        );
        serde_json::from_str(&line).unwrap()
    }

    fn stop(mut self) {
        let _ = self.child.kill();
        let status = self.child.wait().unwrap();
        assert!(
            !status.success(),
            "kill is expected to terminate the test server"
        );
    }
}

fn call(id: u64, tenant: &str, request_id: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "memory.document_recall",
            "arguments": arguments,
            "_meta": { "ccos": {
                "tenant_id": tenant,
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
                "execution_attempt_id": format!("attempt-{id}")
            }}
        }
    })
}

fn query() -> Value {
    json!({ "query": "quarterly revenue report", "k": 8 })
}

fn config() -> RecoveryConfig {
    RecoveryConfig {
        dimension: 2,
        simhash_bits: 64,
        per_tenant_capacity: 8,
        seed: 42,
    }
}

fn token() -> (String, [u8; 32]) {
    let signing = SigningKey::from_bytes(&[9u8; 32]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = IdentityClaims {
        version: IDENTITY_TOKEN_VERSION,
        jti: "docrecall-e2e".into(),
        org: "memorithm".into(),
        actor: "alice".into(),
        audience: "docrecall-test".into(),
        issued_at: now,
        expires_at: now + 600,
        not_before: None,
    };
    (
        issue_identity_token(&[9u8; 32], "test-key", &claims).unwrap(),
        signing.verifying_key().to_bytes(),
    )
}

/// Only the verified, active, loadout-bound asset may surface; nothing else leaks.
fn assert_recall(response: &Value) {
    assert!(response.get("error").is_none(), "{response}");
    let structured = &response["result"]["structuredContent"];
    assert_eq!(structured["tool"], "memory.document_recall");
    assert_eq!(structured["trust_policy"], "verified_only");
    assert_eq!(structured["ranking"], "lexical_bm25");
    assert_eq!(structured["tenant"], "acme");
    assert_eq!(structured["generation"], 0);
    let items = structured["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{structured}");
    assert_eq!(items[0]["asset_id"], "active");
    assert_eq!(items[0]["space"], "tenant");
    assert_eq!(items[0]["text"], text("active"));
    let raw = response.to_string();
    for hidden in ["quarantined", "invalidated", "offloadout"] {
        assert!(!raw.contains(&text(hidden)), "leaked {hidden}: {raw}");
    }
}

#[test]
fn rebuild_from_governed_assets_then_recall_is_admitted_and_tenant_scoped() {
    let root = Directory::new();
    let provider = root.0.join("provider");
    let store =
        ProviderGenerationStore::initialize(&provider, authority(), config(), &records()).unwrap();
    let mut memory = lexical_only_memory();
    let report = store
        .recovered()
        .rebuild_document_index(&mut memory)
        .unwrap();
    // active + quarantined are indexed (trust is enforced at admission, not at indexing);
    // the invalidated asset and the asset outside the loadout never enter the index.
    assert_eq!(report.indexed, 2);
    assert_eq!(report.skipped_inactive, 1);
    assert_eq!(report.skipped_out_of_loadout, 1);
    let acme = TenantId::validated("acme").unwrap();
    let budget = MemoryContextBudget::new(8, 4096).unwrap();
    let assembly = recall_governed_documents(
        &mut memory,
        &acme,
        store.governance(),
        GovernedRecallTrustPolicy::VerifiedOnly,
        "quarterly revenue report",
        8,
        budget,
    )
    .unwrap();
    let ids: Vec<_> = assembly
        .chunks()
        .iter()
        .map(|c| c.asset_id.as_str().to_string())
        .collect();
    assert_eq!(ids, ["active"]);
    let globex = TenantId::validated("globex").unwrap();
    assert!(matches!(
        recall_governed_documents(
            &mut memory,
            &globex,
            store.governance(),
            GovernedRecallTrustPolicy::VerifiedOnly,
            "quarterly revenue report",
            8,
            budget,
        ),
        Err(DocumentRecallError::RecallAdmission(_))
    ));
}

#[test]
fn real_stdio_serves_document_recall_journaled_and_rebuilt_after_restart() {
    let root = Directory::new();
    let provider = root.0.join("provider");
    let state = root.0.join("server");
    drop(
        ProviderGenerationStore::initialize(&provider, authority(), config(), &records()).unwrap(),
    );
    let (token, public) = token();

    let mut first = ServerProcess::spawn(&state, &provider, &token, &public);
    let listed = first.request(json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":null}));
    assert!(listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|tool| tool["name"] == "memory.document_recall"));
    assert_recall(&first.request(call(2, "acme", "doc-1", query())));

    // Durable effect witness + execution journal, same model as memory.context.
    let effect: Value = serde_json::from_slice(
        &std::fs::read(state.join(".enterprise").join("effect.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(effect["tool"], "memory.document_recall");
    assert_eq!(effect["request_id"], "doc-1");
    let mut journaled = false;
    for entry in walk(&state.join(".execution")) {
        let bytes = std::fs::read(entry).unwrap();
        if String::from_utf8_lossy(&bytes).contains("memory.document_recall") {
            journaled = true;
        }
    }
    assert!(journaled, "execution journal has no document_recall event");

    // Client cannot widen scope: unknown arguments (tenant/space) are rejected.
    let widened = first.request(call(
        3,
        "acme",
        "doc-2",
        json!({"query":"quarterly","space":"project:p1"}),
    ));
    assert_eq!(widened["error"]["code"], -32602, "{widened}");
    // Cross-tenant claims are refused before any memory access.
    let foreign = first.request(call(4, "globex", "doc-3", query()));
    assert_eq!(foreign["error"]["code"], -32001, "{foreign}");
    // Replay of the same request id is suppressed, not re-executed.
    let replay = first.request(call(5, "acme", "doc-1", query()));
    assert_eq!(replay["result"]["structuredContent"]["replayed"], true);
    first.stop();

    // A fresh OS process rebuilds the index from the governed assets at boot.
    let mut second = ServerProcess::spawn(&state, &provider, &token, &public);
    assert_recall(&second.request(call(6, "acme", "doc-4", query())));
    second.stop();
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(walk(&path));
            } else {
                out.push(path);
            }
        }
    }
    out
}
