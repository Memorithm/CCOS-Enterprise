use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use ccos_enterprise_auth::{issue_identity_token, IdentityClaims, IDENTITY_TOKEN_VERSION};
use ccos_enterprise_ingest::doc_index::lexical_only_memory;
use ccos_enterprise_mcp::{
    recall_governed_documents, DocumentRanker, DocumentRankingMode, DocumentRecallError,
    ServedDocumentMemory, ServedIndexMut,
};
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
        Self::spawn_with_env(state, provider, token, public_key, roots, &[])
    }

    fn command(
        state: &Path,
        provider: &Path,
        token: &str,
        public_key: &[u8; 32],
        extra: &[(&str, &str)],
    ) -> Command {
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
        for name in [
            "CCOS_ENTERPRISE_DOCUMENT_RANKING",
            "CCOS_ENTERPRISE_DOCUMENT_ENCODER_DIR",
            "CCOS_ENTERPRISE_DOCUMENT_ENCODER_LABEL",
            "CCOS_ENTERPRISE_DOCUMENT_FUSED_ALPHA",
            "CCOS_ENTERPRISE_DOCUMENT_FUSED_POOL",
        ] {
            command.env_remove(name);
        }
        for (name, value) in extra {
            command.env(name, value);
        }
        command
            .env("CCOS_ENTERPRISE_AUDIENCE", "docrecall-test")
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

    fn spawn_with_env(
        state: &Path,
        provider: &Path,
        token: &str,
        public_key: &[u8; 32],
        roots: Option<(&Path, &Path)>,
        extra: &[(&str, &str)],
    ) -> Self {
        let mut command = Self::command(state, provider, token, public_key, extra);
        if let Some((knowledge, blobs)) = roots {
            command
                .env("CCOS_ENTERPRISE_EVIDENCE_KNOWLEDGE_ROOT", knowledge)
                .env("CCOS_ENTERPRISE_SOURCE_BLOBS_ROOT", blobs);
        }
        let mut child = command
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

// ── Encoder injection (dense / fused) ──────────────────────────────────────────────────────

/// Test-only "semantic" encoder: maps synonyms to the same axis so dense recall can match a
/// query with no lexical overlap. Not a model, not a quality claim.
struct ConceptEncoder;
impl ccos_core::retrieval::Encoder for ConceptEncoder {
    fn embedding_dim(&self) -> usize {
        3
    }
    fn encode(&mut self, text: &str) -> Vec<f32> {
        let mut v = vec![0.0f32; 3];
        for w in text.to_lowercase().split_whitespace() {
            match w {
                "revenue" | "earnings" | "income" => v[0] += 1.0,
                "report" | "filing" => v[1] += 1.0,
                _ => v[2] += 0.1,
            }
        }
        v
    }
}

fn ranker(mode: DocumentRankingMode) -> DocumentRanker {
    DocumentRanker::with_encoder(mode, Box::new(ConceptEncoder), "concept-test").unwrap()
}

fn recalled(
    memory: &mut ccos_enterprise_mcp::ServedDocumentMemory,
    store: &ProviderGenerationStore,
    tenant: &str,
    q: &str,
) -> Result<Vec<String>, DocumentRecallError> {
    memory
        .recall(
            &TenantId::validated(tenant).unwrap(),
            store.governance(),
            GovernedRecallTrustPolicy::VerifiedOnly,
            q,
            8,
            MemoryContextBudget::new(8, 4096).unwrap(),
        )
        .map(|a| {
            a.chunks()
                .iter()
                .map(|c| c.asset_id.as_str().to_string())
                .collect()
        })
}

fn rebuilt(store: &ProviderGenerationStore, ranker: &DocumentRanker) -> ServedDocumentMemory {
    let mut memory = ranker.empty_memory();
    let report = match memory.index_mut() {
        ServedIndexMut::Lexical(m) => store.recovered().rebuild_document_index(m),
        ServedIndexMut::Encoded(m) => store.recovered().rebuild_document_index(m),
    }
    .unwrap();
    assert_eq!(report.indexed, 2);
    assert_eq!(report.skipped_inactive, 1);
    assert_eq!(report.skipped_out_of_loadout, 1);
    memory
}

#[test]
fn default_ranker_is_lexical_and_matches_shipped_behaviour() {
    let root = Directory::new();
    let store = ProviderGenerationStore::initialize(
        root.0.join("provider"),
        authority(),
        config(),
        &records(),
    )
    .unwrap();
    let mut served = rebuilt(&store, &DocumentRanker::default());
    let mut shipped = lexical_only_memory();
    store
        .recovered()
        .rebuild_document_index(&mut shipped)
        .unwrap();
    let budget = MemoryContextBudget::new(8, 4096).unwrap();
    let acme = TenantId::validated("acme").unwrap();
    for q in ["quarterly revenue report", "earnings filing", "active"] {
        let a = served
            .recall(
                &acme,
                store.governance(),
                GovernedRecallTrustPolicy::VerifiedOnly,
                q,
                8,
                budget,
            )
            .unwrap();
        let b = recall_governed_documents(
            &mut shipped,
            &acme,
            store.governance(),
            GovernedRecallTrustPolicy::VerifiedOnly,
            q,
            8,
            budget,
        )
        .unwrap();
        let ids = |x: &ccos_enterprise_memory::GovernedMemoryContextAssembly| {
            x.chunks()
                .iter()
                .map(|c| (c.asset_id.as_str().to_string(), c.similarity))
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(&a), ids(&b), "{q}");
    }
    // No lexical overlap => nothing under BM25.
    assert_eq!(
        recalled(&mut served, &store, "acme", "earnings filing").unwrap(),
        Vec::<String>::new()
    );
    let mut r = json!({"structuredContent": {}});
    served.annotate(&mut r);
    assert_eq!(r["structuredContent"], json!({"ranking": "lexical_bm25"}));
}

#[test]
fn injected_encoder_serves_dense_and_fused_through_governed_admission() {
    let root = Directory::new();
    let store = ProviderGenerationStore::initialize(
        root.0.join("provider"),
        authority(),
        config(),
        &records(),
    )
    .unwrap();
    for mode in [
        DocumentRankingMode::Dense,
        DocumentRankingMode::Fused {
            alpha: 0.5,
            pool: 100,
        },
    ] {
        let mut memory = rebuilt(&store, &ranker(mode));
        // Synonym query with zero lexical overlap reaches the asset through the encoder, and
        // the quarantined asset (indexed, same vector) is still dropped by admit_governed_recall.
        assert_eq!(
            recalled(&mut memory, &store, "acme", "earnings filing").unwrap(),
            ["active"],
            "{mode:?}"
        );
        // Tenant isolation: another tenant never reaches the index.
        assert!(matches!(
            recalled(&mut memory, &store, "globex", "earnings filing"),
            Err(DocumentRecallError::RecallAdmission(_))
        ));
        let mut r = json!({"structuredContent": {}});
        memory.annotate(&mut r);
        assert_eq!(r["structuredContent"]["ranking"], mode.label());
        assert_eq!(r["structuredContent"]["ranking_encoder"], "concept-test");
        match mode {
            DocumentRankingMode::Fused { .. } => {
                assert_eq!(r["structuredContent"]["ranking_alpha"], 0.5);
                assert_eq!(r["structuredContent"]["ranking_pool"], 100);
            }
            _ => assert!(r["structuredContent"].get("ranking_alpha").is_none()),
        }
    }
}

#[test]
fn stdio_boot_refuses_dense_or_fused_without_an_encoder() {
    let root = Directory::new();
    let provider = root.0.join("provider");
    drop(
        ProviderGenerationStore::initialize(&provider, authority(), config(), &records()).unwrap(),
    );
    let (token, public) = token();
    for extra in [
        &[("CCOS_ENTERPRISE_DOCUMENT_RANKING", "fused")][..],
        &[("CCOS_ENTERPRISE_DOCUMENT_RANKING", "dense")][..],
        &[("CCOS_ENTERPRISE_DOCUMENT_RANKING", "bm25")][..],
        &[("CCOS_ENTERPRISE_DOCUMENT_ENCODER_DIR", "/nonexistent")][..],
        &[
            ("CCOS_ENTERPRISE_DOCUMENT_RANKING", "fused"),
            (
                "CCOS_ENTERPRISE_DOCUMENT_ENCODER_DIR",
                "/nonexistent/minilm",
            ),
        ][..],
    ] {
        let output =
            ServerProcess::command(&root.0.join("server"), &provider, &token, &public, extra)
                .stdin(Stdio::null())
                .output()
                .unwrap();
        assert!(!output.status.success(), "{extra:?} booted");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("DOCUMENT") || stderr.contains("encoder") || stderr.contains("ranking"),
            "{extra:?}: {stderr}"
        );
    }
}

/// Optional, not run in CI: real pinned all-MiniLM-L6-v2 on CPU through the stdio server.
/// `CCOS_TEST_MINILM_DIR=/path/to/all-MiniLM-L6-v2 cargo test -p ccos-enterprise-mcp -- --ignored`
#[test]
#[ignore = "needs a local MiniLM directory (CCOS_TEST_MINILM_DIR)"]
fn real_stdio_serves_fused_minilm_when_configured() {
    let dir = std::env::var("CCOS_TEST_MINILM_DIR").expect("CCOS_TEST_MINILM_DIR");
    let root = Directory::new();
    let provider = root.0.join("provider");
    let state = root.0.join("server");
    drop(
        ProviderGenerationStore::initialize(&provider, authority(), config(), &records()).unwrap(),
    );
    let (token, public) = token();
    let mut server = ServerProcess::spawn_with_env(
        &state,
        &provider,
        &token,
        &public,
        None,
        &[
            ("CCOS_ENTERPRISE_DOCUMENT_RANKING", "fused"),
            ("CCOS_ENTERPRISE_DOCUMENT_ENCODER_DIR", &dir),
            ("CCOS_ENTERPRISE_DOCUMENT_ENCODER_LABEL", "all-MiniLM-L6-v2"),
        ],
    );
    let response = server.request(call(1, "acme", "doc-m1", query()));
    let structured = &response["result"]["structuredContent"];
    assert_eq!(structured["ranking"], "fused", "{response}");
    assert_eq!(structured["ranking_alpha"], 0.5);
    assert_eq!(structured["ranking_encoder"], "all-MiniLM-L6-v2");
    let items = structured["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["asset_id"], "active");
    server.stop();
}
