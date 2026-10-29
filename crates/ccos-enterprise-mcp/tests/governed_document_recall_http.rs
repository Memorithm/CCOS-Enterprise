//! HTTP transport (feature `http-gateway`) for governed `memory.document_recall`.
//!
//! Spawns the real server binary bound to an ephemeral localhost port and drives it over
//! plain HTTP/1.1. The transport must reuse the stdio admission path: identity, tenant,
//! RBAC/quota/replay via `Deployment::admit`, execution journal and effect witness.
#![cfg(feature = "http-gateway")]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use ccos_enterprise_auth::{issue_identity_token, IdentityClaims, IDENTITY_TOKEN_VERSION};
use ccos_enterprise_memory::{
    GovernedMemoryProjection, MemoryAssetDescriptor, MemoryAssetId, MemoryEvidenceRef,
    MemoryLineage, MemoryLineageGraph, MemoryLoadoutBinding, MemoryLoadoutPlan, MemorySpace,
    MemoryStratum, MemoryTrustMetadata, MemoryUsageMode, MemoryValidationState,
};
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
            "ccos-http-docrecall-{}-{}",
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
        jti: "docrecall-http".into(),
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

fn token_for(actor: &str, jti: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = IdentityClaims {
        version: IDENTITY_TOKEN_VERSION,
        jti: jti.into(),
        org: "memorithm".into(),
        actor: actor.into(),
        audience: "docrecall-test".into(),
        issued_at: now,
        expires_at: now + 600,
        not_before: None,
    };
    issue_identity_token(&[9u8; 32], "test-key", &claims).unwrap()
}

struct HttpServer {
    child: Child,
    addr: String,
}

impl HttpServer {
    fn spawn(state: &Path, provider: &Path, token: &str, public_key: &[u8; 32]) -> Self {
        let public_hex: String = public_key.iter().map(|b| format!("{b:02x}")).collect();
        let mut command = Command::new(env!("CARGO_BIN_EXE_ccos-enterprise-mcp-server"));
        for name in [
            "CCOS_ENTERPRISE_ENVELOPE_CONFIG",
            "CCOS_ENTERPRISE_EVIDENCE_KNOWLEDGE_ROOT",
            "CCOS_ENTERPRISE_SOURCE_BLOBS_ROOT",
            "CCOS_ENTERPRISE_DOCUMENT_RANKING",
            "CCOS_ENTERPRISE_DOCUMENT_ENCODER_DIR",
            "CCOS_ENTERPRISE_DOCUMENT_ENCODER_LABEL",
            "CCOS_ENTERPRISE_DOCUMENT_FUSED_ALPHA",
            "CCOS_ENTERPRISE_DOCUMENT_FUSED_POOL",
        ] {
            command.env_remove(name);
        }
        let mut child = command
            .env("CCOS_ENTERPRISE_HTTP_BIND", "127.0.0.1:0")
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
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stderr = BufReader::new(child.stderr.take().unwrap());
        let mut addr = None;
        let mut line = String::new();
        while addr.is_none() {
            line.clear();
            assert!(
                stderr.read_line(&mut line).unwrap() > 0,
                "server exited before listening"
            );
            if let Some(rest) = line
                .trim()
                .strip_prefix("ccos-enterprise-mcp: http-gateway listening on ")
            {
                addr = Some(rest.to_string());
            }
        }
        // Keep draining stderr so the child can never block on a full pipe.
        std::thread::spawn(move || {
            let mut sink = Vec::new();
            let _ = stderr.read_to_end(&mut sink);
        });
        Self {
            child,
            addr: addr.unwrap(),
        }
    }

    fn send(&self, method: &str, path: &str, auth: Option<&str>, body: &str) -> (u16, Value) {
        let mut stream = TcpStream::connect(&self.addr).unwrap();
        let auth = auth
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut raw = String::new();
        stream.read_to_string(&mut raw).unwrap();
        let (head, payload) = raw.split_once("\r\n\r\n").unwrap();
        let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
        (status, serde_json::from_str(payload).unwrap())
    }

    fn recall(&self, token: &str, body: Value) -> (u16, Value) {
        self.send(
            "POST",
            "/v1/memory/document_recall",
            Some(token),
            &body.to_string(),
        )
    }
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn query() -> Value {
    json!({ "query": "quarterly revenue report", "k": 8 })
}

fn assert_recall(status: u16, body: &Value) {
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["ok"], true);
    assert_eq!(body["tool"], "memory.document_recall");
    let structured = &body["result"]["structuredContent"];
    assert_eq!(structured["tool"], "memory.document_recall");
    assert_eq!(structured["trust_policy"], "verified_only");
    assert_eq!(structured["ranking"], "lexical_bm25");
    assert_eq!(structured["tenant"], "acme");
    let items = structured["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{structured}");
    assert_eq!(items[0]["asset_id"], "active");
    assert_eq!(items[0]["text"], text("active"));
    let raw = body.to_string();
    for hidden in ["quarantined", "invalidated", "offloadout"] {
        assert!(!raw.contains(&text(hidden)), "leaked {hidden}: {raw}");
    }
}

#[test]
fn http_document_recall_is_admitted_journaled_scoped_and_replay_suppressed() {
    let root = Directory::new();
    let provider = root.0.join("provider");
    let state = root.0.join("server");
    drop(
        ProviderGenerationStore::initialize(&provider, authority(), config(), &records()).unwrap(),
    );
    let (token, public) = token();
    let server = HttpServer::spawn(&state, &provider, &token, &public);

    // Governed recall over HTTP, same DocumentMemory path as stdio.
    let (status, body) = server.recall(
        &token,
        json!({ "request_id": "http-1", "arguments": query() }),
    );
    assert_recall(status, &body);

    // Same durable effect witness + execution journal as the stdio transport.
    let effect: Value = serde_json::from_slice(
        &std::fs::read(state.join(".enterprise").join("effect.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(effect["tool"], "memory.document_recall");
    assert_eq!(effect["request_id"], "http-1");
    assert!(
        walk(&state.join(".execution"))
            .iter()
            .any(
                |entry| String::from_utf8_lossy(&std::fs::read(entry).unwrap())
                    .contains("memory.document_recall")
            ),
        "execution journal has no document_recall event"
    );

    // Replay of the same request id is suppressed by Deployment::admit, not re-executed.
    let (status, replay) = server.recall(
        &token,
        json!({ "request_id": "http-1", "arguments": query() }),
    );
    assert_eq!(status, 200, "{replay}");
    assert_eq!(replay["result"]["structuredContent"]["replayed"], true);

    // Unknown tool arguments (scope widening) are refused by the shared parser.
    let (status, widened) = server.recall(
        &token,
        json!({ "request_id": "http-2", "arguments": {"query": "quarterly", "space": "project:p1"} }),
    );
    assert_eq!(status, 400, "{widened}");
    // Unknown envelope fields (client-chosen scope/policy) are refused before dispatch.
    for field in ["tenant_id", "space", "policy", "ranking"] {
        let mut request = json!({ "request_id": "http-3", "arguments": query() });
        request[field] = json!("x");
        let (status, refused) = server.recall(&token, request);
        assert_eq!(status, 400, "{field}: {refused}");
    }

    // A foreign tenant assertion is refused; the bound tenant is accepted.
    let (status, foreign) = server.recall(
        &token,
        json!({ "request_id": "http-4", "tenant": "globex", "arguments": query() }),
    );
    assert_eq!(status, 403, "{foreign}");
    let (status, body) = server.recall(
        &token,
        json!({ "request_id": "http-5", "tenant": "acme", "arguments": query() }),
    );
    assert_recall(status, &body);

    // Identity: missing, forged, or a different principal is refused.
    let (status, _) = server.send(
        "POST",
        "/v1/memory/document_recall",
        None,
        &json!({ "request_id": "http-6", "arguments": query() }).to_string(),
    );
    assert_eq!(status, 401);
    let (status, _) = server.recall(
        "not-a-token",
        json!({ "request_id": "http-7", "arguments": query() }),
    );
    assert_eq!(status, 401);
    let (status, _) = server.recall(
        &token_for("mallory", "docrecall-mallory"),
        json!({ "request_id": "http-8", "arguments": query() }),
    );
    assert_eq!(status, 403);

    // Routing.
    let (status, _) = server.send("GET", "/v1/memory/document_recall", Some(&token), "");
    assert_eq!(status, 405);
    let (status, _) = server.send("POST", "/v1/memory/purge", Some(&token), "{}");
    assert_eq!(status, 404);
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
