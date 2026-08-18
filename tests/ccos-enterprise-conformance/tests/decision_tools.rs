use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ccos_enterprise_auth::AuthStrength;
use ccos_enterprise_decision_service::{DecisionService, DECISION_READ, DECISION_WRITE};
use ccos_enterprise_knowledge::{JournalEntry, KnowledgeOp};
use ccos_enterprise_knowledge_model::{
    AssertionKind, EntityId, EntityRecord, EvidenceId, EvidenceRecord, FactAssertion, FactId,
    FactObject, SourceId, SourceRecord, SourceTrust, TenantId, ValidityInterval,
};
use ccos_enterprise_mcp::{govern_catalogue, Backend, GovernedMcp, McpOutcome};
use ccos_enterprise_runtime::{actor, request, Call, Deployment, TenantState};
use serde_json::{json, Value};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let ordinal = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ccos-governed-decision-tools-{}-{ordinal}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct CoreRecorder {
    calls: usize,
}

impl Backend for CoreRecorder {
    fn dispatch(
        &mut self,
        _tenant: &str,
        _core_tool: &str,
        _arguments: &Value,
    ) -> Result<Value, String> {
        self.calls += 1;
        Ok(json!({"core": true}))
    }
}

fn evidence() -> BTreeSet<EvidenceId> {
    BTreeSet::from([EvidenceId::from("evidence:policy")])
}

fn seed(service: &mut DecisionService) {
    let tenant = TenantId("acme".into());
    service
        .append_knowledge(&[
            JournalEntry::new(
                0,
                KnowledgeOp::RegisterSource(SourceRecord {
                    id: SourceId::from("source:policy"),
                    tenant: tenant.clone(),
                    locator: "file:///acme/policy.json".into(),
                    content_hash: Some("sha256:policy".into()),
                    trust: SourceTrust::Authoritative,
                }),
            ),
            JournalEntry::new(
                1,
                KnowledgeOp::AddEvidence(EvidenceRecord {
                    id: EvidenceId::from("evidence:policy"),
                    tenant: tenant.clone(),
                    source: SourceId::from("source:policy"),
                    locator: Some("$.approval".into()),
                    content_hash: Some("sha256:approval".into()),
                }),
            ),
            JournalEntry::new(
                2,
                KnowledgeOp::AddEntity(EntityRecord {
                    id: EntityId::from("entity:request"),
                    tenant: tenant.clone(),
                    namespace: None,
                    entity_type: "deployment_request".into(),
                    label: Some("Acme deployment".into()),
                    evidence: evidence(),
                    kind: AssertionKind::Authoritative,
                }),
            ),
            JournalEntry::new(
                3,
                KnowledgeOp::AssertFact(FactAssertion {
                    id: FactId::from("fact:eligible"),
                    tenant,
                    subject: EntityId::from("entity:request"),
                    predicate: "eligible".into(),
                    object: FactObject::Literal("true".into()),
                    validity: ValidityInterval::unbounded(),
                    evidence: evidence(),
                    kind: AssertionKind::Authoritative,
                }),
            ),
        ])
        .unwrap();
}

fn deployment() -> Deployment {
    let mut deployment = Deployment::new();
    deployment
        .add_role("decision-reader", &[DECISION_READ])
        .add_role("decision-writer", &[DECISION_READ, DECISION_WRITE]);
    govern_catalogue(&mut deployment);
    let mut tenant = TenantState::new(10_000);
    tenant.allow_model("claude-opus");
    deployment.add_tenant("memorithm", "acme", tenant);
    deployment.assign("alice", "decision-writer");
    deployment.assign("bob", "decision-reader");
    deployment
}

fn front_door(dir: &TestDir) -> GovernedMcp<CoreRecorder, DecisionService> {
    let mut decisions = DecisionService::open(dir.0.join("decision-service")).unwrap();
    seed(&mut decisions);
    GovernedMcp::with_decisions(deployment(), CoreRecorder::default(), decisions)
}

fn record_args() -> Value {
    json!({
        "id": "decision:approve",
        "question": "Should this deployment proceed?",
        "selected": "approve",
        "rationale": "Authoritative eligibility supports approval.",
        "facts": ["fact:eligible"],
        "evidence": ["evidence:policy"],
        "rules": ["rule:approval"]
    })
}

#[test]
fn governed_decision_mutation_is_persisted_once_and_replay_has_no_effect() {
    let dir = TestDir::new();
    let mut mcp = front_door(&dir);
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let request = request("acme", "alice", "decision.record", "r-decision-1");

    let first = mcp.call(
        Call {
            actor: &alice,
            request: &request,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
            justification: None,
        },
        &record_args(),
    );
    let McpOutcome::Ok(record) = first else {
        panic!("first decision mutation was not executed: {first:?}");
    };
    assert_eq!(record["tenant"], json!("acme"));
    assert_eq!(record["actor"], json!("alice"));
    assert_eq!(record["decided_at"], json!(0));
    assert_eq!(mcp.decision_backend().decision_state().next_sequence(), 1);
    assert_eq!(mcp.backend().calls, 0, "decision tools are not Core tools");

    let replay = mcp.call(
        Call {
            actor: &alice,
            request: &request,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
            justification: None,
        },
        &record_args(),
    );
    assert_eq!(replay, McpOutcome::Replayed);
    assert_eq!(mcp.decision_backend().decision_state().next_sequence(), 1);
    assert_eq!(mcp.deployment().spent("acme"), Some(10));
}

#[test]
fn decision_reads_use_the_same_governed_path_and_reader_cannot_mutate() {
    let dir = TestDir::new();
    let mut mcp = front_door(&dir);
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let bob = actor("memorithm", "bob", AuthStrength::Token);

    let write = request("acme", "alice", "decision.record", "r-write");
    assert!(matches!(
        mcp.call(
            Call {
                actor: &alice,
                request: &write,
                model: "claude-opus",
                cost_tokens: 10,
                variant: None,
                justification: None,
            },
            &record_args(),
        ),
        McpOutcome::Ok(_)
    ));

    let read = request("acme", "bob", "decision.get", "r-read");
    let McpOutcome::Ok(record) = mcp.call(
        Call {
            actor: &bob,
            request: &read,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
            justification: None,
        },
        &json!({"decision": "decision:approve"}),
    ) else {
        panic!("decision reader could not read an existing decision");
    };
    assert_eq!(record["id"], json!("decision:approve"));

    let forbidden_write = request("acme", "bob", "decision.record", "r-bob-write");
    let denied = mcp.call(
        Call {
            actor: &bob,
            request: &forbidden_write,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
            justification: None,
        },
        &record_args(),
    );
    assert!(matches!(denied, McpOutcome::Refused(_)));
    assert_eq!(mcp.decision_backend().decision_state().next_sequence(), 1);
}

#[test]
fn client_cannot_smuggle_authority_fields_through_mcp() {
    let dir = TestDir::new();
    let mut mcp = front_door(&dir);
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let request = request("acme", "alice", "decision.record", "r-smuggle");
    let mut args = record_args();
    args.as_object_mut()
        .unwrap()
        .insert("actor".into(), json!("mallory"));

    let outcome = mcp.call(
        Call {
            actor: &alice,
            request: &request,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
            justification: None,
        },
        &args,
    );
    assert!(matches!(outcome, McpOutcome::BackendError(_)));
    assert_eq!(mcp.decision_backend().decision_state().next_sequence(), 0);
}

#[test]
fn unlisted_decision_capability_is_refused_before_local_dispatch() {
    let dir = TestDir::new();
    let mut mcp = front_door(&dir);
    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let request = request("acme", "alice", "decision.delete", "r-delete");
    let outcome = mcp.call(
        Call {
            actor: &alice,
            request: &request,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
            justification: None,
        },
        &json!({"decision": "decision:approve"}),
    );
    assert!(matches!(outcome, McpOutcome::Refused(_)));
    assert_eq!(mcp.decision_backend().decision_state().next_sequence(), 0);
    assert_eq!(mcp.deployment().spent("acme"), Some(0));
}
