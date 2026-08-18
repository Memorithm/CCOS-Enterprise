//! Server-owned Decision Intelligence tools.
//!
//! This crate is deliberately **not** an authorization layer. The Enterprise runtime owns
//! authentication, tenant ownership, RBAC, policy, replay suppression and budget admission.
//! This service owns the authority fields that must never come from MCP arguments once a call has
//! been admitted: tenant, authenticated actor, decision-journal sequence and the exact canonical
//! Knowledge Plane anchor.
//!
//! The service owns one durable [`KnowledgeStore`] and one durable [`DecisionStore`]. A caller may
//! append already-governed Knowledge Plane journal entries through [`DecisionService::append_knowledge`];
//! all decision mutations then capture that store's current canonical state. Public tool payloads
//! use `deny_unknown_fields`, so attempts to smuggle `tenant`, `actor`, `sequence` or `knowledge`
//! are refused rather than silently ignored.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ccos_enterprise_auth::AuthenticatedActor;
use ccos_enterprise_decision::{
    DecisionDraft, DecisionError, DecisionJournalEntry, DecisionOp, DecisionOutcomeDraft,
    DecisionState, KnowledgeAnchor, OutcomeStatus, SimilarDecisionQuery, TraversalLimits,
};
use ccos_enterprise_decision_store::{DecisionStore, StoreError as DecisionStoreError};
use ccos_enterprise_knowledge::{JournalEntry, KnowledgeState};
use ccos_enterprise_knowledge_model::{
    DecisionId, EvidenceId, FactId, RelationId, RuleId, TenantId,
};
use ccos_enterprise_knowledge_store::{KnowledgeStore, StoreError as KnowledgeStoreError};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};

pub const DECISION_READ: &str = "decision.read";
pub const DECISION_WRITE: &str = "decision.write";

pub const RECORD: &str = "decision.record";
pub const RECORD_OUTCOME: &str = "decision.record_outcome";
pub const GET: &str = "decision.get";
pub const SIMILAR: &str = "decision.similar";
pub const ANCESTRY: &str = "decision.ancestry";
pub const DEPENDENTS: &str = "decision.dependents";
pub const IMPACT: &str = "decision.impact";
pub const REGULATORY_TRAIL: &str = "decision.regulatory_trail";

pub const MAX_SEARCH_RESULTS: usize = 1_000;
pub const MAX_TRAVERSAL_DEPTH: usize = 64;
pub const MAX_TRAVERSAL_RESULTS: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionToolSpec {
    pub name: &'static str,
    pub permission: &'static str,
}

pub const DECISION_TOOLS: &[DecisionToolSpec] = &[
    DecisionToolSpec {
        name: ANCESTRY,
        permission: DECISION_READ,
    },
    DecisionToolSpec {
        name: DEPENDENTS,
        permission: DECISION_READ,
    },
    DecisionToolSpec {
        name: GET,
        permission: DECISION_READ,
    },
    DecisionToolSpec {
        name: IMPACT,
        permission: DECISION_READ,
    },
    DecisionToolSpec {
        name: REGULATORY_TRAIL,
        permission: DECISION_READ,
    },
    DecisionToolSpec {
        name: SIMILAR,
        permission: DECISION_READ,
    },
    DecisionToolSpec {
        name: RECORD,
        permission: DECISION_WRITE,
    },
    DecisionToolSpec {
        name: RECORD_OUTCOME,
        permission: DECISION_WRITE,
    },
];

pub fn tool_spec(name: &str) -> Option<&'static DecisionToolSpec> {
    DECISION_TOOLS.iter().find(|tool| tool.name == name)
}

pub fn tool_names() -> Vec<&'static str> {
    DECISION_TOOLS.iter().map(|tool| tool.name).collect()
}

#[derive(Debug)]
pub enum ServiceError {
    KnowledgeStore(KnowledgeStoreError),
    DecisionStore(DecisionStoreError),
    Decision(DecisionError),
    InvalidArguments(String),
    UnknownTool(String),
    LimitExceeded {
        field: &'static str,
        maximum: usize,
        found: usize,
    },
    Serialization(String),
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KnowledgeStore(error) => write!(f, "knowledge store: {error}"),
            Self::DecisionStore(error) => write!(f, "decision store: {error}"),
            Self::Decision(error) => write!(f, "decision: {error}"),
            Self::InvalidArguments(detail) => write!(f, "invalid decision tool arguments: {detail}"),
            Self::UnknownTool(tool) => write!(f, "unknown decision tool {tool:?}"),
            Self::LimitExceeded {
                field,
                maximum,
                found,
            } => write!(f, "{field}={found} exceeds server maximum {maximum}"),
            Self::Serialization(detail) => write!(f, "decision response serialization failed: {detail}"),
        }
    }
}

impl std::error::Error for ServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::KnowledgeStore(error) => Some(error),
            Self::DecisionStore(error) => Some(error),
            Self::Decision(error) => Some(error),
            _ => None,
        }
    }
}

impl From<KnowledgeStoreError> for ServiceError {
    fn from(value: KnowledgeStoreError) -> Self {
        Self::KnowledgeStore(value)
    }
}

impl From<DecisionStoreError> for ServiceError {
    fn from(value: DecisionStoreError) -> Self {
        Self::DecisionStore(value)
    }
}

impl From<DecisionError> for ServiceError {
    fn from(value: DecisionError) -> Self {
        Self::Decision(value)
    }
}

pub struct DecisionService {
    root: PathBuf,
    knowledge: KnowledgeStore,
    decisions: DecisionStore,
}

impl DecisionService {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ServiceError> {
        let root = root.as_ref().to_path_buf();
        let knowledge = KnowledgeStore::open(root.join("knowledge"))?;
        let decisions = DecisionStore::open(root.join("decisions"))?;
        Ok(Self {
            root,
            knowledge,
            decisions,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn knowledge_state(&self) -> &KnowledgeState {
        self.knowledge.state()
    }

    pub fn decision_state(&self) -> &DecisionState {
        self.decisions.state()
    }

    /// Internal canonical Knowledge Plane mutation path. MCP governance is deliberately elsewhere.
    pub fn append_knowledge(&mut self, entries: &[JournalEntry]) -> Result<(), ServiceError> {
        self.knowledge.append(entries)?;
        Ok(())
    }

    /// Execute one already-admitted Decision Intelligence tool.
    ///
    /// `tenant` comes from the request whose ownership was verified by the runtime. `actor` is the
    /// opaque authenticated identity produced by the auth crate. Neither is accepted in `arguments`.
    pub fn dispatch(
        &mut self,
        tenant: &str,
        actor: &AuthenticatedActor,
        tool: &str,
        arguments: &Value,
    ) -> Result<Value, ServiceError> {
        match tool {
            RECORD => self.record(tenant, actor, arguments),
            RECORD_OUTCOME => self.record_outcome(tenant, arguments),
            GET => self.get(tenant, arguments),
            SIMILAR => self.similar(tenant, arguments),
            ANCESTRY => self.ancestry(tenant, arguments),
            DEPENDENTS => self.dependents(tenant, arguments),
            IMPACT => self.impact(tenant, arguments),
            REGULATORY_TRAIL => self.regulatory_trail(tenant, arguments),
            _ => Err(ServiceError::UnknownTool(tool.to_string())),
        }
    }

    fn record(
        &mut self,
        tenant: &str,
        actor: &AuthenticatedActor,
        arguments: &Value,
    ) -> Result<Value, ServiceError> {
        let input: RecordInput = parse(arguments)?;
        let tenant = TenantId(tenant.to_string());
        let knowledge = self.knowledge.state();
        let draft = DecisionDraft {
            id: input.id.clone(),
            tenant: tenant.clone(),
            actor: actor.actor().clone(),
            question: input.question,
            selected: input.selected,
            rationale: input.rationale,
            facts: input.facts,
            relations: input.relations,
            evidence: input.evidence,
            rules: input.rules,
            precedents: input.precedents,
            knowledge: KnowledgeAnchor::capture(knowledge)?,
        };
        let entry = DecisionJournalEntry::new(
            self.decisions.next_sequence(),
            DecisionOp::Record(draft),
        );
        self.decisions.append(&[entry], knowledge)?;
        serialize(self.decisions.state().decision(&tenant, &input.id)?)
    }

    fn record_outcome(&mut self, tenant: &str, arguments: &Value) -> Result<Value, ServiceError> {
        let input: RecordOutcomeInput = parse(arguments)?;
        let tenant = TenantId(tenant.to_string());
        let knowledge = self.knowledge.state();
        let entry = DecisionJournalEntry::new(
            self.decisions.next_sequence(),
            DecisionOp::RecordOutcome {
                tenant: tenant.clone(),
                decision: input.decision.clone(),
                outcome: DecisionOutcomeDraft {
                    status: input.status,
                    summary: input.summary,
                    evidence: input.evidence,
                    knowledge: KnowledgeAnchor::capture(knowledge)?,
                },
            },
        );
        self.decisions.append(&[entry], knowledge)?;
        serialize(
            self.decisions
                .state()
                .decision(&tenant, &input.decision)?,
        )
    }

    fn get(&self, tenant: &str, arguments: &Value) -> Result<Value, ServiceError> {
        let input: DecisionInput = parse(arguments)?;
        serialize(
            self.decisions
                .state()
                .decision(&TenantId(tenant.to_string()), &input.decision)?,
        )
    }

    fn similar(&self, tenant: &str, arguments: &Value) -> Result<Value, ServiceError> {
        let input: SimilarInput = parse(arguments)?;
        require_max("limit", input.limit, MAX_SEARCH_RESULTS)?;
        let matches = self
            .decisions
            .state()
            .similar_decisions(&SimilarDecisionQuery {
                tenant: TenantId(tenant.to_string()),
                question: input.question,
                facts: input.facts,
                relations: input.relations,
                rules: input.rules,
                exclude: input.exclude,
                limit: input.limit,
            })?;
        Ok(Value::Array(
            matches
                .into_iter()
                .map(|found| {
                    json!({
                        "decision": found.decision,
                        "score": {
                            "shared_facts": found.score.shared_facts,
                            "shared_relations": found.score.shared_relations,
                            "shared_rules": found.score.shared_rules,
                            "shared_terms": found.score.shared_terms,
                            "weighted_total": found.score.weighted_total(),
                        }
                    })
                })
                .collect(),
        ))
    }

    fn ancestry(&self, tenant: &str, arguments: &Value) -> Result<Value, ServiceError> {
        let (decision, limits) = traversal(arguments)?;
        serialize(&self.decisions.state().causal_ancestry(
            &TenantId(tenant.to_string()),
            &decision,
            limits,
        )?)
    }

    fn dependents(&self, tenant: &str, arguments: &Value) -> Result<Value, ServiceError> {
        let (decision, limits) = traversal(arguments)?;
        serialize(&self.decisions.state().causal_dependents(
            &TenantId(tenant.to_string()),
            &decision,
            limits,
        )?)
    }

    fn impact(&self, tenant: &str, arguments: &Value) -> Result<Value, ServiceError> {
        let (decision, limits) = traversal(arguments)?;
        let report = self.decisions.state().impact_analysis(
            &TenantId(tenant.to_string()),
            &decision,
            limits,
        )?;
        Ok(json!({
            "decision": report.decision,
            "dependent_decisions": report.dependent_decisions,
            "facts": report.facts,
            "relations": report.relations,
            "evidence": report.evidence,
            "rules": report.rules,
        }))
    }

    fn regulatory_trail(&self, tenant: &str, arguments: &Value) -> Result<Value, ServiceError> {
        let (decision, limits) = traversal(arguments)?;
        serialize(&self.decisions.state().regulatory_trail(
            &TenantId(tenant.to_string()),
            &decision,
            limits,
        )?)
    }
}

fn parse<T: DeserializeOwned>(arguments: &Value) -> Result<T, ServiceError> {
    serde_json::from_value(arguments.clone())
        .map_err(|error| ServiceError::InvalidArguments(error.to_string()))
}

fn serialize<T: serde::Serialize>(value: &T) -> Result<Value, ServiceError> {
    serde_json::to_value(value).map_err(|error| ServiceError::Serialization(error.to_string()))
}

fn require_max(field: &'static str, found: usize, maximum: usize) -> Result<(), ServiceError> {
    if found == 0 {
        return Err(ServiceError::InvalidArguments(format!(
            "{field} must be greater than zero"
        )));
    }
    if found > maximum {
        return Err(ServiceError::LimitExceeded {
            field,
            maximum,
            found,
        });
    }
    Ok(())
}

fn traversal(arguments: &Value) -> Result<(DecisionId, TraversalLimits), ServiceError> {
    let input: TraversalInput = parse(arguments)?;
    require_max("max_depth", input.max_depth, MAX_TRAVERSAL_DEPTH)?;
    require_max(
        "max_results",
        input.max_results,
        MAX_TRAVERSAL_RESULTS,
    )?;
    Ok((
        input.decision,
        TraversalLimits {
            max_depth: input.max_depth,
            max_results: input.max_results,
        },
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordInput {
    id: DecisionId,
    question: String,
    selected: String,
    rationale: String,
    #[serde(default)]
    facts: BTreeSet<FactId>,
    #[serde(default)]
    relations: BTreeSet<RelationId>,
    #[serde(default)]
    evidence: BTreeSet<EvidenceId>,
    #[serde(default)]
    rules: BTreeSet<RuleId>,
    #[serde(default)]
    precedents: BTreeSet<DecisionId>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordOutcomeInput {
    decision: DecisionId,
    status: OutcomeStatus,
    summary: String,
    #[serde(default)]
    evidence: BTreeSet<EvidenceId>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionInput {
    decision: DecisionId,
}

fn default_search_limit() -> usize {
    16
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SimilarInput {
    question: String,
    #[serde(default)]
    facts: BTreeSet<FactId>,
    #[serde(default)]
    relations: BTreeSet<RelationId>,
    #[serde(default)]
    rules: BTreeSet<RuleId>,
    #[serde(default)]
    exclude: Option<DecisionId>,
    #[serde(default = "default_search_limit")]
    limit: usize,
}

fn default_max_depth() -> usize {
    TraversalLimits::default().max_depth
}

fn default_max_results() -> usize {
    TraversalLimits::default().max_results
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TraversalInput {
    decision: DecisionId,
    #[serde(default = "default_max_depth")]
    max_depth: usize,
    #[serde(default = "default_max_results")]
    max_results: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    use ccos_enterprise_auth::AuthStrength;
    use ccos_enterprise_knowledge::KnowledgeOp;
    use ccos_enterprise_knowledge_model::{
        AssertionKind, EntityId, EntityRecord, EvidenceRecord, FactAssertion, FactObject, SourceId,
        SourceRecord, SourceTrust, ValidityInterval,
    };

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let ordinal = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "ccos-decision-service-{}-{ordinal}",
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

    fn actor(name: &str) -> AuthenticatedActor {
        AuthenticatedActor::asserted("memorithm", name, AuthStrength::Token)
    }

    fn evidence() -> BTreeSet<EvidenceId> {
        BTreeSet::from([EvidenceId::from("evidence:policy")])
    }

    fn seed(service: &mut DecisionService, tenant_name: &str) {
        let tenant = TenantId(tenant_name.to_string());
        service
            .append_knowledge(&[
                JournalEntry::new(
                    0,
                    KnowledgeOp::RegisterSource(SourceRecord {
                        id: SourceId::from("source:policy"),
                        tenant: tenant.clone(),
                        locator: format!("file:///{tenant_name}/policy.json"),
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
                        label: Some("deployment".into()),
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

    fn record_args(id: &str) -> Value {
        json!({
            "id": id,
            "question": "Should this deployment proceed?",
            "selected": "approve",
            "rationale": "Authoritative eligibility supports approval.",
            "facts": ["fact:eligible"],
            "evidence": ["evidence:policy"],
            "rules": ["rule:approval"]
        })
    }

    #[test]
    fn catalogue_is_exact_and_permissions_are_closed() {
        assert_eq!(
            tool_names(),
            vec![
                ANCESTRY,
                DEPENDENTS,
                GET,
                IMPACT,
                REGULATORY_TRAIL,
                SIMILAR,
                RECORD,
                RECORD_OUTCOME,
            ]
        );
        let permissions: BTreeSet<&str> = DECISION_TOOLS
            .iter()
            .map(|tool| tool.permission)
            .collect();
        assert_eq!(permissions, BTreeSet::from([DECISION_READ, DECISION_WRITE]));
        assert_eq!(tool_spec("decision.future"), None);
    }

    #[test]
    fn record_uses_server_owned_tenant_actor_sequence_and_anchor() {
        let dir = TestDir::new();
        let mut service = DecisionService::open(&dir.0).unwrap();
        seed(&mut service, "acme");
        let alice = actor("alice");

        let response = service
            .dispatch("acme", &alice, RECORD, &record_args("decision:approve"))
            .unwrap();
        assert_eq!(response["tenant"], json!("acme"));
        assert_eq!(response["actor"], json!("alice"));
        assert_eq!(response["decided_at"], json!(0));
        assert_eq!(
            response["knowledge"]["sequence"],
            json!(service.knowledge_state().next_sequence() - 1)
        );
        assert_eq!(service.decision_state().next_sequence(), 1);
    }

    #[test]
    fn client_authority_fields_are_rejected_not_ignored() {
        let dir = TestDir::new();
        let mut service = DecisionService::open(&dir.0).unwrap();
        seed(&mut service, "acme");
        let alice = actor("alice");
        for field in ["tenant", "actor", "sequence", "knowledge"] {
            let mut args = record_args("decision:smuggle");
            args.as_object_mut()
                .unwrap()
                .insert(field.to_string(), json!("attacker"));
            let error = service.dispatch("acme", &alice, RECORD, &args).unwrap_err();
            assert!(matches!(error, ServiceError::InvalidArguments(_)), "{field}: {error}");
            assert_eq!(service.decision_state().next_sequence(), 0);
        }
    }

    #[test]
    fn read_tools_are_tenant_scoped_and_outcomes_are_append_only() {
        let dir = TestDir::new();
        let mut service = DecisionService::open(&dir.0).unwrap();
        seed(&mut service, "acme");
        let alice = actor("alice");
        service
            .dispatch("acme", &alice, RECORD, &record_args("decision:approve"))
            .unwrap();
        service
            .dispatch(
                "acme",
                &alice,
                RECORD_OUTCOME,
                &json!({
                    "decision": "decision:approve",
                    "status": "Succeeded",
                    "summary": "Deployment completed under policy.",
                    "evidence": ["evidence:policy"]
                }),
            )
            .unwrap();
        let record = service
            .dispatch(
                "acme",
                &alice,
                GET,
                &json!({"decision": "decision:approve"}),
            )
            .unwrap();
        assert_eq!(record["outcome"]["status"], json!("Succeeded"));

        let foreign = service.dispatch(
            "globex",
            &alice,
            GET,
            &json!({"decision": "decision:approve"}),
        );
        assert!(matches!(
            foreign,
            Err(ServiceError::Decision(DecisionError::UnknownTenant))
        ));

        let second_outcome = service.dispatch(
            "acme",
            &alice,
            RECORD_OUTCOME,
            &json!({
                "decision": "decision:approve",
                "status": "Failed",
                "summary": "Cannot overwrite history.",
                "evidence": ["evidence:policy"]
            }),
        );
        assert!(matches!(
            second_outcome,
            Err(ServiceError::DecisionStore(DecisionStoreError::Decision(
                DecisionError::OutcomeAlreadyRecorded(_)
            )))
        ));
    }

    #[test]
    fn server_caps_search_and_graph_traversal() {
        let dir = TestDir::new();
        let mut service = DecisionService::open(&dir.0).unwrap();
        seed(&mut service, "acme");
        let alice = actor("alice");
        service
            .dispatch("acme", &alice, RECORD, &record_args("decision:approve"))
            .unwrap();

        assert!(matches!(
            service.dispatch(
                "acme",
                &alice,
                SIMILAR,
                &json!({"question":"approve", "limit": MAX_SEARCH_RESULTS + 1}),
            ),
            Err(ServiceError::LimitExceeded { field: "limit", .. })
        ));
        assert!(matches!(
            service.dispatch(
                "acme",
                &alice,
                ANCESTRY,
                &json!({
                    "decision":"decision:approve",
                    "max_depth": MAX_TRAVERSAL_DEPTH + 1
                }),
            ),
            Err(ServiceError::LimitExceeded {
                field: "max_depth",
                ..
            })
        ));
    }
}
