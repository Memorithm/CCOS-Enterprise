//! Authenticated stdio MCP transport for the CCOS Enterprise front door.
//!
//! One process is bound to one signed principal and one tenant. Host-supplied
//! `_meta.ccos` values are correlation claims and must match that proof.
//!
//! Three durable layers intentionally cooperate:
//! - the tenant Core workspace;
//! - the Enterprise governance ledger (budget/replay/audit);
//! - an execution journal recording ToolRequested -> ToolStarted -> ToolFinished.
//!
//! `request_id` is stable idempotency identity. `execution_attempt_id` is a
//! fresh physical-attempt identity supplied by the DSH adapter for every MCP
//! request, so a known failed attempt and its retry remain two valid execution
//! lifecycles without weakening replay suppression.

#[path = "../execution.rs"]
mod execution;
#[path = "../execution_backend.rs"]
mod execution_backend;

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ccos_core::agent_session::AgentSession;
use ccos_enterprise_auth::{AuthStrength, Authenticator, TokenAuthenticator};
use ccos_enterprise_gateway::GatewayRequest;
use ccos_enterprise_mcp::{
    govern_catalogue, permission_for, to_enterprise, Backend, GovernedMcp, McpOutcome,
};
use ccos_enterprise_runtime::{
    is_canonical_identifier, AuditRecord, Call, Deployment, DeploymentSnapshot, GovernanceRecord,
    Outcome, TenantState,
};
use ccos_enterprise_store::Store;
use ed25519_dalek::VerifyingKey;
#[cfg(test)]
use execution::ToolRecoveryDisposition;
use execution_backend::{
    failed_output_sha256, successful_output_sha256, DispatchExecution, ExecutionBackend,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const PROTOCOL_VERSION: &str = "2024-11-05";
const HOST_KIND: &str = "deepseek-harness";
const ROLE_NAME: &str = "dsh-memory";
const GOVERNANCE_DIR: &str = ".enterprise";
const EFFECT_FILE: &str = "effect.json";
const EXECUTION_DIR: &str = ".execution";
const CORRELATION_FILE: &str = "correlation.jsonl";
const MAX_HOST_META_BYTES: usize = 256;

#[derive(Debug, Clone)]
struct Config {
    audience: String,
    issuer_kid: String,
    issuer_public_key: [u8; 32],
    identity_token: String,
    tenant: String,
    model: String,
    token_budget: u64,
    call_cost_tokens: u64,
    state_dir: PathBuf,
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let tenant = required_env("CCOS_ENTERPRISE_TENANT")?;
        if !is_canonical_identifier(&tenant) {
            return Err("CCOS_ENTERPRISE_TENANT is not canonical".into());
        }
        let model = required_env("CCOS_ENTERPRISE_MODEL")?;
        if model.len() > 256 {
            return Err("CCOS_ENTERPRISE_MODEL is too long".into());
        }
        Ok(Self {
            audience: required_env("CCOS_ENTERPRISE_AUDIENCE")?,
            issuer_kid: required_env("CCOS_ENTERPRISE_ISSUER_KID")?,
            issuer_public_key: decode_hex_32(&required_env(
                "CCOS_ENTERPRISE_ISSUER_PUBLIC_KEY_HEX",
            )?)?,
            identity_token: required_env("CCOS_ENTERPRISE_IDENTITY_TOKEN")?,
            tenant,
            model,
            token_budget: positive_u64(
                "CCOS_ENTERPRISE_TOKEN_BUDGET",
                &required_env("CCOS_ENTERPRISE_TOKEN_BUDGET")?,
            )?,
            call_cost_tokens: std::env::var("CCOS_ENTERPRISE_CALL_COST_TOKENS")
                .ok()
                .map(|v| positive_u64("CCOS_ENTERPRISE_CALL_COST_TOKENS", &v))
                .transpose()?
                .unwrap_or(1),
            state_dir: PathBuf::from(required_env("CCOS_ENTERPRISE_STATE_DIR")?),
        })
    }
}

fn required_env(name: &str) -> Result<String, String> {
    let value =
        std::env::var(name).map_err(|_| format!("missing required environment variable {name}"))?;
    let value = value.trim();
    if value.is_empty() {
        Err(format!("required environment variable {name} is empty"))
    } else {
        Ok(value.to_string())
    }
}

fn positive_u64(name: &str, value: &str) -> Result<u64, String> {
    let value = value
        .parse::<u64>()
        .map_err(|_| format!("{name} must be a positive integer"))?;
    if value == 0 {
        Err(format!("{name} must be greater than zero"))
    } else {
        Ok(value)
    }
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(
            "CCOS_ENTERPRISE_ISSUER_PUBLIC_KEY_HEX must be 64 hexadecimal characters".into(),
        );
    }
    let mut out = [0; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| "invalid issuer public key hex".to_string())?;
    }
    Ok(out)
}

fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock is before the Unix epoch".into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EffectState {
    Started,
    Succeeded,
    Failed,
    Settled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EffectRecord {
    request_id: String,
    tenant: String,
    actor: String,
    tool: String,
    model: String,
    cost_tokens: u64,
    state: EffectState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    turn_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    step_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    execution_attempt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    output_sha256: Option<String>,
}

impl EffectRecord {
    fn from_request(request: &GatewayRequest, meta: &Meta, cost_tokens: u64) -> Self {
        Self {
            request_id: request.request_id.clone(),
            tenant: request.tenant.clone(),
            actor: request.actor.clone(),
            tool: request.tool.clone(),
            model: meta.model.clone(),
            cost_tokens,
            state: EffectState::Started,
            turn_id: Some(meta.turn_id.clone()),
            step_id: Some(meta.step_id.clone()),
            execution_attempt_id: Some(meta.execution_attempt_id.clone()),
            output_sha256: None,
        }
    }

    fn execution(&self) -> Result<DispatchExecution, String> {
        let turn = self.turn_id.as_deref().ok_or_else(|| {
            "effect marker predates execution correlation (missing turn_id)".to_string()
        })?;
        let step = self.step_id.as_deref().ok_or_else(|| {
            "effect marker predates execution correlation (missing step_id)".to_string()
        })?;
        let attempt = self.execution_attempt_id.as_deref().ok_or_else(|| {
            "effect marker predates execution correlation (missing execution_attempt_id)"
                .to_string()
        })?;
        Ok(DispatchExecution::new(turn, step, attempt))
    }
}

fn effect_path(root: &Path) -> PathBuf {
    root.join(GOVERNANCE_DIR).join(EFFECT_FILE)
}

fn execution_root(root: &Path) -> PathBuf {
    root.join(EXECUTION_DIR)
}

fn correlation_path(root: &Path, tenant: &str) -> PathBuf {
    execution_root(root).join(tenant).join(CORRELATION_FILE)
}

fn write_effect(path: &Path, record: &EffectRecord) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(record)
        .map_err(|error| format!("cannot serialize durable effect marker: {error}"))?;
    ccos_core::util::write_durable(path, &bytes)
        .map_err(|error| format!("cannot persist durable effect marker: {error}"))
}

fn read_effect(path: &Path) -> Result<Option<EffectRecord>, String> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| format!("durable effect marker is corrupt: {error}")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("cannot read durable effect marker: {error}")),
    }
}

#[derive(Clone)]
struct DeploymentCheckpoint {
    snapshot: DeploymentSnapshot,
    audit: Vec<AuditRecord>,
    governance: Vec<GovernanceRecord>,
}

impl DeploymentCheckpoint {
    fn capture(deployment: &Deployment) -> Self {
        Self {
            snapshot: deployment.snapshot(),
            audit: deployment.audit().cloned().collect(),
            governance: deployment.governance().cloned().collect(),
        }
    }

    fn restore(self) -> Result<Deployment, String> {
        Deployment::restore(self.snapshot, &self.audit, &self.governance)
            .map_err(|error| format!("cannot roll back failed backend admission: {error}"))
    }
}

fn persist_deployment(store: &mut Store, deployment: &Deployment) -> Result<(), String> {
    let snapshot = deployment.snapshot();
    if store.next_sequence() > snapshot.sequence_watermark {
        return Err(format!(
            "durable audit is ahead of runtime: store={}, runtime={}",
            store.next_sequence(),
            snapshot.sequence_watermark
        ));
    }

    let decisions: Vec<AuditRecord> = deployment
        .audit()
        .filter(|record| record.sequence >= store.next_sequence())
        .cloned()
        .collect();
    if !decisions.is_empty() {
        store
            .append(&decisions)
            .map_err(|error| format!("cannot persist Enterprise audit: {error}"))?;
    }
    if store.next_sequence() != snapshot.sequence_watermark {
        return Err(format!(
            "runtime audit window cannot fill durable gap: store={}, runtime={}",
            store.next_sequence(),
            snapshot.sequence_watermark
        ));
    }

    let governance: Vec<GovernanceRecord> = deployment
        .governance()
        .filter(|record| record.ordinal >= store.next_ordinal())
        .cloned()
        .collect();
    if !governance.is_empty() {
        store
            .append_governance(&governance)
            .map_err(|error| format!("cannot persist Enterprise governance journal: {error}"))?;
    }

    // Journal first, snapshot second. If the process dies between them,
    // Deployment::restore folds the durable journal tail over the older
    // snapshot. The inverse order could checkpoint a charge whose decision
    // never reached the journal.
    store
        .save_snapshot(&snapshot)
        .map_err(|error| format!("cannot persist Enterprise snapshot: {error}"))
}

struct TenantBackend {
    root: PathBuf,
    effect_path: PathBuf,
    sessions: BTreeMap<String, AgentSession>,
    armed: Option<EffectRecord>,
    outcome_uncertain: bool,
}

impl TenantBackend {
    fn new(root: PathBuf) -> Self {
        Self {
            effect_path: effect_path(&root),
            root,
            sessions: BTreeMap::new(),
            armed: None,
            outcome_uncertain: false,
        }
    }

    fn session(&mut self, tenant: &str) -> Result<&mut AgentSession, String> {
        if !is_canonical_identifier(tenant) {
            return Err("backend received non-canonical tenant id".into());
        }
        if !self.sessions.contains_key(tenant) {
            let dir = self.root.join(tenant);
            fs::create_dir_all(&dir)
                .map_err(|error| format!("cannot create tenant state directory: {error}"))?;
            let session = AgentSession::open(dir.join("workspace.ccos"))
                .map_err(|error| format!("cannot open tenant Core session: {error}"))?;
            self.sessions.insert(tenant.to_string(), session);
        }
        self.sessions
            .get_mut(tenant)
            .ok_or_else(|| "tenant session disappeared".into())
    }

    fn arm(&mut self, effect: EffectRecord) -> Result<(), String> {
        if self.armed.is_some() {
            return Err("backend already has an armed effect".into());
        }
        self.outcome_uncertain = false;
        self.armed = Some(effect);
        Ok(())
    }

    fn disarm(&mut self) {
        self.armed = None;
    }

    fn outcome_uncertain(&self) -> bool {
        self.outcome_uncertain
    }

    fn discard_session(&mut self, tenant: &str) {
        self.sessions.remove(tenant);
    }

    fn settle_marker(&mut self, request_id: &str) -> Result<(), String> {
        let Some(mut record) = read_effect(&self.effect_path)? else {
            return Err("durable effect marker disappeared before settlement".into());
        };
        if record.request_id != request_id {
            return Err("durable effect marker belongs to a different request".into());
        }
        record.state = EffectState::Settled;
        write_effect(&self.effect_path, &record)
    }
}

impl Backend for TenantBackend {
    fn dispatch(
        &mut self,
        tenant: &str,
        core_tool: &str,
        arguments: &Value,
    ) -> Result<Value, String> {
        let mut effect = self
            .armed
            .take()
            .ok_or_else(|| "governed backend dispatch had no armed request context".to_string())?;
        if effect.tenant != tenant {
            return Err("armed request tenant did not match governed dispatch".into());
        }
        effect.state = EffectState::Started;
        write_effect(&self.effect_path, &effect)?;

        let backend_result = (|| {
            let session = self.session(tenant)?;
            let request = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": core_tool, "arguments": arguments }
            });
            let response = ccos_core::mcp::handle(session, &request)
                .ok_or_else(|| "Core returned no tools/call response".to_string())?;
            if let Some(error) = response.get("error") {
                return Err(format!("Core tools/call failed: {error}"));
            }
            let result = response
                .get("result")
                .cloned()
                .ok_or_else(|| "Core tools/call response had no result".to_string())?;
            if result.get("isError").and_then(Value::as_bool) == Some(true) {
                return Err(format!("Core tool reported failure: {result}"));
            }
            if permission_for(core_tool) == Some("memory.write") {
                session
                    .checkpoint()
                    .map_err(|error| format!("tenant checkpoint failed: {error}"))?;
            }
            Ok(result)
        })();

        match backend_result {
            Ok(value) => {
                effect.state = EffectState::Succeeded;
                effect.output_sha256 = Some(
                    successful_output_sha256(&value)
                        .map_err(|error| format!("cannot hash successful Core result: {error}"))?,
                );
                if let Err(error) = write_effect(&self.effect_path, &effect) {
                    self.outcome_uncertain = true;
                    return Err(format!(
                        "Core succeeded but durable outcome marker failed: {error}"
                    ));
                }
                Ok(value)
            }
            Err(error) => {
                effect.state = EffectState::Failed;
                effect.output_sha256 = Some(failed_output_sha256(&error));
                if let Err(marker_error) = write_effect(&self.effect_path, &effect) {
                    return Err(format!(
                        "{error}; additionally could not persist failed outcome: {marker_error}"
                    ));
                }
                Err(error)
            }
        }
    }
}

#[derive(Debug, Clone)]
struct PendingExecution {
    tenant: String,
    execution: DispatchExecution,
}

struct JournaledBackend {
    execution: ExecutionBackend<TenantBackend>,
    pending: Option<PendingExecution>,
}

impl JournaledBackend {
    fn new(inner: TenantBackend, root: impl AsRef<Path>) -> Self {
        Self {
            execution: ExecutionBackend::new(inner, root),
            pending: None,
        }
    }

    fn arm(
        &mut self,
        tenant: &str,
        execution: DispatchExecution,
        effect: EffectRecord,
    ) -> Result<(), String> {
        if self.pending.is_some() {
            return Err("execution backend already has a pending request".into());
        }
        self.execution.inner_mut().arm(effect)?;
        self.pending = Some(PendingExecution {
            tenant: tenant.to_string(),
            execution,
        });
        Ok(())
    }

    fn clear(&mut self) {
        self.pending = None;
        self.execution.inner_mut().disarm();
    }

    fn inner(&self) -> &TenantBackend {
        self.execution.inner()
    }
    fn inner_mut(&mut self) -> &mut TenantBackend {
        self.execution.inner_mut()
    }

    fn reconcile_effect(&mut self, effect: &EffectRecord) -> Result<(), String> {
        let execution = effect.execution()?;
        let hash = effect.output_sha256.as_deref().ok_or_else(|| {
            "effect marker has no output_sha256 for execution reconciliation".to_string()
        })?;
        let success = effect.state == EffectState::Succeeded;
        self.execution
            .reconcile_finished(&effect.tenant, &execution.call_id, success, hash)
            .map_err(|error| error.to_string())
    }

    fn ensure_no_unknown_outcomes(&mut self, tenant: &str) -> Result<(), String> {
        self.execution
            .ensure_no_unknown_outcomes(tenant)
            .map_err(|error| error.to_string())
    }

    #[cfg(test)]
    fn recover_tools(&mut self, tenant: &str) -> Result<Vec<execution::ToolRecovery>, String> {
        self.execution
            .recover_tools(tenant)
            .map_err(|error| error.to_string())
    }
}

impl Backend for JournaledBackend {
    fn dispatch(
        &mut self,
        tenant: &str,
        core_tool: &str,
        arguments: &Value,
    ) -> Result<Value, String> {
        let pending = self
            .pending
            .take()
            .ok_or_else(|| "governed dispatch had no execution attempt context".to_string())?;
        if pending.tenant != tenant {
            return Err("execution attempt tenant did not match governed dispatch".into());
        }
        self.execution
            .dispatch_with_context(tenant, &pending.execution, core_tool, arguments)
            .map_err(|error| error.to_string())
    }
}

struct Meta {
    tenant: String,
    actor: String,
    agent_id: String,
    host: String,
    profile: String,
    host_session_id: String,
    request_id: String,
    trace_id: String,
    model: String,
    turn_id: String,
    step_id: String,
    tool_call_id: Option<String>,
    execution_attempt_id: String,
}

fn valid_host_meta_value(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_HOST_META_BYTES && !value.chars().any(char::is_control)
}

fn valid_trace_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn parse_meta(params: &Value) -> Result<Meta, ()> {
    let meta = params
        .get("_meta")
        .and_then(|v| v.get("ccos"))
        .and_then(Value::as_object)
        .ok_or(())?;
    let field = |name: &str| {
        let value = meta
            .get(name)
            .and_then(Value::as_str)
            .map(str::trim)
            .ok_or(())?;
        valid_host_meta_value(value)
            .then(|| value.to_string())
            .ok_or(())
    };
    let optional_field = |name: &str| match meta.get(name) {
        None => Ok(None),
        Some(Value::String(value)) => {
            let value = value.trim();
            valid_host_meta_value(value)
                .then(|| Some(value.to_string()))
                .ok_or(())
        }
        Some(_) => Err(()),
    };
    let trace_id = field("trace_id")?;
    if !valid_trace_id(&trace_id) {
        return Err(());
    }
    Ok(Meta {
        tenant: field("tenant_id")?,
        actor: field("actor_id")?,
        agent_id: field("agent_id")?,
        host: field("host")?,
        profile: field("dsh_profile")?,
        host_session_id: field("dsh_session_id")?,
        request_id: field("request_id")?,
        trace_id,
        model: field("model")?,
        turn_id: field("turn_id")?,
        step_id: field("step_id")?,
        tool_call_id: optional_field("tool_call_id")?,
        execution_attempt_id: field("execution_attempt_id")?,
    })
}

struct Server {
    config: Config,
    authenticator: TokenAuthenticator,
    org: String,
    actor: String,
    store: Store,
    correlation: execution::ExecutionJournal,
    front_door: GovernedMcp<JournaledBackend>,
    poisoned: Option<String>,
}

impl Server {
    fn provision(config: &Config, org: &str, actor: &str) -> Result<Deployment, String> {
        let mut deployment = Deployment::new();
        deployment.add_role(ROLE_NAME, &["memory.read", "memory.write"]);
        govern_catalogue(&mut deployment);
        let mut tenant = TenantState::new(config.token_budget);
        tenant.allow_model(&config.model);
        if !deployment.add_tenant(org, &config.tenant, tenant) {
            return Err("configured tenant could not be provisioned".into());
        }
        if !deployment.assign(actor, ROLE_NAME) {
            return Err("configured actor could not be assigned the DSH memory role".into());
        }
        Ok(deployment)
    }

    fn validate_restored_snapshot(
        config: &Config,
        org: &str,
        actor: &str,
        snapshot: &DeploymentSnapshot,
    ) -> Result<(), String> {
        if snapshot.tenants.len() != 1 {
            return Err("DSH stdio governance store must contain exactly one tenant".into());
        }
        let tenant = snapshot
            .tenants
            .get(&config.tenant)
            .ok_or_else(|| "governance store belongs to a different tenant".to_string())?;
        if tenant.owner != org {
            return Err("governance store tenant owner does not match signed identity".into());
        }
        if tenant.budget.limit != config.token_budget {
            return Err("configured token budget differs from durable tenant ledger".into());
        }
        if !tenant.models.0.contains(&config.model) {
            return Err("configured model is absent from durable tenant allowlist".into());
        }
        if !snapshot.roles.roles_of(actor).contains(&ROLE_NAME) {
            return Err("signed actor does not hold the durable DSH memory role".into());
        }
        Ok(())
    }

    fn settle_recovered_success(
        deployment: &mut Deployment,
        store: &mut Store,
        identity: &ccos_enterprise_auth::AuthenticatedActor,
        effect: &EffectRecord,
    ) -> Result<(), String> {
        let already_durable = deployment.audit().any(|record| {
            record.tenant == effect.tenant
                && record.request_id == effect.request_id
                && record.outcome.is_forwarded()
        });
        if already_durable {
            return Ok(());
        }
        let request = GatewayRequest {
            tenant: effect.tenant.clone(),
            actor: effect.actor.clone(),
            tool: effect.tool.clone(),
            request_id: effect.request_id.clone(),
        };
        match deployment.admit(Call {
            actor: identity,
            request: &request,
            model: &effect.model,
            cost_tokens: effect.cost_tokens,
            variant: None,
            justification: None,
        }) {
            Outcome::Forwarded | Outcome::Replayed => persist_deployment(store, deployment),
            Outcome::Refused(refusal) => Err(format!(
                "a Core effect succeeded before crash but its governance settlement is now refused: {refusal:?}"
            )),
        }
    }

    fn new(config: Config) -> Result<Self, String> {
        let key = VerifyingKey::from_bytes(&config.issuer_public_key)
            .map_err(|_| "issuer public key is not valid Ed25519".to_string())?;
        let mut authenticator = TokenAuthenticator::new(&config.audience, AuthStrength::Token);
        if !authenticator.add_issuer(&config.issuer_kid, key) {
            return Err("CCOS_ENTERPRISE_ISSUER_KID is not canonical".into());
        }
        let identity = authenticator
            .authenticate(&config.identity_token, now()?)
            .map_err(|error| format!("configured identity token was refused: {error}"))?;
        let org = identity.org().0.clone();
        let actor = identity.actor().0.clone();

        fs::create_dir_all(&config.state_dir)
            .map_err(|error| format!("cannot create Enterprise state directory: {error}"))?;
        let governance_root = config.state_dir.join(GOVERNANCE_DIR);
        let mut store = Store::open(&governance_root)
            .map_err(|error| format!("cannot open Enterprise governance store: {error}"))?;
        let loaded = store
            .load()
            .map_err(|error| format!("cannot load Enterprise governance store: {error}"))?;
        let deployment = match loaded {
            Some(loaded) => {
                if loaded.torn_tail != 0 {
                    return Err(format!(
                        "Enterprise governance journal has {} torn tail bytes; refusing automatic replay",
                        loaded.torn_tail
                    ));
                }
                Self::validate_restored_snapshot(&config, &org, &actor, &loaded.snapshot)?;
                Deployment::restore(loaded.snapshot, &loaded.journal, &loaded.governance).map_err(
                    |error| format!("cannot restore Enterprise governance state: {error}"),
                )?
            }
            None => {
                let deployment = Self::provision(&config, &org, &actor)?;
                store
                    .save_snapshot(&deployment.snapshot())
                    .map_err(|error| {
                        format!("cannot initialize Enterprise governance store: {error}")
                    })?;
                deployment
            }
        };

        let backend = JournaledBackend::new(
            TenantBackend::new(config.state_dir.clone()),
            execution_root(&config.state_dir),
        );
        let mut front_door = GovernedMcp::new(deployment, backend);

        let marker_path = effect_path(&config.state_dir);
        if let Some(mut effect) = read_effect(&marker_path)? {
            if effect.tenant != config.tenant
                || effect.actor != actor
                || effect.model != config.model
                || effect.cost_tokens != config.call_cost_tokens
            {
                return Err(
                    "durable effect marker does not match configured principal/tenant".into(),
                );
            }
            match effect.state {
                EffectState::Started => {
                    return Err(format!(
                        "request {:?} crossed the durable start boundary before the previous crash; outcome is unknown and automatic replay is unsafe",
                        effect.request_id
                    ));
                }
                EffectState::Succeeded => {
                    if effect.execution_attempt_id.is_some() {
                        front_door.backend_mut().reconcile_effect(&effect)?;
                    }
                    Self::settle_recovered_success(
                        front_door.deployment_mut(),
                        &mut store,
                        &identity,
                        &effect,
                    )?;
                    effect.state = EffectState::Settled;
                    write_effect(&marker_path, &effect)?;
                }
                EffectState::Failed => {
                    if effect.execution_attempt_id.is_some() {
                        front_door.backend_mut().reconcile_effect(&effect)?;
                    }
                    effect.state = EffectState::Settled;
                    write_effect(&marker_path, &effect)?;
                }
                EffectState::Settled => {}
            }
        }

        front_door
            .backend_mut()
            .ensure_no_unknown_outcomes(&config.tenant)?;

        let correlation = execution::ExecutionJournal::open(
            correlation_path(&config.state_dir, &config.tenant),
            format!("tenant/{}/host-correlation", config.tenant),
        )
        .map_err(|error| format!("cannot open Enterprise host-correlation journal: {error}"))?
        .journal;

        Ok(Self {
            config,
            authenticator,
            org,
            actor,
            store,
            correlation,
            front_door,
            poisoned: None,
        })
    }

    fn append_host_correlation(&mut self, tool: &str, meta: &Meta) -> Result<(), String> {
        self.correlation
            .append(execution::ExecutionEvent::HostCallCorrelated {
                call_id: meta.execution_attempt_id.clone(),
                request_id: meta.request_id.clone(),
                host: meta.host.clone(),
                host_session_id: meta.host_session_id.clone(),
                trace_id: meta.trace_id.clone(),
                agent_id: meta.agent_id.clone(),
                profile: meta.profile.clone(),
                turn_id: meta.turn_id.clone(),
                step_id: meta.step_id.clone(),
                tool_call_id: meta.tool_call_id.clone(),
                tool: tool.to_string(),
            })
            .map(|_| ())
            .map_err(|error| format!("cannot persist Enterprise host correlation: {error}"))
    }

    fn handle(&mut self, message: &Value) -> Option<Value> {
        let id = message.get("id")?.clone();
        let method = message.get("method")?.as_str()?;
        let result = match method {
            "initialize" => Ok(json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "ccos-enterprise", "version": env!("CARGO_PKG_VERSION") }
            })),
            "ping" => Ok(json!({})),
            "tools/list" => enterprise_specs().map(|tools| json!({ "tools": tools })),
            "tools/call" => self.call_tool(message.get("params").unwrap_or(&Value::Null)),
            "ccos/execution/event" => execution_backend::handle_lifecycle_event(
                self,
                message.get("params").unwrap_or(&Value::Null),
            ),
            _ => Err((-32601, "method not found".to_string())),
        };
        Some(match result {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err((code, message)) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": code, "message": message }
            }),
        })
    }

    fn call_tool(&mut self, params: &Value) -> Result<Value, (i64, String)> {
        if let Some(reason) = &self.poisoned {
            eprintln!("ccos-enterprise-mcp: refusing call after durability failure: {reason}");
            return Err((-32000, "Enterprise durable state unavailable".to_string()));
        }
        let tool = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| (-32602, "invalid params".to_string()))?;
        if !valid_host_meta_value(tool) {
            return Err((-32602, "invalid params".to_string()));
        }
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let meta = parse_meta(params).map_err(|_| (-32602, "invalid params".to_string()))?;
        let identity = self
            .authenticator
            .authenticate(
                &self.config.identity_token,
                now().map_err(|_| (-32000, "server time unavailable".to_string()))?,
            )
            .map_err(|error| {
                eprintln!("ccos-enterprise-mcp: identity refused: {error}");
                (-32001, error.client_message().to_string())
            })?;
        if identity.org().0.as_str() != self.org.as_str()
            || identity.actor().0.as_str() != self.actor.as_str()
            || meta.tenant != self.config.tenant
            || meta.actor != self.actor
            || meta.host != HOST_KIND
            || meta.model != self.config.model
        {
            eprintln!("ccos-enterprise-mcp: host claims did not match configured identity");
            return Err((-32001, "not authenticated".to_string()));
        }

        if let Err(error) = self.append_host_correlation(tool, &meta) {
            self.poisoned = Some(error.clone());
            eprintln!("ccos-enterprise-mcp: host correlation durability failed: {error}");
            return Err((
                -32000,
                "Enterprise host correlation is not durable".to_string(),
            ));
        }

        let request = GatewayRequest {
            tenant: meta.tenant.clone(),
            actor: meta.actor.clone(),
            tool: tool.to_string(),
            request_id: meta.request_id.clone(),
        };
        let checkpoint = DeploymentCheckpoint::capture(self.front_door.deployment());
        let execution = DispatchExecution::new(
            meta.turn_id.clone(),
            meta.step_id.clone(),
            meta.execution_attempt_id.clone(),
        );
        let effect = EffectRecord::from_request(&request, &meta, self.config.call_cost_tokens);
        self.front_door
            .backend_mut()
            .arm(&request.tenant, execution, effect)
            .map_err(|error| (-32000, error))?;

        let outcome = self.front_door.call(
            Call {
                actor: &identity,
                request: &request,
                model: &meta.model,
                cost_tokens: self.config.call_cost_tokens,
                variant: None,
                justification: None,
            },
            &arguments,
        );
        self.front_door.backend_mut().clear();

        if matches!(outcome, McpOutcome::BackendError(_)) {
            let marker = read_effect(&effect_path(&self.config.state_dir)).map_err(|error| {
                self.poisoned = Some(error.clone());
                (-32000, "Enterprise effect state unavailable".to_string())
            })?;
            let marker_for_request = marker
                .as_ref()
                .filter(|record| record.request_id == request.request_id);
            let succeeded = marker_for_request
                .map(|record| record.state == EffectState::Succeeded)
                .unwrap_or(false);
            let started = marker_for_request
                .map(|record| record.state == EffectState::Started)
                .unwrap_or(false);
            if self.front_door.backend().inner().outcome_uncertain() || succeeded || started {
                let reason = "backend effect may have succeeded but its execution outcome is not fully durable";
                self.poisoned = Some(reason.to_string());
                eprintln!("ccos-enterprise-mcp: {reason}");
                return Err((
                    -32000,
                    "Enterprise effect outcome is not durable".to_string(),
                ));
            }

            self.front_door
                .backend_mut()
                .inner_mut()
                .discard_session(&request.tenant);
            let restored = checkpoint.restore().map_err(|error| {
                self.poisoned = Some(error.clone());
                (-32000, "Enterprise admission rollback failed".to_string())
            })?;
            *self.front_door.deployment_mut() = restored;
            if let Some(record) = marker_for_request {
                if record.state == EffectState::Failed {
                    if let Err(error) = self.front_door.backend_mut().reconcile_effect(record) {
                        self.poisoned = Some(error.clone());
                        return Err((
                            -32000,
                            "Enterprise failed execution could not be reconciled".to_string(),
                        ));
                    }
                    if let Err(error) = self
                        .front_door
                        .backend_mut()
                        .inner_mut()
                        .settle_marker(&request.request_id)
                    {
                        self.poisoned = Some(error.clone());
                        return Err((
                            -32000,
                            "Enterprise failed effect could not be settled".to_string(),
                        ));
                    }
                }
            }
            return match outcome {
                McpOutcome::BackendError(error) => {
                    eprintln!("ccos-enterprise-mcp: admitted backend call failed: {error}");
                    Ok(tool_error("CCOS Enterprise backend failed"))
                }
                _ => unreachable!("matched BackendError above"),
            };
        }

        if matches!(outcome, McpOutcome::UnknownTool) {
            let restored = checkpoint.restore().map_err(|error| {
                self.poisoned = Some(error.clone());
                (-32000, "Enterprise catalogue rollback failed".to_string())
            })?;
            *self.front_door.deployment_mut() = restored;
            return Ok(tool_error("unknown CCOS Enterprise tool"));
        }

        if let Err(error) = persist_deployment(&mut self.store, self.front_door.deployment()) {
            self.poisoned = Some(error.clone());
            eprintln!("ccos-enterprise-mcp: durable governance commit failed: {error}");
            return Err((
                -32000,
                "Enterprise governance state is not durable".to_string(),
            ));
        }

        match outcome {
            McpOutcome::Ok(value) => {
                if let Err(error) = self
                    .front_door
                    .backend_mut()
                    .inner_mut()
                    .settle_marker(&request.request_id)
                {
                    self.poisoned = Some(error.clone());
                    eprintln!("ccos-enterprise-mcp: effect settlement marker failed: {error}");
                    return Err((
                        -32000,
                        "Enterprise effect settlement is not durable".to_string(),
                    ));
                }
                Ok(value)
            }
            McpOutcome::Replayed => Ok(json!({
                "content": [{ "type": "text", "text": "CCOS Enterprise replay suppressed" }],
                "structuredContent": { "replayed": true }
            })),
            McpOutcome::Refused(refusal) => {
                eprintln!("ccos-enterprise-mcp: governed request refused: {refusal:?}");
                Ok(tool_error("CCOS Enterprise request refused"))
            }
            McpOutcome::UnknownTool => unreachable!("unknown tools returned before persistence"),
            McpOutcome::BackendError(_) => unreachable!("backend errors returned above"),
        }
    }
}

fn tool_error(message: &str) -> Value {
    json!({
        "content": [{ "type": "text", "text": message }],
        "isError": true
    })
}

fn enterprise_specs() -> Result<Vec<Value>, (i64, String)> {
    let mut session = AgentSession::new();
    let response = ccos_core::mcp::handle(
        &mut session,
        &json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": null }),
    )
    .ok_or_else(|| (-32000, "Core returned no tools/list response".to_string()))?;
    let tools = response
        .get("result")
        .and_then(|v| v.get("tools"))
        .and_then(Value::as_array)
        .ok_or_else(|| (-32000, "Core returned invalid tools/list".to_string()))?;
    let mut governed = Vec::new();
    for tool in tools {
        let Some(core_name) = tool.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(name) = to_enterprise(core_name) else {
            continue;
        };
        let mut translated = tool.clone();
        translated["name"] = Value::String(name.to_string());
        governed.push(translated);
    }
    governed.sort_by(|left, right| {
        left.get("name")
            .and_then(Value::as_str)
            .cmp(&right.get("name").and_then(Value::as_str))
    });
    Ok(governed)
}

fn serve(config: Config) -> Result<(), String> {
    let mut server = Server::new(config)?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    for line in stdin.lock().lines() {
        let line = line.map_err(|error| format!("stdin read failed: {error}"))?;
        let message: Value = match serde_json::from_str(line.trim()) {
            Ok(value) => value,
            Err(_) => {
                write_response(
                    &stdout,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": Value::Null,
                        "error": { "code": -32700, "message": "parse error" }
                    }),
                )?;
                continue;
            }
        };
        if let Some(response) = server.handle(&message) {
            write_response(&stdout, &response)?;
        }
    }
    Ok(())
}

fn write_response(stdout: &io::Stdout, response: &Value) -> Result<(), String> {
    let mut out = stdout.lock();
    writeln!(out, "{response}").map_err(|error| format!("stdout write failed: {error}"))?;
    out.flush()
        .map_err(|error| format!("stdout flush failed: {error}"))
}

fn main() {
    if let Err(error) = Config::from_env().and_then(serve) {
        eprintln!("ccos-enterprise-mcp-server: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ccos_enterprise_auth::{issue_identity_token, IdentityClaims, IDENTITY_TOKEN_VERSION};
    use ed25519_dalek::SigningKey;

    fn test_config(label: &str) -> Config {
        let seed = [7u8; 32];
        let signing = SigningKey::from_bytes(&seed);
        let now = now().unwrap();
        let claims = IdentityClaims {
            version: IDENTITY_TOKEN_VERSION,
            jti: format!("dsh-{label}"),
            org: "memorithm".into(),
            actor: "alice".into(),
            audience: "ccos-test".into(),
            issued_at: now,
            expires_at: now + 600,
            not_before: None,
        };
        Config {
            audience: "ccos-test".into(),
            issuer_kid: "test-key".into(),
            issuer_public_key: signing.verifying_key().to_bytes(),
            identity_token: issue_identity_token(&seed, "test-key", &claims).unwrap(),
            tenant: "acme".into(),
            model: "deepseek-harness".into(),
            token_budget: 1000,
            call_cost_tokens: 1,
            state_dir: std::env::temp_dir().join(format!(
                "ccos-enterprise-mcp-{label}-{}",
                std::process::id()
            )),
        }
    }

    fn call(id: u64, actor: &str, request_id: &str, tool: &str, arguments: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": arguments,
                "_meta": { "ccos": {
                    "tenant_id": "acme",
                    "actor_id": actor,
                    "agent_id": "deepseek-harness-agent",
                    "host": HOST_KIND,
                    "dsh_profile": "test",
                    "dsh_session_id": "test-session",
                    "request_id": request_id,
                    "trace_id": "0123456789abcdef0123456789abcdef",
                    "model": "deepseek-harness",
                    "turn_id": format!("turn-{id}"),
                    "step_id": "step-1",
                    "execution_attempt_id": format!("attempt-{id}")
                }}
            }
        })
    }

    fn lifecycle(id: u64, actor: &str, event: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "ccos/execution/event",
            "params": {
                "event": event,
                "_meta": { "ccos": {
                    "tenant_id": "acme",
                    "actor_id": actor,
                    "host": HOST_KIND,
                    "model": "deepseek-harness"
                }}
            }
        })
    }

    fn cleanup(root: &Path) {
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn catalogue_uses_governed_names_and_core_schemas() {
        let tools = enterprise_specs().unwrap();
        assert!(tools.iter().any(|tool| tool["name"] == "memory.recall"));
        assert!(tools.iter().any(|tool| tool["name"] == "memory.ingest"));
        assert!(tools
            .iter()
            .all(|tool| tool["name"].as_str().unwrap().contains('.')));
        assert!(!tools.iter().any(|tool| tool["name"] == "octa_feedback"));
    }

    #[test]
    fn lifecycle_rpc_is_authenticated_idempotent_and_not_a_tool() {
        let config = test_config("lifecycle-rpc");
        let root = config.state_dir.clone();
        cleanup(&root);
        let mut server = Server::new(config).unwrap();
        let event = json!({
            "type": "turn_started",
            "turn_id": "dsh-session-1:turn:1"
        });
        let first = server
            .handle(&lifecycle(90, "alice", event.clone()))
            .unwrap();
        assert_eq!(first["result"]["recorded"], true);
        assert_eq!(first["result"]["replayed"], false);
        let replay = server.handle(&lifecycle(91, "alice", event)).unwrap();
        assert_eq!(replay["result"]["recorded"], false);
        assert_eq!(replay["result"]["replayed"], true);
        let forged = server
            .handle(&lifecycle(
                92,
                "mallory",
                json!({
                    "type": "turn_finished",
                    "turn_id": "dsh-session-1:turn:1",
                    "success": true
                }),
            ))
            .unwrap();
        assert_eq!(forged["error"]["code"], -32001);
        let tools = enterprise_specs().unwrap();
        assert!(!tools
            .iter()
            .any(|tool| tool["name"] == "ccos/execution/event"));
        let path = execution_root(&root).join("acme").join("execution.jsonl");
        let reopened = execution::ExecutionJournal::open(&path, "tenant/acme/mcp")
            .unwrap()
            .journal;
        assert_eq!(reopened.len(), 1);
        assert!(matches!(
            &reopened.records()[0].event,
            execution::ExecutionEvent::TurnStarted { turn_id }
                if turn_id == "dsh-session-1:turn:1"
        ));
        drop(server);
        cleanup(&root);
    }

    #[test]
    fn actor_claim_cannot_override_the_verified_token() {
        let config = test_config("forged-actor");
        let root = config.state_dir.clone();
        cleanup(&root);
        let mut server = Server::new(config).unwrap();
        let response = server
            .handle(&call(1, "mallory", "r-1", "memory.recall", json!({})))
            .unwrap();
        assert_eq!(response["error"]["code"], -32001);
        assert!(server.correlation.records().is_empty());
        drop(server);
        cleanup(&root);
    }

    #[test]
    fn replay_does_not_create_a_second_execution_attempt() {
        let config = test_config("replay-execution");
        let root = config.state_dir.clone();
        cleanup(&root);
        let mut server = Server::new(config).unwrap();
        let first = server
            .handle(&call(
                1,
                "alice",
                "same-request",
                "memory.ingest",
                json!({
                    "uri": "dsh/test.md", "source": "alpha"
                }),
            ))
            .unwrap();
        assert!(first.get("result").is_some(), "{first}");
        let replay = server
            .handle(&call(
                2,
                "alice",
                "same-request",
                "memory.ingest",
                json!({
                    "uri": "dsh/test.md", "source": "different"
                }),
            ))
            .unwrap();
        assert_eq!(replay["result"]["structuredContent"]["replayed"], true);
        let recovered = server
            .front_door
            .backend_mut()
            .recover_tools("acme")
            .unwrap();
        assert_eq!(
            recovered.len(),
            1,
            "governance replay must never enter the backend journal"
        );
        assert_eq!(recovered[0].call_id, "attempt-1");
        assert!(matches!(
            recovered[0].disposition,
            ToolRecoveryDisposition::Completed { success: true, .. }
        ));
        assert_eq!(server.correlation.records().len(), 2);
        let first_correlation =
            serde_json::to_value(&server.correlation.records()[0].event).unwrap();
        let replay_correlation =
            serde_json::to_value(&server.correlation.records()[1].event).unwrap();
        assert_eq!(first_correlation["type"], "host_call_correlated");
        assert_eq!(first_correlation["request_id"], "same-request");
        assert_eq!(replay_correlation["request_id"], "same-request");
        assert_eq!(first_correlation["call_id"], "attempt-1");
        assert_eq!(replay_correlation["call_id"], "attempt-2");
        assert_eq!(first_correlation["host_session_id"], "test-session");
        assert_eq!(first_correlation["agent_id"], "deepseek-harness-agent");
        assert_eq!(first_correlation["profile"], "test");
        drop(server);
        cleanup(&root);
    }

    #[test]
    fn failed_attempt_and_retry_share_request_id_but_not_execution_call_id() {
        let config = test_config("retry-execution");
        let root = config.state_dir.clone();
        cleanup(&root);
        let mut server = Server::new(config).unwrap();
        let failed = server
            .handle(&call(1, "alice", "retry-me", "memory.ingest", json!({})))
            .unwrap();
        assert_eq!(failed["result"]["isError"], true);
        assert_eq!(server.front_door.deployment().spent("acme"), Some(0));
        let retry = server
            .handle(&call(
                2,
                "alice",
                "retry-me",
                "memory.ingest",
                json!({
                    "uri": "dsh/retry.md", "source": "second attempt succeeds"
                }),
            ))
            .unwrap();
        assert!(retry.get("result").is_some(), "{retry}");
        assert_eq!(server.front_door.deployment().spent("acme"), Some(1));
        let recovered = server
            .front_door
            .backend_mut()
            .recover_tools("acme")
            .unwrap();
        assert_eq!(recovered.len(), 2);
        assert_eq!(recovered[0].call_id, "attempt-1");
        assert_eq!(recovered[1].call_id, "attempt-2");
        assert!(matches!(
            recovered[0].disposition,
            ToolRecoveryDisposition::Completed { success: false, .. }
        ));
        assert!(matches!(
            recovered[1].disposition,
            ToolRecoveryDisposition::Completed { success: true, .. }
        ));
        drop(server);
        cleanup(&root);
    }

    #[test]
    fn budget_replay_and_execution_journal_survive_restart() {
        let config = test_config("restart-journal");
        let root = config.state_dir.clone();
        cleanup(&root);
        {
            let mut server = Server::new(config.clone()).unwrap();
            server
                .handle(&call(
                    1,
                    "alice",
                    "restart-request",
                    "memory.ingest",
                    json!({
                        "uri": "dsh/restart.md", "source": "durable"
                    }),
                ))
                .unwrap();
        }
        {
            let mut restarted = Server::new(config).unwrap();
            assert_eq!(restarted.front_door.deployment().spent("acme"), Some(1));
            let recovered = restarted
                .front_door
                .backend_mut()
                .recover_tools("acme")
                .unwrap();
            assert_eq!(recovered.len(), 1);
            assert!(matches!(
                recovered[0].disposition,
                ToolRecoveryDisposition::Completed { success: true, .. }
            ));
            let replay = restarted
                .handle(&call(
                    2,
                    "alice",
                    "restart-request",
                    "memory.ingest",
                    json!({
                        "uri": "dsh/restart.md", "source": "must-not-run"
                    }),
                ))
                .unwrap();
            assert_eq!(replay["result"]["structuredContent"]["replayed"], true);
        }
        cleanup(&root);
    }

    #[test]
    fn succeeded_marker_reconciles_outcome_unknown_without_rerunning_core() {
        let config = test_config("recover-execution-success");
        let root = config.state_dir.clone();
        cleanup(&root);
        {
            let server = Server::new(config.clone()).unwrap();
            drop(server);
            let path = execution_root(&root).join("acme").join("execution.jsonl");
            let mut journal = execution::ExecutionJournal::open(&path, "tenant/acme/mcp")
                .unwrap()
                .journal;
            journal
                .append(execution::ExecutionEvent::ToolRequested {
                    turn_id: "turn-r".into(),
                    step_id: "step-r".into(),
                    call_id: "attempt-r".into(),
                    tool: "ingest".into(),
                    input_sha256: "input".into(),
                })
                .unwrap();
            journal
                .append(execution::ExecutionEvent::ToolStarted {
                    call_id: "attempt-r".into(),
                })
                .unwrap();
            let effect = EffectRecord {
                request_id: "recovered-success".into(),
                tenant: "acme".into(),
                actor: "alice".into(),
                tool: "memory.ingest".into(),
                model: "deepseek-harness".into(),
                cost_tokens: 1,
                state: EffectState::Succeeded,
                turn_id: Some("turn-r".into()),
                step_id: Some("step-r".into()),
                execution_attempt_id: Some("attempt-r".into()),
                output_sha256: Some("known-output".into()),
            };
            write_effect(&effect_path(&root), &effect).unwrap();
        }
        {
            let mut restarted = Server::new(config).unwrap();
            assert_eq!(restarted.front_door.deployment().spent("acme"), Some(1));
            let recovered = restarted
                .front_door
                .backend_mut()
                .recover_tools("acme")
                .unwrap();
            assert!(matches!(
                &recovered[0].disposition,
                ToolRecoveryDisposition::Completed { success: true, output_sha256 }
                    if output_sha256 == "known-output"
            ));
            assert_eq!(
                read_effect(&effect_path(&root)).unwrap().unwrap().state,
                EffectState::Settled
            );
        }
        cleanup(&root);
    }

    #[test]
    fn unexplained_outcome_unknown_fails_closed() {
        let config = test_config("unknown-journal");
        let root = config.state_dir.clone();
        cleanup(&root);
        {
            let server = Server::new(config.clone()).unwrap();
            drop(server);
            let path = execution_root(&root).join("acme").join("execution.jsonl");
            let mut journal = execution::ExecutionJournal::open(&path, "tenant/acme/mcp")
                .unwrap()
                .journal;
            journal
                .append(execution::ExecutionEvent::ToolRequested {
                    turn_id: "turn-u".into(),
                    step_id: "step-u".into(),
                    call_id: "attempt-u".into(),
                    tool: "recall".into(),
                    input_sha256: "input".into(),
                })
                .unwrap();
            journal
                .append(execution::ExecutionEvent::ToolStarted {
                    call_id: "attempt-u".into(),
                })
                .unwrap();
        }
        let error = Server::new(config)
            .err()
            .expect("unexplained unknown must fail closed");
        assert!(error.contains("unresolved outcome-unknown"), "{error}");
        cleanup(&root);
    }

    #[test]
    fn legacy_settled_effect_marker_remains_readable() {
        let json = r#"{
            "request_id":"old","tenant":"acme","actor":"alice",
            "tool":"memory.ingest","model":"deepseek-harness",
            "cost_tokens":1,"state":"settled"
        }"#;
        let record: EffectRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.state, EffectState::Settled);
        assert!(record.execution_attempt_id.is_none());
    }

    #[test]
    fn issuer_key_hex_is_exact_and_bounded() {
        assert_eq!(decode_hex_32(&"00".repeat(32)).unwrap(), [0; 32]);
        assert!(decode_hex_32("00").is_err());
        assert!(decode_hex_32(&"zz".repeat(32)).is_err());
    }
}
