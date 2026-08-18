//! Authenticated stdio MCP transport for the CCOS Enterprise front door.
//!
//! One process is bound to one signed principal and one tenant. Host-supplied
//! `_meta.ccos` values are correlation claims and must match that proof.
//!
//! The Core workspace and the Enterprise governance ledger are separate durable
//! files, so this server owns a tiny effect marker that closes the transaction
//! gap between them. The marker is synced before Core runs and records whether
//! the effect definitely succeeded or failed before the governance decision is
//! acknowledged. A crash with only `started` is deliberately fail-closed:
//! automatic replay would risk executing an effect twice.

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
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const PROTOCOL_VERSION: &str = "2024-11-05";
const HOST_KIND: &str = "deepseek-harness";
const ROLE_NAME: &str = "dsh-memory";
const GOVERNANCE_DIR: &str = ".enterprise";
const EFFECT_FILE: &str = "effect.json";

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
}

impl EffectRecord {
    fn from_request(request: &GatewayRequest, model: &str, cost_tokens: u64) -> Self {
        Self {
            request_id: request.request_id.clone(),
            tenant: request.tenant.clone(),
            actor: request.actor.clone(),
            tool: request.tool.clone(),
            model: model.to_string(),
            cost_tokens,
            state: EffectState::Started,
        }
    }
}

fn effect_path(root: &Path) -> PathBuf {
    root.join(GOVERNANCE_DIR).join(EFFECT_FILE)
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
                if let Err(error) = write_effect(&self.effect_path, &effect) {
                    // Core may already be durable. Never turn failure to record
                    // that fact into a retryable backend failure.
                    self.outcome_uncertain = true;
                    return Err(format!(
                        "Core succeeded but durable outcome marker failed: {error}"
                    ));
                }
                Ok(value)
            }
            Err(error) => {
                effect.state = EffectState::Failed;
                if let Err(marker_error) = write_effect(&self.effect_path, &effect) {
                    // The backend says it failed, so there is no successful
                    // effect to duplicate. Still surface the marker failure: a
                    // restart with `started` must conservatively block.
                    return Err(format!(
                        "{error}; additionally could not persist failed outcome: {marker_error}"
                    ));
                }
                Err(error)
            }
        }
    }
}

struct Meta {
    tenant: String,
    actor: String,
    host: String,
    request_id: String,
    model: String,
}

fn parse_meta(params: &Value) -> Result<Meta, ()> {
    let meta = params
        .get("_meta")
        .and_then(|v| v.get("ccos"))
        .and_then(Value::as_object)
        .ok_or(())?;
    let field = |name: &str| {
        meta.get(name)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .ok_or(())
    };
    Ok(Meta {
        tenant: field("tenant_id")?,
        actor: field("actor_id")?,
        host: field("host")?,
        request_id: field("request_id")?,
        model: field("model")?,
    })
}

struct Server {
    config: Config,
    authenticator: TokenAuthenticator,
    org: String,
    actor: String,
    store: Store,
    front_door: GovernedMcp<TenantBackend>,
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
        let mut deployment = match loaded {
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
                    Self::settle_recovered_success(
                        &mut deployment,
                        &mut store,
                        &identity,
                        &effect,
                    )?;
                    effect.state = EffectState::Settled;
                    write_effect(&marker_path, &effect)?;
                }
                EffectState::Failed => {
                    // The previous backend explicitly failed and no governance
                    // state was acknowledged. Replaying the same request id is
                    // safe after marking the failed attempt settled.
                    effect.state = EffectState::Settled;
                    write_effect(&marker_path, &effect)?;
                }
                EffectState::Settled => {}
            }
        }

        let backend = TenantBackend::new(config.state_dir.clone());
        Ok(Self {
            config,
            authenticator,
            org,
            actor,
            store,
            front_door: GovernedMcp::new(deployment, backend),
            poisoned: None,
        })
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

        let request = GatewayRequest {
            tenant: meta.tenant,
            actor: meta.actor,
            tool: tool.to_string(),
            request_id: meta.request_id,
        };
        let checkpoint = DeploymentCheckpoint::capture(self.front_door.deployment());
        let effect =
            EffectRecord::from_request(&request, &meta.model, self.config.call_cost_tokens);
        self.front_door
            .backend_mut()
            .arm(effect)
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
        self.front_door.backend_mut().disarm();

        if matches!(outcome, McpOutcome::BackendError(_)) {
            if self.front_door.backend().outcome_uncertain() {
                let reason = "backend may have succeeded but its durable outcome marker failed";
                self.poisoned = Some(reason.to_string());
                eprintln!("ccos-enterprise-mcp: {reason}");
                return Err((
                    -32000,
                    "Enterprise effect outcome is not durable".to_string(),
                ));
            }
            self.front_door
                .backend_mut()
                .discard_session(&request.tenant);
            let restored = checkpoint.restore().map_err(|error| {
                self.poisoned = Some(error.clone());
                (-32000, "Enterprise admission rollback failed".to_string())
            })?;
            *self.front_door.deployment_mut() = restored;
            if let Err(error) = self
                .front_door
                .backend_mut()
                .settle_marker(&request.request_id)
            {
                self.poisoned = Some(error.clone());
                return Err((
                    -32000,
                    "Enterprise failed effect could not be settled".to_string(),
                ));
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
                    "host": HOST_KIND,
                    "request_id": request_id,
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
    fn actor_claim_cannot_override_the_verified_token() {
        let config = test_config("forged-actor");
        let root = config.state_dir.clone();
        cleanup(&root);
        let mut server = Server::new(config).unwrap();
        let response = server
            .handle(&call(1, "mallory", "r-1", "memory.recall", json!({})))
            .unwrap();
        assert_eq!(response["error"]["code"], -32001);
        assert_eq!(response["error"]["message"], "not authenticated");
        drop(server);
        cleanup(&root);
    }

    #[test]
    fn admitted_write_is_checkpointed_and_replay_is_suppressed() {
        let config = test_config("persist");
        let root = config.state_dir.clone();
        cleanup(&root);
        let mut server = Server::new(config).unwrap();
        let first = call(
            1,
            "alice",
            "same-request",
            "memory.ingest",
            json!({ "uri": "dsh/test.md", "source": "alpha beta gamma" }),
        );
        let response = server.handle(&first).unwrap();
        assert!(response.get("result").is_some(), "{response}");
        assert!(root.join("acme").join("workspace.ccos").exists());
        assert_eq!(server.front_door.deployment().spent("acme"), Some(1));

        let replay = server
            .handle(&call(
                2,
                "alice",
                "same-request",
                "memory.ingest",
                json!({ "uri": "dsh/test.md", "source": "different" }),
            ))
            .unwrap();
        assert_eq!(
            replay["result"]["structuredContent"]["replayed"],
            Value::Bool(true)
        );
        assert_eq!(server.front_door.deployment().spent("acme"), Some(1));
        drop(server);
        cleanup(&root);
    }

    #[test]
    fn budget_and_replay_survive_server_restart() {
        let config = test_config("restart-ledger");
        let root = config.state_dir.clone();
        cleanup(&root);
        {
            let mut server = Server::new(config.clone()).unwrap();
            let response = server
                .handle(&call(
                    1,
                    "alice",
                    "restart-request",
                    "memory.ingest",
                    json!({ "uri": "dsh/restart.md", "source": "durable" }),
                ))
                .unwrap();
            assert!(response.get("result").is_some(), "{response}");
            assert_eq!(server.front_door.deployment().spent("acme"), Some(1));
        }
        {
            let mut restarted = Server::new(config).unwrap();
            assert_eq!(restarted.front_door.deployment().spent("acme"), Some(1));
            let replay = restarted
                .handle(&call(
                    2,
                    "alice",
                    "restart-request",
                    "memory.ingest",
                    json!({ "uri": "dsh/restart.md", "source": "must-not-run" }),
                ))
                .unwrap();
            assert_eq!(
                replay["result"]["structuredContent"]["replayed"],
                Value::Bool(true)
            );
            assert_eq!(restarted.front_door.deployment().spent("acme"), Some(1));
        }
        cleanup(&root);
    }

    #[test]
    fn explicit_backend_failure_rolls_back_admission_and_same_id_can_retry() {
        let config = test_config("retry-after-backend-failure");
        let root = config.state_dir.clone();
        cleanup(&root);
        let mut server = Server::new(config).unwrap();

        let failed = server
            .handle(&call(1, "alice", "retry-me", "memory.ingest", json!({})))
            .unwrap();
        assert_eq!(failed["result"]["isError"], Value::Bool(true));
        assert_eq!(
            server.front_door.deployment().spent("acme"),
            Some(0),
            "a backend effect that definitely failed must not consume budget"
        );

        let retry = server
            .handle(&call(
                2,
                "alice",
                "retry-me",
                "memory.ingest",
                json!({ "uri": "dsh/retry.md", "source": "second attempt succeeds" }),
            ))
            .unwrap();
        assert!(retry.get("result").is_some(), "{retry}");
        assert_ne!(
            retry["result"]["structuredContent"]["replayed"],
            Value::Bool(true),
            "the failed first attempt must not reserve the replay id"
        );
        assert_eq!(server.front_door.deployment().spent("acme"), Some(1));
        drop(server);
        cleanup(&root);
    }

    #[test]
    fn recovered_succeeded_marker_settles_governance_without_rerunning_core() {
        let config = test_config("recover-success");
        let root = config.state_dir.clone();
        cleanup(&root);
        {
            let server = Server::new(config.clone()).unwrap();
            let effect = EffectRecord {
                request_id: "recovered-success".into(),
                tenant: "acme".into(),
                actor: "alice".into(),
                tool: "memory.ingest".into(),
                model: "deepseek-harness".into(),
                cost_tokens: 1,
                state: EffectState::Succeeded,
            };
            write_effect(&effect_path(&root), &effect).unwrap();
            drop(server);
        }
        {
            let restarted = Server::new(config).unwrap();
            assert_eq!(restarted.front_door.deployment().spent("acme"), Some(1));
            let marker = read_effect(&effect_path(&root)).unwrap().unwrap();
            assert_eq!(marker.state, EffectState::Settled);
            assert!(restarted.front_door.deployment().audit().any(|record| {
                record.request_id == "recovered-success" && record.outcome.is_forwarded()
            }));
        }
        cleanup(&root);
    }

    #[test]
    fn unresolved_started_marker_fails_closed_on_restart() {
        let config = test_config("unknown-effect");
        let root = config.state_dir.clone();
        cleanup(&root);
        {
            let server = Server::new(config.clone()).unwrap();
            let effect = EffectRecord {
                request_id: "unknown-request".into(),
                tenant: "acme".into(),
                actor: "alice".into(),
                tool: "memory.ingest".into(),
                model: "deepseek-harness".into(),
                cost_tokens: 1,
                state: EffectState::Started,
            };
            write_effect(&effect_path(&root), &effect).unwrap();
            drop(server);
        }
        let error = Server::new(config).err().expect("restart must fail closed");
        assert!(error.contains("outcome is unknown"), "{error}");
        cleanup(&root);
    }

    #[test]
    fn issuer_key_hex_is_exact_and_bounded() {
        assert_eq!(decode_hex_32(&"00".repeat(32)).unwrap(), [0; 32]);
        assert!(decode_hex_32("00").is_err());
        assert!(decode_hex_32(&"zz".repeat(32)).is_err());
    }
}
