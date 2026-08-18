//! Authenticated stdio MCP transport for the CCOS Enterprise front door.
//!
//! One process is bound to one signed principal and one tenant. Host-supplied
//! `_meta.ccos` values are correlation claims and must match that proof.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ccos_core::agent_session::AgentSession;
use ccos_enterprise_auth::{AuthStrength, Authenticator, TokenAuthenticator};
use ccos_enterprise_gateway::GatewayRequest;
use ccos_enterprise_mcp::{
    govern_catalogue, permission_for, to_enterprise, Backend, GovernedMcp, McpOutcome,
};
use ccos_enterprise_runtime::{is_canonical_identifier, Call, Deployment, TenantState};
use ed25519_dalek::VerifyingKey;
use serde_json::{json, Value};

const PROTOCOL_VERSION: &str = "2024-11-05";
const HOST_KIND: &str = "deepseek-harness";
const ROLE_NAME: &str = "dsh-memory";

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
    let value = std::env::var(name)
        .map_err(|_| format!("missing required environment variable {name}"))?;
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

struct TenantBackend {
    root: PathBuf,
    sessions: BTreeMap<String, AgentSession>,
}

impl TenantBackend {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            sessions: BTreeMap::new(),
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
}

impl Backend for TenantBackend {
    fn dispatch(
        &mut self,
        tenant: &str,
        core_tool: &str,
        arguments: &Value,
    ) -> Result<Value, String> {
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
        if permission_for(core_tool) == Some("memory.write") {
            session
                .checkpoint()
                .map_err(|error| format!("tenant checkpoint failed: {error}"))?;
        }
        Ok(result)
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
    front_door: GovernedMcp<TenantBackend>,
}

impl Server {
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

        let mut deployment = Deployment::new();
        deployment.add_role(ROLE_NAME, &["memory.read", "memory.write"]);
        govern_catalogue(&mut deployment);
        let mut tenant = TenantState::new(config.token_budget);
        tenant.allow_model(&config.model);
        if !deployment.add_tenant(&org, &config.tenant, tenant) {
            return Err("configured tenant could not be provisioned".into());
        }
        deployment.assign(&actor, ROLE_NAME);
        let backend = TenantBackend::new(config.state_dir.clone());
        Ok(Self {
            config,
            authenticator,
            org,
            actor,
            front_door: GovernedMcp::new(deployment, backend),
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
        let tool = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| (-32602, "invalid params".to_string()))?;
        let arguments = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
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
        match self.front_door.call(
            Call {
                actor: &identity,
                request: &request,
                model: &meta.model,
                cost_tokens: self.config.call_cost_tokens,
                variant: None,
                justification: None,
            },
            &arguments,
        ) {
            McpOutcome::Ok(value) => Ok(value),
            McpOutcome::Replayed => Ok(json!({
                "content": [{ "type": "text", "text": "CCOS Enterprise replay suppressed" }],
                "structuredContent": { "replayed": true }
            })),
            McpOutcome::BackendError(error) => {
                eprintln!("ccos-enterprise-mcp: admitted backend call failed: {error}");
                Ok(tool_error("CCOS Enterprise backend failed"))
            }
            McpOutcome::Refused(refusal) => {
                eprintln!("ccos-enterprise-mcp: governed request refused: {refusal:?}");
                Ok(tool_error("CCOS Enterprise request refused"))
            }
            McpOutcome::UnknownTool => Ok(tool_error("unknown CCOS Enterprise tool")),
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
        let mut server = Server::new(test_config("forged-actor")).unwrap();
        let response = server
            .handle(&call(1, "mallory", "r-1", "memory.recall", json!({})))
            .unwrap();
        assert_eq!(response["error"]["code"], -32001);
        assert_eq!(response["error"]["message"], "not authenticated");
    }

    #[test]
    fn admitted_write_is_checkpointed_and_replay_is_suppressed() {
        let config = test_config("persist");
        let root = config.state_dir.clone();
        let _ = fs::remove_dir_all(&root);
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
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn issuer_key_hex_is_exact_and_bounded() {
        assert_eq!(decode_hex_32(&"00".repeat(32)).unwrap(), [0; 32]);
        assert!(decode_hex_32("00").is_err());
        assert!(decode_hex_32(&"zz".repeat(32)).is_err());
    }
}
