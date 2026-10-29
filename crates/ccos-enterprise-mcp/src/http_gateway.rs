//! Minimal authenticated HTTP transport for the governed read tools (feature `http-gateway`).
//!
//! This is a *transport*, not a second front door. Every HTTP request is translated into the
//! exact `tools/call` message the stdio transport accepts and handed to the same
//! [`Server::handle`], so identity binding, `Deployment::admit` (RBAC, tenant, quota, replay),
//! the execution journal, the durable effect witness and governance settlement are the stdio
//! code paths, unchanged.
//!
//! Scope (PR1, deliberately small):
//! * `POST /v1/memory/document_recall` -> `memory.document_recall`
//! * `POST /v1/memory/context`         -> `memory.context`
//! * anything else is `404`; a non-`POST` on a known route is `405`.
//!
//! Identity: `Authorization: Bearer <identity token>` is verified per request with the
//! process authenticator and must prove the same org/actor the process is bound to. The
//! process-bound token then drives the stdio call exactly as before.
//!
//! The client never chooses tenant, actor, host, model, space or policy: the server fills the
//! `_meta.ccos` envelope from its own configuration. An optional `tenant` assertion is accepted
//! only so a mismatched caller is refused loudly (`403`) instead of being silently rebound.
//! Ranking is whatever the operator configured at boot (`CCOS_ENTERPRISE_DOCUMENT_RANKING`,
//! lexical BM25 by default); the response echoes it as `ranking`.
//!
//! Single-threaded, `Connection: close`, bounded body, std-only: no framework is pulled in.
//! TLS termination and concurrency are explicitly out of scope (see docs/HTTP_GATEWAY.md).

use super::*;
use std::io::BufReader;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const ALLOWED_BODY_KEYS: &[&str] = &[
    "request_id",
    "turn_id",
    "step_id",
    "execution_attempt_id",
    "tenant",
    "arguments",
];

static ATTEMPT: AtomicU64 = AtomicU64::new(0);

struct HttpResponse {
    status: u16,
    body: Value,
}

impl HttpResponse {
    fn error(status: u16, code: &str, message: impl Into<String>) -> Self {
        Self {
            status,
            body: json!({ "ok": false, "error": { "code": code, "message": message.into() } }),
        }
    }
}

struct HttpRequest {
    method: String,
    path: String,
    authorization: Option<String>,
    body: Vec<u8>,
}

/// Bind `bind` (e.g. `127.0.0.1:0`) and serve until the listener fails.
pub(super) fn serve_http(config: Config, bind: &str) -> Result<(), String> {
    let mut server = Server::new(config)?;
    let listener =
        TcpListener::bind(bind).map_err(|error| format!("cannot bind http gateway: {error}"))?;
    let local = listener
        .local_addr()
        .map_err(|error| format!("cannot read http gateway address: {error}"))?;
    eprintln!("ccos-enterprise-mcp: http-gateway listening on {local}");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = handle_connection(&mut server, stream) {
                    eprintln!("ccos-enterprise-mcp: http-gateway connection error: {error}");
                }
            }
            Err(error) => eprintln!("ccos-enterprise-mcp: http-gateway accept error: {error}"),
        }
    }
    Ok(())
}

fn handle_connection(server: &mut Server, stream: TcpStream) -> Result<(), String> {
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|error| error.to_string())?;
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let response = match read_request(&mut reader) {
        Ok(request) => route(server, &request),
        Err(response) => response,
    };
    write_http(stream, &response)
}

fn read_request(reader: &mut impl BufRead) -> Result<HttpRequest, HttpResponse> {
    let bad = |message: &str| HttpResponse::error(400, "bad_request", message);
    let mut header_bytes = 0usize;
    let mut line = String::new();
    let mut next_line = |line: &mut String| -> Result<(), HttpResponse> {
        line.clear();
        let read = reader
            .take((MAX_HEADER_BYTES - header_bytes.min(MAX_HEADER_BYTES)) as u64)
            .read_line(line)
            .map_err(|_| bad("unreadable request"))?;
        header_bytes += read;
        if read == 0 || header_bytes >= MAX_HEADER_BYTES || !line.ends_with('\n') {
            return Err(bad("truncated or oversized request head"));
        }
        Ok(())
    };
    next_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| bad("empty request line"))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| bad("missing request target"))?
        .to_string();
    let mut authorization = None;
    let mut content_length = None;
    loop {
        next_line(&mut line)?;
        let header = line.trim_end_matches(['\r', '\n']);
        if header.is_empty() {
            break;
        }
        let (name, value) = header
            .split_once(':')
            .ok_or_else(|| bad("malformed header"))?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("authorization") {
            authorization = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(bad("duplicate content-length"));
            }
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| bad("invalid content-length"))?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(bad("transfer-encoding is not supported"));
        }
    }
    let length = content_length.unwrap_or(0);
    if length > MAX_BODY_BYTES {
        return Err(HttpResponse::error(
            413,
            "payload_too_large",
            "body exceeds 1 MiB",
        ));
    }
    let mut body = vec![0u8; length];
    reader
        .read_exact(&mut body)
        .map_err(|_| bad("truncated body"))?;
    Ok(HttpRequest {
        method,
        path,
        authorization,
        body,
    })
}

fn route(server: &mut Server, request: &HttpRequest) -> HttpResponse {
    let tool = match request.path.as_str() {
        "/v1/memory/document_recall" => ccos_enterprise_mcp::GOVERNED_DOCUMENT_RECALL_TOOL,
        "/v1/memory/context" => ccos_enterprise_mcp::GOVERNED_CONTEXT_TOOL,
        _ => return HttpResponse::error(404, "not_found", "unknown route"),
    };
    if request.method != "POST" {
        return HttpResponse::error(405, "method_not_allowed", "use POST");
    }
    if let Err(response) = authenticate(server, request.authorization.as_deref()) {
        return response;
    }
    let body: Value = match serde_json::from_slice(&request.body) {
        Ok(value) => value,
        Err(_) => return HttpResponse::error(400, "bad_request", "body is not JSON"),
    };
    let message = match tools_call(server, tool, &body) {
        Ok(message) => message,
        Err(response) => return response,
    };
    let Some(reply) = server.handle(&message) else {
        return HttpResponse::error(500, "internal", "no response");
    };
    if let Some(error) = reply.get("error") {
        let code = error.get("code").and_then(Value::as_i64).unwrap_or(-32603);
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("error")
            .to_string();
        let (status, label) = match code {
            -32602 => (400, "invalid_arguments"),
            -32001 => (403, "forbidden"),
            -32601 => (404, "not_found"),
            -32000 => (503, "unavailable"),
            _ => (500, "internal"),
        };
        return HttpResponse::error(status, label, message);
    }
    let result = reply.get("result").cloned().unwrap_or(Value::Null);
    if result.get("isError").and_then(Value::as_bool) == Some(true) {
        return HttpResponse {
            status: 422,
            body: json!({ "ok": false, "tool": tool, "result": result }),
        };
    }
    HttpResponse {
        status: 200,
        body: json!({ "ok": true, "tool": tool, "result": result }),
    }
}

fn authenticate(server: &Server, header: Option<&str>) -> Result<(), HttpResponse> {
    let unauthenticated = || HttpResponse::error(401, "unauthenticated", "not authenticated");
    let token = header
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .ok_or_else(unauthenticated)?;
    let time = now().map_err(|_| HttpResponse::error(503, "unavailable", "time unavailable"))?;
    let identity = server
        .authenticator
        .authenticate(token, time)
        .map_err(|error| {
            eprintln!("ccos-enterprise-mcp: http identity refused: {error}");
            unauthenticated()
        })?;
    if identity.org().0.as_str() != server.org.as_str()
        || identity.actor().0.as_str() != server.actor.as_str()
    {
        eprintln!("ccos-enterprise-mcp: http principal differs from process-bound principal");
        return Err(HttpResponse::error(
            403,
            "forbidden",
            "principal not served here",
        ));
    }
    Ok(())
}

/// Build the stdio `tools/call` message; every scope-bearing field comes from the server.
fn tools_call(server: &Server, tool: &str, body: &Value) -> Result<Value, HttpResponse> {
    let bad = |message: &str| HttpResponse::error(400, "invalid_arguments", message);
    let object = body
        .as_object()
        .ok_or_else(|| bad("body must be an object"))?;
    if object
        .keys()
        .any(|key| !ALLOWED_BODY_KEYS.contains(&key.as_str()))
    {
        return Err(bad("body contains an unknown field"));
    }
    let text = |name: &str| -> Result<Option<String>, HttpResponse> {
        match object.get(name) {
            None => Ok(None),
            Some(Value::String(value)) if valid_host_meta_value(value.trim()) => {
                Ok(Some(value.trim().to_string()))
            }
            Some(_) => Err(bad("identifier field is invalid")),
        }
    };
    if let Some(tenant) = text("tenant")? {
        if tenant != server.config.tenant {
            eprintln!("ccos-enterprise-mcp: http caller asserted a foreign tenant");
            return Err(HttpResponse::error(
                403,
                "forbidden",
                "tenant not served here",
            ));
        }
    }
    let request_id = text("request_id")?.ok_or_else(|| bad("request_id is required"))?;
    let turn_id = text("turn_id")?.unwrap_or_else(|| request_id.clone());
    let step_id = text("step_id")?.unwrap_or_else(|| request_id.clone());
    let execution_attempt_id = match text("execution_attempt_id")? {
        Some(value) => value,
        None => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            format!("http-{nanos}-{}", ATTEMPT.fetch_add(1, Ordering::Relaxed))
        }
    };
    let digest = Sha256::digest(request_id.as_bytes());
    let trace_id: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
    Ok(json!({
        "jsonrpc": "2.0",
        "id": 0,
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": object.get("arguments").cloned().unwrap_or_else(|| json!({})),
            "_meta": { "ccos": {
                "tenant_id": server.config.tenant,
                "actor_id": server.actor,
                "agent_id": "http-gateway",
                "host": HOST_KIND,
                "dsh_profile": "http-gateway",
                "dsh_session_id": "http-gateway",
                "request_id": request_id,
                "trace_id": trace_id,
                "model": server.config.model,
                "turn_id": turn_id,
                "step_id": step_id,
                "execution_attempt_id": execution_attempt_id
            }}
        }
    }))
}

fn write_http(mut stream: TcpStream, response: &HttpResponse) -> Result<(), String> {
    let reason = match response.status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        422 => "Unprocessable Entity",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    let body = response.body.to_string();
    write!(
        stream,
        "HTTP/1.1 {} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        response.status,
        body.len()
    )
    .and_then(|()| stream.flush())
    .map_err(|error| error.to_string())
}
