//! Request-correlated governed MCP front door for CCOS Enterprise.
//!
//! `GovernedMcp` owns the admission policy and must remain the authority for
//! identity, tenant, authorization, replay, and budget decisions. This module
//! does not duplicate any of those gates. Instead it decorates its backend so
//! the already-governed `request_id` becomes the durable execution identity
//! when (and only when) the call actually reaches the backend.

use crate::execution_backend::{DispatchExecution, ExecutionBackend, ExecutionBackendError};
use ccos_enterprise_mcp::{AdvertisedTool, Backend, GovernedMcp, McpOutcome};
use ccos_enterprise_runtime::{Call, Deployment};
use serde_json::Value;
use std::path::Path;

/// A context waiting for exactly one governed backend dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingExecution {
    tenant: String,
    execution: DispatchExecution,
}

/// Backend adapter that consumes a request-correlated context at dispatch.
///
/// The pending context is intentionally single-use. `GovernedMcp` dispatches at
/// most once for a forwarded call; a second dispatch would therefore fall back
/// to the execution backend's own monotonic IDs instead of reusing a call ID.
pub struct RequestCorrelatedBackend<B> {
    execution: ExecutionBackend<B>,
    pending: Option<PendingExecution>,
}

impl<B> RequestCorrelatedBackend<B> {
    pub fn new(execution: ExecutionBackend<B>) -> Self {
        Self {
            execution,
            pending: None,
        }
    }

    pub fn execution(&self) -> &ExecutionBackend<B> {
        &self.execution
    }

    pub fn execution_mut(&mut self) -> &mut ExecutionBackend<B> {
        &mut self.execution
    }

    pub fn into_execution(self) -> ExecutionBackend<B> {
        self.execution
    }

    pub fn has_pending_context(&self) -> bool {
        self.pending.is_some()
    }

    fn arm(&mut self, tenant: &str, request_id: &str) {
        // The same already-governed request id names the turn, step and tool
        // call. Their namespaces are distinct in the event schema, so equality
        // is unambiguous and gives audit joins an exact correlation key.
        self.pending = Some(PendingExecution {
            tenant: tenant.to_string(),
            execution: DispatchExecution::new(request_id, request_id, request_id),
        });
    }

    fn clear(&mut self) {
        self.pending = None;
    }
}

impl<B: Backend> Backend for RequestCorrelatedBackend<B> {
    fn dispatch(
        &mut self,
        tenant: &str,
        core_tool: &str,
        arguments: &Value,
    ) -> Result<Value, String> {
        match self.pending.take() {
            Some(pending) if pending.tenant == tenant => self
                .execution
                .dispatch_with_context(tenant, &pending.execution, core_tool, arguments)
                .map_err(|error| error.to_string()),
            Some(pending) => {
                // Put it back: a tenant mismatch is an invariant violation, not
                // permission to consume another tenant's correlation context.
                let expected = pending.tenant.clone();
                self.pending = Some(pending);
                Err(format!(
                    "execution context tenant mismatch: expected {expected:?}, got {tenant:?}"
                ))
            }
            None => self.execution.dispatch(tenant, core_tool, arguments),
        }
    }
}

/// Governed MCP front door whose forwarded calls are correlated to the
/// Enterprise execution journal by `request_id`.
pub struct GovernedExecutionMcp<B: Backend> {
    inner: GovernedMcp<RequestCorrelatedBackend<B>>,
}

impl<B: Backend> GovernedExecutionMcp<B> {
    pub fn new(deployment: Deployment, execution: ExecutionBackend<B>) -> Self {
        Self {
            inner: GovernedMcp::new(deployment, RequestCorrelatedBackend::new(execution)),
        }
    }

    pub fn from_backend(
        deployment: Deployment,
        backend: B,
        execution_root: impl AsRef<Path>,
    ) -> Self {
        Self::new(deployment, ExecutionBackend::new(backend, execution_root))
    }

    pub fn deployment(&self) -> &Deployment {
        self.inner.deployment()
    }

    pub fn deployment_mut(&mut self) -> &mut Deployment {
        self.inner.deployment_mut()
    }

    pub fn backend(&self) -> &RequestCorrelatedBackend<B> {
        self.inner.backend()
    }

    pub fn backend_mut(&mut self) -> &mut RequestCorrelatedBackend<B> {
        self.inner.backend_mut()
    }

    pub fn list_tools(&self) -> Vec<AdvertisedTool> {
        self.inner.list_tools()
    }

    /// Run the authoritative Enterprise admission path and correlate only a
    /// genuinely forwarded backend call. Refused, replayed, and unknown-tool
    /// outcomes always clear the temporary context before returning.
    pub fn call(&mut self, call: Call<'_>, arguments: &Value) -> McpOutcome {
        let tenant = call.request.tenant.clone();
        let request_id = call.request.request_id.clone();
        self.inner.backend_mut().arm(&tenant, &request_id);
        let outcome = self.inner.call(call, arguments);
        self.inner.backend_mut().clear();
        outcome
    }

    /// Recover durable tool states for a tenant without dispatching anything.
    pub fn recover_tools(
        &mut self,
        tenant: &str,
    ) -> Result<Vec<crate::execution::ToolRecovery>, ExecutionBackendError> {
        self.inner
            .backend_mut()
            .execution_mut()
            .recover_tools(tenant)
    }
}

/// Production specialization: one Core session and one execution journal
/// stream per tenant, both rooted under the same Enterprise data directory.
pub type GovernedTenantSessions = GovernedExecutionMcp<crate::TenantSessions>;

impl GovernedExecutionMcp<crate::TenantSessions> {
    pub fn tenant_sessions(deployment: Deployment, root: impl AsRef<Path>) -> Self {
        Self::new(
            deployment,
            ExecutionBackend::tenant_sessions(root.as_ref().to_path_buf()),
        )
    }

    pub fn tenant_sessions_with_capacity(
        deployment: Deployment,
        root: impl AsRef<Path>,
        capacity: usize,
    ) -> Self {
        Self::new(
            deployment,
            ExecutionBackend::tenant_sessions_with_capacity(root.as_ref().to_path_buf(), capacity),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ccos_enterprise_auth::AuthStrength;
    use ccos_enterprise_mcp::govern_catalogue;
    use ccos_enterprise_runtime::{actor, request, TenantState};
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Recorder {
        calls: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl Recorder {
        fn call_count(&self) -> usize {
            self.calls.lock().expect("calls").len()
        }
    }

    impl Backend for Recorder {
        fn dispatch(
            &mut self,
            tenant: &str,
            core_tool: &str,
            _arguments: &Value,
        ) -> Result<Value, String> {
            self.calls
                .lock()
                .expect("calls")
                .push((tenant.to_string(), core_tool.to_string()));
            Ok(json!({"ok": true, "tool": core_tool}))
        }
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("ccos-mcp-execution-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("scratch");
        path
    }

    fn deployment() -> Deployment {
        let mut deployment = Deployment::new();
        deployment
            .add_role("reader", &["memory.read"])
            .add_role("writer", &["memory.read", "memory.write"]);
        govern_catalogue(&mut deployment);
        let mut acme = TenantState::new(10_000);
        acme.allow_model("claude-opus");
        deployment.add_tenant("memorithm", "acme", acme);
        deployment.assign("alice", "writer");
        deployment.assign("bob", "reader");
        deployment
    }

    #[test]
    fn forwarded_request_id_becomes_exact_durable_call_id() {
        let root = scratch("correlation");
        let recorder = Recorder::default();
        let mut mcp = GovernedExecutionMcp::from_backend(deployment(), recorder, &root);
        let alice = actor("memorithm", "alice", AuthStrength::Token);
        let req = request("acme", "alice", "memory.recall", "req-correlation-17");

        let outcome = mcp.call(
            Call {
                actor: &alice,
                request: &req,
                model: "claude-opus",
                cost_tokens: 10,
                variant: None,
                justification: None,
            },
            &json!({}),
        );
        assert!(matches!(outcome, McpOutcome::Ok(_)), "{outcome:?}");
        let recovered = mcp.recover_tools("acme").expect("recover");
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].call_id, "req-correlation-17");
        assert_eq!(recovered[0].tool, "recall");
        assert_eq!(mcp.backend().execution().inner().call_count(), 1);
        assert!(!mcp.backend().has_pending_context());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn governance_replay_never_creates_a_second_execution_call() {
        let root = scratch("replay");
        let mut mcp = GovernedExecutionMcp::from_backend(deployment(), Recorder::default(), &root);
        let alice = actor("memorithm", "alice", AuthStrength::Token);
        let req = request("acme", "alice", "memory.recall", "req-replay");

        assert!(matches!(
            mcp.call(
                Call {
                    actor: &alice,
                    request: &req,
                    model: "claude-opus",
                    cost_tokens: 10,
                    variant: None,
                    justification: None,
                },
                &json!({})
            ),
            McpOutcome::Ok(_)
        ));
        assert_eq!(
            mcp.call(
                Call {
                    actor: &alice,
                    request: &req,
                    model: "claude-opus",
                    cost_tokens: 10,
                    variant: None,
                    justification: None,
                },
                &json!({})
            ),
            McpOutcome::Replayed
        );
        assert_eq!(mcp.backend().execution().inner().call_count(), 1);
        assert_eq!(mcp.recover_tools("acme").expect("recover").len(), 1);
        assert!(!mcp.backend().has_pending_context());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn refused_call_clears_pending_context_without_touching_backend() {
        let root = scratch("refused");
        let mut mcp = GovernedExecutionMcp::from_backend(deployment(), Recorder::default(), &root);
        let bob = actor("memorithm", "bob", AuthStrength::Token);
        let req = request("acme", "bob", "memory.ingest", "req-refused");

        let outcome = mcp.call(
            Call {
                actor: &bob,
                request: &req,
                model: "claude-opus",
                cost_tokens: 10,
                variant: None,
                justification: None,
            },
            &json!({}),
        );
        assert!(matches!(outcome, McpOutcome::Refused(_)), "{outcome:?}");
        assert_eq!(mcp.backend().execution().inner().call_count(), 0);
        assert!(!mcp.backend().has_pending_context());
        assert!(mcp.recover_tools("acme").expect("recover").is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn invalid_execution_request_id_fails_closed_after_admission() {
        let root = scratch("invalid-request-id");
        let mut mcp = GovernedExecutionMcp::from_backend(deployment(), Recorder::default(), &root);
        let alice = actor("memorithm", "alice", AuthStrength::Token);
        let req = request("acme", "alice", "memory.recall", "bad\nrequest");

        let outcome = mcp.call(
            Call {
                actor: &alice,
                request: &req,
                model: "claude-opus",
                cost_tokens: 10,
                variant: None,
                justification: None,
            },
            &json!({}),
        );
        assert!(
            matches!(outcome, McpOutcome::BackendError(_)),
            "{outcome:?}"
        );
        assert_eq!(mcp.backend().execution().inner().call_count(), 0);
        assert!(!mcp.backend().has_pending_context());
        assert!(mcp.recover_tools("acme").expect("recover").is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn tenant_mismatch_refuses_to_consume_another_tenants_context() {
        let root = scratch("tenant-mismatch");
        let execution = ExecutionBackend::new(Recorder::default(), &root);
        let mut backend = RequestCorrelatedBackend::new(execution);
        backend.arm("acme", "req-acme");

        let error = backend
            .dispatch("globex", "recall", &json!({}))
            .expect_err("tenant mismatch");
        assert!(error.contains("tenant mismatch"), "{error}");
        assert!(backend.has_pending_context());
        assert_eq!(backend.execution().inner().call_count(), 0);
        let _ = std::fs::remove_dir_all(root);
    }
}
