//! Execution-journaling decorator for governed MCP backends.

use crate::execution::{
    ExecutionEvent, ExecutionJournal, JournalError, ToolRecovery, ToolRecoveryDisposition,
};
use crate::Backend;
use ccos_enterprise_auth::Authenticator;
use ccos_enterprise_runtime::is_canonical_identifier;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};

pub const DEFAULT_EXECUTION_JOURNAL_CAPACITY: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchExecution {
    pub turn_id: String,
    pub step_id: String,
    pub call_id: String,
}

impl DispatchExecution {
    pub fn new(
        turn_id: impl Into<String>,
        step_id: impl Into<String>,
        call_id: impl Into<String>,
    ) -> Self {
        Self {
            turn_id: turn_id.into(),
            step_id: step_id.into(),
            call_id: call_id.into(),
        }
    }

    fn validate(&self) -> Result<(), ExecutionBackendError> {
        for (kind, value) in [
            ("turn", self.turn_id.as_str()),
            ("step", self.step_id.as_str()),
            ("call", self.call_id.as_str()),
        ] {
            validate_execution_value(kind, value)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum ExecutionBackendError {
    UnsafeTenantId(String),
    InvalidExecutionId {
        kind: &'static str,
        detail: String,
    },
    Journal(JournalError),
    Serialize(serde_json::Error),
    Backend(String),
    OutcomeNotDurable {
        backend_succeeded: bool,
        journal: JournalError,
    },
    RecoveryMismatch(String),
}

impl std::fmt::Display for ExecutionBackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsafeTenantId(tenant) => {
                write!(f, "unsafe tenant id for execution journal: {tenant:?}")
            }
            Self::InvalidExecutionId { kind, detail } => {
                write!(f, "invalid {kind} execution id: {detail}")
            }
            Self::Journal(error) => write!(f, "execution journal: {error}"),
            Self::Serialize(error) => write!(f, "execution serialization: {error}"),
            Self::Backend(error) => write!(f, "backend: {error}"),
            Self::OutcomeNotDurable {
                backend_succeeded,
                journal,
            } => write!(
                f,
                "backend returned (success={backend_succeeded}) but its outcome is not durable: {journal}"
            ),
            Self::RecoveryMismatch(detail) => write!(f, "execution recovery mismatch: {detail}"),
        }
    }
}
impl std::error::Error for ExecutionBackendError {}
impl From<JournalError> for ExecutionBackendError {
    fn from(value: JournalError) -> Self {
        Self::Journal(value)
    }
}
impl From<serde_json::Error> for ExecutionBackendError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialize(value)
    }
}

pub struct ExecutionBackend<B> {
    inner: B,
    root: PathBuf,
    capacity: usize,
    journals: BTreeMap<String, ExecutionJournal>,
    lru: VecDeque<String>,
}

impl<B> ExecutionBackend<B> {
    pub fn new(inner: B, root: impl AsRef<Path>) -> Self {
        Self::with_capacity(inner, root, DEFAULT_EXECUTION_JOURNAL_CAPACITY)
    }

    pub fn with_capacity(inner: B, root: impl AsRef<Path>, capacity: usize) -> Self {
        Self {
            inner,
            root: root.as_ref().to_path_buf(),
            capacity: capacity.max(1),
            journals: BTreeMap::new(),
            lru: VecDeque::new(),
        }
    }

    pub fn inner(&self) -> &B {
        &self.inner
    }
    pub fn inner_mut(&mut self) -> &mut B {
        &mut self.inner
    }

    pub fn journal_path_for(&self, tenant: &str) -> Result<PathBuf, ExecutionBackendError> {
        validate_tenant(tenant)?;
        Ok(self.root.join(tenant).join("execution.jsonl"))
    }

    fn touch(&mut self, tenant: &str) {
        if let Some(index) = self.lru.iter().position(|item| item == tenant) {
            self.lru.remove(index);
        }
        self.lru.push_back(tenant.to_string());
    }

    fn journal_for(
        &mut self,
        tenant: &str,
    ) -> Result<&mut ExecutionJournal, ExecutionBackendError> {
        let path = self.journal_path_for(tenant)?;
        if !self.journals.contains_key(tenant) {
            while self.journals.len() >= self.capacity {
                if let Some(victim) = self.lru.pop_front() {
                    self.journals.remove(&victim);
                } else {
                    break;
                }
            }
            let report = ExecutionJournal::open(path, format!("tenant/{tenant}/mcp"))?;
            self.journals.insert(tenant.to_string(), report.journal);
        }
        self.touch(tenant);
        Ok(self
            .journals
            .get_mut(tenant)
            .expect("journal was inserted or already existed"))
    }

    pub fn append_event(
        &mut self,
        tenant: &str,
        event: ExecutionEvent,
    ) -> Result<(), ExecutionBackendError> {
        validate_tenant(tenant)?;
        self.journal_for(tenant)?.append(event)?;
        Ok(())
    }

    pub fn recover_tools(
        &mut self,
        tenant: &str,
    ) -> Result<Vec<ToolRecovery>, ExecutionBackendError> {
        self.journal_for(tenant)?
            .recover_tools()
            .map_err(Into::into)
    }

    /// Complete an interrupted call from a stronger durable outcome witness.
    ///
    /// Already-completed calls are accepted only when success and hash match
    /// exactly. Anything else is fail-closed rather than silently rewriting
    /// history.
    pub fn reconcile_finished(
        &mut self,
        tenant: &str,
        call_id: &str,
        success: bool,
        output_sha256: &str,
    ) -> Result<(), ExecutionBackendError> {
        validate_execution_value("call", call_id)?;
        let recovered = self.recover_tools(tenant)?;
        let call = recovered
            .iter()
            .find(|item| item.call_id == call_id)
            .ok_or_else(|| {
                ExecutionBackendError::RecoveryMismatch(format!(
                    "call {call_id:?} is absent from durable execution journal"
                ))
            })?;
        match &call.disposition {
            ToolRecoveryDisposition::OutcomeUnknown => {
                self.journal_for(tenant)?
                    .append(ExecutionEvent::ToolFinished {
                        call_id: call_id.to_string(),
                        success,
                        output_sha256: output_sha256.to_string(),
                    })?;
                Ok(())
            }
            ToolRecoveryDisposition::Completed {
                success: prior_success,
                output_sha256: prior_hash,
            } if *prior_success == success && prior_hash == output_sha256 => Ok(()),
            ToolRecoveryDisposition::Completed {
                success: prior_success,
                output_sha256: prior_hash,
            } => Err(ExecutionBackendError::RecoveryMismatch(format!(
                "call {call_id:?} already completed as success={prior_success} hash={prior_hash}, not success={success} hash={output_sha256}"
            ))),
            ToolRecoveryDisposition::NotStarted => {
                Err(ExecutionBackendError::RecoveryMismatch(format!(
                    "call {call_id:?} never crossed the durable start boundary"
                )))
            }
        }
    }

    pub fn ensure_no_unknown_outcomes(
        &mut self,
        tenant: &str,
    ) -> Result<(), ExecutionBackendError> {
        let unknown: Vec<String> = self
            .recover_tools(tenant)?
            .into_iter()
            .filter(|call| call.disposition == ToolRecoveryDisposition::OutcomeUnknown)
            .map(|call| call.call_id)
            .collect();
        if unknown.is_empty() {
            Ok(())
        } else {
            Err(ExecutionBackendError::RecoveryMismatch(format!(
                "unresolved outcome-unknown calls remain: {unknown:?}"
            )))
        }
    }

    pub fn dispatch_with_context(
        &mut self,
        tenant: &str,
        execution: &DispatchExecution,
        core_tool: &str,
        arguments: &Value,
    ) -> Result<Value, ExecutionBackendError>
    where
        B: Backend,
    {
        validate_tenant(tenant)?;
        execution.validate()?;
        let input_sha256 = sha256_hex(&serde_json::to_vec(arguments)?);
        {
            let journal = self.journal_for(tenant)?;
            journal.append(ExecutionEvent::ToolRequested {
                turn_id: execution.turn_id.clone(),
                step_id: execution.step_id.clone(),
                call_id: execution.call_id.clone(),
                tool: core_tool.to_string(),
                input_sha256,
            })?;
            journal.append(ExecutionEvent::ToolStarted {
                call_id: execution.call_id.clone(),
            })?;
        }

        let backend_result = self.inner.dispatch(tenant, core_tool, arguments);
        let (success, output_hash) = match &backend_result {
            Ok(value) => (true, successful_output_sha256(value)?),
            Err(detail) => (false, failed_output_sha256(detail)),
        };
        let finish = self
            .journal_for(tenant)?
            .append(ExecutionEvent::ToolFinished {
                call_id: execution.call_id.clone(),
                success,
                output_sha256: output_hash,
            });
        if let Err(journal) = finish {
            return Err(ExecutionBackendError::OutcomeNotDurable {
                backend_succeeded: success,
                journal,
            });
        }
        backend_result.map_err(ExecutionBackendError::Backend)
    }
}

impl<B: Backend> Backend for ExecutionBackend<B> {
    fn dispatch(
        &mut self,
        tenant: &str,
        core_tool: &str,
        arguments: &Value,
    ) -> Result<Value, String> {
        let sequence = self
            .journal_for(tenant)
            .map_err(|error| error.to_string())?
            .len();
        let execution = DispatchExecution::new(
            format!("mcp-turn-{sequence}"),
            format!("mcp-step-{sequence}"),
            format!("mcp-call-{sequence}"),
        );
        self.dispatch_with_context(tenant, &execution, core_tool, arguments)
            .map_err(|error| error.to_string())
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum LifecycleEventInput {
    TurnStarted {
        turn_id: String,
    },
    StepStarted {
        turn_id: String,
        step_id: String,
    },
    UserMessage {
        turn_id: String,
        message_id: String,
        content_sha256: String,
    },
    AssistantMessage {
        turn_id: String,
        step_id: String,
        message_id: String,
        content_sha256: String,
    },
    StepFinished {
        turn_id: String,
        step_id: String,
        success: bool,
    },
    TurnFinished {
        turn_id: String,
        success: bool,
    },
}

#[derive(Debug)]
struct LifecycleMeta {
    tenant: String,
    actor: String,
    host: String,
    model: String,
}

fn lifecycle_meta(params: &Value) -> Result<LifecycleMeta, ()> {
    let meta = params
        .get("_meta")
        .and_then(|value| value.get("ccos"))
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
    Ok(LifecycleMeta {
        tenant: field("tenant_id")?,
        actor: field("actor_id")?,
        host: field("host")?,
        model: field("model")?,
    })
}

fn lifecycle_event(params: &Value) -> Result<ExecutionEvent, ()> {
    let input: LifecycleEventInput = serde_json::from_value(params.get("event").cloned().ok_or(())?)
        .map_err(|_| ())?;
    let checked = |kind, value: String| {
        validate_execution_value(kind, &value).map_err(|_| ())?;
        Ok::<String, ()>(value)
    };
    let hash = |value: String| {
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            Ok(value)
        } else {
            Err(())
        }
    };
    match input {
        LifecycleEventInput::TurnStarted { turn_id } => Ok(ExecutionEvent::TurnStarted {
            turn_id: checked("turn", turn_id)?,
        }),
        LifecycleEventInput::StepStarted { turn_id, step_id } => Ok(ExecutionEvent::StepStarted {
            turn_id: checked("turn", turn_id)?,
            step_id: checked("step", step_id)?,
        }),
        LifecycleEventInput::UserMessage {
            turn_id,
            message_id,
            content_sha256,
        } => Ok(ExecutionEvent::UserMessage {
            turn_id: checked("turn", turn_id)?,
            message_id: checked("message", message_id)?,
            content_sha256: hash(content_sha256)?,
        }),
        LifecycleEventInput::AssistantMessage {
            turn_id,
            step_id,
            message_id,
            content_sha256,
        } => Ok(ExecutionEvent::AssistantMessage {
            turn_id: checked("turn", turn_id)?,
            step_id: checked("step", step_id)?,
            message_id: checked("message", message_id)?,
            content_sha256: hash(content_sha256)?,
        }),
        LifecycleEventInput::StepFinished {
            turn_id,
            step_id,
            success,
        } => Ok(ExecutionEvent::StepFinished {
            turn_id: checked("turn", turn_id)?,
            step_id: checked("step", step_id)?,
            success,
        }),
        LifecycleEventInput::TurnFinished { turn_id, success } => Ok(ExecutionEvent::TurnFinished {
            turn_id: checked("turn", turn_id)?,
            success,
        }),
    }
}

pub(crate) fn handle_lifecycle_event(
    server: &mut super::Server,
    params: &Value,
) -> Result<Value, (i64, String)> {
    if let Some(reason) = &server.poisoned {
        eprintln!("ccos-enterprise-mcp: refusing lifecycle event after durability failure: {reason}");
        return Err((-32000, "Enterprise durable state unavailable".into()));
    }
    let meta = lifecycle_meta(params).map_err(|_| (-32602, "invalid params".into()))?;
    let event = lifecycle_event(params).map_err(|_| (-32602, "invalid params".into()))?;
    let identity = server
        .authenticator
        .authenticate(
            &server.config.identity_token,
            super::now().map_err(|_| (-32000, "server time unavailable".into()))?,
        )
        .map_err(|error| {
            eprintln!("ccos-enterprise-mcp: lifecycle identity refused: {error}");
            (-32001, error.client_message().to_string())
        })?;
    if identity.org().0.as_str() != server.org.as_str()
        || identity.actor().0.as_str() != server.actor.as_str()
        || meta.tenant != server.config.tenant
        || meta.actor != server.actor
        || meta.host != super::HOST_KIND
        || meta.model != server.config.model
    {
        eprintln!("ccos-enterprise-mcp: lifecycle host claims did not match configured identity");
        return Err((-32001, "not authenticated".into()));
    }

    if let Err(error) = server
        .front_door
        .backend_mut()
        .execution
        .append_event(&meta.tenant, event)
    {
        let reason = error.to_string();
        server.poisoned = Some(reason.clone());
        eprintln!("ccos-enterprise-mcp: lifecycle journal append failed: {reason}");
        return Err((-32000, "Enterprise execution state is not durable".into()));
    }
    Ok(json!({ "recorded": true }))
}

pub fn successful_output_sha256(value: &Value) -> Result<String, serde_json::Error> {
    serde_json::to_vec(value).map(|bytes| sha256_hex(&bytes))
}

pub fn failed_output_sha256(detail: &str) -> String {
    sha256_hex(detail.as_bytes())
}

fn validate_tenant(tenant: &str) -> Result<(), ExecutionBackendError> {
    if is_canonical_identifier(tenant) {
        Ok(())
    } else {
        Err(ExecutionBackendError::UnsafeTenantId(
            tenant.chars().take(64).collect(),
        ))
    }
}

fn validate_execution_value(kind: &'static str, value: &str) -> Result<(), ExecutionBackendError> {
    if value.is_empty() {
        return Err(ExecutionBackendError::InvalidExecutionId {
            kind,
            detail: "must not be empty".into(),
        });
    }
    if value.len() > 256 {
        return Err(ExecutionBackendError::InvalidExecutionId {
            kind,
            detail: "must not exceed 256 bytes".into(),
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ExecutionBackendError::InvalidExecutionId {
            kind,
            detail: "must not contain control characters".into(),
        });
    }
    Ok(())
}

fn sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct BackendOk;
    impl Backend for BackendOk {
        fn dispatch(
            &mut self,
            _tenant: &str,
            _tool: &str,
            _args: &Value,
        ) -> Result<Value, String> {
            Ok(json!({"ok": true}))
        }
    }

    #[test]
    fn explicit_attempt_is_completed_and_reconciliation_is_idempotent() {
        let root =
            std::env::temp_dir().join(format!("ccos-mcp-exec-backend-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut backend = ExecutionBackend::new(BackendOk, &root);
        let execution = DispatchExecution::new("turn-1", "step-2", "attempt-1");
        let value = backend
            .dispatch_with_context("acme", &execution, "recall", &json!({}))
            .unwrap();
        let hash = successful_output_sha256(&value).unwrap();
        backend
            .reconcile_finished("acme", "attempt-1", true, &hash)
            .unwrap();
        backend.ensure_no_unknown_outcomes("acme").unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn explicit_lifecycle_event_uses_the_same_tenant_journal() {
        let root = std::env::temp_dir().join(format!(
            "ccos-mcp-exec-lifecycle-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let mut backend = ExecutionBackend::new(BackendOk, &root);
        backend
            .append_event(
                "acme",
                ExecutionEvent::TurnStarted {
                    turn_id: "dsh-session-1:turn:1".into(),
                },
            )
            .unwrap();
        let path = backend.journal_path_for("acme").unwrap();
        let reopened = ExecutionJournal::open(path, "tenant/acme/mcp").unwrap();
        assert_eq!(reopened.journal.len(), 1);
        assert!(matches!(
            &reopened.journal.records()[0].event,
            ExecutionEvent::TurnStarted { turn_id } if turn_id == "dsh-session-1:turn:1"
        ));
        let _ = std::fs::remove_dir_all(root);
    }
}
