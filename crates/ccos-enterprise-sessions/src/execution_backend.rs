//! Execution-journaling wrapper for Enterprise backends.
//!
//! The governed MCP seam predates turn/step identifiers and exposes only
//! `tenant`, `core_tool`, and `arguments`. This wrapper therefore assigns
//! monotonic execution identifiers from the tenant journal itself. A richer
//! caller can use [`ExecutionBackend::dispatch_with_context`] to preserve its
//! own turn/step/call identifiers.
//!
//! The critical ordering is durable and intentional:
//!
//! 1. `ToolRequested` is appended and synced;
//! 2. `ToolStarted` is appended and synced;
//! 3. only then is the wrapped backend invoked;
//! 4. `ToolFinished` is appended and synced after the backend returns.
//!
//! Consequently a crash after step 2 but before step 4 reconstructs as
//! `OutcomeUnknown`, never as a call that is safe to replay blindly.

use crate::execution::{
    ExecutionEvent, ExecutionJournal, JournalError, ToolRecovery, ToolRecoveryDisposition,
};
use ccos_enterprise_mcp::Backend;
use ccos_enterprise_runtime::is_canonical_identifier;
use serde_json::Value;
use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};

/// Maximum number of open execution journals retained by default.
pub const DEFAULT_EXECUTION_JOURNAL_CAPACITY: usize = 64;

/// Explicit execution identity supplied by an orchestration-aware caller.
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
            if value.is_empty() {
                return Err(ExecutionBackendError::InvalidExecutionId {
                    kind,
                    detail: "must not be empty".to_string(),
                });
            }
            if value.len() > 256 {
                return Err(ExecutionBackendError::InvalidExecutionId {
                    kind,
                    detail: "must not exceed 256 bytes".to_string(),
                });
            }
            if value.chars().any(char::is_control) {
                return Err(ExecutionBackendError::InvalidExecutionId {
                    kind,
                    detail: "must not contain control characters".to_string(),
                });
            }
        }
        Ok(())
    }
}

/// Why the execution wrapper refused or could not finish a dispatch.
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
    /// The wrapped backend returned, but its outcome could not be made durable.
    /// Recovery intentionally sees the corresponding call as `OutcomeUnknown`.
    OutcomeNotDurable {
        backend_succeeded: bool,
        journal: JournalError,
    },
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

/// A backend decorated with Enterprise execution durability.
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

    pub fn into_inner(self) -> B {
        self.inner
    }

    pub fn live_journal_count(&self) -> usize {
        self.journals.len()
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
            let stream_id = format!("tenant/{tenant}/mcp");
            let report = ExecutionJournal::open(path, stream_id)?;
            self.journals.insert(tenant.to_string(), report.journal);
        }
        self.touch(tenant);
        Ok(self
            .journals
            .get_mut(tenant)
            .expect("journal was inserted or already existed"))
    }

    /// Inspect durable recovery state without executing anything.
    pub fn recover_tools(
        &mut self,
        tenant: &str,
    ) -> Result<Vec<ToolRecovery>, ExecutionBackendError> {
        self.journal_for(tenant)?
            .recover_tools()
            .map_err(Into::into)
    }

    /// Execute one tool call under caller-supplied orchestration identifiers.
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
        let input = serde_json::to_vec(arguments)?;
        let input_sha256 = sha256_hex(&input);

        {
            let journal = self.journal_for(tenant)?;
            journal.append(ExecutionEvent::ToolRequested {
                turn_id: execution.turn_id.clone(),
                step_id: execution.step_id.clone(),
                call_id: execution.call_id.clone(),
                tool: core_tool.to_string(),
                input_sha256,
            })?;
            // This fsync-backed record is the irreversible boundary: the inner
            // backend is not called unless ToolStarted is durable.
            journal.append(ExecutionEvent::ToolStarted {
                call_id: execution.call_id.clone(),
            })?;
        }

        let backend_result = self.inner.dispatch(tenant, core_tool, arguments);
        let (success, output_hash) = match &backend_result {
            Ok(value) => (true, sha256_hex(&serde_json::to_vec(value)?)),
            Err(detail) => (false, sha256_hex(detail.as_bytes())),
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

    fn implicit_context(
        &mut self,
        tenant: &str,
    ) -> Result<DispatchExecution, ExecutionBackendError> {
        let sequence = self.journal_for(tenant)?.len();
        Ok(DispatchExecution::new(
            format!("mcp-turn-{sequence}"),
            format!("mcp-step-{sequence}"),
            format!("mcp-call-{sequence}"),
        ))
    }
}

impl<B: Backend> Backend for ExecutionBackend<B> {
    fn dispatch(
        &mut self,
        tenant: &str,
        core_tool: &str,
        arguments: &Value,
    ) -> Result<Value, String> {
        let execution = self
            .implicit_context(tenant)
            .map_err(|error| error.to_string())?;
        self.dispatch_with_context(tenant, &execution, core_tool, arguments)
            .map_err(|error| error.to_string())
    }
}

/// Convenience type for the production session backend.
pub type AuditedTenantSessions = ExecutionBackend<crate::TenantSessions>;

impl ExecutionBackend<crate::TenantSessions> {
    /// Build a tenant-session backend and keep its execution journals under a
    /// sibling `execution` directory beneath the same Enterprise root.
    pub fn tenant_sessions(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref().to_path_buf();
        let sessions = crate::TenantSessions::new(&root);
        Self::new(sessions, root.join("execution"))
    }

    pub fn tenant_sessions_with_capacity(root: impl AsRef<Path>, capacity: usize) -> Self {
        let root = root.as_ref().to_path_buf();
        let sessions = crate::TenantSessions::with_capacity(&root, capacity);
        Self::with_capacity(sessions, root.join("execution"), capacity)
    }
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

fn sha256_hex(input: &[u8]) -> String {
    hex(&sha256(input))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

// Kept local to this Enterprise module so PR2 adds no dependency and therefore
// cannot perturb the workspace lockfile. A known-answer test pins correctness.
fn sha256(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(input.len() + 72);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut state = INITIAL;
    for chunk in padded.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, bytes) in chunk.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for index in 0..64 {
            let upper = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(upper)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let lower = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = lower.wrapping_add(majority);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut output = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct RecordingBackend {
        calls: Arc<Mutex<Vec<(String, String, Value)>>>,
        fail: bool,
    }

    impl RecordingBackend {
        fn failing() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                fail: true,
            }
        }

        fn call_count(&self) -> usize {
            self.calls.lock().expect("calls lock").len()
        }
    }

    impl Backend for RecordingBackend {
        fn dispatch(
            &mut self,
            tenant: &str,
            core_tool: &str,
            arguments: &Value,
        ) -> Result<Value, String> {
            self.calls.lock().expect("calls lock").push((
                tenant.to_string(),
                core_tool.to_string(),
                arguments.clone(),
            ));
            if self.fail {
                Err("synthetic backend failure".to_string())
            } else {
                Ok(json!({"tool": core_tool, "tenant": tenant, "ok": true}))
            }
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ccos-execution-backend-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("scratch");
        path
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn success_crosses_start_before_backend_and_finishes_durably() {
        let root = scratch("success");
        let mut backend = ExecutionBackend::new(RecordingBackend::default(), &root);
        let context = DispatchExecution::new("turn-7", "step-3", "call-9");

        let value = backend
            .dispatch_with_context("acme", &context, "recall", &json!({"budget": 20}))
            .expect("dispatch");
        assert_eq!(value["ok"], true);
        assert_eq!(backend.inner().call_count(), 1);

        let recovered = backend.recover_tools("acme").expect("recover");
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].call_id, "call-9");
        assert_eq!(recovered[0].tool, "recall");
        assert!(matches!(
            recovered[0].disposition,
            ToolRecoveryDisposition::Completed { success: true, .. }
        ));
        let records = backend.journal_for("acme").expect("journal").records();
        assert!(matches!(
            records[0].event,
            ExecutionEvent::ToolRequested { .. }
        ));
        assert!(matches!(
            records[1].event,
            ExecutionEvent::ToolStarted { .. }
        ));
        assert!(matches!(
            records[2].event,
            ExecutionEvent::ToolFinished { .. }
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn backend_failure_is_still_a_durable_completed_outcome() {
        let root = scratch("backend-failure");
        let mut backend = ExecutionBackend::new(RecordingBackend::failing(), &root);
        let error = backend
            .dispatch("acme", "ingest", &json!({"uri": "x", "source": "y"}))
            .expect_err("backend fails");
        assert!(error.contains("synthetic backend failure"), "{error}");
        assert_eq!(backend.inner().call_count(), 1);
        let recovered = backend.recover_tools("acme").expect("recover");
        assert!(matches!(
            recovered[0].disposition,
            ToolRecoveryDisposition::Completed { success: false, .. }
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn journal_failure_before_start_prevents_backend_execution() {
        let root = scratch("prestart-failure");
        let blocker = root.join("not-a-directory");
        std::fs::write(&blocker, b"block").expect("blocker");
        let mut backend = ExecutionBackend::new(RecordingBackend::default(), &blocker);

        let error = backend
            .dispatch("acme", "recall", &json!({}))
            .expect_err("journal path must fail");
        assert!(error.contains("execution journal"), "{error}");
        assert_eq!(backend.inner().call_count(), 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn tenant_streams_are_physically_and_logically_separate() {
        let root = scratch("tenant-separation");
        let mut backend = ExecutionBackend::new(RecordingBackend::default(), &root);
        backend
            .dispatch("acme", "recall", &json!({}))
            .expect("acme");
        backend
            .dispatch("globex", "recall", &json!({}))
            .expect("globex");

        assert_ne!(
            backend.journal_path_for("acme").expect("acme path"),
            backend.journal_path_for("globex").expect("globex path")
        );
        assert_eq!(
            backend.recover_tools("acme").expect("acme recover").len(),
            1
        );
        assert_eq!(
            backend
                .recover_tools("globex")
                .expect("globex recover")
                .len(),
            1
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn bounded_cache_reopens_evicted_journal_without_losing_history() {
        let root = scratch("eviction");
        let mut backend = ExecutionBackend::with_capacity(RecordingBackend::default(), &root, 1);
        backend
            .dispatch("acme", "recall", &json!({}))
            .expect("acme");
        backend
            .dispatch("globex", "recall", &json!({}))
            .expect("globex");
        assert_eq!(backend.live_journal_count(), 1);

        let acme = backend.recover_tools("acme").expect("reopen acme");
        assert_eq!(backend.live_journal_count(), 1);
        assert_eq!(acme.len(), 1);
        assert!(matches!(
            acme[0].disposition,
            ToolRecoveryDisposition::Completed { success: true, .. }
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn hostile_tenant_never_reaches_inner_backend() {
        let root = scratch("hostile-tenant");
        let mut backend = ExecutionBackend::new(RecordingBackend::default(), &root);
        let error = backend
            .dispatch("../escape", "recall", &json!({}))
            .expect_err("hostile tenant");
        assert!(error.contains("unsafe tenant"), "{error}");
        assert_eq!(backend.inner().call_count(), 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn explicit_duplicate_call_id_is_detected_by_recovery() {
        let root = scratch("duplicate-call");
        let mut backend = ExecutionBackend::new(RecordingBackend::default(), &root);
        let context = DispatchExecution::new("turn", "step", "call");
        backend
            .dispatch_with_context("acme", &context, "recall", &json!({}))
            .expect("first");
        backend
            .dispatch_with_context("acme", &context, "recall", &json!({}))
            .expect("second is recorded; recovery owns lifecycle verdict");
        let error = backend
            .recover_tools("acme")
            .expect_err("duplicate lifecycle");
        assert!(matches!(
            error,
            ExecutionBackendError::Journal(JournalError::Lifecycle(_))
        ));
        let _ = std::fs::remove_dir_all(root);
    }
}
