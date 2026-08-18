#![forbid(unsafe_code)]
//! Enterprise-only execution journal for agent turns, steps and tool calls.
//!
//! This crate deliberately lives outside `ccos-core`. It records the execution
//! plane that CCOS Enterprise needs around Core sessions without changing Core's
//! replay contract or the Research Lab product.
//!
//! The journal is append-only JSONL with a SHA-256 hash chain. Tool execution is
//! represented by two durable boundaries: [`ExecutionEvent::ToolRequested`] and
//! [`ExecutionEvent::ToolStarted`]. Recovery is conservative:
//!
//! * requested but not started => [`ToolRecoveryDisposition::NotStarted`];
//! * started but without a durable result =>
//!   [`ToolRecoveryDisposition::OutcomeUnknown`];
//! * started and finished => [`ToolRecoveryDisposition::Completed`].
//!
//! An `OutcomeUnknown` call must never be blindly replayed after a crash: the
//! side effect may already have happened.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// On-disk schema version for execution records.
pub const SCHEMA_VERSION: u16 = 1;

/// Hash-chain predecessor for the first record.
pub const GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// A model-visible or execution-side fact recorded by CCOS Enterprise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExecutionEvent {
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
    /// The model requested this tool call, but the runtime has not crossed the
    /// durable execution boundary yet.
    ToolRequested {
        turn_id: String,
        step_id: String,
        call_id: String,
        tool: String,
        input_sha256: String,
    },
    /// Durable boundary written and synced before invoking the tool.
    ToolStarted {
        call_id: String,
    },
    /// Durable result written after the tool returned.
    ToolFinished {
        call_id: String,
        success: bool,
        output_sha256: String,
    },
    ApprovalAsked {
        approval_id: String,
        capability: String,
    },
    ApprovalDecided {
        approval_id: String,
        allowed: bool,
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

/// One tamper-evident record in the append-only stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRecord {
    pub schema_version: u16,
    pub stream_id: String,
    pub sequence: u64,
    pub previous_hash: String,
    pub event: ExecutionEvent,
    pub hash: String,
}

/// Repair applied while opening a journal after an interrupted append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailRepair {
    None,
    /// The final record was complete and hash-valid but its trailing newline was
    /// missing. The record is preserved and the newline is restored.
    CompletedMissingNewline,
    /// An incomplete final JSON fragment was discarded. Only bytes after the
    /// last complete newline are eligible for this repair.
    DiscardedPartialTail { bytes: usize },
}

/// Result of opening a journal, including any crash-tail repair performed.
pub struct OpenReport {
    pub journal: ExecutionJournal,
    pub tail_repair: TailRepair,
}

/// Why an execution journal operation failed.
#[derive(Debug)]
pub enum JournalError {
    Io(std::io::Error),
    Json(serde_json::Error),
    InvalidStreamId(String),
    Integrity(String),
    Lifecycle(String),
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "execution journal I/O: {error}"),
            Self::Json(error) => write!(f, "execution journal JSON: {error}"),
            Self::InvalidStreamId(detail) => write!(f, "invalid execution stream id: {detail}"),
            Self::Integrity(detail) => write!(f, "execution journal integrity: {detail}"),
            Self::Lifecycle(detail) => write!(f, "execution lifecycle: {detail}"),
        }
    }
}

impl std::error::Error for JournalError {}

impl From<std::io::Error> for JournalError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for JournalError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

/// Durable Enterprise execution stream.
pub struct ExecutionJournal {
    path: PathBuf,
    stream_id: String,
    records: Vec<ExecutionRecord>,
}

impl ExecutionJournal {
    /// Open or create a stream and verify every durable record from genesis.
    ///
    /// A malformed *newline-terminated* record is never repaired: it is treated
    /// as corruption/tampering. Only the unterminated tail can be repaired.
    pub fn open(path: impl AsRef<Path>, stream_id: impl Into<String>) -> Result<OpenReport, JournalError> {
        let path = path.as_ref().to_path_buf();
        let stream_id = stream_id.into();
        validate_stream_id(&stream_id)?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if !path.exists() {
            File::create(&path)?.sync_data()?;
        }

        let mut bytes = Vec::new();
        File::open(&path)?.read_to_end(&mut bytes)?;

        let mut records = Vec::new();
        let mut cursor = 0usize;
        let mut tail_repair = TailRepair::None;

        while cursor < bytes.len() {
            if let Some(relative_newline) = bytes[cursor..].iter().position(|byte| *byte == b'\n') {
                let newline = cursor + relative_newline;
                let line = &bytes[cursor..newline];
                if line.is_empty() {
                    return Err(JournalError::Integrity(format!(
                        "empty durable line at byte offset {cursor}"
                    )));
                }
                let record: ExecutionRecord = serde_json::from_slice(line)?;
                validate_next(&records, &record, &stream_id)?;
                records.push(record);
                cursor = newline + 1;
                continue;
            }

            let tail = &bytes[cursor..];
            if tail.is_empty() {
                break;
            }
            match serde_json::from_slice::<ExecutionRecord>(tail) {
                Ok(record) => {
                    // A parseable tail is not silently discarded. It must also
                    // pass the full chain verification or opening fails.
                    validate_next(&records, &record, &stream_id)?;
                    records.push(record);
                    let mut file = OpenOptions::new().append(true).open(&path)?;
                    file.write_all(b"\n")?;
                    file.sync_data()?;
                    tail_repair = TailRepair::CompletedMissingNewline;
                }
                Err(_) => {
                    let discarded = tail.len();
                    let file = OpenOptions::new().write(true).open(&path)?;
                    file.set_len(cursor as u64)?;
                    file.sync_data()?;
                    tail_repair = TailRepair::DiscardedPartialTail { bytes: discarded };
                }
            }
            cursor = bytes.len();
        }

        Ok(OpenReport {
            journal: Self {
                path,
                stream_id,
                records,
            },
            tail_repair,
        })
    }

    /// Append, flush and sync one execution fact before returning it to the
    /// caller. The in-memory state changes only after the durable write succeeds.
    pub fn append(&mut self, event: ExecutionEvent) -> Result<&ExecutionRecord, JournalError> {
        let sequence = self.records.len() as u64;
        let previous_hash = self
            .records
            .last()
            .map(|record| record.hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.to_string());
        let hash = record_hash(&self.stream_id, sequence, &previous_hash, &event)?;
        let record = ExecutionRecord {
            schema_version: SCHEMA_VERSION,
            stream_id: self.stream_id.clone(),
            sequence,
            previous_hash,
            event,
            hash,
        };
        let mut encoded = serde_json::to_vec(&record)?;
        encoded.push(b'\n');

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(&encoded)?;
        file.sync_data()?;
        self.records.push(record);
        Ok(self.records.last().expect("record was just pushed"))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    pub fn records(&self) -> &[ExecutionRecord] {
        &self.records
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn head_hash(&self) -> &str {
        self.records
            .last()
            .map(|record| record.hash.as_str())
            .unwrap_or(GENESIS_HASH)
    }

    /// Rebuild the durable tool-call state machine from the authoritative log.
    pub fn recover_tools(&self) -> Result<Vec<ToolRecovery>, JournalError> {
        recover_tools(&self.records)
    }
}

/// Recovery status for one durable tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRecovery {
    pub call_id: String,
    pub tool: String,
    pub disposition: ToolRecoveryDisposition,
}

/// Conservative restart disposition for a tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolRecoveryDisposition {
    /// The request is durable but execution never crossed the durable start
    /// boundary. The scheduler may decide to execute it.
    NotStarted,
    /// Execution crossed the durable start boundary but no result is durable.
    /// The side effect may have happened; automatic replay is unsafe.
    OutcomeUnknown,
    /// A durable result exists.
    Completed {
        success: bool,
        output_sha256: String,
    },
}

fn recover_tools(records: &[ExecutionRecord]) -> Result<Vec<ToolRecovery>, JournalError> {
    let mut calls: BTreeMap<String, ToolRecovery> = BTreeMap::new();

    for record in records {
        match &record.event {
            ExecutionEvent::ToolRequested { call_id, tool, .. } => {
                if calls.contains_key(call_id) {
                    return Err(JournalError::Lifecycle(format!(
                        "duplicate tool request for call {call_id:?}"
                    )));
                }
                calls.insert(
                    call_id.clone(),
                    ToolRecovery {
                        call_id: call_id.clone(),
                        tool: tool.clone(),
                        disposition: ToolRecoveryDisposition::NotStarted,
                    },
                );
            }
            ExecutionEvent::ToolStarted { call_id } => {
                let call = calls.get_mut(call_id).ok_or_else(|| {
                    JournalError::Lifecycle(format!(
                        "tool {call_id:?} started before a durable request"
                    ))
                })?;
                if call.disposition != ToolRecoveryDisposition::NotStarted {
                    return Err(JournalError::Lifecycle(format!(
                        "tool {call_id:?} crossed the start boundary more than once"
                    )));
                }
                call.disposition = ToolRecoveryDisposition::OutcomeUnknown;
            }
            ExecutionEvent::ToolFinished {
                call_id,
                success,
                output_sha256,
            } => {
                let call = calls.get_mut(call_id).ok_or_else(|| {
                    JournalError::Lifecycle(format!(
                        "tool {call_id:?} finished before a durable request"
                    ))
                })?;
                if call.disposition != ToolRecoveryDisposition::OutcomeUnknown {
                    return Err(JournalError::Lifecycle(format!(
                        "tool {call_id:?} finished without exactly one durable start"
                    )));
                }
                call.disposition = ToolRecoveryDisposition::Completed {
                    success: *success,
                    output_sha256: output_sha256.clone(),
                };
            }
            _ => {}
        }
    }

    Ok(calls.into_values().collect())
}

fn validate_stream_id(stream_id: &str) -> Result<(), JournalError> {
    if stream_id.is_empty() {
        return Err(JournalError::InvalidStreamId("must not be empty".to_string()));
    }
    if stream_id.len() > 256 {
        return Err(JournalError::InvalidStreamId(
            "must not exceed 256 bytes".to_string(),
        ));
    }
    if stream_id.chars().any(|character| character.is_control()) {
        return Err(JournalError::InvalidStreamId(
            "must not contain control characters".to_string(),
        ));
    }
    Ok(())
}

fn validate_next(
    prior: &[ExecutionRecord],
    record: &ExecutionRecord,
    expected_stream_id: &str,
) -> Result<(), JournalError> {
    if record.schema_version != SCHEMA_VERSION {
        return Err(JournalError::Integrity(format!(
            "unsupported schema version {} at sequence {}",
            record.schema_version, record.sequence
        )));
    }
    if record.stream_id != expected_stream_id {
        return Err(JournalError::Integrity(format!(
            "stream mismatch at sequence {}",
            record.sequence
        )));
    }
    let expected_sequence = prior.len() as u64;
    if record.sequence != expected_sequence {
        return Err(JournalError::Integrity(format!(
            "expected sequence {expected_sequence}, found {}",
            record.sequence
        )));
    }
    let expected_previous = prior
        .last()
        .map(|item| item.hash.as_str())
        .unwrap_or(GENESIS_HASH);
    if record.previous_hash != expected_previous {
        return Err(JournalError::Integrity(format!(
            "broken previous-hash link at sequence {}",
            record.sequence
        )));
    }
    let expected_hash = record_hash(
        &record.stream_id,
        record.sequence,
        &record.previous_hash,
        &record.event,
    )?;
    if record.hash != expected_hash {
        return Err(JournalError::Integrity(format!(
            "content hash mismatch at sequence {}",
            record.sequence
        )));
    }
    Ok(())
}

fn record_hash(
    stream_id: &str,
    sequence: u64,
    previous_hash: &str,
    event: &ExecutionEvent,
) -> Result<String, JournalError> {
    let event_bytes = serde_json::to_vec(event)?;
    let mut hasher = Sha256::new();
    hasher.update(SCHEMA_VERSION.to_le_bytes());
    hasher.update(sequence.to_le_bytes());
    hash_len_prefixed(&mut hasher, stream_id.as_bytes());
    hash_len_prefixed(&mut hasher, previous_hash.as_bytes());
    hash_len_prefixed(&mut hasher, &event_bytes);
    let digest = hasher.finalize();
    Ok(hex(&digest))
}

fn hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(0);

    fn scratch(tag: &str) -> PathBuf {
        let id = NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "ccos-enterprise-execution-{tag}-{}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory");
        dir
    }

    fn journal(tag: &str) -> (PathBuf, ExecutionJournal) {
        let dir = scratch(tag);
        let path = dir.join("execution.jsonl");
        let report = ExecutionJournal::open(&path, "tenant-acme/session-1").expect("open");
        assert_eq!(report.tail_repair, TailRepair::None);
        (dir, report.journal)
    }

    fn requested(call_id: &str, tool: &str) -> ExecutionEvent {
        ExecutionEvent::ToolRequested {
            turn_id: "turn-1".to_string(),
            step_id: "step-1".to_string(),
            call_id: call_id.to_string(),
            tool: tool.to_string(),
            input_sha256: "input-hash".to_string(),
        }
    }

    #[test]
    fn append_reopen_and_verify_from_genesis() {
        let (dir, mut journal) = journal("reopen");
        journal
            .append(ExecutionEvent::TurnStarted {
                turn_id: "turn-1".to_string(),
            })
            .expect("turn");
        journal.append(requested("call-1", "cargo-test")).expect("request");
        let head = journal.head_hash().to_string();
        drop(journal);

        let path = dir.join("execution.jsonl");
        let reopened = ExecutionJournal::open(&path, "tenant-acme/session-1").expect("reopen");
        assert_eq!(reopened.tail_repair, TailRepair::None);
        assert_eq!(reopened.journal.len(), 2);
        assert_eq!(reopened.journal.head_hash(), head);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn tampering_breaks_the_hash_chain() {
        let (dir, mut journal) = journal("tamper");
        journal.append(requested("call-1", "cargo-test")).expect("request");
        drop(journal);

        let path = dir.join("execution.jsonl");
        let encoded = std::fs::read_to_string(&path).expect("read");
        let tampered = encoded.replacen("cargo-test", "cargo-hack", 1);
        std::fs::write(&path, tampered).expect("tamper");
        let error = match ExecutionJournal::open(&path, "tenant-acme/session-1") {
            Ok(_) => panic!("tampering must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, JournalError::Integrity(_)), "{error}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn incomplete_unterminated_tail_is_discarded() {
        let (dir, mut journal) = journal("partial-tail");
        journal.append(requested("call-1", "cargo-test")).expect("request");
        drop(journal);

        let path = dir.join("execution.jsonl");
        let mut file = OpenOptions::new().append(true).open(&path).expect("append");
        file.write_all(br#"{"schema_version":1"#).expect("partial");
        file.sync_data().expect("sync partial");
        drop(file);

        let reopened = ExecutionJournal::open(&path, "tenant-acme/session-1").expect("repair");
        assert!(matches!(
            reopened.tail_repair,
            TailRepair::DiscardedPartialTail { bytes } if bytes > 0
        ));
        assert_eq!(reopened.journal.len(), 1);
        assert!(std::fs::read(&path).expect("read repaired").ends_with(b"\n"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn complete_record_missing_only_newline_is_preserved() {
        let (dir, mut journal) = journal("missing-newline");
        journal.append(requested("call-1", "cargo-test")).expect("request");
        drop(journal);

        let path = dir.join("execution.jsonl");
        let mut bytes = std::fs::read(&path).expect("read");
        assert_eq!(bytes.pop(), Some(b'\n'));
        std::fs::write(&path, bytes).expect("remove newline");

        let reopened = ExecutionJournal::open(&path, "tenant-acme/session-1").expect("repair");
        assert_eq!(reopened.tail_repair, TailRepair::CompletedMissingNewline);
        assert_eq!(reopened.journal.len(), 1);
        assert!(std::fs::read(&path).expect("read repaired").ends_with(b"\n"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn requested_without_start_is_not_started() {
        let (dir, mut journal) = journal("not-started");
        journal.append(requested("call-1", "cargo-test")).expect("request");
        let recovered = journal.recover_tools().expect("recover");
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].disposition, ToolRecoveryDisposition::NotStarted);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn started_without_result_is_outcome_unknown() {
        let (dir, mut journal) = journal("unknown");
        journal.append(requested("call-1", "git-push")).expect("request");
        journal
            .append(ExecutionEvent::ToolStarted {
                call_id: "call-1".to_string(),
            })
            .expect("start");
        let recovered = journal.recover_tools().expect("recover");
        assert_eq!(
            recovered[0].disposition,
            ToolRecoveryDisposition::OutcomeUnknown
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn durable_result_marks_tool_completed() {
        let (dir, mut journal) = journal("completed");
        journal.append(requested("call-1", "cargo-test")).expect("request");
        journal
            .append(ExecutionEvent::ToolStarted {
                call_id: "call-1".to_string(),
            })
            .expect("start");
        journal
            .append(ExecutionEvent::ToolFinished {
                call_id: "call-1".to_string(),
                success: true,
                output_sha256: "output-hash".to_string(),
            })
            .expect("finish");
        let recovered = journal.recover_tools().expect("recover");
        assert_eq!(
            recovered[0].disposition,
            ToolRecoveryDisposition::Completed {
                success: true,
                output_sha256: "output-hash".to_string(),
            }
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn invalid_tool_lifecycle_is_refused_during_recovery() {
        let (dir, mut journal) = journal("bad-lifecycle");
        journal
            .append(ExecutionEvent::ToolStarted {
                call_id: "call-1".to_string(),
            })
            .expect("journal records facts even when caller is buggy");
        let error = journal.recover_tools().expect_err("lifecycle must fail");
        assert!(matches!(error, JournalError::Lifecycle(_)), "{error}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_journal_cannot_be_rebound_to_another_stream() {
        let (dir, mut journal) = journal("stream-binding");
        journal.append(requested("call-1", "cargo-test")).expect("request");
        drop(journal);
        let path = dir.join("execution.jsonl");
        let error = match ExecutionJournal::open(&path, "tenant-globex/session-1") {
            Ok(_) => panic!("stream rebinding must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, JournalError::Integrity(_)), "{error}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
