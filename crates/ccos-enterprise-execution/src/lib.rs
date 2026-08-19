//! Canonical durable Enterprise execution journal.
//!
//! This crate is the single source of truth for orchestration facts shared by
//! tenant sessions and governed host adapters. CCOS Core keeps its cognitive
//! oplog unchanged; Enterprise records turns, steps, approvals and physical
//! tool attempts here.
//!
//! The JSONL schema remains version 1 and is wire-compatible with the journals
//! historically emitted by `ccos-enterprise-sessions` and the DeepSeek Harness
//! MCP transport.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Current JSONL record schema.
pub const SCHEMA_VERSION: u16 = 1;

/// Predecessor of the first record in a stream.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// A durable execution fact.
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
    /// The model requested the call, but the runtime has not crossed the
    /// durable execution boundary.
    ToolRequested {
        turn_id: String,
        step_id: String,
        call_id: String,
        tool: String,
        input_sha256: String,
    },
    /// Written and synced before invoking the tool.
    ToolStarted {
        call_id: String,
    },
    /// Written after the tool returned.
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

/// One hash-chained record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRecord {
    pub schema_version: u16,
    pub stream_id: String,
    pub sequence: u64,
    pub previous_hash: String,
    pub event: ExecutionEvent,
    pub hash: String,
}

/// Repair applied to an interrupted final append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailRepair {
    None,
    CompletedMissingNewline,
    DiscardedPartialTail { bytes: usize },
}

/// Result of opening a journal.
pub struct OpenReport {
    pub journal: ExecutionJournal,
    pub tail_repair: TailRepair,
}

/// Journal and lifecycle failures.
#[derive(Debug)]
pub enum JournalError {
    Io(std::io::Error),
    Json(serde_json::Error),
    InvalidStreamId(String),
    Integrity(String),
    Lifecycle(String),
    /// A live handle observed an ambiguous durable-write failure. It must be
    /// dropped and reopened before any further append or recovery decision.
    Poisoned(String),
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "execution journal I/O: {error}"),
            Self::Json(error) => write!(f, "execution journal JSON: {error}"),
            Self::InvalidStreamId(detail) => write!(f, "invalid execution stream id: {detail}"),
            Self::Integrity(detail) => write!(f, "execution journal integrity: {detail}"),
            Self::Lifecycle(detail) => write!(f, "execution lifecycle: {detail}"),
            Self::Poisoned(detail) => write!(f, "execution journal poisoned: {detail}"),
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

/// Durable, stream-bound execution journal.
pub struct ExecutionJournal {
    path: PathBuf,
    stream_id: String,
    records: Vec<ExecutionRecord>,
    poisoned: bool,
}

impl ExecutionJournal {
    /// Open or create a stream and verify it from genesis.
    ///
    /// Only an unterminated final JSON fragment is discarded automatically.
    /// A malformed newline-terminated record or a parseable record with a bad
    /// hash is corruption, never a repairable crash tail.
    pub fn open(
        path: impl AsRef<Path>,
        stream_id: impl Into<String>,
    ) -> Result<OpenReport, JournalError> {
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
            match serde_json::from_slice::<ExecutionRecord>(tail) {
                Ok(record) => {
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
                poisoned: false,
            },
            tail_repair,
        })
    }

    /// Append, flush and sync one fact before returning.
    ///
    /// Once persistence begins, any I/O error poisons this live handle. The
    /// file may contain zero, some or all of the encoded record, so advancing
    /// only the in-memory sequence would be unsafe. Reopening re-verifies the
    /// durable prefix and repairs only the permitted unterminated tail.
    pub fn append(&mut self, event: ExecutionEvent) -> Result<&ExecutionRecord, JournalError> {
        self.append_with_writer(event, |file, encoded| file.write_all(encoded))
    }

    fn append_with_writer<F>(
        &mut self,
        event: ExecutionEvent,
        writer: F,
    ) -> Result<&ExecutionRecord, JournalError>
    where
        F: FnOnce(&mut File, &[u8]) -> std::io::Result<()>,
    {
        self.ensure_usable("append")?;

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

        let persist = (|| -> std::io::Result<()> {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            writer(&mut file, &encoded)?;
            file.sync_data()
        })();
        if let Err(error) = persist {
            self.poisoned = true;
            return Err(JournalError::Io(error));
        }

        self.records.push(record);
        Ok(self.records.last().expect("record was just pushed"))
    }

    fn ensure_usable(&self, operation: &str) -> Result<(), JournalError> {
        if self.poisoned {
            Err(JournalError::Poisoned(format!(
                "{operation} refused after a previous durable write error; reopen the journal to repair and verify the tail"
            )))
        } else {
            Ok(())
        }
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

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub fn head_hash(&self) -> &str {
        self.records
            .last()
            .map(|record| record.hash.as_str())
            .unwrap_or(GENESIS_HASH)
    }

    /// Rebuild tool recovery state from the authoritative stream.
    ///
    /// Recovery decisions are refused on a poisoned live handle because its
    /// in-memory prefix may be behind bytes that reached the file.
    pub fn recover_tools(&self) -> Result<Vec<ToolRecovery>, JournalError> {
        self.ensure_usable("recovery")?;
        recover_tools(&self.records)
    }
}

/// One tool call reconstructed from the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRecovery {
    pub call_id: String,
    pub tool: String,
    pub disposition: ToolRecoveryDisposition,
}

/// Conservative restart policy for a tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolRecoveryDisposition {
    /// A request exists, but no durable start boundary exists.
    NotStarted,
    /// A durable start exists without a durable result. The side effect may
    /// already have happened and automatic replay is unsafe.
    OutcomeUnknown,
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
        return Err(JournalError::InvalidStreamId("must not be empty".into()));
    }
    if stream_id.len() > 256 {
        return Err(JournalError::InvalidStreamId(
            "must not exceed 256 bytes".into(),
        ));
    }
    if stream_id.chars().any(char::is_control) {
        return Err(JournalError::InvalidStreamId(
            "must not contain control characters".into(),
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
    let mut payload = Vec::new();
    payload.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    payload.extend_from_slice(&sequence.to_le_bytes());
    append_len_prefixed(&mut payload, stream_id.as_bytes());
    append_len_prefixed(&mut payload, previous_hash.as_bytes());
    append_len_prefixed(&mut payload, &event_bytes);
    Ok(hex(Sha256::digest(&payload).as_slice()))
}

fn append_len_prefixed(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    output.extend_from_slice(bytes);
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
        journal
            .append(requested("call-1", "cargo-test"))
            .expect("request");
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
        journal
            .append(requested("call-1", "cargo-test"))
            .expect("request");
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
        journal
            .append(requested("call-1", "cargo-test"))
            .expect("request");
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
        assert!(std::fs::read(&path)
            .expect("read repaired")
            .ends_with(b"\n"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn started_without_result_is_outcome_unknown() {
        let (dir, mut journal) = journal("unknown");
        journal
            .append(requested("call-1", "git-push"))
            .expect("request");
        journal
            .append(ExecutionEvent::ToolStarted {
                call_id: "call-1".to_string(),
            })
            .expect("start");
        assert_eq!(
            journal.recover_tools().expect("recover")[0].disposition,
            ToolRecoveryDisposition::OutcomeUnknown
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn append_error_poisons_handle_until_reopen_repairs_tail() {
        let dir = scratch("poison");
        let path = dir.join("execution.jsonl");
        let mut journal = ExecutionJournal::open(&path, "tenant-acme/session-1")
            .expect("open")
            .journal;

        let error = journal
            .append_with_writer(
                ExecutionEvent::TurnStarted {
                    turn_id: "turn-partial".to_string(),
                },
                |file, encoded| {
                    let partial = (encoded.len() / 2).max(1);
                    file.write_all(&encoded[..partial])?;
                    file.sync_data()?;
                    Err(std::io::Error::other("simulated append failure"))
                },
            )
            .expect_err("partial write must fail");
        assert!(matches!(error, JournalError::Io(_)));
        assert!(journal.is_poisoned());
        assert!(matches!(
            journal.recover_tools(),
            Err(JournalError::Poisoned(_))
        ));
        assert!(matches!(
            journal.append(ExecutionEvent::TurnStarted {
                turn_id: "must-not-append".to_string(),
            }),
            Err(JournalError::Poisoned(_))
        ));
        drop(journal);

        let report = ExecutionJournal::open(&path, "tenant-acme/session-1").expect("repair");
        assert!(matches!(
            report.tail_repair,
            TailRepair::DiscardedPartialTail { bytes } if bytes > 0
        ));
        let mut repaired = report.journal;
        assert!(!repaired.is_poisoned());
        repaired
            .append(ExecutionEvent::TurnStarted {
                turn_id: "after-repair".to_string(),
            })
            .expect("append after repair");
        assert_eq!(repaired.len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }
}
