#![forbid(unsafe_code)]
//! Shared durable Enterprise execution journal.
//!
//! This crate owns the append-only, hash-chained execution facts used by
//! Enterprise hosts and session orchestration. Core's cognitive oplog remains
//! unchanged. A failed append is fail-stop: the live journal is poisoned until
//! it is reopened, at which point only an unterminated crash tail may be
//! repaired.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const SCHEMA_VERSION: u16 = 1;
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExecutionEvent {
    TurnStarted { turn_id: String },
    StepStarted { turn_id: String, step_id: String },
    UserMessage { turn_id: String, message_id: String, content_sha256: String },
    AssistantMessage {
        turn_id: String,
        step_id: String,
        message_id: String,
        content_sha256: String,
    },
    ToolRequested {
        turn_id: String,
        step_id: String,
        call_id: String,
        tool: String,
        input_sha256: String,
    },
    ToolStarted { call_id: String },
    ToolFinished { call_id: String, success: bool, output_sha256: String },
    ApprovalAsked { approval_id: String, capability: String },
    ApprovalDecided { approval_id: String, allowed: bool },
    StepFinished { turn_id: String, step_id: String, success: bool },
    TurnFinished { turn_id: String, success: bool },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRecord {
    pub schema_version: u16,
    pub stream_id: String,
    pub sequence: u64,
    pub previous_hash: String,
    pub event: ExecutionEvent,
    pub hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailRepair {
    None,
    CompletedMissingNewline,
    DiscardedPartialTail { bytes: usize },
}

pub struct OpenReport {
    pub journal: ExecutionJournal,
    pub tail_repair: TailRepair,
}

#[derive(Debug)]
pub enum JournalError {
    Io(std::io::Error),
    Json(serde_json::Error),
    InvalidStreamId(String),
    Integrity(String),
    Lifecycle(String),
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
    fn from(value: std::io::Error) -> Self { Self::Io(value) }
}
impl From<serde_json::Error> for JournalError {
    fn from(value: serde_json::Error) -> Self { Self::Json(value) }
}

pub struct ExecutionJournal {
    path: PathBuf,
    stream_id: String,
    records: Vec<ExecutionRecord>,
    poisoned: bool,
}

impl ExecutionJournal {
    pub fn open(path: impl AsRef<Path>, stream_id: impl Into<String>) -> Result<OpenReport, JournalError> {
        let path = path.as_ref().to_path_buf();
        let stream_id = stream_id.into();
        validate_stream_id(&stream_id)?;
        if let Some(parent) = path.parent() { std::fs::create_dir_all(parent)?; }
        if !path.exists() { File::create(&path)?.sync_data()?; }

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
                    return Err(JournalError::Integrity(format!("empty durable line at byte offset {cursor}")));
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
            journal: Self { path, stream_id, records, poisoned: false },
            tail_repair,
        })
    }

    pub fn append(&mut self, event: ExecutionEvent) -> Result<&ExecutionRecord, JournalError> {
        self.append_with_writer(event, |file, encoded| file.write_all(encoded))
    }

    fn append_with_writer<F>(&mut self, event: ExecutionEvent, writer: F) -> Result<&ExecutionRecord, JournalError>
    where
        F: FnOnce(&mut File, &[u8]) -> std::io::Result<()>,
    {
        if self.poisoned {
            return Err(JournalError::Poisoned(
                "append refused after a previous durable write error; reopen the journal to repair the tail".into(),
            ));
        }
        let sequence = self.records.len() as u64;
        let previous_hash = self.records.last().map(|record| record.hash.clone()).unwrap_or_else(|| GENESIS_HASH.to_string());
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
            let mut file = OpenOptions::new().create(true).append(true).open(&self.path)?;
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

    pub fn path(&self) -> &Path { &self.path }
    pub fn stream_id(&self) -> &str { &self.stream_id }
    pub fn records(&self) -> &[ExecutionRecord] { &self.records }
    pub fn len(&self) -> usize { self.records.len() }
    pub fn is_empty(&self) -> bool { self.records.is_empty() }
    pub fn is_poisoned(&self) -> bool { self.poisoned }
    pub fn head_hash(&self) -> &str {
        self.records.last().map(|record| record.hash.as_str()).unwrap_or(GENESIS_HASH)
    }
    pub fn recover_tools(&self) -> Result<Vec<ToolRecovery>, JournalError> { recover_tools(&self.records) }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRecovery {
    pub call_id: String,
    pub tool: String,
    pub disposition: ToolRecoveryDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolRecoveryDisposition {
    NotStarted,
    OutcomeUnknown,
    Completed { success: bool, output_sha256: String },
}

fn recover_tools(records: &[ExecutionRecord]) -> Result<Vec<ToolRecovery>, JournalError> {
    let mut calls: BTreeMap<String, ToolRecovery> = BTreeMap::new();
    for record in records {
        match &record.event {
            ExecutionEvent::ToolRequested { call_id, tool, .. } => {
                if calls.contains_key(call_id) {
                    return Err(JournalError::Lifecycle(format!("duplicate tool request for call {call_id:?}")));
                }
                calls.insert(call_id.clone(), ToolRecovery {
                    call_id: call_id.clone(), tool: tool.clone(), disposition: ToolRecoveryDisposition::NotStarted,
                });
            }
            ExecutionEvent::ToolStarted { call_id } => {
                let call = calls.get_mut(call_id).ok_or_else(|| JournalError::Lifecycle(format!("tool {call_id:?} started before a durable request")))?;
                if call.disposition != ToolRecoveryDisposition::NotStarted {
                    return Err(JournalError::Lifecycle(format!("tool {call_id:?} crossed the start boundary more than once")));
                }
                call.disposition = ToolRecoveryDisposition::OutcomeUnknown;
            }
            ExecutionEvent::ToolFinished { call_id, success, output_sha256 } => {
                let call = calls.get_mut(call_id).ok_or_else(|| JournalError::Lifecycle(format!("tool {call_id:?} finished before a durable request")))?;
                if call.disposition != ToolRecoveryDisposition::OutcomeUnknown {
                    return Err(JournalError::Lifecycle(format!("tool {call_id:?} finished without exactly one durable start")));
                }
                call.disposition = ToolRecoveryDisposition::Completed { success: *success, output_sha256: output_sha256.clone() };
            }
            _ => {}
        }
    }
    Ok(calls.into_values().collect())
}

fn validate_stream_id(stream_id: &str) -> Result<(), JournalError> {
    if stream_id.is_empty() { return Err(JournalError::InvalidStreamId("must not be empty".into())); }
    if stream_id.len() > 256 { return Err(JournalError::InvalidStreamId("must not exceed 256 bytes".into())); }
    if stream_id.chars().any(char::is_control) {
        return Err(JournalError::InvalidStreamId("must not contain control characters".into()));
    }
    Ok(())
}

fn validate_next(prior: &[ExecutionRecord], record: &ExecutionRecord, expected_stream_id: &str) -> Result<(), JournalError> {
    if record.schema_version != SCHEMA_VERSION {
        return Err(JournalError::Integrity(format!("unsupported schema version {} at sequence {}", record.schema_version, record.sequence)));
    }
    if record.stream_id != expected_stream_id {
        return Err(JournalError::Integrity(format!("stream mismatch at sequence {}", record.sequence)));
    }
    let expected_sequence = prior.len() as u64;
    if record.sequence != expected_sequence {
        return Err(JournalError::Integrity(format!("expected sequence {expected_sequence}, found {}", record.sequence)));
    }
    let expected_previous = prior.last().map(|item| item.hash.as_str()).unwrap_or(GENESIS_HASH);
    if record.previous_hash != expected_previous {
        return Err(JournalError::Integrity(format!("broken previous-hash link at sequence {}", record.sequence)));
    }
    let expected_hash = record_hash(&record.stream_id, record.sequence, &record.previous_hash, &record.event)?;
    if record.hash != expected_hash {
        return Err(JournalError::Integrity(format!("content hash mismatch at sequence {}", record.sequence)));
    }
    Ok(())
}

fn record_hash(stream_id: &str, sequence: u64, previous_hash: &str, event: &ExecutionEvent) -> Result<String, JournalError> {
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
        let dir = std::env::temp_dir().join(format!("ccos-enterprise-execution-{tag}-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory");
        dir
    }

    fn journal(tag: &str) -> (PathBuf, ExecutionJournal) {
        let dir = scratch(tag);
        let report = ExecutionJournal::open(dir.join("execution.jsonl"), "tenant-acme/session-1").expect("open");
        assert_eq!(report.tail_repair, TailRepair::None);
        (dir, report.journal)
    }

    fn requested(call_id: &str, tool: &str) -> ExecutionEvent {
        ExecutionEvent::ToolRequested {
            turn_id: "turn-1".into(), step_id: "step-1".into(), call_id: call_id.into(), tool: tool.into(), input_sha256: "input-hash".into(),
        }
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(hex(Sha256::digest(b"abc").as_slice()), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn append_reopen_and_verify_from_genesis() {
        let (dir, mut journal) = journal("reopen");
        journal.append(ExecutionEvent::TurnStarted { turn_id: "turn-1".into() }).unwrap();
        journal.append(requested("call-1", "cargo-test")).unwrap();
        let head = journal.head_hash().to_string();
        drop(journal);
        let reopened = ExecutionJournal::open(dir.join("execution.jsonl"), "tenant-acme/session-1").unwrap();
        assert_eq!(reopened.tail_repair, TailRepair::None);
        assert_eq!(reopened.journal.len(), 2);
        assert_eq!(reopened.journal.head_hash(), head);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn tampering_breaks_the_hash_chain() {
        let (dir, mut journal) = journal("tamper");
        journal.append(requested("call-1", "cargo-test")).unwrap();
        drop(journal);
        let path = dir.join("execution.jsonl");
        let encoded = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, encoded.replacen("cargo-test", "cargo-hack", 1)).unwrap();
        let error = ExecutionJournal::open(&path, "tenant-acme/session-1").err().expect("tampering must fail");
        assert!(matches!(error, JournalError::Integrity(_)), "{error}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn incomplete_unterminated_tail_is_discarded() {
        let (dir, mut journal) = journal("partial-tail");
        journal.append(requested("call-1", "cargo-test")).unwrap();
        drop(journal);
        let path = dir.join("execution.jsonl");
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(br#"{"schema_version":1"#).unwrap();
        file.sync_data().unwrap();
        drop(file);
        let reopened = ExecutionJournal::open(&path, "tenant-acme/session-1").unwrap();
        assert!(matches!(reopened.tail_repair, TailRepair::DiscardedPartialTail { bytes } if bytes > 0));
        assert_eq!(reopened.journal.len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn complete_record_missing_only_newline_is_preserved() {
        let (dir, mut journal) = journal("missing-newline");
        journal.append(requested("call-1", "cargo-test")).unwrap();
        drop(journal);
        let path = dir.join("execution.jsonl");
        let mut bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.pop(), Some(b'\n'));
        std::fs::write(&path, bytes).unwrap();
        let reopened = ExecutionJournal::open(&path, "tenant-acme/session-1").unwrap();
        assert_eq!(reopened.tail_repair, TailRepair::CompletedMissingNewline);
        assert_eq!(reopened.journal.len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn recovery_distinguishes_not_started_unknown_and_completed() {
        let (dir, mut journal) = journal("recovery");
        journal.append(requested("call-1", "cargo-test")).unwrap();
        assert_eq!(journal.recover_tools().unwrap()[0].disposition, ToolRecoveryDisposition::NotStarted);
        journal.append(ExecutionEvent::ToolStarted { call_id: "call-1".into() }).unwrap();
        assert_eq!(journal.recover_tools().unwrap()[0].disposition, ToolRecoveryDisposition::OutcomeUnknown);
        journal.append(ExecutionEvent::ToolFinished { call_id: "call-1".into(), success: true, output_sha256: "output-hash".into() }).unwrap();
        assert_eq!(journal.recover_tools().unwrap()[0].disposition, ToolRecoveryDisposition::Completed { success: true, output_sha256: "output-hash".into() });
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn append_error_poisons_instance_until_reopen_repairs_tail() {
        let (dir, mut journal) = journal("poison");
        let error = journal.append_with_writer(
            ExecutionEvent::TurnStarted { turn_id: "turn-partial".into() },
            |file, encoded| {
                let partial = (encoded.len() / 2).max(1);
                file.write_all(&encoded[..partial])?;
                file.sync_data()?;
                Err(std::io::Error::other("simulated append failure"))
            },
        ).unwrap_err();
        assert!(matches!(error, JournalError::Io(_)));
        assert!(journal.is_poisoned());
        assert!(matches!(journal.append(ExecutionEvent::TurnStarted { turn_id: "must-not-append".into() }), Err(JournalError::Poisoned(_))));
        drop(journal);

        let path = dir.join("execution.jsonl");
        let report = ExecutionJournal::open(&path, "tenant-acme/session-1").unwrap();
        assert!(matches!(report.tail_repair, TailRepair::DiscardedPartialTail { bytes } if bytes > 0));
        let mut repaired = report.journal;
        assert!(!repaired.is_poisoned());
        repaired.append(ExecutionEvent::TurnStarted { turn_id: "after-repair".into() }).unwrap();
        assert_eq!(repaired.len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_journal_cannot_be_rebound_to_another_stream() {
        let (dir, mut journal) = journal("stream-binding");
        journal.append(requested("call-1", "cargo-test")).unwrap();
        drop(journal);
        let error = ExecutionJournal::open(dir.join("execution.jsonl"), "tenant-globex/session-1").err().expect("stream rebinding must fail");
        assert!(matches!(error, JournalError::Integrity(_)), "{error}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
