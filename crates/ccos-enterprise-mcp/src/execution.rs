//! Durable Enterprise execution journal shared by governed MCP hosts.
//!
//! The schema intentionally matches the execution journal historically shipped
//! by `ccos-enterprise-sessions`. Keeping the orchestration facts at the MCP
//! boundary lets hosts such as DeepSeek Harness preserve their own turn/step
//! and physical-attempt identities without changing Core's cognitive oplog.

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
    ToolRequested {
        turn_id: String,
        step_id: String,
        call_id: String,
        tool: String,
        input_sha256: String,
    },
    ToolStarted {
        call_id: String,
    },
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

pub struct ExecutionJournal {
    path: PathBuf,
    stream_id: String,
    records: Vec<ExecutionRecord>,
}

impl ExecutionJournal {
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
            },
            tail_repair,
        })
    }

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
    pub fn recover_tools(&self) -> Result<Vec<ToolRecovery>, JournalError> {
        recover_tools(&self.records)
    }
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
    Completed {
        success: bool,
        output_sha256: String,
    },
}

fn recover_tools(records: &[ExecutionRecord]) -> Result<Vec<ToolRecovery>, JournalError> {
    let mut calls = BTreeMap::new();
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

    #[test]
    fn started_without_finish_is_unknown_and_can_be_completed() {
        let root = std::env::temp_dir().join(format!("ccos-mcp-execution-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let path = root.join("execution.jsonl");
        let mut journal = ExecutionJournal::open(&path, "tenant/acme/mcp")
            .unwrap()
            .journal;
        journal
            .append(ExecutionEvent::ToolRequested {
                turn_id: "t".into(),
                step_id: "s".into(),
                call_id: "c".into(),
                tool: "recall".into(),
                input_sha256: "i".into(),
            })
            .unwrap();
        journal
            .append(ExecutionEvent::ToolStarted {
                call_id: "c".into(),
            })
            .unwrap();
        assert_eq!(
            journal.recover_tools().unwrap()[0].disposition,
            ToolRecoveryDisposition::OutcomeUnknown
        );
        journal
            .append(ExecutionEvent::ToolFinished {
                call_id: "c".into(),
                success: true,
                output_sha256: "o".into(),
            })
            .unwrap();
        assert!(matches!(
            journal.recover_tools().unwrap()[0].disposition,
            ToolRecoveryDisposition::Completed { success: true, .. }
        ));
        let _ = std::fs::remove_dir_all(root);
    }
}
