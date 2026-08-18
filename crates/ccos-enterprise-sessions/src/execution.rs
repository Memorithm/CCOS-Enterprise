//! Durable Enterprise execution journal for turns, steps and tool calls.
//!
//! This module is intentionally owned by `ccos-enterprise-sessions`: CCOS Core
//! keeps its existing cognitive oplog unchanged, while Enterprise records the
//! orchestration plane around Core sessions.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Current JSONL record schema.
pub const SCHEMA_VERSION: u16 = 1;

/// Predecessor of the first record in a stream.
pub const GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

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

/// Durable, tenant/session-bound execution stream.
pub struct ExecutionJournal {
    path: PathBuf,
    stream_id: String,
    records: Vec<ExecutionRecord>,
}

impl ExecutionJournal {
    /// Open or create a stream and verify it from genesis.
    ///
    /// Only an unterminated final JSON fragment is discarded automatically.
    /// A malformed newline-terminated record or a parseable record with a bad
    /// hash is treated as corruption, never as a repairable crash tail.
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

    /// Append, flush and sync one fact before returning.
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

    /// Rebuild tool recovery state from the authoritative stream.
    pub fn recover_tools(&self) -> Result<Vec<ToolRecovery>, JournalError> {
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
    let mut payload = Vec::new();
    payload.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    payload.extend_from_slice(&sequence.to_le_bytes());
    append_len_prefixed(&mut payload, stream_id.as_bytes());
    append_len_prefixed(&mut payload, previous_hash.as_bytes());
    append_len_prefixed(&mut payload, &event_bytes);
    Ok(hex(&sha256(&payload)))
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

fn sha256(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
        0x1f83d9ab, 0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
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
    fn sha256_matches_known_vector() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
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
            .expect("record");
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
