//! Durable journal for the CCOS Enterprise Knowledge Plane.
//!
//! The journal is the authority. [`KnowledgeStore`] keeps no hidden mutation path:
//! every accepted append is first validated by replaying it against a cloned canonical
//! [`KnowledgeState`], then serialized as one JSON line and `sync_data`'d before the
//! in-memory state advances. A restart reconstructs state exclusively from that journal.
//!
//! A crash may leave an unterminated final JSON fragment. Only that final fragment is
//! discarded; malformed complete lines are corruption and fail closed.

#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use ccos_enterprise_knowledge::{JournalEntry, KnowledgeError, KnowledgeState};

pub const JOURNAL_FILE: &str = "knowledge.jsonl";
pub const LOCK_FILE: &str = "knowledge.lock";

#[derive(Debug)]
pub enum StoreError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    JournalCorrupt {
        path: PathBuf,
        line: usize,
        detail: String,
    },
    JournalInvalid {
        path: PathBuf,
        line: usize,
        detail: String,
    },
    Serialization(String),
    Knowledge(KnowledgeError),
    AlreadyOpen {
        path: PathBuf,
    },
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::JournalCorrupt { path, line, detail } => {
                write!(
                    f,
                    "{}:{line}: corrupt knowledge journal: {detail}",
                    path.display()
                )
            }
            Self::JournalInvalid { path, line, detail } => {
                write!(
                    f,
                    "{}:{line}: invalid knowledge journal: {detail}",
                    path.display()
                )
            }
            Self::Serialization(detail) => {
                write!(f, "cannot serialize knowledge journal: {detail}")
            }
            Self::Knowledge(error) => write!(f, "knowledge mutation refused: {error}"),
            Self::AlreadyOpen { path } => write!(
                f,
                "{}: another live writer already owns this knowledge store",
                path.display()
            ),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Knowledge(error) => Some(error),
            _ => None,
        }
    }
}

impl From<KnowledgeError> for StoreError {
    fn from(value: KnowledgeError) -> Self {
        Self::Knowledge(value)
    }
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> StoreError + '_ {
    move |source| StoreError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[derive(Debug)]
pub struct Loaded {
    pub entries: Vec<JournalEntry>,
    pub state: KnowledgeState,
    /// Bytes ignored after the last newline because the process died mid-append.
    pub torn_tail: usize,
}

pub struct KnowledgeStore {
    root: PathBuf,
    journal: BufWriter<File>,
    state: KnowledgeState,
    _lock: File,
}

impl KnowledgeStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root).map_err(io(&root))?;

        let lock_path = root.join(LOCK_FILE);
        let lock = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(io(&lock_path))?;
        lock.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => StoreError::AlreadyOpen {
                path: lock_path.clone(),
            },
            std::fs::TryLockError::Error(source) => StoreError::Io {
                path: lock_path.clone(),
                source,
            },
        })?;

        let loaded = Self::load(&root)?;
        let journal_path = root.join(JOURNAL_FILE);
        let journal = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&journal_path)
            .map_err(io(&journal_path))?;

        Ok(Self {
            root,
            journal: BufWriter::new(journal),
            state: loaded.state,
            _lock: lock,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn state(&self) -> &KnowledgeState {
        &self.state
    }

    pub fn next_sequence(&self) -> u64 {
        self.state.next_sequence()
    }

    pub fn load(root: impl AsRef<Path>) -> Result<Loaded, StoreError> {
        let journal_path = root.as_ref().join(JOURNAL_FILE);
        if !journal_path.exists() {
            return Ok(Loaded {
                entries: Vec::new(),
                state: KnowledgeState::new(),
                torn_tail: 0,
            });
        }

        let mut file = File::open(&journal_path).map_err(io(&journal_path))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(io(&journal_path))?;
        let (complete, torn_tail) = complete_prefix(&bytes);

        let mut entries = Vec::new();
        for (index, line) in complete.split(|byte| *byte == b'\n').enumerate() {
            if line.is_empty() {
                continue;
            }
            let entry = serde_json::from_slice::<JournalEntry>(line).map_err(|error| {
                StoreError::JournalCorrupt {
                    path: journal_path.clone(),
                    line: index + 1,
                    detail: error.to_string(),
                }
            })?;
            entries.push(entry);
        }

        let mut state = KnowledgeState::new();
        for (index, entry) in entries.iter().cloned().enumerate() {
            state
                .apply(entry)
                .map_err(|error| StoreError::JournalInvalid {
                    path: journal_path.clone(),
                    line: index + 1,
                    detail: error.to_string(),
                })?;
        }

        Ok(Loaded {
            entries,
            state,
            torn_tail,
        })
    }

    /// Validate an entire batch before writing a byte, then make the batch durable.
    pub fn append(&mut self, entries: &[JournalEntry]) -> Result<(), StoreError> {
        if entries.is_empty() {
            return Ok(());
        }

        let mut candidate = self.state.clone();
        let mut encoded = Vec::new();
        for entry in entries {
            candidate.apply(entry.clone())?;
            serde_json::to_writer(&mut encoded, entry)
                .map_err(|error| StoreError::Serialization(error.to_string()))?;
            encoded.push(b'\n');
        }

        let path = self.root.join(JOURNAL_FILE);
        self.journal.write_all(&encoded).map_err(io(&path))?;
        self.journal.flush().map_err(io(&path))?;
        self.journal.get_ref().sync_data().map_err(io(&path))?;
        self.state = candidate;
        Ok(())
    }
}

/// Return only newline-terminated records. An unterminated tail is a possible crash
/// fragment and is observable through the returned byte count.
fn complete_prefix(bytes: &[u8]) -> (&[u8], usize) {
    if bytes.is_empty() || bytes.ends_with(b"\n") {
        return (bytes, 0);
    }
    match bytes.iter().rposition(|byte| *byte == b'\n') {
        Some(last_newline) => (&bytes[..=last_newline], bytes.len() - last_newline - 1),
        None => (&[], bytes.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ccos_enterprise_knowledge::model::{SourceId, SourceRecord, SourceTrust, TenantId};
    use ccos_enterprise_knowledge::KnowledgeOp;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let ordinal = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "ccos-knowledge-store-{}-{ordinal}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn source(sequence: u64, tenant: &str, id: &str) -> JournalEntry {
        JournalEntry::new(
            sequence,
            KnowledgeOp::RegisterSource(SourceRecord {
                id: SourceId::from(id),
                tenant: TenantId(tenant.to_owned()),
                locator: format!("file:///{id}"),
                content_hash: None,
                trust: SourceTrust::Internal,
            }),
        )
    }

    #[test]
    fn durable_replay_restores_identical_state() {
        let dir = TestDir::new();
        let expected_hash;
        {
            let mut store = KnowledgeStore::open(&dir.0).unwrap();
            store.append(&[source(0, "acme", "source:1")]).unwrap();
            expected_hash = store.state().canonical_hash().unwrap();
        }

        let loaded = KnowledgeStore::load(&dir.0).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.torn_tail, 0);
        assert_eq!(loaded.state.canonical_hash().unwrap(), expected_hash);
    }

    #[test]
    fn invalid_batch_writes_nothing() {
        let dir = TestDir::new();
        let mut store = KnowledgeStore::open(&dir.0).unwrap();
        let result = store.append(&[source(0, "acme", "source:1"), source(2, "acme", "source:2")]);
        assert!(matches!(result, Err(StoreError::Knowledge(_))));
        assert_eq!(store.next_sequence(), 0);
        drop(store);

        let bytes = std::fs::read(dir.0.join(JOURNAL_FILE)).unwrap();
        assert!(bytes.is_empty());
    }

    #[test]
    fn unterminated_final_fragment_is_ignored_and_reported() {
        let dir = TestDir::new();
        {
            let mut store = KnowledgeStore::open(&dir.0).unwrap();
            store.append(&[source(0, "acme", "source:1")]).unwrap();
        }
        let path = dir.0.join(JOURNAL_FILE);
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(br#"{"sequence":1,"op":{"broken""#).unwrap();
        file.sync_data().unwrap();

        let loaded = KnowledgeStore::load(&dir.0).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert!(loaded.torn_tail > 0);
        assert_eq!(loaded.state.next_sequence(), 1);
    }

    #[test]
    fn malformed_complete_line_fails_closed() {
        let dir = TestDir::new();
        let path = dir.0.join(JOURNAL_FILE);
        std::fs::write(&path, b"not-json\n").unwrap();
        assert!(matches!(
            KnowledgeStore::load(&dir.0),
            Err(StoreError::JournalCorrupt { line: 1, .. })
        ));
    }

    #[test]
    fn only_one_live_writer_can_own_a_store() {
        let dir = TestDir::new();
        let first = KnowledgeStore::open(&dir.0).unwrap();
        assert!(matches!(
            KnowledgeStore::open(&dir.0),
            Err(StoreError::AlreadyOpen { .. })
        ));
        drop(first);
        KnowledgeStore::open(&dir.0).unwrap();
    }
}
