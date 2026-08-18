//! Durable journal for CCOS Enterprise Decision Intelligence.
//!
//! The journal is the authority. [`DecisionStore`] has no hidden mutation path:
//! every append is validated against a cloned [`DecisionState`] and the caller's
//! current canonical [`KnowledgeState`] before a byte is written. Accepted entries
//! are serialized as newline-delimited JSON, flushed and `sync_data`'d before the
//! in-memory decision state advances.
//!
//! Restart replay deliberately does not consult a live Knowledge Plane. Historical
//! entries were already admitted against their immutable `KnowledgeAnchor`; replay
//! therefore uses [`DecisionState::replay`] and reconstructs only the deterministic
//! decision state. A crash may leave an unterminated final fragment. Only that final
//! fragment is ignored and reported; malformed complete records fail closed.

#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use ccos_enterprise_decision::{DecisionError, DecisionJournalEntry, DecisionState};
use ccos_enterprise_knowledge::KnowledgeState;

pub const JOURNAL_FILE: &str = "decisions.jsonl";
pub const LOCK_FILE: &str = "decisions.lock";

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
        detail: String,
    },
    Serialization(String),
    Decision(DecisionError),
    AlreadyOpen {
        path: PathBuf,
    },
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::JournalCorrupt { path, line, detail } => write!(
                f,
                "{}:{line}: corrupt decision journal: {detail}",
                path.display()
            ),
            Self::JournalInvalid { path, detail } => {
                write!(f, "{}: invalid decision journal: {detail}", path.display())
            }
            Self::Serialization(detail) => {
                write!(f, "cannot serialize decision journal: {detail}")
            }
            Self::Decision(error) => write!(f, "decision mutation refused: {error}"),
            Self::AlreadyOpen { path } => write!(
                f,
                "{}: another live writer already owns this decision store",
                path.display()
            ),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Decision(error) => Some(error),
            _ => None,
        }
    }
}

impl From<DecisionError> for StoreError {
    fn from(value: DecisionError) -> Self {
        Self::Decision(value)
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
    pub entries: Vec<DecisionJournalEntry>,
    pub state: DecisionState,
    /// Bytes ignored after the last newline because the process died mid-append.
    pub torn_tail: usize,
}

pub struct DecisionStore {
    root: PathBuf,
    journal: BufWriter<File>,
    state: DecisionState,
    _lock: File,
}

impl DecisionStore {
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

    pub fn state(&self) -> &DecisionState {
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
                state: DecisionState::new(),
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
            let entry = serde_json::from_slice::<DecisionJournalEntry>(line).map_err(|error| {
                StoreError::JournalCorrupt {
                    path: journal_path.clone(),
                    line: index + 1,
                    detail: error.to_string(),
                }
            })?;
            entries.push(entry);
        }

        let state = DecisionState::replay(entries.iter().cloned()).map_err(|error| {
            StoreError::JournalInvalid {
                path: journal_path.clone(),
                detail: error.to_string(),
            }
        })?;

        Ok(Loaded {
            entries,
            state,
            torn_tail,
        })
    }

    /// Validate the whole batch against one exact current Knowledge Plane snapshot before writing.
    ///
    /// This intentionally means every entry in a batch must carry a `KnowledgeAnchor` matching the
    /// supplied `knowledge`. If knowledge changes, callers start a new append against the new state.
    pub fn append(
        &mut self,
        entries: &[DecisionJournalEntry],
        knowledge: &KnowledgeState,
    ) -> Result<(), StoreError> {
        if entries.is_empty() {
            return Ok(());
        }

        let mut candidate = self.state.clone();
        let mut encoded = Vec::new();
        for entry in entries {
            candidate.apply(entry.clone(), knowledge)?;
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

/// Return only newline-terminated records. An unterminated tail is a possible crash fragment and
/// remains observable through the returned byte count.
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
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicU64, Ordering};

    use ccos_enterprise_auth::ActorId;
    use ccos_enterprise_decision::{
        DecisionDraft, DecisionOp, DecisionOutcomeDraft, KnowledgeAnchor, OutcomeStatus,
        TraversalLimits,
    };
    use ccos_enterprise_knowledge::{JournalEntry, KnowledgeOp};
    use ccos_enterprise_knowledge_model::{
        AssertionKind, DecisionId, EntityId, EntityRecord, EvidenceId, EvidenceRecord,
        FactAssertion, FactId, FactObject, RuleId, SourceId, SourceRecord, SourceTrust, TenantId,
        ValidityInterval,
    };

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let ordinal = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "ccos-decision-store-{}-{ordinal}",
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

    fn tenant() -> TenantId {
        TenantId("acme".into())
    }

    fn evidence() -> BTreeSet<EvidenceId> {
        BTreeSet::from([EvidenceId::from("evidence:policy")])
    }

    fn knowledge() -> KnowledgeState {
        let tenant = tenant();
        KnowledgeState::replay(vec![
            JournalEntry::new(
                0,
                KnowledgeOp::RegisterSource(SourceRecord {
                    id: SourceId::from("source:policy"),
                    tenant: tenant.clone(),
                    locator: "file:///policy.json".into(),
                    content_hash: Some("sha256:policy".into()),
                    trust: SourceTrust::Authoritative,
                }),
            ),
            JournalEntry::new(
                1,
                KnowledgeOp::AddEvidence(EvidenceRecord {
                    id: EvidenceId::from("evidence:policy"),
                    tenant: tenant.clone(),
                    source: SourceId::from("source:policy"),
                    locator: Some("$.approval".into()),
                    content_hash: Some("sha256:approval".into()),
                }),
            ),
            JournalEntry::new(
                2,
                KnowledgeOp::AddEntity(EntityRecord {
                    id: EntityId::from("entity:request"),
                    tenant: tenant.clone(),
                    namespace: None,
                    entity_type: "deployment_request".into(),
                    label: Some("Acme deployment".into()),
                    evidence: evidence(),
                    kind: AssertionKind::Authoritative,
                }),
            ),
            JournalEntry::new(
                3,
                KnowledgeOp::AssertFact(FactAssertion {
                    id: FactId::from("fact:eligible"),
                    tenant,
                    subject: EntityId::from("entity:request"),
                    predicate: "eligible".into(),
                    object: FactObject::Literal("true".into()),
                    validity: ValidityInterval::unbounded(),
                    evidence: evidence(),
                    kind: AssertionKind::Authoritative,
                }),
            ),
        ])
        .unwrap()
    }

    fn draft(id: &str, knowledge: &KnowledgeState) -> DecisionDraft {
        DecisionDraft {
            id: DecisionId::from(id),
            tenant: tenant(),
            actor: ActorId("agent-7".into()),
            question: "Should this request be approved?".into(),
            selected: "approve".into(),
            rationale: "Authoritative eligibility supports approval.".into(),
            facts: BTreeSet::from([FactId::from("fact:eligible")]),
            relations: BTreeSet::new(),
            evidence: evidence(),
            rules: BTreeSet::from([RuleId::from("rule:approval")]),
            precedents: BTreeSet::new(),
            knowledge: KnowledgeAnchor::capture(knowledge).unwrap(),
        }
    }

    #[test]
    fn durable_replay_restores_decisions_precedents_and_outcomes() {
        let dir = TestDir::new();
        let knowledge = knowledge();
        let expected_hash;
        {
            let mut store = DecisionStore::open(&dir.0).unwrap();
            let first = DecisionJournalEntry::new(
                0,
                DecisionOp::Record(draft("decision:approve", &knowledge)),
            );
            let mut second_draft = draft("decision:deploy", &knowledge);
            second_draft
                .precedents
                .insert(DecisionId::from("decision:approve"));
            let second = DecisionJournalEntry::new(1, DecisionOp::Record(second_draft));
            let outcome = DecisionJournalEntry::new(
                2,
                DecisionOp::RecordOutcome {
                    tenant: tenant(),
                    decision: DecisionId::from("decision:deploy"),
                    outcome: DecisionOutcomeDraft {
                        status: OutcomeStatus::Succeeded,
                        summary: "Deployment completed under policy.".into(),
                        evidence: evidence(),
                        knowledge: KnowledgeAnchor::capture(&knowledge).unwrap(),
                    },
                },
            );
            store.append(&[first, second, outcome], &knowledge).unwrap();
            expected_hash = store.state().canonical_hash().unwrap();
        }

        let loaded = DecisionStore::load(&dir.0).unwrap();
        assert_eq!(loaded.entries.len(), 3);
        assert_eq!(loaded.torn_tail, 0);
        assert_eq!(loaded.state.canonical_hash().unwrap(), expected_hash);
        assert_eq!(
            loaded
                .state
                .causal_ancestry(
                    &tenant(),
                    &DecisionId::from("decision:deploy"),
                    TraversalLimits::default(),
                )
                .unwrap(),
            vec![DecisionId::from("decision:approve")]
        );
        assert_eq!(
            loaded
                .state
                .decision(&tenant(), &DecisionId::from("decision:deploy"))
                .unwrap()
                .outcome
                .as_ref()
                .unwrap()
                .status,
            OutcomeStatus::Succeeded
        );
    }

    #[test]
    fn invalid_batch_writes_nothing() {
        let dir = TestDir::new();
        let knowledge = knowledge();
        let mut store = DecisionStore::open(&dir.0).unwrap();
        let result = store.append(
            &[
                DecisionJournalEntry::new(0, DecisionOp::Record(draft("decision:1", &knowledge))),
                DecisionJournalEntry::new(2, DecisionOp::Record(draft("decision:2", &knowledge))),
            ],
            &knowledge,
        );
        assert!(matches!(result, Err(StoreError::Decision(_))));
        assert_eq!(store.next_sequence(), 0);
        drop(store);

        let bytes = std::fs::read(dir.0.join(JOURNAL_FILE)).unwrap();
        assert!(bytes.is_empty());
    }

    #[test]
    fn mismatched_knowledge_anchor_writes_nothing() {
        let dir = TestDir::new();
        let knowledge = knowledge();
        let mut bad = draft("decision:1", &knowledge);
        bad.knowledge.canonical_hash.push('x');
        let mut store = DecisionStore::open(&dir.0).unwrap();
        let result = store.append(
            &[DecisionJournalEntry::new(0, DecisionOp::Record(bad))],
            &knowledge,
        );
        assert!(matches!(
            result,
            Err(StoreError::Decision(DecisionError::KnowledgeAnchorMismatch))
        ));
        assert_eq!(store.next_sequence(), 0);
        drop(store);
        assert!(std::fs::read(dir.0.join(JOURNAL_FILE)).unwrap().is_empty());
    }

    #[test]
    fn unterminated_final_fragment_is_ignored_and_reported() {
        let dir = TestDir::new();
        let knowledge = knowledge();
        {
            let mut store = DecisionStore::open(&dir.0).unwrap();
            store
                .append(
                    &[DecisionJournalEntry::new(
                        0,
                        DecisionOp::Record(draft("decision:1", &knowledge)),
                    )],
                    &knowledge,
                )
                .unwrap();
        }
        let path = dir.0.join(JOURNAL_FILE);
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(br#"{"sequence":1,"op":{"broken""#).unwrap();
        file.sync_data().unwrap();

        let loaded = DecisionStore::load(&dir.0).unwrap();
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
            DecisionStore::load(&dir.0),
            Err(StoreError::JournalCorrupt { line: 1, .. })
        ));
    }

    #[test]
    fn only_one_live_writer_can_own_a_store() {
        let dir = TestDir::new();
        let first = DecisionStore::open(&dir.0).unwrap();
        assert!(matches!(
            DecisionStore::open(&dir.0),
            Err(StoreError::AlreadyOpen { .. })
        ));
        drop(first);
        DecisionStore::open(&dir.0).unwrap();
    }
}
