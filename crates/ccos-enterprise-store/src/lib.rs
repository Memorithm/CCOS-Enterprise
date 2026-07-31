//! # CCOS Enterprise — durable state
//!
//! Before this crate the only durable state in the whole product was the
//! licence vault. Tenants, roles, budgets, model allowlists, Q-Page
//! activations and the audit journal lived in memory and vanished on restart,
//! with two severe consequences:
//!
//! * the audit trail compliance depends on **did not survive a restart**, so
//!   the answer to "what did this deployment authorize last Tuesday" was
//!   "nothing, as far as the product is concerned";
//! * `TokenBudget::spent` returned to zero, so **a tenant got a fresh full
//!   quota every time the process bounced** — a fail-open quota, and the one
//!   direction a governance product must never fail.
//!
//! ## Shape: a snapshot plus a journal
//!
//! [`Store`] keeps two files under one root:
//!
//! | file | contents | written by |
//! |---|---|---|
//! | `deployment.json` | the governed state: tenants, owners, ledgers, roles, tool governance, allowlists, activations, cells | [`Store::save_snapshot`], atomically |
//! | `audit.jsonl` | one decision per line, in decision order | [`Store::append`], append-only |
//!
//! The snapshot is a checkpoint, not the truth: the **journal is the
//! authority** for ordering and for everything decided since the last
//! checkpoint. [`Store::load`] returns both, and
//! `Deployment::restore(snapshot, &journal)` folds the tail back in. That is
//! what makes "kill the process mid-flight and restart" lose nothing: a
//! decision is durable once its journal line is fsynced, whether or not a
//! snapshot followed it.
//!
//! ## Why the journal is not written with `write_durable`
//!
//! [`ccos_core::util::write_durable`] is the right tool for the snapshot and is
//! used for it. It is the wrong tool for the journal: it rewrites and fsyncs
//! the **whole file** per call, so journaling N decisions would move O(N²)
//! bytes. That is not hypothetical — it is exactly the defect the licence
//! vault has, measured at gigabytes to record 200 flips, and reproducing it
//! here would make the audit trail the most expensive thing in the product.
//! The journal is opened once in append mode and `sync_data`'d per batch: an
//! append of a single line to a page-aligned file is the one write POSIX
//! actually makes cheap.
//!
//! ## Fail closed, and the one exception
//!
//! Every read path refuses rather than guesses. A missing root is
//! [`Store::load`]'s `Ok(None)` — a genuinely new install — but a root that
//! exists with an unreadable, malformed or discontinuous file is an error, and
//! **never** an empty deployment. Starting empty on corruption is the failure
//! mode that silently resets every quota in the fleet.
//!
//! The single exception is a **torn tail**: a crash during an append can leave
//! a final line with no terminating newline. That line is discarded and
//! reported in [`Loaded::torn_tail`], because the alternative — refusing to
//! start after any crash — makes the durability worthless. A malformed line
//! anywhere *before* the end is corruption and is refused: the tail is the
//! only place a crash can damage an append-only file.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use ccos_enterprise_runtime::{AuditRecord, DeploymentSnapshot};

/// Snapshot file name under the store root.
pub const SNAPSHOT_FILE: &str = "deployment.json";
/// Journal file name under the store root.
pub const JOURNAL_FILE: &str = "audit.jsonl";

/// Why the store refused. Nothing here is recoverable by guessing.
#[derive(Debug)]
pub enum StoreError {
    /// The filesystem said no. Carries the path so an operator can act.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// The snapshot is not valid JSON, or not a snapshot.
    SnapshotCorrupt { path: PathBuf, detail: String },
    /// A journal line before the end could not be parsed. Refused: only the
    /// final line can be damaged by a crash.
    JournalCorrupt {
        path: PathBuf,
        line: usize,
        detail: String,
    },
    /// The journal's sequences are not dense and ascending, so it is not the
    /// record of one deployment's decisions.
    JournalDiscontinuity {
        path: PathBuf,
        line: usize,
        expected: u64,
        found: u64,
    },
    /// The root exists but holds a journal with no snapshot beside it. The
    /// ledger the journal must be replayed onto is missing, so replaying it
    /// would invent one.
    SnapshotMissing { path: PathBuf },
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::SnapshotCorrupt { path, detail } => {
                write!(f, "{}: snapshot is unreadable: {detail}", path.display())
            }
            Self::JournalCorrupt { path, line, detail } => write!(
                f,
                "{}:{line}: journal line is unreadable: {detail}",
                path.display()
            ),
            Self::JournalDiscontinuity {
                path,
                line,
                expected,
                found,
            } => write!(
                f,
                "{}:{line}: journal jumps to sequence {found}, expected {expected}",
                path.display()
            ),
            Self::SnapshotMissing { path } => write!(
                f,
                "{}: a journal with no snapshot — there is no ledger to replay onto",
                path.display()
            ),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> StoreError + '_ {
    move |source| StoreError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// What [`Store::load`] recovered.
#[derive(Debug)]
pub struct Loaded {
    pub snapshot: DeploymentSnapshot,
    /// Every journaled decision, in sequence order.
    pub journal: Vec<AuditRecord>,
    /// Bytes discarded from the end of the journal because the process died
    /// mid-append. `0` on a clean shutdown. Non-zero means one decision was
    /// made and not durably recorded — the caller should say so out loud, and
    /// a client that never saw a response for it will retry under the same
    /// `request_id`, which replay suppression then handles.
    pub torn_tail: usize,
}

/// A durable Enterprise deployment on disk.
///
/// Holds the journal file open for append, so a decision costs one `write` and
/// one `sync_data` rather than an open/close pair.
pub struct Store {
    root: PathBuf,
    journal: BufWriter<File>,
    /// The next sequence this store expects to append, so a caller cannot
    /// journal decisions out of order or skip one.
    next_sequence: u64,
}

impl Store {
    /// Open (creating if absent) the store rooted at `root`.
    ///
    /// Creating the directory is deliberate and safe: an empty directory is
    /// still an empty *store*, which [`Store::load`] reports as `Ok(None)`.
    /// What is never created is state — a deployment that cannot read its
    /// ledger does not get a blank one.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root).map_err(io(&root))?;
        let journal_path = root.join(JOURNAL_FILE);
        let next_sequence = match read_journal(&journal_path)? {
            Some((records, _)) => records.last().map(|r| r.sequence + 1).unwrap_or(0),
            None => 0,
        };
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&journal_path)
            .map_err(io(&journal_path))?;
        Ok(Self {
            root,
            journal: BufWriter::new(file),
            next_sequence,
        })
    }

    /// The directory this store lives in.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The sequence the next appended record must carry.
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    fn snapshot_path(&self) -> PathBuf {
        self.root.join(SNAPSHOT_FILE)
    }

    fn journal_path(&self) -> PathBuf {
        self.root.join(JOURNAL_FILE)
    }

    /// Write the governed state atomically.
    ///
    /// Uses [`ccos_core::util::write_durable`], so a crash leaves either the
    /// previous snapshot or the new one, never a half-written file — and, since
    /// Core's repair, never a temp file that wedges the next attempt either.
    pub fn save_snapshot(&self, snapshot: &DeploymentSnapshot) -> Result<(), StoreError> {
        let path = self.snapshot_path();
        let bytes =
            serde_json::to_vec_pretty(snapshot).map_err(|e| StoreError::SnapshotCorrupt {
                path: path.clone(),
                detail: format!("cannot be serialized: {e}"),
            })?;
        ccos_core::util::write_durable(&path, &bytes).map_err(io(&path))
    }

    /// Append decisions and make them durable before returning.
    ///
    /// The caller must not report a decision to a client until this returns:
    /// that is the whole contract. Records must continue this store's
    /// sequence exactly — a caller that skips or repeats one is refused rather
    /// than silently writing a journal that cannot be replayed.
    pub fn append(&mut self, records: &[AuditRecord]) -> Result<(), StoreError> {
        let path = self.journal_path();
        for record in records {
            if record.sequence != self.next_sequence {
                return Err(StoreError::JournalDiscontinuity {
                    path,
                    line: 0,
                    expected: self.next_sequence,
                    found: record.sequence,
                });
            }
            let mut line = serde_json::to_vec(record).map_err(|e| StoreError::JournalCorrupt {
                path: path.clone(),
                line: 0,
                detail: format!("cannot be serialized: {e}"),
            })?;
            line.push(b'\n');
            self.journal.write_all(&line).map_err(io(&path))?;
            self.next_sequence += 1;
        }
        self.journal.flush().map_err(io(&path))?;
        // `sync_data` rather than `sync_all`: the file's length is data, and
        // an append never changes anything else in its metadata that a replay
        // depends on.
        self.journal.get_ref().sync_data().map_err(io(&path))
    }

    /// Read the durable state back.
    ///
    /// `Ok(None)` means "no store here yet" and is the *only* empty answer:
    /// anything present but unreadable is an error, because a governance
    /// deployment that silently starts empty has reset every quota it holds.
    pub fn load(&self) -> Result<Option<Loaded>, StoreError> {
        let snapshot_path = self.snapshot_path();
        let journal_path = self.journal_path();

        let snapshot_bytes = match std::fs::read(&snapshot_path) {
            Ok(b) => Some(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(io(&snapshot_path)(e)),
        };
        let journal = read_journal(&journal_path)?;

        match (snapshot_bytes, journal) {
            (None, None) => Ok(None),
            (None, Some((records, _))) if records.is_empty() => Ok(None),
            // A journal with decisions but no snapshot: the tenants, limits and
            // roles those decisions were made against are gone, so there is
            // nothing to replay onto. Refuse rather than invent a deployment.
            (None, Some(_)) => Err(StoreError::SnapshotMissing {
                path: snapshot_path,
            }),
            (Some(bytes), journal) => {
                let snapshot: DeploymentSnapshot =
                    serde_json::from_slice(&bytes).map_err(|e| StoreError::SnapshotCorrupt {
                        path: snapshot_path,
                        detail: e.to_string(),
                    })?;
                let (journal, torn_tail) = journal.unwrap_or_default();
                Ok(Some(Loaded {
                    snapshot,
                    journal,
                    torn_tail,
                }))
            }
        }
    }
}

/// Parse the journal. `None` when the file does not exist.
///
/// Returns the records and how many bytes of torn tail were discarded.
fn read_journal(path: &Path) -> Result<Option<(Vec<AuditRecord>, usize)>, StoreError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io(path)(e)),
    };

    // A crash mid-append leaves a final line with no newline. Everything up to
    // the last newline is what the process durably committed.
    let (committed, torn_tail) = match bytes.iter().rposition(|b| *b == b'\n') {
        Some(end) => (&bytes[..=end], bytes.len() - end - 1),
        // No newline at all: either empty, or a single torn line.
        None => (&bytes[..0], bytes.len()),
    };

    let mut records: Vec<AuditRecord> = Vec::new();
    let mut expected = 0u64;
    for (index, line) in committed.split(|b| *b == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        let record: AuditRecord =
            serde_json::from_slice(line).map_err(|e| StoreError::JournalCorrupt {
                path: path.to_path_buf(),
                line: index + 1,
                detail: e.to_string(),
            })?;
        if record.sequence != expected {
            return Err(StoreError::JournalDiscontinuity {
                path: path.to_path_buf(),
                line: index + 1,
                expected,
                found: record.sequence,
            });
        }
        expected = record.sequence + 1;
        records.push(record);
    }
    Ok(Some((records, torn_tail)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ccos_enterprise_runtime::{
        actor, request, two_tenant_deployment, Call, Deployment, Outcome, Refusal, RestoreError,
        TenantState,
    };

    use ccos_enterprise_auth::AuthStrength;

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ccos-store-{tag}-{pid}", pid = std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    /// Drive a deployment and journal every decision, the way a server would.
    fn run(d: &mut Deployment, store: &mut Store, calls: &[(&str, &str, u64)]) {
        let mut journaled = store.next_sequence();
        for (tenant, id, cost) in calls {
            let a = actor("memorithm", "alice", AuthStrength::Token);
            let req = request(tenant, "alice", "memory.ingest", id);
            d.admit(Call {
                actor: &a,
                request: &req,
                model: "claude-opus",
                cost_tokens: *cost,
                variant: None,
            });
            let fresh: Vec<_> = d
                .audit()
                .filter(|r| r.sequence >= journaled)
                .cloned()
                .collect();
            journaled += fresh.len() as u64;
            store.append(&fresh).expect("append");
        }
    }

    #[test]
    fn a_new_root_is_empty_and_says_so() {
        let dir = scratch("new");
        let store = Store::open(&dir).expect("open");
        assert!(store.load().expect("load").is_none(), "a new install");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_restart_reproduces_the_ledger_exactly() {
        let dir = scratch("restart");
        let mut store = Store::open(&dir).expect("open");
        let mut d = two_tenant_deployment();
        store.save_snapshot(&d.snapshot()).expect("snapshot");
        run(
            &mut d,
            &mut store,
            &[
                ("acme", "r-1", 100),
                ("acme", "r-2", 250),
                ("acme", "r-3", 7),
            ],
        );
        assert_eq!(d.spent("acme"), Some(357));
        drop(store);

        // The process dies here. No snapshot was taken after the calls, so
        // everything below comes from replaying the journal.
        let store = Store::open(&dir).expect("reopen");
        let loaded = store.load().expect("load").expect("a store exists");
        assert_eq!(loaded.torn_tail, 0, "clean shutdown");
        let restored = Deployment::restore(loaded.snapshot, &loaded.journal).expect("restore");
        assert_eq!(restored.spent("acme"), Some(357), "the ledger survived");
        assert_eq!(restored.spent("globex"), Some(0));
        assert_eq!(
            restored.audit().cloned().collect::<Vec<_>>(),
            d.audit().cloned().collect::<Vec<_>>(),
            "and so did the journal, record for record"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bounced_process_does_not_hand_the_tenant_a_fresh_quota() {
        let dir = scratch("quota");
        let mut store = Store::open(&dir).expect("open");
        let mut d = two_tenant_deployment();
        store.save_snapshot(&d.snapshot()).expect("snapshot");
        // Drain acme's 1 000-token budget.
        run(&mut d, &mut store, &[("acme", "drain", 1_000)]);
        assert_eq!(d.spent("acme"), Some(1_000));
        drop(store);

        let store = Store::open(&dir).expect("reopen");
        let loaded = store.load().expect("load").expect("store");
        let mut restored = Deployment::restore(loaded.snapshot, &loaded.journal).expect("restore");
        let a = actor("memorithm", "alice", AuthStrength::Token);
        let req = request("acme", "alice", "memory.ingest", "after-restart");
        assert_eq!(
            restored
                .admit(Call {
                    actor: &a,
                    request: &req,
                    model: "claude-opus",
                    cost_tokens: 1,
                    variant: None,
                })
                .refusal(),
            Some(&Refusal::BudgetExhausted),
            "bouncing the process must not refill the budget"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_replayed_request_id_is_still_suppressed_after_a_restart() {
        let dir = scratch("replay");
        let mut store = Store::open(&dir).expect("open");
        let mut d = two_tenant_deployment();
        store.save_snapshot(&d.snapshot()).expect("snapshot");
        run(&mut d, &mut store, &[("acme", "once", 100)]);
        drop(store);

        let store = Store::open(&dir).expect("reopen");
        let loaded = store.load().expect("load").expect("store");
        let mut restored = Deployment::restore(loaded.snapshot, &loaded.journal).expect("restore");
        let a = actor("memorithm", "alice", AuthStrength::Token);
        let req = request("acme", "alice", "memory.ingest", "once");
        assert_eq!(
            restored.admit(Call {
                actor: &a,
                request: &req,
                model: "claude-opus",
                cost_tokens: 100,
                variant: None,
            }),
            Outcome::Forwarded
        );
        assert_eq!(
            restored.spent("acme"),
            Some(100),
            "the retry after a restart must not be billed twice"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_torn_tail_is_discarded_and_reported_but_the_rest_survives() {
        let dir = scratch("torn");
        let mut store = Store::open(&dir).expect("open");
        let mut d = two_tenant_deployment();
        store.save_snapshot(&d.snapshot()).expect("snapshot");
        run(
            &mut d,
            &mut store,
            &[("acme", "r-1", 10), ("acme", "r-2", 20)],
        );
        drop(store);

        // A crash mid-append: half a line, no newline.
        let journal = dir.join(JOURNAL_FILE);
        let mut bytes = std::fs::read(&journal).expect("read");
        bytes.extend_from_slice(br#"{"sequence":2,"request_id":"r-3","ten"#);
        std::fs::write(&journal, &bytes).expect("write");

        let store = Store::open(&dir).expect("reopen");
        let loaded = store.load().expect("load").expect("store");
        assert_eq!(loaded.torn_tail, 37, "the partial line is measured");
        assert_eq!(loaded.journal.len(), 2, "and the committed lines survive");
        let restored = Deployment::restore(loaded.snapshot, &loaded.journal).expect("restore");
        assert_eq!(restored.spent("acme"), Some(30));
        // The store resumes at the next sequence, not at the torn one.
        assert_eq!(store.next_sequence(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_line_before_the_end_is_refused_not_skipped() {
        let dir = scratch("corrupt");
        let mut store = Store::open(&dir).expect("open");
        let mut d = two_tenant_deployment();
        store.save_snapshot(&d.snapshot()).expect("snapshot");
        run(
            &mut d,
            &mut store,
            &[("acme", "r-1", 10), ("acme", "r-2", 20)],
        );
        drop(store);

        let journal = dir.join(JOURNAL_FILE);
        let text = std::fs::read_to_string(&journal).expect("read");
        let mut lines: Vec<&str> = text.lines().collect();
        lines[0] = "{ this is not a record }";
        std::fs::write(&journal, format!("{}\n", lines.join("\n"))).expect("write");

        let err = match Store::open(&dir) {
            Ok(_) => panic!("a corrupt journal must not open silently"),
            Err(e) => e,
        };
        assert!(
            matches!(err, StoreError::JournalCorrupt { line: 1, .. }),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_snapshot_is_refused_rather_than_started_empty() {
        let dir = scratch("badsnap");
        let store = Store::open(&dir).expect("open");
        let d = two_tenant_deployment();
        store.save_snapshot(&d.snapshot()).expect("snapshot");
        std::fs::write(dir.join(SNAPSHOT_FILE), b"{\"schema\":").expect("write");

        let err = store
            .load()
            .expect_err("a corrupt snapshot must not read as empty");
        assert!(matches!(err, StoreError::SnapshotCorrupt { .. }), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_journal_without_a_snapshot_has_nothing_to_replay_onto() {
        let dir = scratch("orphan");
        let mut store = Store::open(&dir).expect("open");
        let mut d = two_tenant_deployment();
        store.save_snapshot(&d.snapshot()).expect("snapshot");
        run(&mut d, &mut store, &[("acme", "r-1", 10)]);
        drop(store);
        std::fs::remove_file(dir.join(SNAPSHOT_FILE)).expect("the snapshot is lost");

        let store = Store::open(&dir).expect("open");
        let err = store
            .load()
            .expect_err("an orphaned journal must be refused");
        assert!(matches!(err, StoreError::SnapshotMissing { .. }), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_ledger_over_its_limit_is_refused_on_load() {
        let dir = scratch("overspent");
        let store = Store::open(&dir).expect("open");
        let mut d = Deployment::new();
        let mut t = TenantState::new(100);
        t.allow_model("claude-opus");
        d.add_tenant("memorithm", "acme", t);
        store.save_snapshot(&d.snapshot()).expect("snapshot");

        // An editor, a bad merge, or a corrupted byte.
        let text = std::fs::read_to_string(dir.join(SNAPSHOT_FILE)).expect("read");
        let text = text.replace("\"spent\": 0", "\"spent\": 5000");
        std::fs::write(dir.join(SNAPSHOT_FILE), text).expect("write");

        let loaded = store.load().expect("the file still parses").expect("store");
        let err = match Deployment::restore(loaded.snapshot, &loaded.journal) {
            Ok(_) => panic!("an impossible ledger must be refused"),
            Err(e) => e,
        };
        assert_eq!(
            err,
            RestoreError::LedgerOverLimit {
                tenant: "acme".into(),
                spent: 5_000,
                limit: 100,
            }
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn appending_out_of_order_is_refused() {
        let dir = scratch("order");
        let mut store = Store::open(&dir).expect("open");
        let record = AuditRecord {
            sequence: 7,
            request_id: "r".into(),
            tenant: "acme".into(),
            actor: "alice".into(),
            tool: "memory.ingest".into(),
            cost: 1,
            outcome: Outcome::Forwarded,
        };
        let err = store
            .append(&[record])
            .expect_err("a store that starts at 0 cannot accept sequence 7");
        assert!(
            matches!(
                err,
                StoreError::JournalDiscontinuity {
                    expected: 0,
                    found: 7,
                    ..
                }
            ),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A snapshot taken mid-life overlaps the journal. The overlap must be
    /// counted once in the ledger and once in the counters — which are two
    /// different rules, because the snapshot carries the ledger and does not
    /// carry the counters.
    #[test]
    fn a_mid_life_snapshot_neither_double_bills_nor_loses_the_earlier_trail() {
        let dir = scratch("midlife");
        let mut store = Store::open(&dir).expect("open");
        let mut d = two_tenant_deployment();
        store.save_snapshot(&d.snapshot()).expect("initial");

        run(
            &mut d,
            &mut store,
            &[("acme", "r-1", 100), ("acme", "r-2", 50)],
        );
        // A checkpoint here: the ledger below is carried by the snapshot, and
        // the journal still holds those same two records.
        store.save_snapshot(&d.snapshot()).expect("checkpoint");
        run(
            &mut d,
            &mut store,
            &[("acme", "r-3", 25), ("acme", "r-4", 5)],
        );
        assert_eq!(d.spent("acme"), Some(180));
        drop(store);

        let store = Store::open(&dir).expect("reopen");
        let loaded = store.load().expect("load").expect("store");
        assert_eq!(
            loaded.snapshot.sequence_watermark, 2,
            "the checkpoint's mark"
        );
        assert_eq!(loaded.journal.len(), 4, "the journal keeps all four");
        let restored = Deployment::restore(loaded.snapshot, &loaded.journal).expect("restore");

        assert_eq!(
            restored.spent("acme"),
            Some(180),
            "the two records the snapshot already folded in must not be billed again"
        );
        assert_eq!(
            restored.audit().count(),
            4,
            "…but the trail must start at the beginning, not at the checkpoint"
        );
        assert_eq!(restored.metrics(), d.metrics(), "and so must the counters");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_journal_alone_reproduces_the_ledger_from_an_empty_snapshot() {
        // The acceptance property, stated directly: replaying an admitted-call
        // sequence from the journal reproduces the same ledger, without any
        // checkpoint carrying it.
        let dir = scratch("property");
        let mut store = Store::open(&dir).expect("open");
        let mut d = two_tenant_deployment();
        // Snapshot BEFORE any call, so the ledger below comes only from replay.
        store.save_snapshot(&d.snapshot()).expect("snapshot");

        let calls: Vec<(&str, String, u64)> = (0..200)
            .map(|i| {
                let tenant = if i % 3 == 0 { "globex" } else { "acme" };
                (tenant, format!("r-{i:04}"), (i as u64 % 17) + 1)
            })
            .collect();
        let refs: Vec<(&str, &str, u64)> = calls
            .iter()
            .map(|(t, id, c)| (*t, id.as_str(), *c))
            .collect();
        run(&mut d, &mut store, &refs);
        drop(store);

        let store = Store::open(&dir).expect("reopen");
        let loaded = store.load().expect("load").expect("store");
        let restored = Deployment::restore(loaded.snapshot, &loaded.journal).expect("restore");
        for tenant in ["acme", "globex"] {
            assert_eq!(
                restored.spent(tenant),
                d.spent(tenant),
                "{tenant}: the replayed ledger differs from the live one"
            );
            // …and the journal reconciles it independently of both.
            let billed: u64 = loaded
                .journal
                .iter()
                .filter(|r| r.tenant == tenant)
                .map(|r| r.cost)
                .sum();
            assert_eq!(Some(billed), restored.spent(tenant));
        }
        assert_eq!(restored.metrics(), d.metrics(), "counters replay too");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
