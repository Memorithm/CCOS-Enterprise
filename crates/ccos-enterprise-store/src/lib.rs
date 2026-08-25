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
//! [`Store`] keeps three files under one root:
//!
//! | file | contents | written by |
//! |---|---|---|
//! | `deployment.json` | the governed state: tenants, owners, ledgers, roles, tool governance, allowlists, activations, cells | [`Store::save_snapshot`], atomically |
//! | `audit.jsonl` | one decision per line, in decision order | [`Store::append`], append-only |
//! | `governance.jsonl` | one rule change per line, in the order made | [`Store::append_governance`], append-only |
//!
//! The snapshot is a checkpoint, not the truth: the **journals are the
//! authority** for ordering and for everything that happened since the last
//! checkpoint. [`Store::load`] returns all three, and
//! `Deployment::restore(snapshot, &journal, &governance)` folds the tails back
//! in. That is what makes "kill the process mid-flight and restart" lose
//! nothing: a decision is durable once its journal line is fsynced, whether or
//! not a snapshot followed it.
//!
//! The two journals are separate files rather than one stream of two record
//! kinds. The decision journal's dense-sequence check — a gap means a decision
//! was made and lost — is the strongest guarantee this crate offers, and it
//! only holds if nothing else consumes sequences. Rule changes carry their own
//! ordering instead (`GovernanceRecord::at_sequence` anchors each one between
//! two decisions), so they merge into one readable trail without weakening the
//! check. Both are replayed as **evidence**, never as instructions: the
//! snapshot already holds the state a rule change produced, so re-applying the
//! record would apply it twice.
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
//! ## Bounded startup: journal rotation
//!
//! The journals are append-only and their dense-sequence checks forbid
//! rewriting history in place, so [`Store::load`] reads every decision ever
//! made — unless the deployment compacts. [`Store::compact`] seals the live
//! decision journal into an immutable segment (`audit.through-<last>.jsonl`)
//! behind a durable snapshot of the same watermark and starts a fresh live
//! file; startup then replays segments plus the short live tail. The order —
//! snapshot first, then fsync + rename + directory fsync — makes every crash
//! window land on a loadable state. Segments are complete by construction,
//! so a torn or missing one is refused rather than forgiven.
//!
//! The governance journal is deliberately not rotated: it grows with rule
//! changes rather than traffic, and anchoring its rotation would need an
//! ordinal watermark the snapshot does not carry. Callers should compact on
//! a size threshold at their durability boundary — see the MCP server's
//! `persist_deployment`, which rotates once the live journal passes 128 MiB.
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

use ccos_enterprise_runtime::{AuditRecord, DeploymentSnapshot, GovernanceRecord};

/// Snapshot file name under the store root.
pub const SNAPSHOT_FILE: &str = "deployment.json";
/// Journal file name under the store root.
pub const JOURNAL_FILE: &str = "audit.jsonl";

/// Prefix of a rotated decision-journal segment: `audit.through-<last>.jsonl`
/// holds decisions `..=<last>` and is complete and immutable once published.
pub const SEGMENT_PREFIX: &str = "audit.through-";
const SEGMENT_SUFFIX: &str = ".jsonl";

/// Rule changes, one JSON object per line, in the order they were made.
///
/// A second file rather than a second kind of line in `audit.jsonl`: the
/// decision journal's framing and its dense-sequence check are the strongest
/// guarantees this crate offers, and widening its record type would weaken
/// both to carry a stream that has its own ordering anyway
/// (`GovernanceRecord::at_sequence`/`ordinal`).
pub const GOVERNANCE_FILE: &str = "governance.jsonl";
/// Single-writer lock file under the store root. Never read or written — only
/// the kernel lock held on it means anything. See [`Store::open`].
pub const LOCK_FILE: &str = "store.lock";

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
    /// Another live `Store` already holds this root. The store is
    /// single-writer: two handles cache independent sequence counters and
    /// their appends collide, so the second opener is refused rather than
    /// allowed to corrupt the journal.
    AlreadyOpen { path: PathBuf },
    /// An earlier append failed partway through writing, so this handle can no
    /// longer promise what is durable. Every further append is refused until
    /// the store is reopened; reopening recomputes the sequence from disk and
    /// rolls any partial write back out of the replay.
    Poisoned { path: PathBuf, detail: String },
    /// Compaction was refused: the caller's snapshot does not match the
    /// durable journal end, or the rotation target already exists. Nothing
    /// was moved — the store is exactly as it was.
    CompactRefused { path: PathBuf, detail: String },
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
            Self::AlreadyOpen { path } => write!(
                f,
                "{}: another process or handle already has this store open; \
                 the store is single-writer",
                path.display()
            ),
            Self::Poisoned { path, detail } => write!(
                f,
                "{}: store is poisoned after an earlier append failure ({detail}); \
                 reopen to recover from disk",
                path.display()
            ),
            Self::CompactRefused { path, detail } => write!(
                f,
                "{}: compaction refused ({detail}); nothing was moved",
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
    /// Every journaled decision, in sequence order — rotated segments first,
    /// then the live journal.
    pub journal: Vec<AuditRecord>,
    /// Every journaled rule change, in the order it was made. Anchored to the
    /// decision stream by `at_sequence`, so the two merge without sharing a
    /// counter — see [`ccos_enterprise_runtime::GovernanceRecord`].
    pub governance: Vec<GovernanceRecord>,
    /// Bytes discarded from the end of the journal because the process died
    /// mid-append. `0` on a clean shutdown. Non-zero means one decision was
    /// made and not durably recorded — the caller should say so out loud, and
    /// a client that never saw a response for it will retry under the same
    /// `request_id`, which replay suppression then handles.
    pub torn_tail: usize,
    /// How many rotated decision-journal segments were folded into `journal`.
    /// Observability for operators: this is how much history compaction has
    /// already moved off the live file.
    pub rotated_segments: usize,
}

/// A durable Enterprise deployment on disk.
///
/// Holds the journal file open for append, so a decision costs one `write` and
/// one `sync_data` rather than an open/close pair — and holds an exclusive
/// lock for as long as it lives (see [`Store::open`]).
pub struct Store {
    root: PathBuf,
    journal: BufWriter<File>,
    governance: BufWriter<File>,
    /// The next governance ordinal this store expects, so a rule change cannot
    /// be journaled out of order or reuse an ordinal.
    next_ordinal: u64,
    /// The next sequence this store expects to append, so a caller cannot
    /// journal decisions out of order or skip one.
    next_sequence: u64,
    /// Set when an append fails partway through writing. The file may then
    /// hold bytes this process has already been told (and reported) nothing
    /// about: retrying would reuse sequence numbers and brick the journal at
    /// the next open. Every further append refuses until the store is
    /// reopened — fail-closed beats a corrupted ledger.
    poisoned: Option<String>,
    /// Held open, and exclusively locked, for the lifetime of the store. Never
    /// read or written: the file is a handle for the kernel's lock, nothing
    /// more. Dropping it releases the lock, and so does the process dying.
    _lock: File,
}

/// Make a newly created directory entry durable.
///
/// Appending data with `sync_data` makes the *bytes* durable but not the
/// *entry*: after a power loss a just-created `audit.jsonl` can vanish whole
/// while every append returned success — the authoritative trail lost without
/// a trace. One `sync_all` on the parent directory pins the name.
fn sync_directory(dir: &Path) -> Result<(), StoreError> {
    let handle = File::open(dir).map_err(io(dir))?;
    handle.sync_all().map_err(io(dir))
}

impl Store {
    /// Open (creating if absent) the store rooted at `root`, taking the
    /// **exclusive single-writer lock**.
    ///
    /// Creating the directory is deliberate and safe: an empty directory is
    /// still an empty *store*, which [`Store::load`] reports as `Ok(None)`.
    /// What is never created is state — a deployment that cannot read its
    /// ledger does not get a blank one.
    ///
    /// ## Why a kernel lock and not a lock *file*
    ///
    /// Two `Store` handles on one root each cache their own `next_sequence` at
    /// open, so their appends collide at the same sequence. That damage used
    /// to be caught only by the *next* reader — fail-closed on read, silent on
    /// write, and by then the journal is already unreplayable.
    ///
    /// The obvious fix, a `store.lock` created with `create_new`, would
    /// reintroduce exactly the defect Core just removed from `write_durable`:
    /// a process that dies leaves the file behind, and every later start is
    /// wedged until an operator deletes it by hand. A crash must not cost
    /// availability.
    ///
    /// [`std::fs::File::try_lock`] is an *advisory kernel* lock instead. It is
    /// released when the descriptor closes — including when the process dies,
    /// however it dies — so there is no such thing as a stale one. The file
    /// itself is never read or written; only the lock on it means anything.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root).map_err(io(&root))?;

        // Take the lock BEFORE reading the journal: the sequence this store
        // caches must not be computed from a file another writer is extending.
        let lock_path = root.join(LOCK_FILE);
        let lock = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(io(&lock_path))?;
        lock.try_lock().map_err(|e| match e {
            std::fs::TryLockError::WouldBlock => StoreError::AlreadyOpen {
                path: lock_path.clone(),
            },
            std::fs::TryLockError::Error(source) => StoreError::Io {
                path: lock_path.clone(),
                source,
            },
        })?;

        let journal_path = root.join(JOURNAL_FILE);
        let next_sequence = match read_audit_history(&root)? {
            Some((records, _)) => records.last().map(|r| r.sequence + 1).unwrap_or(0),
            None => 0,
        };
        let journal_existed = journal_path.exists();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&journal_path)
            .map_err(io(&journal_path))?;

        let governance_path = root.join(GOVERNANCE_FILE);
        let next_ordinal = match read_governance(&governance_path)? {
            Some((records, _)) => records.last().map(|r| r.ordinal + 1).unwrap_or(0),
            None => 0,
        };
        let governance_existed = governance_path.exists();
        let governance_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&governance_path)
            .map_err(io(&governance_path))?;

        if !journal_existed || !governance_existed {
            sync_directory(&root)?;
        }

        Ok(Self {
            root,
            journal: BufWriter::new(file),
            governance: BufWriter::new(governance_file),
            next_ordinal,
            next_sequence,
            poisoned: None,
            _lock: lock,
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

    fn governance_path(&self) -> PathBuf {
        self.root.join(GOVERNANCE_FILE)
    }

    /// The ordinal the next appended rule change must carry.
    pub fn next_ordinal(&self) -> u64 {
        self.next_ordinal
    }

    /// Seal the decisions up to `snapshot.sequence_watermark` into an
    /// immutable segment file and start a fresh live journal, so startup cost
    /// stays bounded by traffic *since the last checkpoint* rather than by the
    /// deployment's whole lifetime.
    ///
    /// ## The order is the correctness argument
    ///
    /// 1. **Snapshot first**, durably. From this instant every decision in
    ///    the journal is already folded into the snapshot's ledgers.
    /// 2. Then rotate: flush + fsync the live journal, rename it to its
    ///    `through-<last>` name (atomic), recreate an empty live file, fsync
    ///    the directory so the renames themselves survive a power cut.
    ///
    /// Every crash window therefore lands on a loadable state: before the
    /// snapshot nothing moved; between snapshot and rotation the old pairing
    /// still replays exactly (costs fold only at or after the watermark);
    /// after rotation the segment plus fresh live journal concatenate into
    /// the same dense stream. A refused compaction — snapshot watermark not
    /// matching the durable end, or a name collision — moves nothing.
    ///
    /// The governance journal is deliberately *not* rotated: it grows with
    /// rule changes, not traffic, and rotating it would need an ordinal
    /// anchor the snapshot does not carry. See the crate docs.
    pub fn compact(&mut self, snapshot: &DeploymentSnapshot) -> Result<(), StoreError> {
        let journal_path = self.journal_path();
        if let Some(reason) = &self.poisoned {
            return Err(StoreError::Poisoned {
                path: journal_path,
                detail: reason.clone(),
            });
        }

        let watermark = snapshot.sequence_watermark;
        if watermark != self.next_sequence {
            return Err(StoreError::CompactRefused {
                path: journal_path,
                detail: format!(
                    "snapshot watermark {watermark} does not match the durable \
                     journal end {}",
                    self.next_sequence
                ),
            });
        }

        // 1. Durable checkpoint before anything moves.
        self.save_snapshot(snapshot)?;

        // 2. Seal the live journal only if it actually holds decisions since
        //    the last rotation. Existence alone proves nothing — after every
        //    rotation an empty live file sits there by design.
        let live_len = std::fs::metadata(&journal_path)
            .map(|meta| meta.len())
            .unwrap_or(0);
        if live_len > 0 {
            let last =
                self.next_sequence
                    .checked_sub(1)
                    .ok_or_else(|| StoreError::CompactRefused {
                        path: journal_path.clone(),
                        detail: "a non-empty journal must end at sequence >= 0".into(),
                    })?;
            let segment_path = self
                .root
                .join(format!("{SEGMENT_PREFIX}{last}{SEGMENT_SUFFIX}"));
            if segment_path.exists() {
                return Err(StoreError::CompactRefused {
                    path: segment_path,
                    detail: "a segment with this name already exists".into(),
                });
            }
            // Flush the buffered tail through to the disk before the fd that
            // wrote it goes away. An empty buffer makes `into_inner` unable
            // to fail; the error arm restores the writer anyway.
            self.journal.flush().map_err(io(&journal_path))?;
            let writer = std::mem::replace(
                &mut self.journal,
                BufWriter::new(
                    OpenOptions::new()
                        .append(true)
                        .open(&journal_path)
                        .map_err(io(&journal_path))?,
                ),
            );
            let file = match writer.into_inner() {
                Ok(file) => file,
                // The buffered tail could not be flushed, so this handle's
                // notion of "what is on disk" is gone with it. Poison rather
                // than pretend; nothing has been renamed yet.
                Err(error) => {
                    let source = error.into_error();
                    let reason = format!("rotation could not flush the live journal: {source}");
                    self.poisoned = Some(reason.clone());
                    return Err(StoreError::Poisoned {
                        path: journal_path,
                        detail: reason,
                    });
                }
            };
            file.sync_data().map_err(io(&journal_path))?;
            drop(file);
            std::fs::rename(&journal_path, &segment_path).map_err(io(&segment_path))?;

            let fresh = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&journal_path)
                .map_err(io(&journal_path))?;
            self.journal = BufWriter::new(fresh);
        }

        // Pin both names: the sealed segment and the fresh live file.
        sync_directory(&self.root)?;
        Ok(())
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
    ///
    /// **A refused batch writes nothing.** The whole batch is validated and
    /// serialized before a single byte reaches the writer, because the naive
    /// loop — check, write, check, write — has a nasty failure: a batch whose
    /// second record is out of order would already have buffered the first,
    /// and returning `Err` without flushing does not unbuffer it. The next
    /// successful append would then flush that orphan, and a caller who was
    /// told "nothing was written" and retried the batch would duplicate it.
    /// Validate-then-write makes the error mean what it says.
    pub fn append(&mut self, records: &[AuditRecord]) -> Result<(), StoreError> {
        let path = self.journal_path();

        // A prior IO failure may have left bytes in the file that no caller
        // was told about. Retrying from here would reuse their sequence
        // numbers; only a reopen (which recomputes the sequence from disk) is
        // safe.
        if let Some(reason) = &self.poisoned {
            return Err(StoreError::Poisoned {
                path,
                detail: reason.clone(),
            });
        }

        // Phase 1: nothing is written until the entire batch is known good.
        let mut expected = self.next_sequence;
        let mut buffer: Vec<u8> = Vec::new();
        for record in records {
            if record.sequence != expected {
                return Err(StoreError::JournalDiscontinuity {
                    path,
                    line: 0,
                    expected,
                    found: record.sequence,
                });
            }
            let line = serde_json::to_vec(record).map_err(|e| StoreError::JournalCorrupt {
                path: path.clone(),
                line: 0,
                detail: format!("cannot be serialized: {e}"),
            })?;
            // A record that serialized with an embedded newline would split
            // into two lines and corrupt the framing of every later read.
            // `serde_json` escapes newlines, so this cannot happen — which is
            // exactly why it is worth asserting rather than assuming.
            if line.contains(&b'\n') {
                return Err(StoreError::JournalCorrupt {
                    path,
                    line: 0,
                    detail: "a serialized record contains a raw newline, which \
                             would break the one-record-per-line framing"
                        .to_string(),
                });
            }
            buffer.extend_from_slice(&line);
            buffer.push(b'\n');
            expected += 1;
        }

        // Phase 2: one write, one sync, then the sequence advances. The file's
        // length before the write is the rollback point: if any step fails
        // partway, the store truncates back to it (best effort), poisons
        // itself, and refuses every later append until reopened. A retry from
        // a poisoned store would write the same sequences twice and turn this
        // process's confusion into permanent journal corruption.
        let durable_length = self.journal.get_ref().metadata().map_err(io(&path))?.len();
        let outcome = self
            .journal
            .write_all(&buffer)
            .and_then(|()| self.journal.flush())
            .and_then(|()| self.journal.get_ref().sync_data());
        if let Err(source) = outcome {
            let file = self.journal.get_ref();
            let _ = file.set_len(durable_length);
            let _ = file.sync_data();
            let reason = format!("journal append failed after {durable_length} durable bytes");
            self.poisoned = Some(reason);
            return Err(StoreError::Io { path, source });
        }
        self.next_sequence = expected;
        Ok(())
    }

    /// Enter the poisoned state directly. Test scaffolding: a real poisoning
    /// needs a filesystem failure mid-append, which no test wants to stage.
    #[cfg(test)]
    fn poison(&mut self, reason: &str) {
        self.poisoned = Some(reason.to_string());
    }

    /// Append rule changes, with the same validate-then-write discipline as
    /// [`Store::append`]: nothing reaches the writer until the whole batch is
    /// known good, so a refused batch really did write nothing. Like
    /// [`Store::append`], an IO failure poisons the store until reopen.
    pub fn append_governance(&mut self, records: &[GovernanceRecord]) -> Result<(), StoreError> {
        let path = self.governance_path();

        if let Some(reason) = &self.poisoned {
            return Err(StoreError::Poisoned {
                path,
                detail: reason.clone(),
            });
        }

        let mut expected = self.next_ordinal;
        let mut buffer: Vec<u8> = Vec::new();
        for record in records {
            if record.ordinal != expected {
                return Err(StoreError::JournalDiscontinuity {
                    path,
                    line: 0,
                    expected,
                    found: record.ordinal,
                });
            }
            let line = serde_json::to_vec(record).map_err(|e| StoreError::JournalCorrupt {
                path: path.clone(),
                line: 0,
                detail: format!("cannot be serialized: {e}"),
            })?;
            if line.contains(&b'\n') {
                return Err(StoreError::JournalCorrupt {
                    path,
                    line: 0,
                    detail: "a serialized record contains a raw newline, which \
                             would break the one-record-per-line framing"
                        .to_string(),
                });
            }
            buffer.extend_from_slice(&line);
            buffer.push(b'\n');
            expected += 1;
        }

        // Roll back and poison on failure, exactly as `append` does: partial
        // governance bytes plus an unadvanced ordinal would duplicate rule
        // changes on retry.
        let durable_length = self
            .governance
            .get_ref()
            .metadata()
            .map_err(io(&path))?
            .len();
        let outcome = self
            .governance
            .write_all(&buffer)
            .and_then(|()| self.governance.flush())
            .and_then(|()| self.governance.get_ref().sync_data());
        if let Err(source) = outcome {
            let file = self.governance.get_ref();
            let _ = file.set_len(durable_length);
            let _ = file.sync_data();
            let reason = format!("governance append failed after {durable_length} durable bytes");
            self.poisoned = Some(reason);
            return Err(StoreError::Io { path, source });
        }
        self.next_ordinal = expected;
        Ok(())
    }

    /// Read the durable state back.
    ///
    /// `Ok(None)` means "no store here yet" and is the *only* empty answer:
    /// anything present but unreadable is an error, because a governance
    /// deployment that silently starts empty has reset every quota it holds.
    pub fn load(&self) -> Result<Option<Loaded>, StoreError> {
        let snapshot_path = self.snapshot_path();

        let snapshot_bytes = match std::fs::read(&snapshot_path) {
            Ok(b) => Some(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(io(&snapshot_path)(e)),
        };
        let journal = read_audit_history(&self.root)?;
        let governance = read_governance(&self.governance_path())?;

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
                let (governance, governance_torn) = governance.unwrap_or_default();
                Ok(Some(Loaded {
                    rotated_segments: segment_paths(&self.root)?.len(),
                    snapshot,
                    journal,
                    governance,
                    // One torn-tail figure for the store, not one per file:
                    // what the caller has to say out loud is "a write did not
                    // survive", and which file it was in does not change that.
                    torn_tail: torn_tail + governance_torn,
                }))
            }
        }
    }
}

/// A journal file's committed lines, and how many bytes of torn tail were
/// discarded to get them.
type Committed = (Vec<Vec<u8>>, usize);

/// Split a journal file into its committed lines. `None` when the file does
/// not exist.
///
/// Returns the lines and how many bytes of torn tail were discarded. Both
/// journals share this because both share the framing: one JSON object per
/// line, appended, never rewritten.
fn read_lines(path: &Path) -> Result<Option<Committed>, StoreError> {
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

    // `committed` ends with the final newline, so splitting on it always
    // yields one trailing empty element. That one is an artefact of the split
    // and is dropped. Every *other* empty element is a blank line in the
    // middle of the file, which an append cannot produce — so it is corruption,
    // not whitespace to be tolerant of. Skipping blank lines silently is how a
    // hand-edited journal reads as valid.
    let mut lines: Vec<&[u8]> = committed.split(|b| *b == b'\n').collect();
    let trailing = lines.pop();
    debug_assert!(matches!(trailing, None | Some(&[])));

    for (index, line) in lines.iter().enumerate() {
        if line.is_empty() {
            return Err(StoreError::JournalCorrupt {
                path: path.to_path_buf(),
                line: index + 1,
                detail: "blank line: an append never writes one, so the file \
                         has been edited or damaged"
                    .to_string(),
            });
        }
    }
    Ok(Some((
        lines.into_iter().map(<[u8]>::to_vec).collect(),
        torn_tail,
    )))
}

/// Parse the decision journal: every rotated segment in watermark order,
/// then the live file. The concatenation must be one dense stream starting
/// at sequence zero — exactly what a single un-rotated journal used to be.
///
/// A gap anywhere means a decision was made and lost, and this is the only
/// place that can still say so.
fn read_audit_history(root: &Path) -> Result<Option<(Vec<AuditRecord>, usize)>, StoreError> {
    let mut records: Vec<AuditRecord> = Vec::new();
    let mut expected = 0u64;
    let mut seen_any = false;

    for path in segment_paths(root)? {
        let Some((lines, torn)) = read_lines(&path)? else {
            continue;
        };
        // A segment is published by an atomic rename of a fully synced file,
        // so a torn tail here is damage, not a crash window to forgive.
        if torn != 0 {
            return Err(StoreError::JournalCorrupt {
                path,
                line: 0,
                detail: format!(
                    "rotated segment ends with {torn} bytes that no newline \
                     commits — a complete segment can only be damaged"
                ),
            });
        }
        append_audit_records(&mut records, &mut expected, &path, lines)?;
        seen_any = true;
    }

    let live_path = root.join(JOURNAL_FILE);
    let torn_live = match read_lines(&live_path)? {
        None => 0,
        Some((lines, torn)) => {
            append_audit_records(&mut records, &mut expected, &live_path, lines)?;
            seen_any = true;
            torn
        }
    };

    Ok(seen_any.then_some((records, torn_live)))
}

fn append_audit_records(
    records: &mut Vec<AuditRecord>,
    expected: &mut u64,
    path: &Path,
    lines: Vec<Vec<u8>>,
) -> Result<(), StoreError> {
    for (index, line) in lines.into_iter().enumerate() {
        let record: AuditRecord =
            serde_json::from_slice(&line).map_err(|e| StoreError::JournalCorrupt {
                path: path.to_path_buf(),
                line: index + 1,
                detail: e.to_string(),
            })?;
        if record.sequence != *expected {
            return Err(StoreError::JournalDiscontinuity {
                path: path.to_path_buf(),
                line: index + 1,
                expected: *expected,
                found: record.sequence,
            });
        }
        *expected = record.sequence + 1;
        records.push(record);
    }
    Ok(())
}

/// Every rotated decision-journal segment under `root`, ordered by the last
/// sequence it holds. A name that matches the prefix but not its exact
/// grammar is operator debris sitting where the loader looks — refused rather
/// than silently skipped, or it would hide exactly the history it names.
fn segment_paths(root: &Path) -> Result<Vec<PathBuf>, StoreError> {
    let mut segments: Vec<(u64, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(root).map_err(io(root))? {
        let entry = entry.map_err(io(root))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(rest) = name.strip_prefix(SEGMENT_PREFIX) else {
            continue;
        };
        let Some(last) = rest.strip_suffix(SEGMENT_SUFFIX) else {
            continue;
        };
        let Ok(last) = last.parse::<u64>() else {
            let detail = format!("segment name {name:?} does not carry a decimal watermark");
            return Err(StoreError::JournalCorrupt {
                path,
                line: 0,
                detail,
            });
        };
        segments.push((last, path));
    }
    segments.sort_by_key(|(last, _)| *last);
    Ok(segments.into_iter().map(|(_, path)| path).collect())
}

/// Parse the governance journal. `None` when the file does not exist.
///
/// Ordinals must be dense from zero, for the same reason and with the same
/// force as the decision journal's sequences: a rule change that was made and
/// then lost is precisely the thing this file exists to make impossible.
fn read_governance(path: &Path) -> Result<Option<(Vec<GovernanceRecord>, usize)>, StoreError> {
    let Some((lines, torn_tail)) = read_lines(path)? else {
        return Ok(None);
    };
    let mut records: Vec<GovernanceRecord> = Vec::new();
    let mut expected = 0u64;
    for (index, line) in lines.into_iter().enumerate() {
        let record: GovernanceRecord =
            serde_json::from_slice(&line).map_err(|e| StoreError::JournalCorrupt {
                path: path.to_path_buf(),
                line: index + 1,
                detail: e.to_string(),
            })?;
        if record.ordinal != expected {
            return Err(StoreError::JournalDiscontinuity {
                path: path.to_path_buf(),
                line: index + 1,
                expected,
                found: record.ordinal,
            });
        }
        expected = record.ordinal + 1;
        records.push(record);
    }
    Ok(Some((records, torn_tail)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ccos_enterprise_runtime::{
        actor, request, two_tenant_deployment, Call, Deployment, JournalEntry, Outcome, Refusal,
        RestoreError, TenantState,
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
                justification: None,
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
    fn an_append_failure_poisons_every_later_append_until_reopen() {
        let dir = scratch("poison");
        let mut store = Store::open(&dir).expect("open");
        let mut d = two_tenant_deployment();
        store.save_snapshot(&d.snapshot()).expect("snapshot");
        run(&mut d, &mut store, &[("acme", "r-1", 10)]);
        assert_eq!(store.next_sequence(), 1);

        // Simulate what a real mid-append IO failure leaves behind: unknown
        // bytes in the file and an unadvanced sequence counter.
        store.poison("simulated io failure");

        d.admit(Call {
            actor: &actor("memorithm", "alice", AuthStrength::Token),
            request: &request("acme", "alice", "memory.ingest", "r-2"),
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
            justification: None,
        });
        let fresh: Vec<_> = d.audit().filter(|r| r.sequence >= 1).cloned().collect();
        assert_eq!(fresh.len(), 1);

        // A retry must be refused — writing sequence 1 again would brick the
        // journal at the next open — for both journals.
        assert!(matches!(
            store.append(&fresh),
            Err(StoreError::Poisoned { .. })
        ));
        assert!(matches!(
            store.append_governance(&[GovernanceRecord {
                at_sequence: 1,
                ordinal: 0,
                actor: None,
                justification: None,
                change: ccos_enterprise_runtime::GovernanceChange::RoleDefined {
                    role: "x".into(),
                    permissions: vec![],
                },
            }]),
            Err(StoreError::Poisoned { .. })
        ));

        drop(store);
        // Reopening recomputes the sequence from what is actually durable, so
        // the deployment recovers instead of carrying silent damage forward.
        let mut reopened = Store::open(&dir).expect("reopen");
        assert_eq!(reopened.next_sequence(), 1, "sequence recomputed from disk");
        reopened.append(&fresh).expect("append after reopen");
        assert_eq!(reopened.next_sequence(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_created_journal_file_survives_a_simulated_lost_directory_entry() {
        // The directory-entry fsync cannot be crash-tested here; what can be
        // asserted is that opening a fresh root leaves a loadable store whose
        // files exist (the entry was pinned), and reopening finds them.
        let dir = scratch("dirsync");
        {
            let store = Store::open(&dir).expect("open");
            assert!(dir.join(JOURNAL_FILE).exists());
            assert!(dir.join(GOVERNANCE_FILE).exists());
            drop(store);
        }
        let store = Store::open(&dir).expect("reopen");
        assert!(store.load().expect("load").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn compaction_rotates_history_and_startup_stays_exact() {
        let dir = scratch("compact1");
        let mut store = Store::open(&dir).expect("open");
        let mut d = two_tenant_deployment();
        store.save_snapshot(&d.snapshot()).expect("snapshot");

        // History that will be sealed away.
        run(
            &mut d,
            &mut store,
            &[("acme", "c-1", 100), ("acme", "c-2", 50)],
        );
        assert_eq!(store.next_sequence(), 2);

        // Compact at exactly the deployment's own watermark.
        let snapshot = d.snapshot();
        assert_eq!(snapshot.sequence_watermark, 2);
        store.compact(&snapshot).expect("compact");

        // The segment exists under its watermark name; the live journal is
        // fresh; the store keeps appending densely.
        assert!(dir
            .join(format!("{SEGMENT_PREFIX}1{SEGMENT_SUFFIX}"))
            .exists());
        assert_eq!(store.next_sequence(), 2);
        run(&mut d, &mut store, &[("acme", "c-3", 25)]);
        assert_eq!(
            store.next_sequence(),
            3,
            "sequences continue after rotation"
        );

        // A second compaction seals only the new tail.
        store.compact(&d.snapshot()).expect("second compact");
        assert!(dir
            .join(format!("{SEGMENT_PREFIX}2{SEGMENT_SUFFIX}"))
            .exists());
        drop(store);

        // Startup folds segments plus live journal into one exact ledger.
        let store = Store::open(&dir).expect("reopen");
        assert_eq!(store.next_sequence(), 3);
        let loaded = store.load().expect("load").expect("state");
        assert_eq!(loaded.rotated_segments, 2);
        assert_eq!(loaded.torn_tail, 0);
        let restored = Deployment::restore(loaded.snapshot, &loaded.journal, &loaded.governance)
            .expect("restore over segmented history");
        assert_eq!(
            restored.spent("acme"),
            Some(175),
            "100 + 50 + 25, billed once"
        );
        assert_eq!(
            restored.audit().cloned().collect::<Vec<_>>(),
            d.audit().cloned().collect::<Vec<_>>(),
            "the trail is record-for-record identical across two rotations"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn compacting_an_empty_journal_is_a_no_op_that_moves_nothing() {
        let dir = scratch("compact2");
        let mut store = Store::open(&dir).expect("open");
        let mut d = two_tenant_deployment();
        store.save_snapshot(&d.snapshot()).expect("snapshot");
        run(&mut d, &mut store, &[("acme", "e-1", 10)]);

        store.compact(&d.snapshot()).expect("first compact");
        let segment = format!("{SEGMENT_PREFIX}0{SEGMENT_SUFFIX}");
        assert!(dir.join(&segment).exists());

        // Nothing new was decided: the live journal is empty now, so the
        // second pass must succeed without touching the existing segment.
        store.compact(&d.snapshot()).expect("idempotent compact");
        assert!(dir.join(&segment).exists());
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(SEGMENT_PREFIX))
            .collect();
        assert_eq!(names.len(), 1, "no duplicate segment: {names:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn compaction_refuses_a_snapshot_that_does_not_match_the_durable_end() {
        let dir = scratch("compact3");
        let mut store = Store::open(&dir).expect("open");
        let mut d = two_tenant_deployment();
        store.save_snapshot(&d.snapshot()).expect("snapshot");
        run(&mut d, &mut store, &[("acme", "m-1", 10)]);
        assert_eq!(store.next_sequence(), 1);

        // A stale snapshot (watermark 0) must be refused outright.
        let stale = two_tenant_deployment();
        let err = match store.compact(&stale.snapshot()) {
            Ok(()) => panic!("stale watermark must refuse"),
            Err(e) => e,
        };
        assert!(matches!(err, StoreError::CompactRefused { .. }), "{err}");

        // And nothing moved: the live journal still holds the decision.
        assert!(!dir
            .join(format!("{SEGMENT_PREFIX}0{SEGMENT_SUFFIX}"))
            .exists());
        drop(store);
        let store = Store::open(&dir).expect("reopen");
        assert_eq!(store.next_sequence(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_lost_segment_is_refused_at_the_layer_that_can_name_the_loss() {
        // Two rotations: `through-1` holds sequences 0..=1, `through-2` holds
        // sequence 2, and the live journal is empty.
        let build = |tag: &str| -> (PathBuf, u64) {
            let dir = scratch(tag);
            let mut store = Store::open(&dir).expect("open");
            let mut d = two_tenant_deployment();
            store.save_snapshot(&d.snapshot()).expect("snapshot");
            run(
                &mut d,
                &mut store,
                &[("acme", "l-1", 10), ("acme", "l-2", 10)],
            );
            store.compact(&d.snapshot()).expect("compact 1");
            run(&mut d, &mut store, &[("acme", "l-3", 5)]);
            store.compact(&d.snapshot()).expect("compact 2");
            drop(store);
            (dir, d.spent("acme").unwrap_or(0))
        };

        // Losing the LATER segment leaves history that is dense from zero
        // and simply stops early: the store cannot tell that from a shorter
        // life, but restore can — its watermark check names the exact gap.
        let (dir_a, _spent_a) = build("compact4a");
        std::fs::remove_file(dir_a.join(format!("{SEGMENT_PREFIX}2{SEGMENT_SUFFIX}")))
            .expect("lose the late segment");
        {
            let store = Store::open(&dir_a).expect("open");
            let loaded = store
                .load()
                .expect("load still reads the rest")
                .expect("state");
            assert_eq!(loaded.journal.len(), 2);
            let err =
                match Deployment::restore(loaded.snapshot, &loaded.journal, &loaded.governance) {
                    Ok(_) => panic!("a journal short of the watermark must refuse"),
                    Err(e) => e,
                };
            assert!(
                matches!(err, RestoreError::JournalDiscontinuity { .. }),
                "{err}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir_a);

        // Losing the EARLIER segment breaks the stream's own density: what
        // remains starts at sequence 2, and nothing dense can begin there.
        // The store refuses while opening, before any handle exists.
        let (dir_b, _) = build("compact4b");
        std::fs::remove_file(dir_b.join(format!("{SEGMENT_PREFIX}1{SEGMENT_SUFFIX}")))
            .expect("lose the early segment");
        let err = match Store::open(&dir_b) {
            Ok(_) => panic!("a density break across segments must refuse open"),
            Err(e) => e,
        };
        assert!(
            matches!(err, StoreError::JournalDiscontinuity { .. }),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&dir_b);
    }

    #[test]
    fn a_damaged_segment_is_corruption_not_a_forgivable_tail() {
        // A rotated segment was published by fsync+rename: unlike the live
        // journal it has no crash window, so a torn end is damage and is
        // refused rather than trimmed.
        let dir = scratch("compact5");
        let mut store = Store::open(&dir).expect("open");
        let mut d = two_tenant_deployment();
        store.save_snapshot(&d.snapshot()).expect("snapshot");
        run(&mut d, &mut store, &[("acme", "d-1", 10)]);
        store.compact(&d.snapshot()).expect("compact");
        drop(store);
        let segment = dir.join(format!("{SEGMENT_PREFIX}0{SEGMENT_SUFFIX}"));
        let mut bytes = std::fs::read(&segment).expect("read segment");
        bytes.truncate(bytes.len() - 3); // tear mid-record, newline gone
        std::fs::write(&segment, &bytes).expect("damage segment");
        let err = match Store::open(&dir) {
            Ok(_) => panic!("a torn segment must refuse open"),
            Err(e) => e,
        };
        assert!(matches!(err, StoreError::JournalCorrupt { .. }), "{err}");
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
        let restored = Deployment::restore(loaded.snapshot, &loaded.journal, &loaded.governance)
            .expect("restore");
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
        let mut restored =
            Deployment::restore(loaded.snapshot, &loaded.journal, &loaded.governance)
                .expect("restore");
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
                    justification: None,
                })
                .refusal(),
            Some(&Refusal::BudgetExhausted),
            "bouncing the process must not refill the budget"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A rule change survives a restart, keeps its place in the decision
    /// stream, and is not re-applied.
    ///
    /// The last part is the one worth being explicit about: the snapshot
    /// already holds the roles and allowlists the change produced, so replaying
    /// the record as an instruction would apply it twice. Governance records
    /// are evidence — read back into the trail, never back into the state.
    #[test]
    fn a_rule_change_survives_a_restart_in_its_place_in_the_journal() {
        let dir = scratch("governance");
        let mut store = Store::open(&dir).expect("open");
        let mut d = two_tenant_deployment();
        store.save_snapshot(&d.snapshot()).expect("snapshot");

        // A decision, then a change, then another decision.
        run(&mut d, &mut store, &[("acme", "before", 10)]);
        assert!(d
            .as_admin("root", "incident 902")
            .redefine_role("reader", &["memory.read", "policy.admin"]));
        let changes: Vec<_> = d.governance().cloned().collect();
        assert_eq!(changes.len(), 1);
        store.append_governance(&changes).expect("append");
        run(&mut d, &mut store, &[("acme", "after", 10)]);
        store.save_snapshot(&d.snapshot()).expect("snapshot");
        drop(store);

        let store = Store::open(&dir).expect("reopen");
        let loaded = store.load().expect("load").expect("store");
        assert_eq!(loaded.governance.len(), 1, "the change is on disk");
        assert_eq!(loaded.torn_tail, 0);
        let restored = Deployment::restore(loaded.snapshot, &loaded.journal, &loaded.governance)
            .expect("restore");

        // Same trail, same order, same attribution.
        let rows = restored.journal();
        assert_eq!(rows.len(), 3, "{rows:?}");
        let JournalEntry::Governance(change) = rows[1] else {
            panic!("the change lost its place: {rows:?}");
        };
        assert_eq!(change.at_sequence, 1);
        assert_eq!(change.actor.as_deref(), Some("root"));
        assert_eq!(change.justification.as_deref(), Some("incident 902"));

        // The state is the snapshot's, not the record re-applied: `reader`
        // holds exactly what it held when the snapshot was taken.
        assert_eq!(
            restored.roles_of("bob"),
            vec!["reader"],
            "no grant was invented by the replay"
        );
        // And the next change continues the ordinal rather than restarting it,
        // so a second restart cannot renumber history.
        let mut restored = restored;
        assert!(restored.remove_role("reader"));
        assert_eq!(
            restored.governance().last().expect("journaled").ordinal,
            1,
            "the ordinal continues across the restart"
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
        let mut restored =
            Deployment::restore(loaded.snapshot, &loaded.journal, &loaded.governance)
                .expect("restore");
        let a = actor("memorithm", "alice", AuthStrength::Token);
        let req = request("acme", "alice", "memory.ingest", "once");
        assert_eq!(
            restored.admit(Call {
                actor: &a,
                request: &req,
                model: "claude-opus",
                cost_tokens: 100,
                variant: None,
                justification: None,
            }),
            Outcome::Replayed
        );
        assert_eq!(
            restored.spent("acme"),
            Some(100),
            "the retry after a restart is an explicit replay and must not be billed twice"
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
        let restored = Deployment::restore(loaded.snapshot, &loaded.journal, &loaded.governance)
            .expect("restore");
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
        let err = match Deployment::restore(loaded.snapshot, &loaded.journal, &loaded.governance) {
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
            justification: None,
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
        let restored = Deployment::restore(loaded.snapshot, &loaded.journal, &loaded.governance)
            .expect("restore");

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

    /// A refused batch must write nothing at all — not "nothing visible yet".
    ///
    /// The first version of `append` checked and wrote record by record, so a
    /// batch whose second record was out of order had already buffered the
    /// first. Returning `Err` did not unbuffer it, the next successful append
    /// flushed the orphan, and a caller who was told nothing was written and
    /// retried the batch duplicated its first record. This pins the repair on
    /// the far side of a real reopen, which is the only place the buffer can
    /// no longer hide anything.
    #[test]
    fn a_refused_batch_leaves_no_orphan_behind_it() {
        let dir = scratch("orphan-batch");
        let mut store = Store::open(&dir).expect("open");
        store
            .save_snapshot(&two_tenant_deployment().snapshot())
            .expect("snapshot");

        let good = AuditRecord {
            sequence: 0,
            request_id: "r-0".into(),
            tenant: "acme".into(),
            actor: "alice".into(),
            tool: "memory.ingest".into(),
            cost: 1,
            justification: None,
            outcome: Outcome::Forwarded,
        };
        let mut skips = good.clone();
        skips.sequence = 7; // 1 is expected after `good`
        skips.request_id = "r-7".into();

        let err = store
            .append(&[good.clone(), skips])
            .expect_err("the batch skips a sequence");
        assert!(
            matches!(
                err,
                StoreError::JournalDiscontinuity {
                    expected: 1,
                    found: 7,
                    ..
                }
            ),
            "{err}"
        );
        assert_eq!(
            store.next_sequence(),
            0,
            "a refused batch must not advance the sequence"
        );

        // The store is still usable, and the retried batch is not duplicated.
        store.append(&[good]).expect("the corrected batch");
        drop(store);

        let reopened = Store::open(&dir).expect("reopen");
        let loaded = reopened.load().expect("load").expect("store");
        assert_eq!(
            loaded.journal.len(),
            1,
            "exactly one record survived — the refused batch wrote nothing"
        );
        assert_eq!(loaded.journal[0].request_id, "r-0");
        assert_eq!(reopened.next_sequence(), 1);
        let text = std::fs::read_to_string(dir.join(JOURNAL_FILE)).expect("read");
        assert_eq!(text.lines().count(), 1, "one line on disk: {text:?}");
        assert!(!text.contains("r-7"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A blank line in the middle of the journal is damage, not whitespace.
    /// The first version skipped empty lines silently, so a hand-edited file
    /// read as valid.
    #[test]
    fn a_blank_line_in_the_middle_is_corruption_not_whitespace() {
        let dir = scratch("blank");
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
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(&journal, format!("{}\n\n{}\n", lines[0], lines[1])).expect("write");

        let err = match Store::open(&dir) {
            Ok(_) => panic!("a blank line must not read as a valid journal"),
            Err(e) => e,
        };
        assert!(
            matches!(err, StoreError::JournalCorrupt { line: 2, .. }),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The framing assumption, asserted rather than assumed: a refusal message
    /// carrying a raw newline would split one record across two lines and
    /// desynchronise every later read. `serde_json` escapes it — this is the
    /// test that notices if that ever stops being true.
    #[test]
    fn a_hostile_refusal_message_cannot_break_the_line_framing() {
        let dir = scratch("framing");
        let mut store = Store::open(&dir).expect("open");
        let d = two_tenant_deployment();
        store.save_snapshot(&d.snapshot()).expect("snapshot");

        let hostile = AuditRecord {
            sequence: 0,
            request_id: "r\n{\"sequence\":99}\n".into(),
            tenant: "acme".into(),
            actor: "a\"lice\\".into(),
            tool: "memory.\u{202e}recall\u{0000}".into(),
            cost: 0,
            justification: None,
            outcome: Outcome::Refused(Refusal::OutsideBoundary(
                "line one\nline two\r\n\"quoted\"".into(),
            )),
        };
        store
            .append(std::slice::from_ref(&hostile))
            .expect("append");
        drop(store);

        let text = std::fs::read_to_string(dir.join(JOURNAL_FILE)).expect("read");
        assert_eq!(
            text.lines().count(),
            1,
            "the record spread across more than one line: {text:?}"
        );

        let store = Store::open(&dir).expect("reopen");
        let loaded = store.load().expect("load").expect("store");
        assert_eq!(
            loaded.journal.len(),
            1,
            "the injected record did not appear"
        );
        assert_eq!(
            loaded.journal[0], hostile,
            "a hostile record must round-trip byte for byte"
        );
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
        let restored = Deployment::restore(loaded.snapshot, &loaded.journal, &loaded.governance)
            .expect("restore");
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
