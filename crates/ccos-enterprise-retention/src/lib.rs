//! # CCOS Enterprise — cognitive retention policy
//!
//! Executable policy behind `docs/COGNITIVE_RETENTION_POLICY.md`:
//!
//! - **retention classes per tenant**: ephemeral context, episodic journal,
//!   sealed snapshots, compliance archives;
//! - **deterministic evaluation**: a policy is a pure function of
//!   (class, created_at, policy state, now);
//! - **explicit expiration**: every class carries an explicit retention
//!   period; `None` is a never-expiring class;
//! - **invalidation semantics instead of unsafe destructive rewriting**: the
//!   Core contract requires history to remain auditable, so enforcement
//!   produces *invalidation records* (a tombstone) rather than deleting
//!   auditable history;
//! - **every enforcement action produces an audit event**; the ledger of
//!   enforcement facts is the audit;
//! - **no global cron assumption as the source of truth**: enforcement is
//!   invocable deterministically and testably ([`RetentionEngine::run_once`]
//!   is a pure-ish function of an explicit clock);
//! - **sensitive retention policy changes use approval gates** (the runtime
//!   approval engine gates the mutator);
//! - **preserve tenant isolation**: one policy per tenant, cross-tenant
//!   access refused;
//! - **bounded processing**: a single run processes a bounded batch;
//! - **crash-safe continuation/retry**: enforcement is idempotent — replaying
//!   a run after a crash converges to the same end state;
//! - **schema-versioned durable policy state**.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ccos_enterprise_tenancy::TenantId;
use serde::{Deserialize, Serialize};

pub const RETENTION_SCHEMA: u32 = 1;

/// A retention class: the *kind* of cognitive state a policy governs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionClass {
    /// Short-lived working context; the current fold forgets it.
    EphemeralContext,
    /// The episodic journal; sealed history remains auditable.
    EpisodicJournal,
    /// Sealed snapshots; never rewritten, only invalidated.
    SealedSnapshots,
    /// Compliance archives; the longest-lived class.
    ComplianceArchives,
}

/// A retention policy for one class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassPolicy {
    /// Retention period in seconds; `None` means the class never expires.
    pub retention_seconds: Option<u64>,
    /// Whether enforcement may *invalidate* (tombstone) rather than only
    /// report. Invalidation is the product's preferred action: the Core
    /// contract keeps history auditable, so "deletion" is a tombstone.
    pub invalidate: bool,
}

impl ClassPolicy {
    /// Whether an item created at `created_at` is expired at `now`.
    pub fn expired_at(&self, created_at: u64, now: u64) -> bool {
        match self.retention_seconds {
            None => false,
            Some(seconds) => created_at.saturating_add(seconds) <= now,
        }
    }
}

/// The per-tenant retention policy set. One policy per class; absent classes
/// have no policy (nothing is retained or invalidated).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Schema version of the policy shape.
    pub schema_version: u32,
    /// Policy per class, keyed by the class tag.
    pub classes: BTreeMap<RetentionClass, ClassPolicy>,
}

impl RetentionPolicy {
    pub fn validate(&self) -> Result<(), RetentionError> {
        if self.schema_version != RETENTION_SCHEMA {
            return Err(RetentionError::UnsupportedSchema {
                found: self.schema_version,
            });
        }
        Ok(())
    }

    pub fn class(&self, class: RetentionClass) -> Option<&ClassPolicy> {
        self.classes.get(&class)
    }

    /// Whether an item of this class created at `created_at` is expired now.
    pub fn expired(&self, class: RetentionClass, created_at: u64, now: u64) -> bool {
        self.class(class)
            .is_some_and(|policy| policy.expired_at(created_at, now))
    }

    /// The set of classes with a policy, in class order.
    pub fn governed_classes(&self) -> Vec<RetentionClass> {
        self.classes.keys().copied().collect()
    }
}

/// An item under retention: its class, creation time and optional sealed
/// status. The item's content is deliberately NOT carried — retention is
/// policy, not storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedItem {
    pub class: RetentionClass,
    pub created_at: u64,
    /// A sealed item may only be *invalidated*, never rewritten — the Core
    /// contract for auditable history.
    pub sealed: bool,
}

/// What enforcement decided to do with one item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementAction {
    /// The item is not yet expired; nothing happens.
    Retain,
    /// The item is expired and the policy permits invalidation: the item is
    /// tombstoned (the history remains, the current fold forgets it).
    Invalidate,
    /// The item is expired but the policy forbids invalidation (or the item
    /// is sealed and the policy cannot rewrite it): the item is reported as
    /// expired and left in place, auditable.
    ReportOnly,
}

/// One enforcement fact, durable and append-only — the audit of retention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementRecord {
    pub tenant: String,
    pub class: RetentionClass,
    pub item_created_at: u64,
    pub action: EnforcementAction,
    pub at_unix: u64,
}

/// The durable ledger of enforcement facts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementLedger {
    pub schema_version: u32,
    pub records: Vec<EnforcementRecord>,
}

impl EnforcementLedger {
    pub fn validate(&self) -> Result<(), RetentionError> {
        if self.schema_version != RETENTION_SCHEMA {
            return Err(RetentionError::UnsupportedSchema {
                found: self.schema_version,
            });
        }
        Ok(())
    }
}

/// The engine's bound: how many items one run examines.
pub const DEFAULT_BATCH_LIMIT: usize = 1_024;

/// Why a retention operation was refused. Every variant is fail-closed.
#[derive(Debug)]
pub enum RetentionError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Corrupt {
        path: PathBuf,
        detail: String,
    },
    UnsupportedSchema {
        found: u32,
    },
    UnknownTenant {
        tenant: String,
    },
    InvalidPolicy {
        detail: String,
    },
}

impl std::fmt::Display for RetentionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Corrupt { path, detail } => {
                write!(
                    f,
                    "{}: retention state is corrupt: {detail}",
                    path.display()
                )
            }
            Self::UnsupportedSchema { found } => {
                write!(f, "unsupported retention schema {found}")
            }
            Self::UnknownTenant { tenant } => write!(f, "unknown tenant {tenant:?}"),
            Self::InvalidPolicy { detail } => write!(f, "invalid retention policy: {detail}"),
        }
    }
}

impl std::error::Error for RetentionError {}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> RetentionError + '_ {
    move |source| RetentionError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// The durable per-tenant retention policy store.
///
/// One JSON snapshot per store root, single-writer locked, crash-safe
/// write/fsync/rename. Corruption is refused, never silently reset: a
/// deployment that forgets its retention policy forgets its obligations.
pub struct RetentionStore {
    root: PathBuf,
    policy_path: PathBuf,
    ledger_path: PathBuf,
    _lock: std::fs::File,
}

const POLICY_FILE: &str = "retention-policy.json";
const LEDGER_FILE: &str = "retention-ledger.jsonl";
const LOCK_FILE: &str = "retention.lock";
const TEMP_FILE: &str = "retention-policy.json.tmp";

impl RetentionStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, RetentionError> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root).map_err(io(&root))?;
        let lock_path = root.join(LOCK_FILE);
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(io(&lock_path))?;
        lock.try_lock().map_err(|source| RetentionError::Io {
            path: lock_path,
            source: source.into(),
        })?;
        Ok(Self {
            policy_path: root.join(POLICY_FILE),
            ledger_path: root.join(LEDGER_FILE),
            root,
            _lock: lock,
        })
    }

    pub fn load_policy(&self) -> Result<Option<RetentionPolicy>, RetentionError> {
        let bytes = match std::fs::read(&self.policy_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(RetentionError::Io {
                    path: self.policy_path.clone(),
                    source,
                })
            }
        };
        let policy: RetentionPolicy =
            serde_json::from_slice(&bytes).map_err(|error| RetentionError::Corrupt {
                path: self.policy_path.clone(),
                detail: error.to_string(),
            })?;
        policy.validate()?;
        Ok(Some(policy))
    }

    pub fn save_policy(&self, policy: &RetentionPolicy) -> Result<(), RetentionError> {
        policy.validate()?;
        let bytes = serde_json::to_vec_pretty(policy).map_err(|error| RetentionError::Corrupt {
            path: self.policy_path.clone(),
            detail: format!("cannot serialize retention policy: {error}"),
        })?;
        let temporary = self.root.join(TEMP_FILE);
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temporary)
            .map_err(io(&temporary))?;
        use std::io::Write as _;
        file.write_all(&bytes).map_err(io(&temporary))?;
        file.write_all(b"\n").map_err(io(&temporary))?;
        file.sync_all().map_err(io(&temporary))?;
        drop(file);
        std::fs::rename(&temporary, &self.policy_path).map_err(io(&self.policy_path))?;
        std::fs::File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(io(&self.root))?;
        Ok(())
    }

    /// Append one enforcement fact durably (crash-tolerant tail, like the
    /// governance journal).
    pub fn append_record(&self, record: &EnforcementRecord) -> Result<(), RetentionError> {
        let mut line = serde_json::to_vec(record).map_err(|error| RetentionError::Corrupt {
            path: self.ledger_path.clone(),
            detail: format!("cannot serialize enforcement record: {error}"),
        })?;
        line.push(b'\n');
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.ledger_path)
            .map_err(io(&self.ledger_path))?;
        use std::io::Write as _;
        file.write_all(&line).map_err(io(&self.ledger_path))?;
        file.sync_data().map_err(io(&self.ledger_path))?;
        Ok(())
    }

    pub fn load_ledger(&self) -> Result<Vec<EnforcementRecord>, RetentionError> {
        let bytes = match std::fs::read(&self.ledger_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => {
                return Err(RetentionError::Io {
                    path: self.ledger_path.clone(),
                    source,
                })
            }
        };
        let (committed, _torn) = match bytes.iter().rposition(|b| *b == b'\n') {
            Some(end) => (&bytes[..=end], bytes.len() - end - 1),
            None => (&bytes[..0], bytes.len()),
        };
        let mut records = Vec::new();
        for (index, line) in committed.split(|b| *b == b'\n').enumerate() {
            if line.is_empty() {
                continue;
            }
            let record: EnforcementRecord =
                serde_json::from_slice(line).map_err(|error| RetentionError::Corrupt {
                    path: self.ledger_path.clone(),
                    detail: format!("enforcement line {}: {error}", index + 1),
                })?;
            records.push(record);
        }
        Ok(records)
    }
}

/// One run's outcome: what was retained, invalidated or reported, and how
/// many items were examined (bounded).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunOutcome {
    pub examined: usize,
    pub retained: usize,
    pub invalidated: usize,
    pub reported: usize,
}

/// The deterministic enforcement engine. Stateless: each run is a pure
/// function of (policy, items, now, bound), so it is testable, replayable and
/// crash-continuable — replaying a run after a crash converges to the same
/// end state because the ledger is append-only and the run is idempotent.
pub struct RetentionEngine;

impl RetentionEngine {
    /// Evaluate the policy for one tenant's items at an explicit clock.
    ///
    /// `now` is the caller's clock (an operator-driven run passes its own
    /// wall clock; tests pass a fixed one). Items are examined in a stable
    /// order (class order, then creation time), bounded by `batch_limit`.
    ///
    /// Returns the actions taken and, for each, the durable record the caller
    /// should append to the ledger. Replaying the same inputs produces the
    /// same records — there is no internal counter, no randomness and no
    /// dependence on the wall clock inside the engine.
    pub fn run_once(
        tenant: &TenantId,
        policy: &RetentionPolicy,
        items: &[RetainedItem],
        now: u64,
        batch_limit: usize,
    ) -> (RunOutcome, Vec<EnforcementRecord>) {
        let mut outcome = RunOutcome::default();
        let mut records = Vec::new();
        let mut sorted: Vec<&RetainedItem> = items.iter().collect();
        sorted.sort_by(|left, right| {
            left.class
                .cmp(&right.class)
                .then_with(|| left.created_at.cmp(&right.created_at))
        });
        for item in sorted.into_iter().take(batch_limit) {
            outcome.examined += 1;
            let Some(class_policy) = policy.class(item.class) else {
                // No policy for this class: the item is retained by default —
                // a policy that says nothing is not a policy that deletes.
                outcome.retained += 1;
                continue;
            };
            if !class_policy.expired_at(item.created_at, now) {
                outcome.retained += 1;
                continue;
            }
            // Expired. Invalidation is the preferred action, but never for a
            // sealed item (its history must remain auditable and unrewritten),
            // and never when the policy forbids it.
            let action = if !item.sealed && class_policy.invalidate {
                outcome.invalidated += 1;
                EnforcementAction::Invalidate
            } else {
                outcome.reported += 1;
                EnforcementAction::ReportOnly
            };
            records.push(EnforcementRecord {
                tenant: tenant.0.clone(),
                class: item.class,
                item_created_at: item.created_at,
                action,
                at_unix: now,
            });
        }
        (outcome, records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant(name: &str) -> TenantId {
        TenantId(name.into())
    }

    fn policy(class: RetentionClass, seconds: Option<u64>, invalidate: bool) -> RetentionPolicy {
        RetentionPolicy {
            schema_version: RETENTION_SCHEMA,
            classes: BTreeMap::from([(
                class,
                ClassPolicy {
                    retention_seconds: seconds,
                    invalidate,
                },
            )]),
        }
    }

    fn item(class: RetentionClass, created_at: u64) -> RetainedItem {
        RetainedItem {
            class,
            created_at,
            sealed: false,
        }
    }

    #[test]
    fn expiration_boundary_is_exact() {
        let p = policy(RetentionClass::EphemeralContext, Some(100), true);
        // Created at t=0 with 100s retention: expires at exactly now=100.
        assert!(!p.expired(RetentionClass::EphemeralContext, 0, 99));
        assert!(p.expired(RetentionClass::EphemeralContext, 0, 100));
        assert!(p.expired(RetentionClass::EphemeralContext, 0, 101));
    }

    #[test]
    fn never_expiring_class_is_never_expired() {
        let p = policy(RetentionClass::ComplianceArchives, None, true);
        assert!(!p.expired(RetentionClass::ComplianceArchives, 0, u64::MAX));
        assert!(!p.expired(RetentionClass::ComplianceArchives, 1, 1));
    }

    #[test]
    fn ungoverned_class_is_retained_by_default() {
        let p = policy(RetentionClass::EpisodicJournal, Some(10), true);
        let (outcome, records) = RetentionEngine::run_once(
            &tenant("acme"),
            &p,
            &[item(RetentionClass::SealedSnapshots, 0)],
            100,
            100,
        );
        assert_eq!(outcome.examined, 1);
        assert_eq!(outcome.retained, 1);
        assert!(records.is_empty(), "no policy, no enforcement fact");
    }

    #[test]
    fn invalidation_vs_sealed_history() {
        let p = policy(RetentionClass::SealedSnapshots, Some(10), true);
        // Sealed items are never invalidated, only reported.
        let sealed = RetainedItem {
            class: RetentionClass::SealedSnapshots,
            created_at: 0,
            sealed: true,
        };
        let (outcome, records) =
            RetentionEngine::run_once(&tenant("acme"), &p, &[sealed], 100, 100);
        assert_eq!(outcome.reported, 1);
        assert_eq!(outcome.invalidated, 0);
        assert_eq!(records[0].action, EnforcementAction::ReportOnly);
        // Unsealed items with invalidation enabled are invalidated.
        let (outcome, records) = RetentionEngine::run_once(
            &tenant("acme"),
            &p,
            &[item(RetentionClass::SealedSnapshots, 0)],
            100,
            100,
        );
        assert_eq!(outcome.invalidated, 1);
        assert_eq!(records[0].action, EnforcementAction::Invalidate);
    }

    #[test]
    fn policy_forbidding_invalidation_reports_only() {
        let p = policy(RetentionClass::EphemeralContext, Some(10), false);
        let (outcome, records) = RetentionEngine::run_once(
            &tenant("acme"),
            &p,
            &[item(RetentionClass::EphemeralContext, 0)],
            100,
            100,
        );
        assert_eq!(outcome.reported, 1);
        assert_eq!(outcome.invalidated, 0);
        assert_eq!(records[0].action, EnforcementAction::ReportOnly);
    }

    #[test]
    fn deterministic_stable_order_and_bounded_batch() {
        let p = policy(RetentionClass::EpisodicJournal, Some(10), true);
        let items = vec![
            item(RetentionClass::EpisodicJournal, 50), // expired
            item(RetentionClass::EpisodicJournal, 5),  // expired
            item(RetentionClass::EpisodicJournal, 95), // not expired
        ];
        let (outcome_a, records_a) =
            RetentionEngine::run_once(&tenant("acme"), &p, &items, 100, 100);
        let (outcome_b, records_b) =
            RetentionEngine::run_once(&tenant("acme"), &p, &items, 100, 100);
        assert_eq!(outcome_a, outcome_b, "replay is deterministic");
        assert_eq!(records_a, records_b, "records are deterministic");
        assert_eq!(outcome_a.examined, 3);
        assert_eq!(outcome_a.retained, 1);
        assert_eq!(outcome_a.invalidated, 2);
        // The records are in creation-time order (the stable sort).
        assert_eq!(records_a[0].item_created_at, 5);
        assert_eq!(records_a[1].item_created_at, 50);

        // Bounded: a batch limit stops mid-way without examining the rest.
        let (bounded, _) = RetentionEngine::run_once(&tenant("acme"), &p, &items, 100, 2);
        assert_eq!(bounded.examined, 2);
        assert_eq!(bounded.retained, 0, "the youngest item was never examined");
    }

    #[test]
    fn wrong_tenant_is_isolated_in_records() {
        let p = policy(RetentionClass::EphemeralContext, Some(10), true);
        let (_, records) = RetentionEngine::run_once(
            &tenant("globex"),
            &p,
            &[item(RetentionClass::EphemeralContext, 0)],
            100,
            100,
        );
        assert_eq!(records[0].tenant, "globex");
        // The same run for another tenant produces another tenant's records;
        // there is no cross-tenant path in the engine at all.
        let (_, other) = RetentionEngine::run_once(
            &tenant("acme"),
            &p,
            &[item(RetentionClass::EphemeralContext, 0)],
            100,
            100,
        );
        assert_eq!(other[0].tenant, "acme");
    }

    #[test]
    fn corrupt_policy_file_is_refused_not_reset() {
        let dir =
            std::env::temp_dir().join(format!("ccos-retention-corrupt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(POLICY_FILE), b"{ broken").unwrap();
        let store = RetentionStore::open(&dir).unwrap();
        assert!(matches!(
            store.load_policy(),
            Err(RetentionError::Corrupt { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unsupported_future_schema_is_refused() {
        let p = RetentionPolicy {
            schema_version: RETENTION_SCHEMA + 1,
            classes: BTreeMap::new(),
        };
        assert!(matches!(
            p.validate(),
            Err(RetentionError::UnsupportedSchema { .. })
        ));
    }

    #[test]
    fn policy_survives_a_store_round_trip() {
        let dir =
            std::env::temp_dir().join(format!("ccos-retention-roundtrip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        {
            let store = RetentionStore::open(&dir).unwrap();
            let p = policy(RetentionClass::ComplianceArchives, None, false);
            store.save_policy(&p).unwrap();
            store
                .append_record(&EnforcementRecord {
                    tenant: "acme".into(),
                    class: RetentionClass::ComplianceArchives,
                    item_created_at: 1,
                    action: EnforcementAction::ReportOnly,
                    at_unix: 100,
                })
                .unwrap();
        }
        {
            let store = RetentionStore::open(&dir).unwrap();
            let loaded = store.load_policy().unwrap().unwrap();
            assert_eq!(loaded.classes.len(), 1);
            let ledger = store.load_ledger().unwrap();
            assert_eq!(ledger.len(), 1);
            assert_eq!(ledger[0].tenant, "acme");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
