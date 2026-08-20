//! # CCOS Enterprise — cognitive retention policy
//!
//! Executable policy behind `docs/COGNITIVE_RETENTION_POLICY.md`.
//!
//! Retention is tenant-scoped and invalidation-based: an expired item is
//! tombstoned rather than destructively rewritten, so sealed history remains
//! auditable. Evaluation takes an explicit clock, never reads wall time, and
//! emits deterministic audit facts. Durable policy and audit state fail closed
//! on corruption and use single-writer, fsync/rename persistence.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ccos_enterprise_tenancy::TenantId;
use serde::{Deserialize, Serialize};

pub const RETENTION_SCHEMA: u32 = 1;
pub const DEFAULT_BATCH_LIMIT: usize = 1_024;
/// Absolute number of actions one invocation may emit.
pub const MAX_BATCH_LIMIT: usize = 4_096;
/// Absolute input bound. A caller must page a larger inventory instead of
/// making one invocation allocate/sort an unbounded attacker-controlled slice.
pub const MAX_INPUT_ITEMS: usize = 65_536;
pub const MAX_ITEM_ID_BYTES: usize = 128;

fn canonical_id(value: &str, max: usize) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    value.len() <= max
        && (first.is_ascii_lowercase() || first.is_ascii_digit())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionClass {
    EphemeralContext,
    EpisodicJournal,
    SealedSnapshots,
    ComplianceArchives,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassPolicy {
    /// Retention period in seconds. `None` means never expires.
    pub retention_seconds: Option<u64>,
    /// `true` emits an invalidation tombstone; `false` emits a report-only
    /// audit fact.
    pub invalidate: bool,
}

impl ClassPolicy {
    pub fn expired_at(&self, created_at: u64, now: u64) -> bool {
        self.retention_seconds
            .is_some_and(|seconds| created_at.saturating_add(seconds) <= now)
    }
}

/// Durable policy for exactly one tenant. Binding the tenant into the policy
/// closes the class of bugs where a valid Acme policy is accidentally applied
/// to Globex and the resulting records are merely relabelled by the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub schema_version: u32,
    pub tenant: String,
    pub classes: BTreeMap<RetentionClass, ClassPolicy>,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            schema_version: RETENTION_SCHEMA,
            tenant: String::new(),
            classes: BTreeMap::new(),
        }
    }
}

impl RetentionPolicy {
    pub fn validate(&self) -> Result<(), RetentionError> {
        if self.schema_version != RETENTION_SCHEMA {
            return Err(RetentionError::UnsupportedSchema {
                found: self.schema_version,
            });
        }
        if !canonical_id(&self.tenant, 128) {
            return Err(RetentionError::InvalidPolicy {
                detail: "tenant is not a canonical identifier".into(),
            });
        }
        Ok(())
    }

    pub fn class(&self, class: RetentionClass) -> Option<&ClassPolicy> {
        self.classes.get(&class)
    }

    pub fn expired(&self, class: RetentionClass, created_at: u64, now: u64) -> bool {
        self.class(class)
            .is_some_and(|policy| policy.expired_at(created_at, now))
    }

    pub fn governed_classes(&self) -> Vec<RetentionClass> {
        self.classes.keys().copied().collect()
    }
}

/// An opaque stable item identity is mandatory. Retention never stores the
/// item's content, but without an identity two distinct artifacts created in
/// the same class at the same second collapse into one audit fact during
/// idempotent replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedItem {
    pub tenant: String,
    pub item_id: String,
    pub class: RetentionClass,
    pub created_at: u64,
    /// Sealed content may never be rewritten. A tombstone is not a rewrite, so
    /// sealed items may still be invalidated when policy requires it.
    pub sealed: bool,
}

impl RetainedItem {
    fn validate(&self) -> Result<(), RetentionError> {
        if !canonical_id(&self.tenant, 128) {
            return Err(RetentionError::UnknownTenant {
                tenant: self.tenant.clone(),
            });
        }
        if !canonical_id(&self.item_id, MAX_ITEM_ID_BYTES) {
            return Err(RetentionError::InvalidItem {
                item_id: self.item_id.clone(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementAction {
    Retain,
    Invalidate,
    ReportOnly,
}

/// One durable enforcement fact. `item_id` makes the audit/idempotency key an
/// artifact identity rather than an accidental `(class, timestamp)` tuple.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EnforcementRecord {
    pub tenant: String,
    pub item_id: String,
    pub class: RetentionClass,
    pub item_created_at: u64,
    pub action: EnforcementAction,
    pub at_unix: u64,
}

impl EnforcementRecord {
    fn validate(&self) -> Result<(), RetentionError> {
        if !canonical_id(&self.tenant, 128) {
            return Err(RetentionError::UnknownTenant {
                tenant: self.tenant.clone(),
            });
        }
        if !canonical_id(&self.item_id, MAX_ITEM_ID_BYTES) {
            return Err(RetentionError::InvalidItem {
                item_id: self.item_id.clone(),
            });
        }
        Ok(())
    }
}

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
        for record in &self.records {
            record.validate()?;
        }
        Ok(())
    }
}

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
    InvalidItem {
        item_id: String,
    },
    LimitOutOfRange {
        found: usize,
        max: usize,
    },
}

impl std::fmt::Display for RetentionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Corrupt { path, detail } => {
                write!(f, "{}: retention state is corrupt: {detail}", path.display())
            }
            Self::UnsupportedSchema { found } => write!(f, "unsupported retention schema {found}"),
            Self::UnknownTenant { tenant } => write!(f, "unknown tenant {tenant:?}"),
            Self::InvalidPolicy { detail } => write!(f, "invalid retention policy: {detail}"),
            Self::InvalidItem { item_id } => write!(f, "invalid retention item id {item_id:?}"),
            Self::LimitOutOfRange { found, max } => {
                write!(f, "retention limit {found} is outside 1..={max}")
            }
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

    /// Append enforcement facts durably and idempotently. A final torn JSONL
    /// line is truncated before append; committed malformed lines are refused.
    pub fn append_records(&self, records: &[EnforcementRecord]) -> Result<(), RetentionError> {
        if records.is_empty() {
            return Ok(());
        }
        for record in records {
            record.validate()?;
        }

        let existing = match std::fs::read(&self.ledger_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(source) => {
                return Err(RetentionError::Io {
                    path: self.ledger_path.clone(),
                    source,
                })
            }
        };
        let committed_len = existing
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |end| end + 1);
        if committed_len != existing.len() {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&self.ledger_path)
                .map_err(io(&self.ledger_path))?;
            file.set_len(committed_len as u64)
                .map_err(io(&self.ledger_path))?;
            file.sync_data().map_err(io(&self.ledger_path))?;
        }

        let committed: BTreeSet<EnforcementRecord> = self.load_ledger()?.into_iter().collect();
        let mut incoming = BTreeSet::new();
        let mut buffer = Vec::new();
        for record in records {
            if committed.contains(record) || !incoming.insert(record.clone()) {
                continue;
            }
            let mut line = serde_json::to_vec(record).map_err(|error| RetentionError::Corrupt {
                path: self.ledger_path.clone(),
                detail: format!("cannot serialize enforcement record: {error}"),
            })?;
            line.push(b'\n');
            buffer.extend_from_slice(&line);
        }
        if buffer.is_empty() {
            return Ok(());
        }

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.ledger_path)
            .map_err(io(&self.ledger_path))?;
        use std::io::Write as _;
        file.write_all(&buffer).map_err(io(&self.ledger_path))?;
        file.sync_data().map_err(io(&self.ledger_path))?;
        // The append can create the JSONL entry for the first time; sync the
        // parent directory as well as the file contents.
        std::fs::File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(io(&self.root))?;
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
        let committed = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(&bytes[..0], |end| &bytes[..=end]);
        let mut records = Vec::new();
        for (index, line) in committed.split(|byte| *byte == b'\n').enumerate() {
            if line.is_empty() {
                continue;
            }
            let record: EnforcementRecord =
                serde_json::from_slice(line).map_err(|error| RetentionError::Corrupt {
                    path: self.ledger_path.clone(),
                    detail: format!("enforcement line {}: {error}", index + 1),
                })?;
            record.validate()?;
            records.push(record);
        }
        Ok(records)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunOutcome {
    /// Input items inspected. Always `<= MAX_INPUT_ITEMS`.
    pub examined: usize,
    /// Ungoverned or unexpired items.
    pub retained: usize,
    pub invalidated: usize,
    pub reported: usize,
    /// Expired governed items left for a later bounded invocation.
    pub deferred: usize,
}

pub struct RetentionEngine;

impl RetentionEngine {
    pub fn run_once(
        tenant: &TenantId,
        policy: &RetentionPolicy,
        items: &[RetainedItem],
        now: u64,
        batch_limit: usize,
    ) -> Result<(RunOutcome, Vec<EnforcementRecord>), RetentionError> {
        policy.validate()?;
        if policy.tenant != tenant.0 {
            return Err(RetentionError::UnknownTenant {
                tenant: policy.tenant.clone(),
            });
        }
        if batch_limit == 0 || batch_limit > MAX_BATCH_LIMIT {
            return Err(RetentionError::LimitOutOfRange {
                found: batch_limit,
                max: MAX_BATCH_LIMIT,
            });
        }
        if items.len() > MAX_INPUT_ITEMS {
            return Err(RetentionError::LimitOutOfRange {
                found: items.len(),
                max: MAX_INPUT_ITEMS,
            });
        }

        // Validate the complete bounded input before emitting any action. A
        // late cross-tenant item can therefore never leave a partial valid
        // prefix for the caller to persist.
        for item in items {
            item.validate()?;
            if item.tenant != tenant.0 {
                return Err(RetentionError::UnknownTenant {
                    tenant: item.tenant.clone(),
                });
            }
        }

        let mut eligible: Vec<&RetainedItem> = items
            .iter()
            .filter(|item| {
                policy
                    .class(item.class)
                    .is_some_and(|class_policy| class_policy.expired_at(item.created_at, now))
            })
            .collect();
        eligible.sort_by(|left, right| {
            left.class
                .cmp(&right.class)
                .then_with(|| left.created_at.cmp(&right.created_at))
                .then_with(|| left.item_id.cmp(&right.item_id))
        });

        let processed = eligible.len().min(batch_limit);
        let mut outcome = RunOutcome {
            examined: items.len(),
            retained: items.len().saturating_sub(eligible.len()),
            deferred: eligible.len().saturating_sub(processed),
            ..RunOutcome::default()
        };
        let mut records = Vec::with_capacity(processed);
        for item in eligible.into_iter().take(batch_limit) {
            let class_policy = policy
                .class(item.class)
                .expect("eligible items have a class policy");
            let action = if class_policy.invalidate {
                outcome.invalidated += 1;
                EnforcementAction::Invalidate
            } else {
                outcome.reported += 1;
                EnforcementAction::ReportOnly
            };
            records.push(EnforcementRecord {
                tenant: tenant.0.clone(),
                item_id: item.item_id.clone(),
                class: item.class,
                item_created_at: item.created_at,
                action,
                at_unix: now,
            });
        }
        Ok((outcome, records))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant(name: &str) -> TenantId {
        TenantId(name.into())
    }

    fn policy_for(
        tenant: &str,
        class: RetentionClass,
        seconds: Option<u64>,
        invalidate: bool,
    ) -> RetentionPolicy {
        RetentionPolicy {
            schema_version: RETENTION_SCHEMA,
            tenant: tenant.into(),
            classes: BTreeMap::from([(
                class,
                ClassPolicy {
                    retention_seconds: seconds,
                    invalidate,
                },
            )]),
        }
    }

    fn item(id: &str, class: RetentionClass, created_at: u64) -> RetainedItem {
        RetainedItem {
            tenant: "acme".into(),
            item_id: id.into(),
            class,
            created_at,
            sealed: false,
        }
    }

    #[test]
    fn expiration_boundary_is_exact() {
        let p = policy_for("acme", RetentionClass::EphemeralContext, Some(100), true);
        assert!(!p.expired(RetentionClass::EphemeralContext, 0, 99));
        assert!(p.expired(RetentionClass::EphemeralContext, 0, 100));
    }

    #[test]
    fn never_expiring_class_is_never_expired() {
        let p = policy_for("acme", RetentionClass::ComplianceArchives, None, true);
        assert!(!p.expired(RetentionClass::ComplianceArchives, 0, u64::MAX));
    }

    #[test]
    fn policy_and_items_are_both_tenant_bound() {
        let p = policy_for("globex", RetentionClass::EphemeralContext, Some(10), true);
        let err = RetentionEngine::run_once(
            &tenant("acme"),
            &p,
            &[item("item-1", RetentionClass::EphemeralContext, 0)],
            100,
            10,
        )
        .unwrap_err();
        assert!(matches!(err, RetentionError::UnknownTenant { tenant } if tenant == "globex"));

        let p = policy_for("acme", RetentionClass::EphemeralContext, Some(10), true);
        let mut wrong = item("item-1", RetentionClass::EphemeralContext, 0);
        wrong.tenant = "globex".into();
        assert!(matches!(
            RetentionEngine::run_once(&tenant("acme"), &p, &[wrong], 100, 10),
            Err(RetentionError::UnknownTenant { tenant }) if tenant == "globex"
        ));
    }

    #[test]
    fn sealed_content_can_be_tombstoned_without_rewrite() {
        let p = policy_for("acme", RetentionClass::SealedSnapshots, Some(10), true);
        let mut sealed = item("snap-1", RetentionClass::SealedSnapshots, 0);
        sealed.sealed = true;
        let (outcome, records) =
            RetentionEngine::run_once(&tenant("acme"), &p, &[sealed], 100, 10).unwrap();
        assert_eq!(outcome.invalidated, 1);
        assert_eq!(records[0].action, EnforcementAction::Invalidate);
    }

    #[test]
    fn bounded_run_filters_expired_items_before_the_action_limit() {
        let p = RetentionPolicy {
            schema_version: RETENTION_SCHEMA,
            tenant: "acme".into(),
            classes: BTreeMap::from([
                (
                    RetentionClass::EphemeralContext,
                    ClassPolicy {
                        retention_seconds: Some(10),
                        invalidate: true,
                    },
                ),
                (
                    RetentionClass::EpisodicJournal,
                    ClassPolicy {
                        retention_seconds: Some(10),
                        invalidate: true,
                    },
                ),
            ]),
        };
        let mut items: Vec<_> = (0..1_000)
            .map(|i| item(&format!("fresh-{i}"), RetentionClass::EphemeralContext, 95))
            .collect();
        items.push(item("expired-1", RetentionClass::EpisodicJournal, 0));
        let (outcome, records) =
            RetentionEngine::run_once(&tenant("acme"), &p, &items, 100, 1).unwrap();
        assert_eq!(outcome.invalidated, 1);
        assert_eq!(records[0].item_id, "expired-1");
        assert_eq!(records[0].class, RetentionClass::EpisodicJournal);
    }

    #[test]
    fn hard_input_and_action_bounds_are_enforced() {
        let p = policy_for("acme", RetentionClass::EphemeralContext, Some(10), true);
        assert!(matches!(
            RetentionEngine::run_once(&tenant("acme"), &p, &[], 100, 0),
            Err(RetentionError::LimitOutOfRange { .. })
        ));
        let too_many: Vec<_> = (0..=MAX_INPUT_ITEMS)
            .map(|i| item(&format!("item-{i}"), RetentionClass::EphemeralContext, 0))
            .collect();
        assert!(matches!(
            RetentionEngine::run_once(&tenant("acme"), &p, &too_many, 100, 1),
            Err(RetentionError::LimitOutOfRange { .. })
        ));
    }

    #[test]
    fn distinct_same_timestamp_items_never_collapse() {
        let p = policy_for("acme", RetentionClass::EphemeralContext, Some(10), true);
        let items = [
            item("item-a", RetentionClass::EphemeralContext, 0),
            item("item-b", RetentionClass::EphemeralContext, 0),
        ];
        let (_, records) =
            RetentionEngine::run_once(&tenant("acme"), &p, &items, 100, 10).unwrap();
        assert_eq!(records.len(), 2);
        assert_ne!(records[0].item_id, records[1].item_id);
    }

    #[test]
    fn append_is_idempotent_and_repairs_torn_tail() {
        let dir = std::env::temp_dir().join(format!("ccos-retention-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = RetentionStore::open(&dir).unwrap();
        let record = EnforcementRecord {
            tenant: "acme".into(),
            item_id: "item-1".into(),
            class: RetentionClass::EphemeralContext,
            item_created_at: 1,
            action: EnforcementAction::Invalidate,
            at_unix: 100,
        };
        store.append_records(&[record.clone(), record.clone()]).unwrap();
        store.append_records(&[record]).unwrap();
        assert_eq!(store.load_ledger().unwrap().len(), 1);

        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join(LEDGER_FILE))
            .unwrap();
        file.write_all(b"{\"partial").unwrap();
        drop(file);
        let other = EnforcementRecord {
            tenant: "acme".into(),
            item_id: "item-2".into(),
            class: RetentionClass::EphemeralContext,
            item_created_at: 2,
            action: EnforcementAction::Invalidate,
            at_unix: 101,
        };
        store.append_records(&[other]).unwrap();
        assert_eq!(store.load_ledger().unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn policy_store_refuses_corruption_and_round_trips_tenant_binding() {
        let dir = std::env::temp_dir().join(format!("ccos-retention-policy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = RetentionStore::open(&dir).unwrap();
        let p = policy_for("acme", RetentionClass::ComplianceArchives, None, false);
        store.save_policy(&p).unwrap();
        assert_eq!(store.load_policy().unwrap().unwrap(), p);
        drop(store);
        std::fs::write(dir.join(POLICY_FILE), b"{broken").unwrap();
        let store = RetentionStore::open(&dir).unwrap();
        assert!(matches!(store.load_policy(), Err(RetentionError::Corrupt { .. })));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
