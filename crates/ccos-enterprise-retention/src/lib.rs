//! # CCOS Enterprise — cognitive retention policy
//!
//! Tenant-scoped, deterministic retention enforcement with bounded input,
//! stable artifact identity, append-only audit facts, crash-safe persistence,
//! and an explicit approval-gate callback for every policy write.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ccos_enterprise_tenancy::TenantId;
use serde::{Deserialize, Serialize};

pub const RETENTION_SCHEMA: u32 = 1;
pub const DEFAULT_BATCH_LIMIT: usize = 1_024;
pub const MAX_BATCH_LIMIT: usize = 4_096;
pub const MAX_INPUT_ITEMS: usize = 65_536;
pub const MAX_ITEM_ID_BYTES: usize = 128;
pub const RETENTION_POLICY_TOOL: &str = "retention.policy.set";

const POLICY_FILE: &str = "retention-policy.json";
const LEDGER_FILE: &str = "retention-ledger.jsonl";
const LOCK_FILE: &str = "retention.lock";
const TEMP_FILE: &str = "retention-policy.json.tmp";

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
    pub retention_seconds: Option<u64>,
    pub invalidate: bool,
}

impl ClassPolicy {
    pub fn expired_at(&self, created_at: u64, now: u64) -> bool {
        self.retention_seconds
            .is_some_and(|seconds| created_at.saturating_add(seconds) <= now)
    }
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedItem {
    pub tenant: String,
    pub item_id: String,
    pub class: RetentionClass,
    pub created_at: u64,
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
    ApprovalRequired {
        detail: String,
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
            Self::ApprovalRequired { detail } => write!(f, "retention policy approval denied: {detail}"),
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

/// SHA-256 for the small canonical policy artifact. Kept local so the crate's
/// dependency surface does not grow merely to derive the approval identity.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    const H0: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
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

    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    let mut padded = bytes.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut h = H0;
    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (dst, word) in out.chunks_exact_mut(4).zip(h) {
        dst.copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Canonical SHA-256 identity used by the human-approval ledger.
pub fn policy_artifact_hash(policy: &RetentionPolicy) -> Result<String, RetentionError> {
    policy.validate()?;
    let bytes = serde_json::to_vec(policy).map_err(|error| RetentionError::InvalidPolicy {
        detail: format!("cannot serialize retention policy: {error}"),
    })?;
    Ok(hex(&sha256(&bytes)))
}

pub struct RetentionStore {
    root: PathBuf,
    policy_path: PathBuf,
    ledger_path: PathBuf,
    _lock: std::fs::File,
}

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
                });
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

    fn persist_policy(&self, policy: &RetentionPolicy) -> Result<(), RetentionError> {
        let bytes = serde_json::to_vec_pretty(policy).map_err(|error| RetentionError::InvalidPolicy {
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

    /// Persist a sensitive policy only after the supplied product approval gate
    /// authorizes the exact tenant/action/artifact tuple. There is deliberately
    /// no public unchecked writer.
    pub fn save_policy_with_approval<F>(
        &self,
        policy: &RetentionPolicy,
        approve: F,
    ) -> Result<(), RetentionError>
    where
        F: FnOnce(&str, &str, &str) -> Result<(), String>,
    {
        policy.validate()?;
        if let Some(existing) = self.load_policy()? {
            if existing.tenant != policy.tenant {
                return Err(RetentionError::UnknownTenant {
                    tenant: policy.tenant.clone(),
                });
            }
        }
        let artifact_hash = policy_artifact_hash(policy)?;
        approve(&policy.tenant, RETENTION_POLICY_TOOL, &artifact_hash)
            .map_err(|detail| RetentionError::ApprovalRequired { detail })?;
        self.persist_policy(policy)
    }

    fn policy_tenant(&self) -> Result<String, RetentionError> {
        self.load_policy()?
            .map(|policy| policy.tenant)
            .ok_or_else(|| RetentionError::InvalidPolicy {
                detail: "a validated tenant policy must exist before ledger access".into(),
            })
    }

    pub fn append_records(&self, records: &[EnforcementRecord]) -> Result<(), RetentionError> {
        if records.is_empty() {
            return Ok(());
        }
        let expected_tenant = self.policy_tenant()?;
        for record in records {
            record.validate()?;
            if record.tenant != expected_tenant {
                return Err(RetentionError::UnknownTenant {
                    tenant: record.tenant.clone(),
                });
            }
        }

        let existing = match std::fs::read(&self.ledger_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(source) => {
                return Err(RetentionError::Io {
                    path: self.ledger_path.clone(),
                    source,
                });
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
        std::fs::File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(io(&self.root))?;
        Ok(())
    }

    pub fn load_ledger(&self) -> Result<Vec<EnforcementRecord>, RetentionError> {
        let expected_tenant = self.policy_tenant()?;
        let bytes = match std::fs::read(&self.ledger_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => {
                return Err(RetentionError::Io {
                    path: self.ledger_path.clone(),
                    source,
                });
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
            if record.tenant != expected_tenant {
                return Err(RetentionError::Corrupt {
                    path: self.ledger_path.clone(),
                    detail: format!(
                        "ledger tenant {:?} does not match policy tenant {:?}",
                        record.tenant, expected_tenant
                    ),
                });
            }
            records.push(record);
        }
        Ok(records)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunOutcome {
    pub examined: usize,
    pub retained: usize,
    pub invalidated: usize,
    pub reported: usize,
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
            let action = if item.sealed || !class_policy.invalidate {
                outcome.reported += 1;
                EnforcementAction::ReportOnly
            } else {
                outcome.invalidated += 1;
                EnforcementAction::Invalidate
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

    fn approve_all(_: &str, _: &str, _: &str) -> Result<(), String> {
        Ok(())
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sealed_expired_item_is_report_only() {
        let p = policy_for("acme", RetentionClass::SealedSnapshots, Some(10), true);
        let mut sealed = item("snap-1", RetentionClass::SealedSnapshots, 0);
        sealed.sealed = true;
        let (outcome, records) =
            RetentionEngine::run_once(&tenant("acme"), &p, &[sealed], 100, 10).unwrap();
        assert_eq!(outcome.invalidated, 0);
        assert_eq!(outcome.reported, 1);
        assert_eq!(records[0].action, EnforcementAction::ReportOnly);
    }

    #[test]
    fn policy_and_items_are_tenant_bound() {
        let p = policy_for("globex", RetentionClass::EphemeralContext, Some(10), true);
        assert!(matches!(
            RetentionEngine::run_once(
                &tenant("acme"),
                &p,
                &[item("item-1", RetentionClass::EphemeralContext, 0)],
                100,
                10,
            ),
            Err(RetentionError::UnknownTenant { tenant }) if tenant == "globex"
        ));
    }

    #[test]
    fn ledger_rejects_cross_tenant_records() {
        let dir = std::env::temp_dir().join(format!("ccos-retention-tenant-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = RetentionStore::open(&dir).unwrap();
        let policy = policy_for("acme", RetentionClass::EphemeralContext, Some(10), true);
        store
            .save_policy_with_approval(&policy, approve_all)
            .unwrap();
        let foreign = EnforcementRecord {
            tenant: "globex".into(),
            item_id: "item-1".into(),
            class: RetentionClass::EphemeralContext,
            item_created_at: 0,
            action: EnforcementAction::Invalidate,
            at_unix: 100,
        };
        assert!(matches!(
            store.append_records(&[foreign]),
            Err(RetentionError::UnknownTenant { tenant }) if tenant == "globex"
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn policy_writer_fails_closed_when_approval_callback_denies() {
        let dir = std::env::temp_dir().join(format!("ccos-retention-approval-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = RetentionStore::open(&dir).unwrap();
        let policy = policy_for("acme", RetentionClass::EphemeralContext, Some(10), true);
        let result = store.save_policy_with_approval(&policy, |tenant, action, hash| {
            assert_eq!(tenant, "acme");
            assert_eq!(action, RETENTION_POLICY_TOOL);
            assert_eq!(hash.len(), 64);
            Err("runtime approval gate denied".into())
        });
        assert!(matches!(result, Err(RetentionError::ApprovalRequired { .. })));
        assert!(store.load_policy().unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn append_is_idempotent_and_repairs_torn_tail() {
        let dir = std::env::temp_dir().join(format!("ccos-retention-replay-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = RetentionStore::open(&dir).unwrap();
        let policy = policy_for("acme", RetentionClass::EphemeralContext, Some(10), true);
        store
            .save_policy_with_approval(&policy, approve_all)
            .unwrap();
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
}
