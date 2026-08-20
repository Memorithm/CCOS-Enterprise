//! # CCOS Enterprise — durable human approval
//!
//! A privileged action is authorized only by a validated, unexpired,
//! unrevoked approval bound to the exact tenant, action and artifact. Durable
//! state is fail-closed: malformed records, unsupported schemas, conflicting
//! revocations and torn/committed journal corruption are refused rather than
//! reset.
//!
//! Approval ids are versioned independently from the snapshot schema. New
//! records use `approval-v2-*`, whose digest binds every field that changes
//! authorization semantics. Legacy `approval-v1-*` records remain readable so
//! an upgrade can audit them, but are deliberately never accepted by the
//! authorization gate because v1 did not bind decision/expiry/timestamp/reason.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use ccos_enterprise_tenancy::TenantId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const APPROVAL_SCHEMA: u32 = 1;
pub const MAX_ACTION_BYTES: usize = 128;
pub const MAX_APPROVER_BYTES: usize = 256;
pub const MAX_JUSTIFICATION_BYTES: usize = 4_096;

const APPROVAL_FILE: &str = "approvals.json";
const REVOCATION_FILE: &str = "revocations.jsonl";
const LOCK_FILE: &str = "approvals.lock";
const TEMP_FILE: &str = "approvals.json.tmp";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approved,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub id: String,
    pub tenant: String,
    pub approver: String,
    pub action: String,
    pub artifact_hash: String,
    pub decision: ApprovalDecision,
    pub recorded_at: u64,
    pub expires_at: Option<u64>,
    pub justification: Option<String>,
    pub schema_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationRecord {
    pub approval_id: String,
    pub revoked_by: String,
    pub revoked_at: u64,
    pub justification: String,
}

/// Authoritative approval state. Revocations are part of the snapshot so a
/// deployment checkpoint/restore cannot resurrect a revoked approval. The
/// JSONL sidecar remains useful as append-only operational evidence and is
/// reconciled against this map on load.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalSnapshot {
    pub schema_version: u32,
    pub approvals: BTreeMap<String, ApprovalRecord>,
    #[serde(default)]
    pub revocations: BTreeMap<String, RevocationRecord>,
}

impl Default for ApprovalSnapshot {
    fn default() -> Self {
        Self {
            schema_version: APPROVAL_SCHEMA,
            approvals: BTreeMap::new(),
            revocations: BTreeMap::new(),
        }
    }
}

#[derive(Debug)]
pub enum ApprovalError {
    Invalid {
        detail: String,
    },
    UnsupportedSchema {
        found: u32,
    },
    AlreadyExists {
        id: String,
    },
    Unknown {
        id: String,
    },
    AlreadyRevoked {
        id: String,
    },
    /// Runtime requested a usable approval but cannot guarantee an audit fact.
    AuditUnavailable,
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Corrupt {
        path: PathBuf,
        detail: String,
    },
}

impl PartialEq for ApprovalError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Invalid { detail: a }, Self::Invalid { detail: b }) => a == b,
            (Self::UnsupportedSchema { found: a }, Self::UnsupportedSchema { found: b }) => a == b,
            (Self::AlreadyExists { id: a }, Self::AlreadyExists { id: b }) => a == b,
            (Self::Unknown { id: a }, Self::Unknown { id: b }) => a == b,
            (Self::AlreadyRevoked { id: a }, Self::AlreadyRevoked { id: b }) => a == b,
            (Self::AuditUnavailable, Self::AuditUnavailable) => true,
            (
                Self::Corrupt {
                    path: a,
                    detail: ad,
                },
                Self::Corrupt {
                    path: b,
                    detail: bd,
                },
            ) => a == b && ad == bd,
            _ => false,
        }
    }
}

impl Eq for ApprovalError {}

impl std::fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid { detail } => write!(f, "invalid approval: {detail}"),
            Self::UnsupportedSchema { found } => write!(f, "unsupported approval schema {found}"),
            Self::AlreadyExists { id } => write!(f, "approval {id} already exists"),
            Self::Unknown { id } => write!(f, "unknown approval {id}"),
            Self::AlreadyRevoked { id } => write!(f, "approval {id} is already revoked"),
            Self::AuditUnavailable => write!(f, "approval audit trail is unavailable"),
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Corrupt { path, detail } => {
                write!(f, "{}: approval state is corrupt: {detail}", path.display())
            }
        }
    }
}

impl std::error::Error for ApprovalError {}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> ApprovalError + '_ {
    move |source| ApprovalError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn canonical_action(action: &str) -> bool {
    !action.is_empty()
        && action.len() <= MAX_ACTION_BYTES
        && action.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
}

const ZERO_WIDTH: &[char] = &[
    '\u{00AD}', '\u{061C}', '\u{180E}', '\u{200B}', '\u{200C}', '\u{200D}', '\u{200E}', '\u{200F}',
    '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2060}', '\u{2061}', '\u{2800}',
    '\u{3164}', '\u{FEFF}', '\u{FFA0}',
];

fn renders_blank(value: &str) -> bool {
    value
        .chars()
        .all(|c| c.is_whitespace() || c.is_control() || ZERO_WIDTH.contains(&c))
}

fn legible_bounded(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !renders_blank(value)
}

fn framed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn hex(digest: sha2::digest::generic_array::GenericArray<u8, sha2::digest::consts::U32>) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub tenant: TenantId,
    pub action: String,
    pub artifact_hash: String,
    pub approver: String,
    pub decision: ApprovalDecision,
    pub recorded_at: u64,
    pub expires_at: Option<u64>,
    pub justification: String,
}

impl ApprovalRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: TenantId,
        action: &str,
        artifact_hash: &str,
        approver: &str,
        decision: ApprovalDecision,
        recorded_at: u64,
        expires_at: Option<u64>,
        justification: &str,
    ) -> Result<Self, ApprovalError> {
        if tenant.0.is_empty()
            || tenant.0.len() > 128
            || !tenant
                .0
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
        {
            return Err(ApprovalError::Invalid {
                detail: "tenant must be a canonical identifier".into(),
            });
        }
        if !canonical_action(action) {
            return Err(ApprovalError::Invalid {
                detail: "action must be canonical dot-separated [a-z0-9_]".into(),
            });
        }
        if !is_sha256_hex(artifact_hash) {
            return Err(ApprovalError::Invalid {
                detail: "artifact_hash must be 64 lowercase hex characters".into(),
            });
        }
        if !legible_bounded(approver, MAX_APPROVER_BYTES) {
            return Err(ApprovalError::Invalid {
                detail: "approver must be bounded and legible".into(),
            });
        }
        if !legible_bounded(justification, MAX_JUSTIFICATION_BYTES) {
            return Err(ApprovalError::Invalid {
                detail: "justification must be bounded and legible".into(),
            });
        }
        if expires_at.is_some_and(|expiry| expiry <= recorded_at) {
            return Err(ApprovalError::Invalid {
                detail: "expiry must be after the recording time".into(),
            });
        }
        Ok(Self {
            tenant,
            action: action.to_string(),
            artifact_hash: artifact_hash.to_string(),
            approver: approver.to_string(),
            decision,
            recorded_at,
            expires_at,
            justification: justification.to_string(),
        })
    }

    /// v2 binds every authorization-bearing field and permits legitimate
    /// renewal because a later timestamp/expiry produces a different identity.
    pub fn id(&self) -> String {
        let mut hasher = Sha256::new();
        framed(&mut hasher, b"ccos-enterprise-approval-v2");
        framed(&mut hasher, self.tenant.0.as_bytes());
        framed(&mut hasher, self.action.as_bytes());
        framed(&mut hasher, self.artifact_hash.as_bytes());
        framed(&mut hasher, self.approver.as_bytes());
        framed(
            &mut hasher,
            match self.decision {
                ApprovalDecision::Approved => b"approved",
                ApprovalDecision::Denied => b"denied",
            },
        );
        framed(&mut hasher, &self.recorded_at.to_be_bytes());
        framed(&mut hasher, &[u8::from(self.expires_at.is_some())]);
        framed(
            &mut hasher,
            &self.expires_at.unwrap_or_default().to_be_bytes(),
        );
        framed(&mut hasher, self.justification.as_bytes());
        format!("approval-v2-{}", hex(hasher.finalize()))
    }

    fn legacy_id(&self) -> String {
        let mut hasher = Sha256::new();
        for part in [
            b"ccos-enterprise-approval-v1".as_slice(),
            self.tenant.0.as_bytes(),
            self.action.as_bytes(),
            self.artifact_hash.as_bytes(),
            self.approver.as_bytes(),
        ] {
            framed(&mut hasher, part);
        }
        format!("approval-v1-{}", hex(hasher.finalize()))
    }
}

fn request_from_record(record: &ApprovalRecord) -> Result<ApprovalRequest, ApprovalError> {
    ApprovalRequest::new(
        TenantId(record.tenant.clone()),
        &record.action,
        &record.artifact_hash,
        &record.approver,
        record.decision,
        record.recorded_at,
        record.expires_at,
        record.justification.as_deref().unwrap_or(""),
    )
}

fn validate_record(record: &ApprovalRecord) -> Result<(), ApprovalError> {
    if record.schema_version != APPROVAL_SCHEMA {
        return Err(ApprovalError::UnsupportedSchema {
            found: record.schema_version,
        });
    }
    let request = request_from_record(record)?;
    let matches = if record.id.starts_with("approval-v2-") {
        request.id() == record.id
    } else if record.id.starts_with("approval-v1-") {
        request.legacy_id() == record.id
    } else {
        false
    };
    if !matches {
        return Err(ApprovalError::Invalid {
            detail: "approval id does not match its fields".into(),
        });
    }
    Ok(())
}

fn validate_revocation_shape(record: &RevocationRecord) -> Result<(), ApprovalError> {
    if !(record.approval_id.starts_with("approval-v1-")
        || record.approval_id.starts_with("approval-v2-"))
        || !legible_bounded(&record.revoked_by, MAX_APPROVER_BYTES)
        || !legible_bounded(&record.justification, MAX_JUSTIFICATION_BYTES)
    {
        return Err(ApprovalError::Invalid {
            detail: "malformed revocation record".into(),
        });
    }
    Ok(())
}

fn validate_revocation(
    snapshot: &ApprovalSnapshot,
    key: &str,
    record: &RevocationRecord,
) -> Result<(), ApprovalError> {
    validate_revocation_shape(record)?;
    if key != record.approval_id {
        return Err(ApprovalError::Invalid {
            detail: "revocation map key does not match approval id".into(),
        });
    }
    let approval =
        snapshot
            .approvals
            .get(&record.approval_id)
            .ok_or_else(|| ApprovalError::Unknown {
                id: record.approval_id.clone(),
            })?;
    if approval.decision != ApprovalDecision::Approved {
        return Err(ApprovalError::Invalid {
            detail: "a denied approval cannot be revoked".into(),
        });
    }
    Ok(())
}

pub struct ApprovalQuery<'a> {
    pub tenant: &'a TenantId,
    pub action: &'a str,
    pub artifact_hash: &'a str,
    pub now: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateOutcome {
    Approved,
    Denied,
    ArtifactMismatch { found: String },
    Expired,
    Revoked,
}

#[derive(Debug, Clone)]
pub struct ApprovalRegistry {
    snapshot: ApprovalSnapshot,
}

impl Default for ApprovalRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ApprovalRegistry {
    pub fn new() -> Self {
        Self {
            snapshot: ApprovalSnapshot::default(),
        }
    }

    pub fn from_snapshot(snapshot: ApprovalSnapshot) -> Result<Self, ApprovalError> {
        if snapshot.schema_version != APPROVAL_SCHEMA {
            return Err(ApprovalError::UnsupportedSchema {
                found: snapshot.schema_version,
            });
        }
        for (id, record) in &snapshot.approvals {
            if id != &record.id {
                return Err(ApprovalError::Invalid {
                    detail: "approval map key does not match record id".into(),
                });
            }
            validate_record(record)?;
        }
        for (id, record) in &snapshot.revocations {
            validate_revocation(&snapshot, id, record)?;
        }
        Ok(Self { snapshot })
    }

    pub fn snapshot(&self) -> &ApprovalSnapshot {
        &self.snapshot
    }

    pub fn is_revoked(&self, id: &str) -> bool {
        self.snapshot.revocations.contains_key(id)
    }

    pub fn record(&mut self, request: ApprovalRequest) -> Result<String, ApprovalError> {
        let id = request.id();
        if self.snapshot.approvals.contains_key(&id) {
            return Err(ApprovalError::AlreadyExists { id });
        }
        let record = ApprovalRecord {
            id: id.clone(),
            tenant: request.tenant.0,
            approver: request.approver,
            action: request.action,
            artifact_hash: request.artifact_hash,
            decision: request.decision,
            recorded_at: request.recorded_at,
            expires_at: request.expires_at,
            justification: Some(request.justification),
            schema_version: APPROVAL_SCHEMA,
        };
        validate_record(&record)?;
        self.snapshot.approvals.insert(id.clone(), record);
        Ok(id)
    }

    pub fn evaluate(&self, query: &ApprovalQuery<'_>) -> GateOutcome {
        if !canonical_action(query.action) || !is_sha256_hex(query.artifact_hash) {
            return GateOutcome::Denied;
        }
        let mut saw_other_artifact = None;
        for record in self.snapshot.approvals.values().rev() {
            if record.tenant != query.tenant.0 || record.action != query.action {
                continue;
            }
            if record.artifact_hash != query.artifact_hash {
                saw_other_artifact = Some(record.artifact_hash.clone());
                continue;
            }
            // Legacy ids are audit-only after upgrade: their identity did not
            // bind all authorization fields, so trusting them would preserve
            // the exact vulnerability this version repairs.
            if !record.id.starts_with("approval-v2-")
                || record.decision != ApprovalDecision::Approved
            {
                continue;
            }
            if self.is_revoked(&record.id) {
                return GateOutcome::Revoked;
            }
            if record.expires_at.is_some_and(|expiry| expiry <= query.now) {
                return GateOutcome::Expired;
            }
            return GateOutcome::Approved;
        }
        saw_other_artifact
            .map(|found| GateOutcome::ArtifactMismatch { found })
            .unwrap_or(GateOutcome::Denied)
    }

    pub fn revoke(
        &mut self,
        approval_id: &str,
        revoked_by: &str,
        revoked_at: u64,
        justification: &str,
    ) -> Result<(), ApprovalError> {
        if self.is_revoked(approval_id) {
            return Err(ApprovalError::AlreadyRevoked {
                id: approval_id.to_string(),
            });
        }
        let approval =
            self.snapshot
                .approvals
                .get(approval_id)
                .ok_or_else(|| ApprovalError::Unknown {
                    id: approval_id.to_string(),
                })?;
        if approval.decision != ApprovalDecision::Approved {
            return Err(ApprovalError::Invalid {
                detail: "a denied approval cannot be revoked".into(),
            });
        }
        let record = RevocationRecord {
            approval_id: approval_id.to_string(),
            revoked_by: revoked_by.to_string(),
            revoked_at,
            justification: justification.to_string(),
        };
        validate_revocation_shape(&record)?;
        self.snapshot
            .revocations
            .insert(approval_id.to_string(), record);
        Ok(())
    }
}

pub struct ApprovalStore {
    root: PathBuf,
    snapshot_path: PathBuf,
    revocation_path: PathBuf,
    _lock: File,
}

impl ApprovalStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ApprovalError> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root).map_err(io(&root))?;
        let lock_path = root.join(LOCK_FILE);
        let lock = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(io(&lock_path))?;
        lock.try_lock().map_err(|source| ApprovalError::Io {
            path: lock_path,
            source: source.into(),
        })?;
        Ok(Self {
            snapshot_path: root.join(APPROVAL_FILE),
            revocation_path: root.join(REVOCATION_FILE),
            root,
            _lock: lock,
        })
    }

    pub fn load_snapshot(&self) -> Result<Option<ApprovalSnapshot>, ApprovalError> {
        let bytes = match std::fs::read(&self.snapshot_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(ApprovalError::Io {
                    path: self.snapshot_path.clone(),
                    source,
                })
            }
        };
        let snapshot: ApprovalSnapshot =
            serde_json::from_slice(&bytes).map_err(|error| ApprovalError::Corrupt {
                path: self.snapshot_path.clone(),
                detail: error.to_string(),
            })?;
        ApprovalRegistry::from_snapshot(snapshot.clone())?;
        Ok(Some(snapshot))
    }

    pub fn load_revocations(&self) -> Result<Vec<RevocationRecord>, ApprovalError> {
        let bytes = match std::fs::read(&self.revocation_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => {
                return Err(ApprovalError::Io {
                    path: self.revocation_path.clone(),
                    source,
                })
            }
        };
        let committed = bytes
            .iter()
            .rposition(|b| *b == b'\n')
            .map_or(&bytes[..0], |end| &bytes[..=end]);
        let mut records = Vec::new();
        for (index, line) in committed.split(|b| *b == b'\n').enumerate() {
            if line.is_empty() {
                continue;
            }
            let record: RevocationRecord =
                serde_json::from_slice(line).map_err(|error| ApprovalError::Corrupt {
                    path: self.revocation_path.clone(),
                    detail: format!("revocation line {}: {error}", index + 1),
                })?;
            validate_revocation_shape(&record)?;
            records.push(record);
        }
        Ok(records)
    }

    pub fn save(&self, snapshot: &ApprovalSnapshot) -> Result<(), ApprovalError> {
        ApprovalRegistry::from_snapshot(snapshot.clone())?;
        let bytes =
            serde_json::to_vec_pretty(snapshot).map_err(|error| ApprovalError::Corrupt {
                path: self.snapshot_path.clone(),
                detail: format!("cannot serialize approval ledger: {error}"),
            })?;
        let temporary = self.root.join(TEMP_FILE);
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temporary)
            .map_err(io(&temporary))?;
        file.write_all(&bytes).map_err(io(&temporary))?;
        file.write_all(b"\n").map_err(io(&temporary))?;
        file.sync_all().map_err(io(&temporary))?;
        drop(file);
        std::fs::rename(&temporary, &self.snapshot_path).map_err(io(&self.snapshot_path))?;
        File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(io(&self.root))?;
        Ok(())
    }

    pub fn append_revocation(&self, record: &RevocationRecord) -> Result<(), ApprovalError> {
        validate_revocation_shape(record)?;
        // Remove a crash-torn final line before appending, otherwise the new
        // record would make the partial bytes a committed malformed line.
        let existing = match std::fs::read(&self.revocation_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(source) => {
                return Err(ApprovalError::Io {
                    path: self.revocation_path.clone(),
                    source,
                })
            }
        };
        let committed_len = existing
            .iter()
            .rposition(|b| *b == b'\n')
            .map_or(0, |end| end + 1);
        if committed_len != existing.len() {
            let file = OpenOptions::new()
                .write(true)
                .open(&self.revocation_path)
                .map_err(io(&self.revocation_path))?;
            file.set_len(committed_len as u64)
                .map_err(io(&self.revocation_path))?;
            file.sync_data().map_err(io(&self.revocation_path))?;
        }
        let committed = self.load_revocations()?;
        if let Some(existing) = committed
            .iter()
            .find(|existing| existing.approval_id == record.approval_id)
        {
            if existing == record {
                return Ok(());
            }
            return Err(ApprovalError::Invalid {
                detail: "conflicting revocation for the same approval".into(),
            });
        }
        let mut line = serde_json::to_vec(record).map_err(|error| ApprovalError::Corrupt {
            path: self.revocation_path.clone(),
            detail: format!("cannot serialize revocation: {error}"),
        })?;
        line.push(b'\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.revocation_path)
            .map_err(io(&self.revocation_path))?;
        file.write_all(&line).map_err(io(&self.revocation_path))?;
        file.sync_data().map_err(io(&self.revocation_path))?;
        // The append may have created the directory entry. Syncing only the
        // file is not sufficient to guarantee revocation durability.
        File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(io(&self.root))?;
        Ok(())
    }

    pub fn load_registry(&self) -> Result<ApprovalRegistry, ApprovalError> {
        let mut registry = match self.load_snapshot()? {
            Some(snapshot) => ApprovalRegistry::from_snapshot(snapshot)?,
            None => ApprovalRegistry::new(),
        };
        for revocation in self.load_revocations()? {
            let approval = registry
                .snapshot
                .approvals
                .get(&revocation.approval_id)
                .ok_or_else(|| ApprovalError::Unknown {
                    id: revocation.approval_id.clone(),
                })?;
            if approval.decision != ApprovalDecision::Approved {
                return Err(ApprovalError::Invalid {
                    detail: "revocation points to a denied approval".into(),
                });
            }
            match registry.snapshot.revocations.get(&revocation.approval_id) {
                Some(existing) if existing == &revocation => {}
                Some(_) => {
                    return Err(ApprovalError::Invalid {
                        detail: "snapshot and revocation journal disagree".into(),
                    })
                }
                None => {
                    validate_revocation(&registry.snapshot, &revocation.approval_id, &revocation)?;
                    registry
                        .snapshot
                        .revocations
                        .insert(revocation.approval_id.clone(), revocation);
                }
            }
        }
        Ok(registry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn request(at: u64, expires: Option<u64>) -> ApprovalRequest {
        ApprovalRequest::new(
            TenantId("acme".into()),
            "tenant.delete",
            &artifact(1),
            "operator",
            ApprovalDecision::Approved,
            at,
            expires,
            "approved for this exact artifact",
        )
        .unwrap()
    }

    #[test]
    fn v2_id_binds_every_authorization_field_and_allows_renewal() {
        let base = request(100, Some(200));
        let id = base.id();
        let mut changed = base.clone();
        changed.decision = ApprovalDecision::Denied;
        assert_ne!(id, changed.id());
        let mut changed = base.clone();
        changed.recorded_at = 101;
        assert_ne!(id, changed.id());
        let mut changed = base.clone();
        changed.expires_at = Some(201);
        assert_ne!(id, changed.id());
        let mut changed = base.clone();
        changed.justification = "different reason".into();
        assert_ne!(id, changed.id());

        let mut registry = ApprovalRegistry::new();
        let first = registry.record(base).unwrap();
        let renewal = registry.record(request(201, Some(300))).unwrap();
        assert_ne!(first, renewal, "renewal receives a new identity");
    }

    #[test]
    fn gate_is_exact_tenant_artifact_expiry_and_revocation() {
        let mut registry = ApprovalRegistry::new();
        let id = registry.record(request(100, Some(200))).unwrap();
        let tenant = TenantId("acme".into());
        let artifact_hash = artifact(1);
        let query = |now| ApprovalQuery {
            tenant: &tenant,
            action: "tenant.delete",
            artifact_hash: &artifact_hash,
            now,
        };
        assert_eq!(registry.evaluate(&query(199)), GateOutcome::Approved);
        assert_eq!(registry.evaluate(&query(200)), GateOutcome::Expired);
        registry
            .revoke(&id, "operator", 150, "approval withdrawn")
            .unwrap();
        assert_eq!(registry.evaluate(&query(160)), GateOutcome::Revoked);

        let globex = TenantId("globex".into());
        assert_eq!(
            registry.evaluate(&ApprovalQuery {
                tenant: &globex,
                action: "tenant.delete",
                artifact_hash: &artifact(1),
                now: 160,
            }),
            GateOutcome::Denied
        );
    }

    #[test]
    fn revocation_survives_snapshot_restore() {
        let mut registry = ApprovalRegistry::new();
        let id = registry.record(request(100, None)).unwrap();
        registry.revoke(&id, "operator", 150, "withdrawn").unwrap();
        let restored = ApprovalRegistry::from_snapshot(registry.snapshot().clone()).unwrap();
        assert!(restored.is_revoked(&id));
        let tenant = TenantId("acme".into());
        assert_eq!(
            restored.evaluate(&ApprovalQuery {
                tenant: &tenant,
                action: "tenant.delete",
                artifact_hash: &artifact(1),
                now: 160,
            }),
            GateOutcome::Revoked
        );
    }

    #[test]
    fn legacy_v1_record_is_readable_but_cannot_authorize() {
        let old = request(100, None);
        let record = ApprovalRecord {
            id: old.legacy_id(),
            tenant: old.tenant.0.clone(),
            approver: old.approver.clone(),
            action: old.action.clone(),
            artifact_hash: old.artifact_hash.clone(),
            decision: old.decision,
            recorded_at: old.recorded_at,
            expires_at: old.expires_at,
            justification: Some(old.justification.clone()),
            schema_version: APPROVAL_SCHEMA,
        };
        let mut snapshot = ApprovalSnapshot::default();
        snapshot.approvals.insert(record.id.clone(), record);
        let registry = ApprovalRegistry::from_snapshot(snapshot).unwrap();
        let tenant = TenantId("acme".into());
        assert_eq!(
            registry.evaluate(&ApprovalQuery {
                tenant: &tenant,
                action: "tenant.delete",
                artifact_hash: &artifact(1),
                now: 110,
            }),
            GateOutcome::Denied
        );
    }

    #[test]
    fn store_round_trip_and_torn_revocation_tail_are_fail_closed_safe() {
        let dir = std::env::temp_dir().join(format!("ccos-approval-v2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = ApprovalStore::open(&dir).unwrap();
        let mut registry = ApprovalRegistry::new();
        let id = registry.record(request(100, None)).unwrap();
        store.save(registry.snapshot()).unwrap();
        let revocation = RevocationRecord {
            approval_id: id.clone(),
            revoked_by: "operator".into(),
            revoked_at: 150,
            justification: "withdrawn".into(),
        };
        store.append_revocation(&revocation).unwrap();
        // Exact retry is idempotent.
        store.append_revocation(&revocation).unwrap();
        assert!(store.load_registry().unwrap().is_revoked(&id));

        let mut file = OpenOptions::new()
            .append(true)
            .open(dir.join(REVOCATION_FILE))
            .unwrap();
        file.write_all(b"{\"partial").unwrap();
        drop(file);
        // Appending the same committed record repairs the torn tail without
        // duplicating it.
        store.append_revocation(&revocation).unwrap();
        assert_eq!(store.load_revocations().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn corrupt_snapshot_is_refused_never_reset() {
        let mut registry = ApprovalRegistry::new();
        registry.record(request(100, None)).unwrap();
        let mut snapshot = registry.snapshot().clone();
        snapshot.approvals.values_mut().next().unwrap().expires_at = Some(999);
        assert!(matches!(
            ApprovalRegistry::from_snapshot(snapshot),
            Err(ApprovalError::Invalid { .. })
        ));
    }
}
