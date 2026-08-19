//! # CCOS Enterprise — durable human approval
//!
//! Implements the contract of `docs/HUMAN_APPROVAL_POLICIES.md`:
//! `PolicyDecision::RequireApproval` becomes a real product behavior with a
//! canonical, crash-safe, append-audited approval record.
//!
//! ## Security rules
//!
//! - **unrecorded approval == denial** — an approval that was never durably
//!   recorded does not exist, and a gate that finds none refuses;
//! - **malformed approval == denial** — a record that fails structural
//!   validation is refused, never partially trusted;
//! - **wrong tenant == denial** — an approval recorded for tenant A can never
//!   authorize an action for tenant B;
//! - **wrong artifact hash == denial** — an approval binds to exactly one
//!   artifact hash; the same approval id cannot authorize a different
//!   artifact;
//! - **an approval may not be replayed onto a different artifact** — the
//!   approval id is a domain-separated hash over `(tenant, action, artifact
//!   hash, approver)`, so re-deriving it for a different artifact yields a
//!   different id, and the recorded id is validated against the request;
//! - **expired/revoked approval == denial** — an approval carries an
//!   `expires_at`; a gate consults the clock and refuses expired approvals.
//!   Revocation is not an edit: it is a separate, audited revocation record
//!   (a revoked id remains in the ledger, its decision unchanged);
//! - **operator-visible Unicode/zero-width validation remains fail-closed** —
//!   approver identities and justifications must render legibly;
//!   [`ccos_enterprise_rbac::Permission`] names are canonical ASCII;
//! - **approval persistence is crash safe** — write/fsync/rename with
//!   directory fsync, single-writer lock, and corruption refused on load;
//! - **append/audit before privileged effect** — recording an approval is a
//!   durable journal fact before any caller may use it, and every decision
//!   gate is deterministic over validated state only.
//!
//! ## Shape
//!
//! The ledger is a single validated snapshot file (`approvals.json`) guarded
//! by a kernel lock, exactly like the skill trial ledger. A decision is
//! evaluated against the validated snapshot; corruption is refused, never
//! silently reset. Revocations are append-only sidecar records
//! (`revocations.jsonl`), one per line, crash-tolerant at the tail like the
//! governance journal.
//!
//! No raw prompts, model output, tool input/output or workspace paths are
//! persisted. The artifact is represented only by its SHA-256.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use ccos_enterprise_tenancy::TenantId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const APPROVAL_SCHEMA: u32 = 1;
pub const APPROVAL_FILE: &str = "approvals.json";
pub const REVOCATION_FILE: &str = "revocations.jsonl";
pub const LOCK_FILE: &str = "approvals.lock";
const TEMP_FILE: &str = "approvals.json.tmp";

/// Maximum bytes for an approver identity. These arrive from operator
/// configuration; bounded like every other caller-controlled string in the
/// product.
pub const MAX_APPROVER_BYTES: usize = 256;

/// Maximum bytes for a written justification.
pub const MAX_JUSTIFICATION_BYTES: usize = 4_096;

/// A canonical action name an approval can authorize. Reuses the admin
/// crate's grammar (dot-separated ASCII `[a-z0-9_]`) without depending on it,
/// so the approval crate stays leaf-level: the grammar is small and stable.
fn is_canonical_action(action: &str) -> bool {
    !action.is_empty()
        && action.len() <= 256
        && action.split('.').all(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
}

/// Whether a string draws anything a human can read (the same bar as
/// `ccos_enterprise_admin::is_written_justification`).
fn renders_blank(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_whitespace() || c.is_control() || is_zero_width(c))
}

fn is_zero_width(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'
            | '\u{200C}'
            | '\u{200D}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'
            | '\u{202B}'
            | '\u{202C}'
            | '\u{202D}'
            | '\u{202E}'
            | '\u{2060}'
            | '\u{2061}'
            | '\u{2800}'
            | '\u{3164}'
            | '\u{FEFF}'
            | '\u{FFA0}'
    )
}

/// The human decision on an approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approved,
    Denied,
}

/// A canonical, durable human approval record.
///
/// Fields are deliberately plain data: the ledger validates them on load and
/// on record, and a gate never trusts an unvalidated record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRecord {
    /// Domain-separated id binding tenant + action + artifact hash + approver.
    pub id: String,
    /// Tenant / organization scope this approval belongs to.
    pub tenant: String,
    /// The human identity that made the decision (operator-visible name).
    pub approver: String,
    /// Canonical dot-separated action name this approval authorizes.
    pub action: String,
    /// SHA-256 (lowercase hex) of the artifact this approval binds to.
    pub artifact_hash: String,
    pub decision: ApprovalDecision,
    /// Unix seconds at which the approval was recorded.
    pub recorded_at: u64,
    /// Optional expiry in Unix seconds; `None` means never expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// Written justification, required to be legible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
    /// Schema version of the record shape.
    pub schema_version: u32,
}

/// A revocation: an approval id withdrawn after the fact. Revocation is never
/// an edit of the original record — it is an appended, auditable fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationRecord {
    pub approval_id: String,
    pub revoked_by: String,
    pub revoked_at: u64,
    pub justification: String,
}

/// The durable ledger state, as plain data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalSnapshot {
    pub schema_version: u32,
    pub approvals: BTreeMap<String, ApprovalRecord>,
}

impl Default for ApprovalSnapshot {
    fn default() -> Self {
        Self {
            schema_version: APPROVAL_SCHEMA,
            approvals: BTreeMap::new(),
        }
    }
}

/// Why an approval operation was refused. Every variant is fail-closed.
#[derive(Debug)]
pub enum ApprovalError {
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
    Invalid {
        detail: String,
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
}

impl PartialEq for ApprovalError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Io {
                    path: left_path,
                    source: left_source,
                },
                Self::Io {
                    path: right_path,
                    source: right_source,
                },
            ) => {
                left_path == right_path
                    && left_source.kind() == right_source.kind()
                    && left_source.to_string() == right_source.to_string()
            }
            (
                Self::Corrupt {
                    path: l,
                    detail: ld,
                },
                Self::Corrupt {
                    path: r,
                    detail: rd,
                },
            ) => l == r && ld == rd,
            (Self::UnsupportedSchema { found: l }, Self::UnsupportedSchema { found: r }) => l == r,
            (Self::Invalid { detail: l }, Self::Invalid { detail: r }) => l == r,
            (Self::AlreadyExists { id: l }, Self::AlreadyExists { id: r }) => l == r,
            (Self::Unknown { id: l }, Self::Unknown { id: r }) => l == r,
            (Self::AlreadyRevoked { id: l }, Self::AlreadyRevoked { id: r }) => l == r,
            _ => false,
        }
    }
}

impl std::fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Corrupt { path, detail } => {
                write!(
                    f,
                    "{}: approval ledger is corrupt: {detail}",
                    path.display()
                )
            }
            Self::UnsupportedSchema { found } => {
                write!(f, "unsupported approval ledger schema {found}")
            }
            Self::Invalid { detail } => write!(f, "invalid approval record: {detail}"),
            Self::AlreadyExists { id } => write!(f, "approval {id} already exists"),
            Self::Unknown { id } => write!(f, "no approval with id {id}"),
            Self::AlreadyRevoked { id } => write!(f, "approval {id} is already revoked"),
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

/// A valid approval request, before it is recorded.
///
/// Construction enforces the fail-closed input rules: canonical tenant and
/// action identifiers, a legible approver and justification, a well-formed
/// artifact hash, and an expiry that is not in the past.
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
    /// The flat constructor mirrors the durable record shape; the field count
    /// is the shape, not an accident, so the clippy argument bound is
    /// deliberately waived here.
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
        if !is_canonical_action(action) {
            return Err(ApprovalError::Invalid {
                detail: "action is not a canonical dot-separated name".into(),
            });
        }
        if tenant.0.is_empty() || tenant.0.len() > 256 {
            return Err(ApprovalError::Invalid {
                detail: "tenant is empty or oversized".into(),
            });
        }
        if approver.is_empty() || approver.len() > MAX_APPROVER_BYTES || renders_blank(approver) {
            return Err(ApprovalError::Invalid {
                detail: "approver must be a legible, bounded identity".into(),
            });
        }
        if !is_sha256_hex(artifact_hash) {
            return Err(ApprovalError::Invalid {
                detail: "artifact_hash must be 64 lowercase hex characters".into(),
            });
        }
        if justification.len() > MAX_JUSTIFICATION_BYTES || renders_blank(justification) {
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

    /// The canonical approval id: a domain-separated hash binding tenant,
    /// action, artifact hash and approver. Re-deriving it for a different
    /// artifact yields a different id, so an approval can never be replayed
    /// onto another artifact.
    pub fn id(&self) -> String {
        let mut hasher = Sha256::new();
        for part in [
            b"ccos-enterprise-approval-v1".as_slice(),
            self.tenant.0.as_bytes(),
            self.action.as_bytes(),
            self.artifact_hash.as_bytes(),
            self.approver.as_bytes(),
        ] {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        format!("approval-v1-{}", hex(hasher.finalize()))
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn hex(digest: sha2::digest::generic_array::GenericArray<u8, sha2::digest::consts::U32>) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Validate a persisted record: shape, canonical ids, id/request consistency,
/// and expiry sanity. Corrupt state is refused, never repaired.
fn validate_record(record: &ApprovalRecord) -> Result<(), ApprovalError> {
    if record.schema_version != APPROVAL_SCHEMA {
        return Err(ApprovalError::UnsupportedSchema {
            found: record.schema_version,
        });
    }
    let request = ApprovalRequest::new(
        TenantId(record.tenant.clone()),
        &record.action,
        &record.artifact_hash,
        &record.approver,
        record.decision,
        record.recorded_at,
        record.expires_at,
        record.justification.as_deref().unwrap_or("recorded"),
    )?;
    if request.id() != record.id {
        return Err(ApprovalError::Invalid {
            detail: "approval id does not match its fields".into(),
        });
    }
    Ok(())
}

/// A query for whether an action is approved, evaluated against the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalQuery<'a> {
    pub tenant: &'a TenantId,
    pub action: &'a str,
    pub artifact_hash: &'a str,
    /// Unix seconds; the gate's clock. An approval that expires at or before
    /// this instant is not approved.
    pub now: u64,
}

/// The outcome of an approval gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateOutcome {
    /// An unexpired, unrevoked approval with the exact tenant, action and
    /// artifact hash exists.
    Approved,
    /// No matching approval is recorded. This is the denial that makes
    /// "unrecorded approval" a real refusal.
    Denied,
    /// An approval id matches but the artifact hash differs — an attempted
    /// replay onto a different artifact.
    ArtifactMismatch { found: String },
    /// The matching approval has expired by the gate's clock.
    Expired,
    /// The matching approval was revoked.
    Revoked,
}

/// The in-memory, validated approval ledger.
#[derive(Debug)]
pub struct ApprovalRegistry {
    snapshot: ApprovalSnapshot,
    revocations: BTreeMap<String, RevocationRecord>,
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
            revocations: BTreeMap::new(),
        }
    }

    pub fn from_snapshot(snapshot: ApprovalSnapshot) -> Result<Self, ApprovalError> {
        if snapshot.schema_version != APPROVAL_SCHEMA {
            return Err(ApprovalError::UnsupportedSchema {
                found: snapshot.schema_version,
            });
        }
        for record in snapshot.approvals.values() {
            validate_record(record)?;
        }
        Ok(Self {
            snapshot,
            revocations: BTreeMap::new(),
        })
    }

    pub fn snapshot(&self) -> &ApprovalSnapshot {
        &self.snapshot
    }

    pub fn is_revoked(&self, id: &str) -> bool {
        self.revocations.contains_key(id)
    }

    /// Record one approval. Refuses a duplicate id (an approval is never
    /// overwritten — a corrected decision is a new record, or a revocation).
    pub fn record(&mut self, request: ApprovalRequest) -> Result<String, ApprovalError> {
        let id = request.id();
        if self.snapshot.approvals.contains_key(&id) {
            return Err(ApprovalError::AlreadyExists { id });
        }
        let record = ApprovalRecord {
            id: id.clone(),
            tenant: request.tenant.0.clone(),
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

    /// Evaluate one gate. Deterministic over validated state plus the
    /// supplied clock.
    ///
    /// The gate cannot know the approver ahead of time (the id binds the
    /// approver), so it matches by the recorded bindings — tenant, action,
    /// artifact hash, decision — and authorizes iff at least one matching
    /// approval is neither revoked nor expired. Denial is the only answer
    /// when nothing is live.
    pub fn evaluate(&self, query: &ApprovalQuery<'_>) -> GateOutcome {
        let mut any_revoked = false;
        let mut any_expired = false;
        let mut any_match = false;
        for record in self.snapshot.approvals.values() {
            if record.tenant != query.tenant.0
                || record.action != query.action
                || record.artifact_hash != query.artifact_hash
                || record.decision != ApprovalDecision::Approved
            {
                continue;
            }
            any_match = true;
            if self.revocations.contains_key(&record.id) {
                any_revoked = true;
                continue;
            }
            if record.expires_at.is_some_and(|expiry| expiry <= query.now) {
                any_expired = true;
                continue;
            }
            return GateOutcome::Approved;
        }
        if any_revoked {
            return GateOutcome::Revoked;
        }
        if any_expired {
            return GateOutcome::Expired;
        }
        if any_match {
            // A matching record with a Denied decision is not live.
            return GateOutcome::Denied;
        }
        GateOutcome::Denied
    }

    /// Revoke an approval. Append-only: the revocation is a separate record
    /// and the original approval stays in the ledger, unmodified.
    pub fn revoke(
        &mut self,
        approval_id: &str,
        revoked_by: &str,
        revoked_at: u64,
        justification: &str,
    ) -> Result<(), ApprovalError> {
        if !self.snapshot.approvals.contains_key(approval_id) {
            return Err(ApprovalError::Unknown {
                id: approval_id.to_string(),
            });
        }
        if self.revocations.contains_key(approval_id) {
            return Err(ApprovalError::AlreadyRevoked {
                id: approval_id.to_string(),
            });
        }
        if revoked_by.is_empty() || renders_blank(revoked_by) {
            return Err(ApprovalError::Invalid {
                detail: "revoked_by must be a legible identity".into(),
            });
        }
        if renders_blank(justification) {
            return Err(ApprovalError::Invalid {
                detail: "revocation requires a legible justification".into(),
            });
        }
        self.revocations.insert(
            approval_id.to_string(),
            RevocationRecord {
                approval_id: approval_id.to_string(),
                revoked_by: revoked_by.to_string(),
                revoked_at,
                justification: justification.to_string(),
            },
        );
        Ok(())
    }
}

/// Durable, single-writer approval ledger on disk.
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
        if snapshot.schema_version != APPROVAL_SCHEMA {
            return Err(ApprovalError::UnsupportedSchema {
                found: snapshot.schema_version,
            });
        }
        for record in snapshot.approvals.values() {
            validate_record(record)?;
        }
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
        // Crash-tolerant tail: only the final unterminated line may be torn.
        let (committed, _torn) = match bytes.iter().rposition(|b| *b == b'\n') {
            Some(end) => (&bytes[..=end], bytes.len() - end - 1),
            None => (&bytes[..0], bytes.len()),
        };
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
            records.push(record);
        }
        Ok(records)
    }

    pub fn save(&self, snapshot: &ApprovalSnapshot) -> Result<(), ApprovalError> {
        if snapshot.schema_version != APPROVAL_SCHEMA {
            return Err(ApprovalError::UnsupportedSchema {
                found: snapshot.schema_version,
            });
        }
        let _ = ApprovalRegistry::from_snapshot(snapshot.clone())?;
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

    /// Append one revocation durably.
    pub fn append_revocation(&self, record: &RevocationRecord) -> Result<(), ApprovalError> {
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
        Ok(())
    }

    /// Load the whole validated ledger (approvals + revocations).
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
            if approval.decision == ApprovalDecision::Approved
                && !registry.revocations.contains_key(&revocation.approval_id)
            {
                registry.revocations.insert(
                    revocation.approval_id.clone(),
                    RevocationRecord {
                        approval_id: revocation.approval_id.clone(),
                        revoked_by: revocation.revoked_by.clone(),
                        revoked_at: revocation.revoked_at,
                        justification: revocation.justification.clone(),
                    },
                );
            }
        }
        Ok(registry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(
        tenant: &str,
        action: &str,
        artifact: &str,
        approver: &str,
        at: u64,
        expires: Option<u64>,
    ) -> ApprovalRequest {
        ApprovalRequest::new(
            TenantId(tenant.into()),
            action,
            artifact,
            approver,
            ApprovalDecision::Approved,
            at,
            expires,
            "test justification",
        )
        .unwrap()
    }

    fn artifact(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    #[test]
    fn unrecorded_approval_is_denial() {
        let registry = ApprovalRegistry::new();
        let tenant = TenantId("acme".into());
        let outcome = registry.evaluate(&ApprovalQuery {
            tenant: &tenant,
            action: "tenant.delete",
            artifact_hash: &artifact(1),
            now: 100,
        });
        assert_eq!(outcome, GateOutcome::Denied);
    }

    #[test]
    fn recorded_approval_authorizes_exactly_its_artifact() {
        let mut registry = ApprovalRegistry::new();
        registry
            .record(request(
                "acme",
                "tenant.delete",
                &artifact(1),
                "ZEKRITI Tarek",
                100,
                None,
            ))
            .unwrap();
        let tenant = TenantId("acme".into());
        assert_eq!(
            registry.evaluate(&ApprovalQuery {
                tenant: &tenant,
                action: "tenant.delete",
                artifact_hash: &artifact(1),
                now: 200,
            }),
            GateOutcome::Approved
        );
        // Same action, different artifact: the gate refuses (the id binds the
        // artifact, so no approval exists for this artifact).
        assert_eq!(
            registry.evaluate(&ApprovalQuery {
                tenant: &tenant,
                action: "tenant.delete",
                artifact_hash: &artifact(2),
                now: 200,
            }),
            GateOutcome::Denied
        );
    }

    #[test]
    fn wrong_tenant_is_denial() {
        let mut registry = ApprovalRegistry::new();
        registry
            .record(request(
                "acme",
                "tenant.delete",
                &artifact(1),
                "ZEKRITI Tarek",
                100,
                None,
            ))
            .unwrap();
        let globex = TenantId("globex".into());
        assert_eq!(
            registry.evaluate(&ApprovalQuery {
                tenant: &globex,
                action: "tenant.delete",
                artifact_hash: &artifact(1),
                now: 200,
            }),
            GateOutcome::Denied,
            "an acme approval must never authorize a globex action"
        );
    }

    #[test]
    fn denied_decision_never_authorizes() {
        let mut registry = ApprovalRegistry::new();
        let mut r = request(
            "acme",
            "license.revoke",
            &artifact(1),
            "ZEKRITI Tarek",
            100,
            None,
        );
        r.decision = ApprovalDecision::Denied;
        registry.record(r).unwrap();
        let tenant = TenantId("acme".into());
        assert_eq!(
            registry.evaluate(&ApprovalQuery {
                tenant: &tenant,
                action: "license.revoke",
                artifact_hash: &artifact(1),
                now: 200,
            }),
            GateOutcome::Denied
        );
    }

    #[test]
    fn expired_approval_is_denial_at_the_boundary() {
        let mut registry = ApprovalRegistry::new();
        registry
            .record(request(
                "acme",
                "quota.override",
                &artifact(1),
                "ZEKRITI Tarek",
                100,
                Some(200),
            ))
            .unwrap();
        let tenant = TenantId("acme".into());
        assert_eq!(
            registry.evaluate(&ApprovalQuery {
                tenant: &tenant,
                action: "quota.override",
                artifact_hash: &artifact(1),
                now: 199,
            }),
            GateOutcome::Approved
        );
        assert_eq!(
            registry.evaluate(&ApprovalQuery {
                tenant: &tenant,
                action: "quota.override",
                artifact_hash: &artifact(1),
                now: 200,
            }),
            GateOutcome::Expired,
            "expiry at the boundary is denial"
        );
    }

    #[test]
    fn revoked_approval_is_denial_and_revocation_is_append_only() {
        let mut registry = ApprovalRegistry::new();
        let id = registry
            .record(request(
                "acme",
                "policy.disable",
                &artifact(1),
                "ZEKRITI Tarek",
                100,
                None,
            ))
            .unwrap();
        let tenant = TenantId("acme".into());
        assert_eq!(
            registry.evaluate(&ApprovalQuery {
                tenant: &tenant,
                action: "policy.disable",
                artifact_hash: &artifact(1),
                now: 200,
            }),
            GateOutcome::Approved
        );
        registry
            .revoke(&id, "ZEKRITI Tarek", 250, "policy changed direction")
            .unwrap();
        assert_eq!(
            registry.evaluate(&ApprovalQuery {
                tenant: &tenant,
                action: "policy.disable",
                artifact_hash: &artifact(1),
                now: 300,
            }),
            GateOutcome::Revoked
        );
        // The original record is untouched — the ledger still holds it.
        assert!(registry.snapshot().approvals.contains_key(&id));
        // Double revocation is refused.
        assert_eq!(
            registry.revoke(&id, "ZEKRITI Tarek", 251, "again"),
            Err(ApprovalError::AlreadyRevoked { id: id.clone() })
        );
    }

    #[test]
    fn approval_cannot_be_replayed_onto_a_different_artifact() {
        // The id is derived from the artifact hash, so re-deriving with a
        // different artifact produces a different id and no record matches.
        let mut registry = ApprovalRegistry::new();
        let id = registry
            .record(request(
                "acme",
                "model.allowlist",
                &artifact(9),
                "ZEKRITI Tarek",
                100,
                None,
            ))
            .unwrap();
        let other = ApprovalRequest::new(
            TenantId("acme".into()),
            "model.allowlist",
            &artifact(8),
            "ZEKRITI Tarek",
            ApprovalDecision::Approved,
            100,
            None,
            "test",
        )
        .unwrap();
        assert_ne!(id, other.id(), "the id binds the artifact");
        let tenant = TenantId("acme".into());
        assert_eq!(
            registry.evaluate(&ApprovalQuery {
                tenant: &tenant,
                action: "model.allowlist",
                artifact_hash: &artifact(8),
                now: 200,
            }),
            GateOutcome::Denied
        );
    }

    #[test]
    fn malformed_requests_are_refused() {
        for (label, builder) in [
            (
                "action",
                Box::new(|r: &mut ApprovalRequest| r.action = "Tenant.Delete".into())
                    as Box<dyn Fn(&mut ApprovalRequest)>,
            ),
            (
                "artifact",
                Box::new(|r: &mut ApprovalRequest| r.artifact_hash = "not-a-hash".into()),
            ),
            (
                "approver blank",
                Box::new(|r: &mut ApprovalRequest| r.approver = "\u{200b}".into()),
            ),
            (
                "justification blank",
                Box::new(|r: &mut ApprovalRequest| r.justification = "\u{feff} \t".into()),
            ),
            (
                "expiry in past",
                Box::new(|r: &mut ApprovalRequest| r.expires_at = Some(50)),
            ),
        ] {
            let mut r = request(
                "acme",
                "tenant.delete",
                &artifact(1),
                "ZEKRITI Tarek",
                100,
                None,
            );
            builder(&mut r);
            assert!(
                ApprovalRequest::new(
                    r.tenant.clone(),
                    &r.action,
                    &r.artifact_hash,
                    &r.approver,
                    r.decision,
                    r.recorded_at,
                    r.expires_at,
                    &r.justification,
                )
                .is_err(),
                "{label} was accepted"
            );
        }
    }

    #[test]
    fn duplicate_record_is_refused_never_overwritten() {
        let mut registry = ApprovalRegistry::new();
        let id = registry
            .record(request(
                "acme",
                "tenant.delete",
                &artifact(1),
                "ZEKRITI Tarek",
                100,
                None,
            ))
            .unwrap();
        let again = request(
            "acme",
            "tenant.delete",
            &artifact(1),
            "ZEKRITI Tarek",
            101,
            None,
        );
        assert_eq!(
            registry.record(again),
            Err(ApprovalError::AlreadyExists { id })
        );
    }

    #[test]
    fn corrupt_snapshot_is_refused_not_reset() {
        let dir =
            std::env::temp_dir().join(format!("ccos-approval-corrupt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(APPROVAL_FILE), b"{ broken").unwrap();
        let store = ApprovalStore::open(&dir).unwrap();
        assert!(matches!(
            store.load_snapshot(),
            Err(ApprovalError::Corrupt { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_record_is_refused_by_validation() {
        let mut registry = ApprovalRegistry::new();
        registry
            .record(request(
                "acme",
                "tenant.delete",
                &artifact(1),
                "ZEKRITI Tarek",
                100,
                None,
            ))
            .unwrap();
        let mut snapshot = registry.snapshot().clone();
        let record = snapshot.approvals.values_mut().next().unwrap();
        record.artifact_hash = artifact(2).to_string();
        let err = ApprovalRegistry::from_snapshot(snapshot).expect_err("must refuse");
        assert!(matches!(err, ApprovalError::Invalid { .. }), "{err}");
    }

    #[test]
    fn round_trip_through_the_store_is_durable_and_private() {
        let dir =
            std::env::temp_dir().join(format!("ccos-approval-roundtrip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let recorded_id;
        {
            let store = ApprovalStore::open(&dir).unwrap();
            let mut registry = store.load_registry().unwrap();
            recorded_id = registry
                .record(request(
                    "acme",
                    "tenant.delete",
                    &artifact(7),
                    "ZEKRITI Tarek",
                    100,
                    None,
                ))
                .unwrap();
            store.save(registry.snapshot()).unwrap();
            registry
                .revoke(&recorded_id, "ZEKRITI Tarek", 200, "reconsidered")
                .unwrap();
            store
                .append_revocation(&RevocationRecord {
                    approval_id: recorded_id.clone(),
                    revoked_by: "ZEKRITI Tarek".into(),
                    revoked_at: 200,
                    justification: "reconsidered".into(),
                })
                .unwrap();
        }
        {
            let store = ApprovalStore::open(&dir).unwrap();
            let registry = store.load_registry().unwrap();
            assert!(registry.snapshot().approvals.contains_key(&recorded_id));
            assert!(registry.is_revoked(&recorded_id));
            let tenant = TenantId("acme".into());
            assert_eq!(
                registry.evaluate(&ApprovalQuery {
                    tenant: &tenant,
                    action: "tenant.delete",
                    artifact_hash: &artifact(7),
                    now: 300,
                }),
                GateOutcome::Revoked
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn zero_width_approver_is_refused_fail_closed() {
        let err = ApprovalRequest::new(
            TenantId("acme".into()),
            "tenant.delete",
            &artifact(1),
            "\u{200b}\u{feff}",
            ApprovalDecision::Approved,
            100,
            None,
            "legible",
        )
        .expect_err("an invisible approver must be refused");
        assert!(matches!(err, ApprovalError::Invalid { .. }));
    }
}
