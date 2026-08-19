use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const PROJECTION_SCHEMA: u32 = 1;
const PENDING_FILE: &str = "projection-pending.json";
const MAX_ID_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingProjection {
    pub schema_version: u32,
    pub tenant: String,
    pub request_id: String,
    pub source_sha256: String,
}

pub struct ProjectionState {
    root: PathBuf,
    path: PathBuf,
    tenant: String,
    pending: Option<PendingProjection>,
}

impl ProjectionState {
    pub fn open(root: impl AsRef<Path>, tenant: &str) -> Result<Self, String> {
        validate_id("tenant", tenant)?;
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)
            .map_err(|error| format!("cannot create skill projection directory: {error}"))?;
        let path = root.join(PENDING_FILE);
        let pending = match std::fs::read(&path) {
            Ok(bytes) => {
                let pending: PendingProjection = serde_json::from_slice(&bytes)
                    .map_err(|error| format!("skill projection receipt is corrupt: {error}"))?;
                validate_pending(&pending, tenant)?;
                Some(pending)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(format!(
                    "cannot read durable skill projection receipt: {error}"
                ))
            }
        };
        Ok(Self {
            root,
            path,
            tenant: tenant.to_string(),
            pending,
        })
    }

    pub fn pending(&self) -> Option<&PendingProjection> {
        self.pending.as_ref()
    }

    /// Persist proof that the Core ingest already succeeded and this exact
    /// source still needs deterministic skill projection.
    pub fn prepare(&mut self, request_id: &str, source_sha256: &str) -> Result<(), String> {
        validate_id("request_id", request_id)?;
        validate_sha256(source_sha256)?;
        if let Some(existing) = &self.pending {
            if existing.request_id == request_id && existing.source_sha256 == source_sha256 {
                return Ok(());
            }
            return Err(format!(
                "skill projection for request {:?} is still pending",
                existing.request_id
            ));
        }
        let pending = PendingProjection {
            schema_version: PROJECTION_SCHEMA,
            tenant: self.tenant.clone(),
            request_id: request_id.to_string(),
            source_sha256: source_sha256.to_string(),
        };
        let bytes = serde_json::to_vec_pretty(&pending)
            .map_err(|error| format!("cannot serialize skill projection receipt: {error}"))?;
        ccos_core::util::write_durable(&self.path, &bytes)
            .map_err(|error| format!("cannot persist skill projection receipt: {error}"))?;
        self.pending = Some(pending);
        Ok(())
    }

    pub fn require_match(&self, request_id: &str, source_sha256: &str) -> Result<(), String> {
        let pending = self
            .pending
            .as_ref()
            .ok_or_else(|| "no skill projection is pending".to_string())?;
        if pending.request_id != request_id {
            return Err(format!(
                "skill projection for request {:?} must be reconciled first",
                pending.request_id
            ));
        }
        if pending.source_sha256 != source_sha256 {
            return Err("replayed memory.ingest source does not match pending projection".into());
        }
        Ok(())
    }

    pub fn clear(&mut self, request_id: &str, source_sha256: &str) -> Result<(), String> {
        self.require_match(request_id, source_sha256)?;
        std::fs::remove_file(&self.path)
            .map_err(|error| format!("cannot remove skill projection receipt: {error}"))?;
        File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("cannot fsync skill projection directory: {error}"))?;
        self.pending = None;
        Ok(())
    }
}

pub fn source_sha256(source: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"ccos.skill.projection.source.v1\0");
    hash.update((source.len() as u64).to_be_bytes());
    hash.update(source.as_bytes());
    to_hex(&hash.finalize())
}

fn validate_pending(pending: &PendingProjection, expected_tenant: &str) -> Result<(), String> {
    if pending.schema_version != PROJECTION_SCHEMA {
        return Err(format!(
            "unsupported skill projection schema {}",
            pending.schema_version
        ));
    }
    validate_id("tenant", &pending.tenant)?;
    validate_id("request_id", &pending.request_id)?;
    validate_sha256(&pending.source_sha256)?;
    if pending.tenant != expected_tenant {
        return Err("skill projection receipt belongs to a different tenant".into());
    }
    Ok(())
}

fn validate_id(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_ID_BYTES || value.chars().any(char::is_control) {
        Err(format!("skill projection {label} is invalid"))
    } else {
        Ok(())
    }
}

fn validate_sha256(value: &str) -> Result<(), String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err("skill projection source hash is not lowercase sha256".into())
    }
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "ccos-skill-projection-{}-{name}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn pending_receipt_is_durable_hash_only_and_match_checked() {
        let root = temp_dir("roundtrip");
        let source = "RAW-PROMPT-MUST-NOT-PERSIST";
        let hash = source_sha256(source);
        {
            let mut state = ProjectionState::open(&root, "acme").unwrap();
            state.prepare("request-1", &hash).unwrap();
            let disk = std::fs::read_to_string(root.join(PENDING_FILE)).unwrap();
            assert!(!disk.contains(source));
            assert!(disk.contains(&hash));
        }
        {
            let mut state = ProjectionState::open(&root, "acme").unwrap();
            state.require_match("request-1", &hash).unwrap();
            assert!(state.require_match("request-2", &hash).is_err());
            assert!(state
                .require_match("request-1", &source_sha256("different"))
                .is_err());
            state.clear("request-1", &hash).unwrap();
            assert!(state.pending().is_none());
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn preparing_same_receipt_after_reopen_is_idempotent() {
        let root = temp_dir("reopen-idempotent");
        let hash = source_sha256("canonical-l1-capture");
        {
            let mut state = ProjectionState::open(&root, "acme").unwrap();
            state.prepare("request-1", &hash).unwrap();
        }
        {
            let mut reopened = ProjectionState::open(&root, "acme").unwrap();
            reopened.prepare("request-1", &hash).unwrap();
            assert_eq!(reopened.pending().unwrap().request_id, "request-1");
            assert_eq!(reopened.pending().unwrap().source_sha256, hash);
            reopened.clear("request-1", &hash).unwrap();
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn second_pending_request_is_refused() {
        let root = temp_dir("single");
        let mut state = ProjectionState::open(&root, "acme").unwrap();
        state.prepare("request-1", &source_sha256("one")).unwrap();
        assert!(state.prepare("request-2", &source_sha256("two")).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn corrupt_or_cross_tenant_receipt_fails_closed() {
        let root = temp_dir("corrupt");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(PENDING_FILE), b"{broken").unwrap();
        assert!(ProjectionState::open(&root, "acme").is_err());

        std::fs::write(
            root.join(PENDING_FILE),
            serde_json::to_vec(&PendingProjection {
                schema_version: PROJECTION_SCHEMA,
                tenant: "other".into(),
                request_id: "r".into(),
                source_sha256: source_sha256("x"),
            })
            .unwrap(),
        )
        .unwrap();
        assert!(ProjectionState::open(&root, "acme").is_err());
        let _ = std::fs::remove_dir_all(root);
    }
}
