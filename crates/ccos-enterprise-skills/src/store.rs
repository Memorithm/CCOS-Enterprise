use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::{
    io, parse_capture, ObserveDisposition, ObserveResult, SkillConfig, SkillError, SkillRegistry,
    SkillSnapshot, SKILL_SNAPSHOT_SCHEMA,
};

pub const SKILLS_FILE: &str = "skills.json";
pub const SKILLS_LOCK_FILE: &str = "skills.lock";
const TEMP_FILE: &str = "skills.json.tmp";

/// Single-writer durable registry rooted at a caller-scoped directory.
///
/// Tenant scoping is intentionally performed by the Enterprise host that
/// chooses this root. The file itself carries no tenant selector, which avoids
/// a second identity source that could disagree with the authenticated request.
pub struct SkillStore {
    root: PathBuf,
    snapshot_path: PathBuf,
    _lock: File,
}

impl SkillStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, SkillError> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root).map_err(io(&root))?;
        let lock_path = root.join(SKILLS_LOCK_FILE);
        let lock = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(io(&lock_path))?;
        lock.try_lock().map_err(|source| SkillError::Io {
            path: lock_path,
            source: source.into(),
        })?;
        Ok(Self {
            snapshot_path: root.join(SKILLS_FILE),
            root,
            _lock: lock,
        })
    }

    pub fn load(&self) -> Result<Option<SkillSnapshot>, SkillError> {
        let bytes = match std::fs::read(&self.snapshot_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(SkillError::Io {
                    path: self.snapshot_path.clone(),
                    source,
                })
            }
        };
        let snapshot: SkillSnapshot =
            serde_json::from_slice(&bytes).map_err(|error| SkillError::Corrupt {
                path: self.snapshot_path.clone(),
                detail: error.to_string(),
            })?;
        if snapshot.schema_version != SKILL_SNAPSHOT_SCHEMA {
            return Err(SkillError::UnsupportedSchema {
                found: snapshot.schema_version,
            });
        }
        Ok(Some(snapshot))
    }

    pub fn load_registry(&self, config: SkillConfig) -> Result<SkillRegistry, SkillError> {
        match self.load()? {
            Some(snapshot) => SkillRegistry::from_snapshot(config, snapshot),
            None => SkillRegistry::new(config),
        }
    }

    pub fn save(&self, snapshot: &SkillSnapshot) -> Result<(), SkillError> {
        if snapshot.schema_version != SKILL_SNAPSHOT_SCHEMA {
            return Err(SkillError::UnsupportedSchema {
                found: snapshot.schema_version,
            });
        }
        // Validate through the public constructor before writing bytes: the
        // disk must never become the first place a malformed snapshot is found.
        let _ = SkillRegistry::from_snapshot(SkillConfig::default(), snapshot.clone())?;

        let bytes = serde_json::to_vec_pretty(snapshot).map_err(|error| SkillError::Corrupt {
            path: self.snapshot_path.clone(),
            detail: format!("cannot serialize skill snapshot: {error}"),
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

    /// Observe one complete DSH capture and atomically persist any resulting
    /// lifecycle update. A document without L1 evidence is a no-op.
    pub fn observe_capture(
        &self,
        config: SkillConfig,
        source: &str,
    ) -> Result<ObserveResult, SkillError> {
        let Some(episode) = parse_capture(source)? else {
            return Ok(ObserveResult {
                disposition: ObserveDisposition::Ignored,
                skill_id: None,
                status: None,
            });
        };
        let mut registry = self.load_registry(config)?;
        let result = registry.observe(&episode)?;
        if matches!(
            result.disposition,
            ObserveDisposition::Created | ObserveDisposition::Updated
        ) {
            self.save(registry.snapshot())?;
        }
        Ok(result)
    }
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
            "ccos-enterprise-skills-{}-{name}-{nonce}",
            std::process::id()
        ))
    }

    fn capture(secret: &str) -> String {
        format!(
            "# DeepSeek Harness turn 1\nsession: s1\n\n## User\n{secret}\n\n## Tools\n- memory.recall (c1)\n  input: {{\"secret\":\"{secret}\"}}\n  output: {secret}\nturn_end_reason: {{\"kind\":\"completed\"}}\n\n## CCOS Episode (evidence-only)\n```json\n{{\"schema\":\"ccos.dsh.episode.v1\",\"evidence_only\":true,\"host\":\"deepseek-harness\",\"session_id\":\"s1\",\"turn\":1,\"observed_outcome\":{{\"reason_kind\":\"completed\"}},\"evidence\":{{\"tool_calls\":1,\"tool_failures\":0,\"unresolved_tool_calls\":0}}}}\n```\n"
        )
    }

    #[test]
    fn round_trip_is_durable_idempotent_and_drops_raw_content() {
        let root = temp_dir("roundtrip");
        let secret = "DO-NOT-PERSIST-RAW-CONTENT";
        {
            let store = SkillStore::open(&root).unwrap();
            let first = store
                .observe_capture(SkillConfig::default(), &capture(secret))
                .unwrap();
            assert_eq!(first.disposition, ObserveDisposition::Created);
            let disk = std::fs::read_to_string(root.join(SKILLS_FILE)).unwrap();
            assert!(!disk.contains(secret));
            assert!(!disk.contains("input"));
            assert!(!disk.contains("output"));
        }
        {
            let store = SkillStore::open(&root).unwrap();
            let duplicate = store
                .observe_capture(SkillConfig::default(), &capture(secret))
                .unwrap();
            assert_eq!(duplicate.disposition, ObserveDisposition::Duplicate);
            let registry = store.load_registry(SkillConfig::default()).unwrap();
            let skill = registry.snapshot().skills.values().next().unwrap();
            assert_eq!(skill.support, 1);
            assert_eq!(skill.trials_attempted, 1);
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn corrupt_snapshot_is_refused_not_reset() {
        let root = temp_dir("corrupt");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(SKILLS_FILE), b"{ definitely-not-json").unwrap();
        let store = SkillStore::open(&root).unwrap();
        assert!(matches!(store.load(), Err(SkillError::Corrupt { .. })));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn lock_prevents_two_live_writers() {
        let root = temp_dir("lock");
        let first = SkillStore::open(&root).unwrap();
        assert!(matches!(
            SkillStore::open(&root),
            Err(SkillError::Io { .. })
        ));
        drop(first);
        assert!(SkillStore::open(&root).is_ok());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn ordinary_memory_document_is_not_a_skill_observation() {
        let root = temp_dir("ordinary");
        let store = SkillStore::open(&root).unwrap();
        let out = store
            .observe_capture(SkillConfig::default(), "plain memory document")
            .unwrap();
        assert_eq!(out.disposition, ObserveDisposition::Ignored);
        assert!(!root.join(SKILLS_FILE).exists());
        let _ = std::fs::remove_dir_all(root);
    }
}
