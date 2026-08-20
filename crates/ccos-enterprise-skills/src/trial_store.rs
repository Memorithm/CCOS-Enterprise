use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::{
    io, EpisodeObservation, ExposureResult, SkillError, SkillRegistry, SkillTrialConfig,
    SkillTrialRegistry, SkillTrialSnapshot, TrialResolution, SKILL_TRIAL_SNAPSHOT_SCHEMA,
};

pub const SKILL_TRIALS_FILE: &str = "skill-trials.json";
pub const SKILL_TRIALS_LOCK_FILE: &str = "skill-trials.lock";
const TEMP_FILE: &str = "skill-trials.json.tmp";

/// Durable, caller-scoped observational trial ledger.
///
/// The store never persists raw session ids, prompts, tool arguments/results,
/// or model output. Exposure correlation is represented only by a
/// domain-separated hash of `(session_id, turn)`.
pub struct SkillTrialStore {
    root: PathBuf,
    snapshot_path: PathBuf,
    _lock: File,
}

impl SkillTrialStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, SkillError> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root).map_err(io(&root))?;
        let lock_path = root.join(SKILL_TRIALS_LOCK_FILE);
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
            snapshot_path: root.join(SKILL_TRIALS_FILE),
            root,
            _lock: lock,
        })
    }

    /// Canonical root backing this validated store. Audit code uses this
    /// identity to bind loaded registries to their actual tenant-scoped store.
    pub fn canonical_root(&self) -> Result<PathBuf, SkillError> {
        std::fs::canonicalize(&self.root).map_err(io(&self.root))
    }

    pub fn load(&self) -> Result<Option<SkillTrialSnapshot>, SkillError> {
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
        let snapshot: SkillTrialSnapshot =
            serde_json::from_slice(&bytes).map_err(|error| SkillError::CorruptTrial {
                path: self.snapshot_path.clone(),
                detail: error.to_string(),
            })?;
        if snapshot.schema_version != SKILL_TRIAL_SNAPSHOT_SCHEMA {
            return Err(SkillError::UnsupportedTrialSchema {
                found: snapshot.schema_version,
            });
        }
        Ok(Some(snapshot))
    }

    pub fn load_registry(
        &self,
        config: SkillTrialConfig,
    ) -> Result<SkillTrialRegistry, SkillError> {
        match self.load()? {
            Some(snapshot) => SkillTrialRegistry::from_snapshot(config, snapshot),
            None => SkillTrialRegistry::new(config),
        }
    }

    pub fn save(&self, snapshot: &SkillTrialSnapshot) -> Result<(), SkillError> {
        if snapshot.schema_version != SKILL_TRIAL_SNAPSHOT_SCHEMA {
            return Err(SkillError::UnsupportedTrialSchema {
                found: snapshot.schema_version,
            });
        }
        let _ = SkillTrialRegistry::from_snapshot(
            SkillTrialConfig {
                trial_cap: snapshot.trials.len().max(1),
                exposure_cap: 1,
            },
            snapshot.clone(),
        )?;
        let bytes =
            serde_json::to_vec_pretty(snapshot).map_err(|error| SkillError::CorruptTrial {
                path: self.snapshot_path.clone(),
                detail: format!("cannot serialize skill trial snapshot: {error}"),
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

    pub fn expose(
        &self,
        config: SkillTrialConfig,
        session_id: &str,
        turn: u64,
        skills: &SkillRegistry,
        skill_ids: &[String],
    ) -> Result<ExposureResult, SkillError> {
        let mut registry = self.load_registry(config)?;
        let result = registry.expose(session_id, turn, skills, skill_ids)?;
        if result.created > 0 {
            self.save(registry.snapshot())?;
        }
        Ok(result)
    }

    pub fn resolve_episode(
        &self,
        config: SkillTrialConfig,
        episode: &EpisodeObservation,
        skills: &SkillRegistry,
    ) -> Result<TrialResolution, SkillError> {
        let mut registry = self.load_registry(config)?;
        let before = registry.snapshot().clone();
        let result = registry.resolve_episode(episode, skills)?;
        if registry.snapshot() != &before {
            self.save(registry.snapshot())?;
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::{SkillConfig, ToolObservation, ToolOutcome};

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "ccos-enterprise-skill-trials-{}-{name}-{nonce}",
            std::process::id()
        ))
    }

    fn active_skill_registry() -> (SkillRegistry, String) {
        let mut registry = SkillRegistry::new(SkillConfig::default()).unwrap();
        for turn in 1..=3 {
            registry
                .observe(&EpisodeObservation {
                    evidence_id: format!("{turn:064x}"),
                    session_id: "source-session".into(),
                    turn,
                    reason_kind: "completed".into(),
                    tools: vec![ToolObservation {
                        name: "memory.recall".into(),
                        call_id: format!("call-{turn}"),
                        outcome: ToolOutcome::Succeeded,
                    }],
                })
                .unwrap();
        }
        let skill_id = registry.active().next().unwrap().id.clone();
        (registry, skill_id)
    }

    #[test]
    fn exposure_round_trip_is_durable_idempotent_and_private() {
        let root = temp_dir("roundtrip");
        let (skills, skill_id) = active_skill_registry();
        let ids = vec![skill_id];
        {
            let store = SkillTrialStore::open(&root).unwrap();
            let first = store
                .expose(
                    SkillTrialConfig::default(),
                    "RAW-SESSION-ID",
                    42,
                    &skills,
                    &ids,
                )
                .unwrap();
            assert_eq!(first.created, 1);
            let disk = std::fs::read_to_string(root.join(SKILL_TRIALS_FILE)).unwrap();
            assert!(!disk.contains("RAW-SESSION-ID"));
            assert!(!disk.contains("\"turn\": 42"));
        }
        {
            let store = SkillTrialStore::open(&root).unwrap();
            let duplicate = store
                .expose(
                    SkillTrialConfig::default(),
                    "RAW-SESSION-ID",
                    42,
                    &skills,
                    &ids,
                )
                .unwrap();
            assert_eq!(duplicate.created, 0);
            assert_eq!(duplicate.duplicates, 1);
            assert_eq!(store.load().unwrap().unwrap().trials.len(), 1);
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn resolution_is_durable_and_replay_idempotent() {
        let root = temp_dir("resolve");
        let (skills, skill_id) = active_skill_registry();
        let store = SkillTrialStore::open(&root).unwrap();
        store
            .expose(
                SkillTrialConfig::default(),
                "trial-session",
                5,
                &skills,
                &[skill_id],
            )
            .unwrap();
        let episode = EpisodeObservation {
            evidence_id: "f".repeat(64),
            session_id: "trial-session".into(),
            turn: 5,
            reason_kind: "completed".into(),
            tools: vec![ToolObservation {
                name: "memory.recall".into(),
                call_id: "trial-call".into(),
                outcome: ToolOutcome::Succeeded,
            }],
        };
        let first = store
            .resolve_episode(SkillTrialConfig::default(), &episode, &skills)
            .unwrap();
        assert_eq!(first.passed, 1);
        let second = store
            .resolve_episode(SkillTrialConfig::default(), &episode, &skills)
            .unwrap();
        assert_eq!(second.passed, 0);
        assert_eq!(second.already_resolved, 1);
        drop(store);

        let reopened = SkillTrialStore::open(&root).unwrap();
        let snapshot = reopened.load().unwrap().unwrap();
        let trial = snapshot.trials.values().next().unwrap();
        assert_eq!(trial.status, crate::SkillTrialStatus::Passed);
        assert_eq!(
            trial.evidence_id.as_deref(),
            Some("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn corrupt_snapshot_is_refused_not_reset() {
        let root = temp_dir("corrupt");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(SKILL_TRIALS_FILE), b"{ broken").unwrap();
        let store = SkillTrialStore::open(&root).unwrap();
        assert!(matches!(store.load(), Err(SkillError::CorruptTrial { .. })));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn lock_prevents_two_live_trial_writers() {
        let root = temp_dir("lock");
        let first = SkillTrialStore::open(&root).unwrap();
        assert!(matches!(
            SkillTrialStore::open(&root),
            Err(SkillError::Io { .. })
        ));
        drop(first);
        assert!(SkillTrialStore::open(&root).is_ok());
        let _ = std::fs::remove_dir_all(root);
    }
}
