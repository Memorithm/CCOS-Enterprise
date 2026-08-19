use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::{
    io, EpisodeObservation, ExposureResult, SkillError, SkillRegistry, SkillTrialConfig,
    SkillTrialRecord, SkillTrialRegistry, SkillTrialSnapshot, SkillTrialStatus, TrialResolution,
    SKILL_TRIAL_SNAPSHOT_SCHEMA,
};

pub const SKILL_TRIALS_FILE: &str = "skill-trials.json";
pub const SKILL_TRIALS_LOCK_FILE: &str = "skill-trials.lock";
const TEMP_FILE: &str = "skill-trials.json.tmp";
const MAX_SKILL_ID_BYTES: usize = 256;

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

    /// Reapply a previously authorized exposure from a stronger durable
    /// witness after a crash.
    ///
    /// Unlike a fresh [`Self::expose`] call, this path does not require the
    /// referenced skill to remain `Active`: the live read already proved that
    /// at exposure time, while lifecycle state may legitimately drift before
    /// recovery. Every skill must still exist, the correlation key and skill
    /// ids are validated, exact duplicates remain idempotent, and unresolved
    /// trials are never evicted to make room.
    pub fn replay_exposure_turn_key(
        &self,
        config: SkillTrialConfig,
        turn_key: &str,
        skills: &SkillRegistry,
        skill_ids: &[String],
    ) -> Result<ExposureResult, SkillError> {
        config.validate()?;
        if !is_lower_hex_64(turn_key) {
            return Err(SkillError::InvalidTrial(
                "replayed turn_key must be a lowercase SHA-256".into(),
            ));
        }
        let unique: BTreeSet<&str> = skill_ids.iter().map(String::as_str).collect();
        if unique.len() > config.exposure_cap {
            return Err(SkillError::InvalidTrial(format!(
                "replayed exposure references {} skills, above cap {}",
                unique.len(),
                config.exposure_cap
            )));
        }

        let restored = self.load_registry(config.clone())?;
        let mut snapshot = restored.snapshot().clone();
        let mut new_count = 0usize;
        let mut duplicates = 0usize;
        for skill_id in &unique {
            validate_replayed_skill_id(skill_id)?;
            if skills.get(skill_id).is_none() {
                return Err(SkillError::InvalidTrial(format!(
                    "replayed exposure references missing skill {skill_id:?}"
                )));
            }
            let id = recovery_trial_id(turn_key, skill_id);
            if snapshot.trials.contains_key(&id) {
                duplicates = duplicates.saturating_add(1);
            } else {
                new_count = new_count.saturating_add(1);
            }
        }

        let pending = snapshot
            .trials
            .values()
            .filter(|trial| trial.status == SkillTrialStatus::Pending)
            .count();
        if pending.saturating_add(new_count) > config.trial_cap {
            return Err(SkillError::InvalidTrial(
                "trial cap is exhausted by unresolved replayed exposures".into(),
            ));
        }

        let mut created = 0usize;
        for skill_id in unique {
            let id = recovery_trial_id(turn_key, skill_id);
            if snapshot.trials.contains_key(&id) {
                continue;
            }
            let ordinal = snapshot.next_ordinal;
            snapshot.next_ordinal = snapshot
                .next_ordinal
                .checked_add(1)
                .ok_or_else(|| SkillError::InvalidTrial("trial ordinal overflow".into()))?;
            snapshot.trials.insert(
                id.clone(),
                SkillTrialRecord {
                    id,
                    skill_id: skill_id.to_string(),
                    turn_key: turn_key.to_string(),
                    status: SkillTrialStatus::Pending,
                    evidence_id: None,
                    ordinal,
                },
            );
            created = created.saturating_add(1);
        }

        if created > 0 {
            let normalized = SkillTrialRegistry::from_snapshot(config, snapshot)?;
            self.save(normalized.snapshot())?;
        }
        Ok(ExposureResult {
            turn_key: turn_key.to_string(),
            created,
            duplicates,
        })
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

fn validate_replayed_skill_id(skill_id: &str) -> Result<(), SkillError> {
    if skill_id.is_empty()
        || skill_id.len() > MAX_SKILL_ID_BYTES
        || skill_id.chars().any(char::is_control)
        || !skill_id.starts_with("skill-v1-")
    {
        return Err(SkillError::InvalidTrial(
            "replayed skill id is not canonical".into(),
        ));
    }
    let fingerprint = &skill_id["skill-v1-".len()..];
    if !is_lower_hex_64(fingerprint) {
        return Err(SkillError::InvalidTrial(
            "replayed skill fingerprint is not a lowercase SHA-256".into(),
        ));
    }
    Ok(())
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn recovery_trial_id(turn_key: &str, skill_id: &str) -> String {
    let mut hasher = Sha256::new();
    for part in [
        b"ccos-enterprise-skill-trial-id-v1".as_slice(),
        turn_key.as_bytes(),
        skill_id.as_bytes(),
    ] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    format!("trial-v1-{output}")
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::{trial_turn_key, SkillConfig, SkillStatus, ToolObservation, ToolOutcome};

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
    fn crash_replay_matches_live_trial_identity_and_is_idempotent() {
        let root = temp_dir("replay");
        let (skills, skill_id) = active_skill_registry();
        let turn_key = trial_turn_key("recovery-session", 12);
        let store = SkillTrialStore::open(&root).unwrap();
        let first = store
            .replay_exposure_turn_key(
                SkillTrialConfig::default(),
                &turn_key,
                &skills,
                std::slice::from_ref(&skill_id),
            )
            .unwrap();
        assert_eq!(first.created, 1);
        let replay_id = store
            .load()
            .unwrap()
            .unwrap()
            .trials
            .keys()
            .next()
            .unwrap()
            .clone();
        let duplicate = store
            .replay_exposure_turn_key(
                SkillTrialConfig::default(),
                &turn_key,
                &skills,
                std::slice::from_ref(&skill_id),
            )
            .unwrap();
        assert_eq!(duplicate.created, 0);
        assert_eq!(duplicate.duplicates, 1);
        drop(store);

        let live_root = temp_dir("live-identity");
        let live_store = SkillTrialStore::open(&live_root).unwrap();
        live_store
            .expose(
                SkillTrialConfig::default(),
                "recovery-session",
                12,
                &skills,
                &[skill_id],
            )
            .unwrap();
        let live_id = live_store
            .load()
            .unwrap()
            .unwrap()
            .trials
            .keys()
            .next()
            .unwrap()
            .clone();
        assert_eq!(replay_id, live_id);
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(live_root);
    }

    #[test]
    fn crash_replay_can_restore_prior_exposure_after_skill_retires() {
        let root = temp_dir("retired-replay");
        let (mut skills, skill_id) = active_skill_registry();
        for turn in 4..=10 {
            skills
                .observe(&EpisodeObservation {
                    evidence_id: format!("{turn:064x}"),
                    session_id: "retire-session".into(),
                    turn,
                    reason_kind: "error".into(),
                    tools: vec![ToolObservation {
                        name: "memory.recall".into(),
                        call_id: format!("fail-{turn}"),
                        outcome: ToolOutcome::Failed,
                    }],
                })
                .unwrap();
        }
        assert_eq!(skills.get(&skill_id).unwrap().status, SkillStatus::Retired);

        let store = SkillTrialStore::open(&root).unwrap();
        let turn_key = trial_turn_key("prior-valid-read", 44);
        let restored = store
            .replay_exposure_turn_key(
                SkillTrialConfig::default(),
                &turn_key,
                &skills,
                &[skill_id],
            )
            .unwrap();
        assert_eq!(restored.created, 1);
        assert_eq!(store.load().unwrap().unwrap().trials.len(), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn crash_replay_refuses_bad_hash_missing_skill_and_cap_overflow() {
        let root = temp_dir("replay-refusal");
        let (skills, skill_id) = active_skill_registry();
        let store = SkillTrialStore::open(&root).unwrap();
        assert!(store
            .replay_exposure_turn_key(
                SkillTrialConfig::default(),
                "not-a-hash",
                &skills,
                std::slice::from_ref(&skill_id),
            )
            .is_err());
        assert!(store
            .replay_exposure_turn_key(
                SkillTrialConfig::default(),
                &trial_turn_key("missing", 1),
                &skills,
                &["skill-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .into()],
            )
            .is_err());
        let config = SkillTrialConfig {
            trial_cap: 1,
            exposure_cap: 1,
        };
        store
            .replay_exposure_turn_key(
                config.clone(),
                &trial_turn_key("first", 1),
                &skills,
                std::slice::from_ref(&skill_id),
            )
            .unwrap();
        assert!(store
            .replay_exposure_turn_key(
                config,
                &trial_turn_key("second", 2),
                &skills,
                &[skill_id],
            )
            .is_err());
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
