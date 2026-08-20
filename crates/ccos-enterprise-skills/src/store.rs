use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::{
    io, parse_capture, parse_skill_exposures, ObserveDisposition, ObserveResult, SkillConfig,
    SkillError, SkillRegistry, SkillSnapshot, SkillTrialConfig, SkillTrialStore,
    SKILL_SNAPSHOT_SCHEMA,
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

    /// Canonical root backing this validated store. Audit code uses this
    /// identity to bind loaded registries to their actual tenant-scoped store.
    pub fn canonical_root(&self) -> Result<PathBuf, SkillError> {
        std::fs::canonicalize(&self.root).map_err(io(&self.root))
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
    ///
    /// A successful governed `ccos_skills` result in the adapter-owned
    /// transcript is auxiliary evidence that those Active skills were visible
    /// during this turn. Exposures are therefore inserted against the registry
    /// state *before* the current L1 trial is applied, then resolved after the
    /// skill lifecycle update. This ordering also makes crash retries safe:
    /// #58 guarantees an exact duplicate exposure remains idempotent even if
    /// the current L1 already moved an Active skill to Retired before a retry.
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
        let exposed = parse_skill_exposures(source);
        let mut registry = self.load_registry(config)?;

        let known: Vec<String> = exposed
            .into_iter()
            .filter(|skill_id| registry.get(skill_id).is_some())
            .collect();
        let trials = if known.is_empty() {
            None
        } else {
            let trials = SkillTrialStore::open(&self.root)?;
            for skill_id in &known {
                match trials.expose(
                    SkillTrialConfig::default(),
                    &episode.session_id,
                    episode.turn,
                    &registry,
                    std::slice::from_ref(skill_id),
                ) {
                    Ok(_) => {}
                    // A stale or tampered transcript can claim that a known but
                    // non-Active skill was exposed. Such auxiliary evidence is
                    // ignored; durable trial-store faults still fail closed.
                    Err(SkillError::InvalidTrial(_)) => {}
                    Err(error) => return Err(error),
                }
            }
            Some(trials)
        };

        let result = registry.observe(&episode)?;
        if matches!(
            result.disposition,
            ObserveDisposition::Created | ObserveDisposition::Updated
        ) {
            self.save(registry.snapshot())?;
        }

        if let Some(trials) = trials {
            trials.resolve_episode(SkillTrialConfig::default(), &episode, &registry)?;
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::{
        trial_turn_key, EpisodeObservation, SkillTrialStatus, ToolObservation, ToolOutcome,
    };

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

    fn install_active_recall_skill(store: &SkillStore) -> String {
        let mut registry = SkillRegistry::new(SkillConfig::default()).unwrap();
        for turn in 1..=3 {
            registry
                .observe(&EpisodeObservation {
                    evidence_id: format!("{turn:064x}"),
                    session_id: "skill-source".into(),
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
        store.save(registry.snapshot()).unwrap();
        skill_id
    }

    fn exposed_capture(skill_id: &str) -> String {
        let structured = serde_json::json!({
            "skills": [{
                "id": skill_id,
                "tool_sequence": ["memory.recall"],
                "status": "active",
                "support": 3,
                "trials_attempted": 3,
                "trials_passed": 3,
                "eta": 0.8
            }],
            "returned": 1,
            "total_active": 1,
            "truncated": false
        })
        .to_string();
        let rendered = serde_json::json!([{ "type": "text", "text": structured }]).to_string();
        format!(
            "# DeepSeek Harness turn 9\nsession: trial-session\n\n## User\nuse the skill\n\n## Tools\n- ccos_skills (read-skill)\n  input: {{\"limit\":4}}\n  output: {rendered}\n- memory.recall (use-skill)\n  input: {{}}\n  output: ok\nturn_end_reason: {{\"kind\":\"completed\"}}\n\n## CCOS Episode (evidence-only)\n```json\n{{\"schema\":\"ccos.dsh.episode.v1\",\"evidence_only\":true,\"host\":\"deepseek-harness\",\"session_id\":\"trial-session\",\"turn\":9,\"observed_outcome\":{{\"reason_kind\":\"completed\"}},\"evidence\":{{\"tool_calls\":2,\"tool_failures\":0,\"unresolved_tool_calls\":0}}}}\n```\n"
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
    fn transcript_exposure_creates_and_resolves_private_trial_in_same_projection() {
        let root = temp_dir("trial-projection");
        let store = SkillStore::open(&root).unwrap();
        let skill_id = install_active_recall_skill(&store);
        let source = exposed_capture(&skill_id);
        let observed = store
            .observe_capture(SkillConfig::default(), &source)
            .unwrap();
        assert!(matches!(
            observed.disposition,
            ObserveDisposition::Created | ObserveDisposition::Updated
        ));

        let trials = SkillTrialStore::open(&root).unwrap();
        let snapshot = trials.load().unwrap().unwrap();
        assert_eq!(snapshot.trials.len(), 1);
        let trial = snapshot.trials.values().next().unwrap();
        assert_eq!(trial.skill_id, skill_id);
        assert_eq!(trial.status, SkillTrialStatus::Passed);
        assert_eq!(trial.turn_key, trial_turn_key("trial-session", 9));
        assert!(trial.evidence_id.is_some());
        drop(trials);

        let disk = std::fs::read_to_string(root.join(crate::SKILL_TRIALS_FILE)).unwrap();
        assert!(!disk.contains("trial-session"));
        assert!(!disk.contains("use the skill"));
        assert!(!disk.contains("input"));
        assert!(!disk.contains("output"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn repeated_projection_is_trial_idempotent() {
        let root = temp_dir("trial-replay");
        let store = SkillStore::open(&root).unwrap();
        let skill_id = install_active_recall_skill(&store);
        let source = exposed_capture(&skill_id);
        store
            .observe_capture(SkillConfig::default(), &source)
            .unwrap();
        store
            .observe_capture(SkillConfig::default(), &source)
            .unwrap();
        let trials = SkillTrialStore::open(&root).unwrap();
        let snapshot = trials.load().unwrap().unwrap();
        assert_eq!(snapshot.trials.len(), 1);
        assert_eq!(
            snapshot.trials.values().next().unwrap().status,
            SkillTrialStatus::Passed
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn unknown_exposure_id_never_wedges_memory_projection() {
        let root = temp_dir("unknown-exposure");
        let store = SkillStore::open(&root).unwrap();
        let missing = format!("skill-v1-{}", "a".repeat(64));
        let result = store.observe_capture(SkillConfig::default(), &exposed_capture(&missing));
        assert!(result.is_ok());
        assert!(!root.join(crate::SKILL_TRIALS_FILE).exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn stale_non_active_exposure_never_wedges_memory_projection() {
        let root = temp_dir("stale-exposure");
        let store = SkillStore::open(&root).unwrap();
        let skill_id = install_active_recall_skill(&store);
        let mut registry = store.load_registry(SkillConfig::default()).unwrap();
        for turn in 4..=10 {
            registry
                .observe(&EpisodeObservation {
                    evidence_id: format!("{turn:064x}"),
                    session_id: "retire-before-turn".into(),
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
        store.save(registry.snapshot()).unwrap();
        let result = store.observe_capture(SkillConfig::default(), &exposed_capture(&skill_id));
        assert!(result.is_ok());
        assert!(!root.join(crate::SKILL_TRIALS_FILE).exists());
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
