use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{EpisodeObservation, SkillError, SkillRegistry, SkillStatus};

pub const SKILL_TRIAL_SNAPSHOT_SCHEMA: u32 = 1;
const MAX_SESSION_ID_BYTES: usize = 256;
const MAX_SKILL_ID_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillTrialStatus {
    Pending,
    Passed,
    Failed,
    Inconclusive,
    NotObserved,
}

impl SkillTrialStatus {
    pub fn is_terminal(self) -> bool {
        self != Self::Pending
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillTrialRecord {
    pub id: String,
    pub skill_id: String,
    pub turn_key: String,
    pub status: SkillTrialStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_id: Option<String>,
    pub ordinal: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillTrialSnapshot {
    pub schema_version: u32,
    pub next_ordinal: u64,
    pub trials: BTreeMap<String, SkillTrialRecord>,
}

impl Default for SkillTrialSnapshot {
    fn default() -> Self {
        Self {
            schema_version: SKILL_TRIAL_SNAPSHOT_SCHEMA,
            next_ordinal: 0,
            trials: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillTrialConfig {
    pub trial_cap: usize,
    pub exposure_cap: usize,
}

impl Default for SkillTrialConfig {
    fn default() -> Self {
        Self {
            trial_cap: 4096,
            exposure_cap: 128,
        }
    }
}

impl SkillTrialConfig {
    pub fn validate(&self) -> Result<(), SkillError> {
        if self.trial_cap == 0 {
            return Err(SkillError::InvalidTrial(
                "trial_cap must be greater than zero".into(),
            ));
        }
        if self.exposure_cap == 0 {
            return Err(SkillError::InvalidTrial(
                "exposure_cap must be greater than zero".into(),
            ));
        }
        if self.exposure_cap > self.trial_cap {
            return Err(SkillError::InvalidTrial(
                "exposure_cap must not exceed trial_cap".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposureResult {
    pub turn_key: String,
    pub created: usize,
    pub duplicates: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrialResolution {
    pub turn_key: String,
    pub passed: usize,
    pub failed: usize,
    pub inconclusive: usize,
    pub not_observed: usize,
    pub already_resolved: usize,
}

pub struct SkillTrialRegistry {
    config: SkillTrialConfig,
    snapshot: SkillTrialSnapshot,
}

impl SkillTrialRegistry {
    pub fn new(config: SkillTrialConfig) -> Result<Self, SkillError> {
        config.validate()?;
        Ok(Self {
            config,
            snapshot: SkillTrialSnapshot::default(),
        })
    }

    pub fn from_snapshot(
        config: SkillTrialConfig,
        mut snapshot: SkillTrialSnapshot,
    ) -> Result<Self, SkillError> {
        config.validate()?;
        if snapshot.schema_version != SKILL_TRIAL_SNAPSHOT_SCHEMA {
            return Err(SkillError::UnsupportedTrialSchema {
                found: snapshot.schema_version,
            });
        }
        validate_snapshot(&snapshot)?;
        trim_to_cap(&mut snapshot, config.trial_cap)?;
        Ok(Self { config, snapshot })
    }

    pub fn snapshot(&self) -> &SkillTrialSnapshot {
        &self.snapshot
    }

    pub fn expose(
        &mut self,
        session_id: &str,
        turn: u64,
        skills: &SkillRegistry,
        skill_ids: &[String],
    ) -> Result<ExposureResult, SkillError> {
        validate_bounded("session_id", session_id, MAX_SESSION_ID_BYTES)?;
        let unique: BTreeSet<&str> = skill_ids.iter().map(String::as_str).collect();
        if unique.len() > self.config.exposure_cap {
            return Err(SkillError::InvalidTrial(format!(
                "one turn exposed {} skills, above cap {}",
                unique.len(),
                self.config.exposure_cap
            )));
        }

        let turn_key = trial_turn_key(session_id, turn);
        let mut new_count = 0usize;
        for skill_id in &unique {
            validate_bounded("skill_id", skill_id, MAX_SKILL_ID_BYTES)?;
            let id = trial_id(&turn_key, skill_id);
            if self.snapshot.trials.contains_key(&id) {
                continue;
            }
            let skill = skills.get(skill_id).ok_or_else(|| {
                SkillError::InvalidTrial(format!("exposure references missing skill {skill_id:?}"))
            })?;
            if skill.status != SkillStatus::Active {
                return Err(SkillError::InvalidTrial(format!(
                    "exposure references non-active skill {skill_id:?}"
                )));
            }
            new_count = new_count.saturating_add(1);
        }
        let pending = self
            .snapshot
            .trials
            .values()
            .filter(|trial| trial.status == SkillTrialStatus::Pending)
            .count();
        if pending.saturating_add(new_count) > self.config.trial_cap {
            return Err(SkillError::InvalidTrial(
                "trial cap is exhausted by unresolved exposures".into(),
            ));
        }
        let mut created = 0usize;
        let mut duplicates = 0usize;
        for skill_id in unique {
            let id = trial_id(&turn_key, skill_id);
            if self.snapshot.trials.contains_key(&id) {
                duplicates = duplicates.saturating_add(1);
                continue;
            }
            let ordinal = self.snapshot.next_ordinal;
            self.snapshot.next_ordinal = self
                .snapshot
                .next_ordinal
                .checked_add(1)
                .ok_or_else(|| SkillError::InvalidTrial("trial ordinal overflow".into()))?;
            self.snapshot.trials.insert(
                id.clone(),
                SkillTrialRecord {
                    id,
                    skill_id: skill_id.to_string(),
                    turn_key: turn_key.clone(),
                    status: SkillTrialStatus::Pending,
                    evidence_id: None,
                    ordinal,
                },
            );
            created = created.saturating_add(1);
        }
        trim_to_cap(&mut self.snapshot, self.config.trial_cap)?;
        Ok(ExposureResult {
            turn_key,
            created,
            duplicates,
        })
    }

    pub fn resolve_episode(
        &mut self,
        episode: &EpisodeObservation,
        skills: &SkillRegistry,
    ) -> Result<TrialResolution, SkillError> {
        let turn_key = trial_turn_key(&episode.session_id, episode.turn);
        let observed_tools: Vec<&str> = episode
            .tools
            .iter()
            .map(|tool| tool.name.as_str())
            .collect();
        let positive = episode.is_positive_anchor();
        let negative = episode.is_negative_trial();
        let mut result = TrialResolution {
            turn_key: turn_key.clone(),
            passed: 0,
            failed: 0,
            inconclusive: 0,
            not_observed: 0,
            already_resolved: 0,
        };

        let ids: Vec<String> = self
            .snapshot
            .trials
            .values()
            .filter(|trial| trial.turn_key == turn_key)
            .map(|trial| trial.id.clone())
            .collect();

        for id in ids {
            let trial = self
                .snapshot
                .trials
                .get_mut(&id)
                .expect("trial id came from the same snapshot");
            if trial.status.is_terminal() {
                result.already_resolved = result.already_resolved.saturating_add(1);
                continue;
            }
            let skill = skills.get(&trial.skill_id).ok_or_else(|| {
                SkillError::InvalidTrial(format!(
                    "pending trial references missing skill {:?}",
                    trial.skill_id
                ))
            })?;
            let sequence: Vec<&str> = skill.tool_sequence.iter().map(String::as_str).collect();
            let observed = contains_contiguous_sequence(&observed_tools, &sequence);
            trial.status = if !observed {
                result.not_observed = result.not_observed.saturating_add(1);
                SkillTrialStatus::NotObserved
            } else if positive {
                result.passed = result.passed.saturating_add(1);
                SkillTrialStatus::Passed
            } else if negative {
                result.failed = result.failed.saturating_add(1);
                SkillTrialStatus::Failed
            } else {
                result.inconclusive = result.inconclusive.saturating_add(1);
                SkillTrialStatus::Inconclusive
            };
            trial.evidence_id = Some(episode.evidence_id.clone());
        }
        Ok(result)
    }
}

pub fn trial_turn_key(session_id: &str, turn: u64) -> String {
    domain_hash(&[
        b"ccos-enterprise-skill-trial-turn-v1",
        session_id.as_bytes(),
        turn.to_string().as_bytes(),
    ])
}

fn trial_id(turn_key: &str, skill_id: &str) -> String {
    format!(
        "trial-v1-{}",
        domain_hash(&[
            b"ccos-enterprise-skill-trial-id-v1",
            turn_key.as_bytes(),
            skill_id.as_bytes(),
        ])
    )
}

fn domain_hash(parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn contains_contiguous_sequence(observed: &[&str], expected: &[&str]) -> bool {
    !expected.is_empty()
        && expected.len() <= observed.len()
        && observed
            .windows(expected.len())
            .any(|window| window == expected)
}

fn validate_bounded(kind: &str, value: &str, max: usize) -> Result<(), SkillError> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(SkillError::InvalidTrial(format!(
            "{kind} must be non-empty, at most {max} bytes, and control-character-free"
        )));
    }
    Ok(())
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn validate_snapshot(snapshot: &SkillTrialSnapshot) -> Result<(), SkillError> {
    let mut ordinals = BTreeSet::new();
    let mut max_ordinal = None;
    for (id, trial) in &snapshot.trials {
        if id != &trial.id || !id.starts_with("trial-v1-") || !is_lower_hex_64(&id[9..]) {
            return Err(SkillError::InvalidTrial(
                "invalid persisted trial id".into(),
            ));
        }
        validate_bounded("skill_id", &trial.skill_id, MAX_SKILL_ID_BYTES)?;
        if !is_lower_hex_64(&trial.turn_key) {
            return Err(SkillError::InvalidTrial(
                "persisted turn_key is not a lowercase SHA-256".into(),
            ));
        }
        if trial.id != trial_id(&trial.turn_key, &trial.skill_id) {
            return Err(SkillError::InvalidTrial(
                "persisted trial id does not match turn_key and skill_id".into(),
            ));
        }
        if !ordinals.insert(trial.ordinal) {
            return Err(SkillError::InvalidTrial(
                "persisted trial ordinals are not unique".into(),
            ));
        }
        max_ordinal =
            Some(max_ordinal.map_or(trial.ordinal, |value: u64| value.max(trial.ordinal)));
        match (trial.status, trial.evidence_id.as_deref()) {
            (SkillTrialStatus::Pending, None) => {}
            (SkillTrialStatus::Pending, Some(_)) => {
                return Err(SkillError::InvalidTrial(
                    "pending trial unexpectedly has evidence".into(),
                ));
            }
            (_, Some(evidence_id)) if is_lower_hex_64(evidence_id) => {}
            (_, Some(_)) => {
                return Err(SkillError::InvalidTrial(
                    "terminal trial evidence_id is not a lowercase SHA-256".into(),
                ));
            }
            (_, None) => {
                return Err(SkillError::InvalidTrial(
                    "terminal trial is missing evidence_id".into(),
                ));
            }
        }
    }
    if let Some(max_ordinal) = max_ordinal {
        if snapshot.next_ordinal <= max_ordinal {
            return Err(SkillError::InvalidTrial(
                "next_ordinal does not follow persisted trials".into(),
            ));
        }
    }
    Ok(())
}

fn trim_to_cap(snapshot: &mut SkillTrialSnapshot, cap: usize) -> Result<(), SkillError> {
    while snapshot.trials.len() > cap {
        let Some(id) = snapshot
            .trials
            .values()
            .filter(|trial| trial.status.is_terminal())
            .min_by_key(|trial| trial.ordinal)
            .map(|trial| trial.id.clone())
        else {
            return Err(SkillError::InvalidTrial(
                "trial cap is smaller than the number of unresolved exposures".into(),
            ));
        };
        snapshot.trials.remove(&id);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SkillConfig, ToolObservation, ToolOutcome};

    fn episode(
        session: &str,
        turn: u64,
        names: &[(&str, ToolOutcome)],
        reason: &str,
        evidence_byte: char,
    ) -> EpisodeObservation {
        EpisodeObservation {
            evidence_id: evidence_byte.to_string().repeat(64),
            session_id: session.into(),
            turn,
            reason_kind: reason.into(),
            tools: names
                .iter()
                .enumerate()
                .map(|(index, (name, outcome))| ToolObservation {
                    name: (*name).into(),
                    call_id: format!("call-{index}"),
                    outcome: *outcome,
                })
                .collect(),
        }
    }

    fn active_skill_registry(names: &[&str]) -> (SkillRegistry, String) {
        let mut registry = SkillRegistry::new(SkillConfig::default()).unwrap();
        for (turn, evidence_byte) in [(1, '1'), (2, '2'), (3, '3')] {
            let observation = episode(
                "skill-source",
                turn,
                &names
                    .iter()
                    .map(|name| (*name, ToolOutcome::Succeeded))
                    .collect::<Vec<_>>(),
                "completed",
                evidence_byte,
            );
            registry.observe(&observation).unwrap();
        }
        let skill_id = registry
            .active()
            .next()
            .expect("three positive trials activate skill")
            .id
            .clone();
        (registry, skill_id)
    }

    #[test]
    fn exposure_is_idempotent_and_hashes_session_turn() {
        let (skills, skill_id) = active_skill_registry(&["memory.recall"]);
        let mut trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        let ids = vec![skill_id.clone(), skill_id];
        let first = trials
            .expose("raw-session-secret", 7, &skills, &ids)
            .unwrap();
        assert_eq!(first.created, 1);
        let second = trials
            .expose("raw-session-secret", 7, &skills, &ids)
            .unwrap();
        assert_eq!(second.created, 0);
        assert_eq!(second.duplicates, 1);
        let disk = serde_json::to_string(trials.snapshot()).unwrap();
        assert!(!disk.contains("raw-session-secret"));
        assert!(!disk.contains("\"turn\":7"));
    }

    #[test]
    fn duplicate_exposure_remains_idempotent_after_skill_retires() {
        let (mut skills, skill_id) = active_skill_registry(&["memory.recall"]);
        let mut trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        trials
            .expose(
                "session-retired",
                7,
                &skills,
                std::slice::from_ref(&skill_id),
            )
            .unwrap();

        for (turn, evidence_byte) in [(4, '4'), (5, '5'), (6, '6'), (7, '7'), (8, '8'), (9, '9')] {
            skills
                .observe(&episode(
                    "skill-source",
                    turn,
                    &[("memory.recall", ToolOutcome::Failed)],
                    "error",
                    evidence_byte,
                ))
                .unwrap();
        }
        assert_eq!(skills.get(&skill_id).unwrap().status, SkillStatus::Retired);

        let replay = trials
            .expose(
                "session-retired",
                7,
                &skills,
                std::slice::from_ref(&skill_id),
            )
            .unwrap();
        assert_eq!(replay.created, 0);
        assert_eq!(replay.duplicates, 1);
        assert_eq!(trials.snapshot().trials.len(), 1);
    }

    #[test]
    fn exposure_refuses_missing_or_non_active_skills() {
        let (skills, _) = active_skill_registry(&["memory.recall"]);
        let mut trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        assert!(trials
            .expose("session", 1, &skills, &["skill-v1-missing".into()])
            .is_err());

        let mut candidate_skills = SkillRegistry::new(SkillConfig::default()).unwrap();
        let candidate = episode(
            "candidate-source",
            1,
            &[("memory.verify", ToolOutcome::Succeeded)],
            "completed",
            '4',
        );
        let observed = candidate_skills.observe(&candidate).unwrap();
        let candidate_id = observed.skill_id.unwrap();
        assert!(trials
            .expose("session", 2, &candidate_skills, &[candidate_id])
            .is_err());
    }

    #[test]
    fn contiguous_observed_sequence_resolves_pass() {
        let (skills, skill_id) = active_skill_registry(&["memory.recall", "memory.verify"]);
        let mut trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        trials.expose("session-1", 9, &skills, &[skill_id]).unwrap();
        let out = trials
            .resolve_episode(
                &episode(
                    "session-1",
                    9,
                    &[
                        ("memory.stats", ToolOutcome::Succeeded),
                        ("memory.recall", ToolOutcome::Succeeded),
                        ("memory.verify", ToolOutcome::Succeeded),
                    ],
                    "completed",
                    'a',
                ),
                &skills,
            )
            .unwrap();
        assert_eq!(out.passed, 1);
        assert_eq!(out.failed, 0);
        assert_eq!(out.not_observed, 0);
        let record = trials.snapshot().trials.values().next().unwrap();
        assert_eq!(record.status, SkillTrialStatus::Passed);
    }

    #[test]
    fn observed_failure_and_non_observation_are_distinct() {
        let (skills, skill_id) = active_skill_registry(&["memory.recall"]);
        let mut failed = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        failed
            .expose("session-2", 1, &skills, std::slice::from_ref(&skill_id))
            .unwrap();
        let out = failed
            .resolve_episode(
                &episode(
                    "session-2",
                    1,
                    &[("memory.recall", ToolOutcome::Failed)],
                    "error",
                    'b',
                ),
                &skills,
            )
            .unwrap();
        assert_eq!(out.failed, 1);

        let mut absent = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        absent
            .expose("session-3", 1, &skills, std::slice::from_ref(&skill_id))
            .unwrap();
        let out = absent
            .resolve_episode(
                &episode(
                    "session-3",
                    1,
                    &[("memory.timeline", ToolOutcome::Succeeded)],
                    "completed",
                    'c',
                ),
                &skills,
            )
            .unwrap();
        assert_eq!(out.not_observed, 1);
        assert_eq!(out.passed, 0);
        assert_eq!(out.failed, 0);
    }

    #[test]
    fn repeated_resolution_is_idempotent() {
        let (skills, skill_id) = active_skill_registry(&["memory.recall"]);
        let ep = episode(
            "session-4",
            3,
            &[("memory.recall", ToolOutcome::Succeeded)],
            "completed",
            'd',
        );
        let mut trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        trials.expose("session-4", 3, &skills, &[skill_id]).unwrap();
        assert_eq!(trials.resolve_episode(&ep, &skills).unwrap().passed, 1);
        let again = trials.resolve_episode(&ep, &skills).unwrap();
        assert_eq!(again.passed, 0);
        assert_eq!(again.already_resolved, 1);
    }

    #[test]
    fn snapshot_refuses_trial_id_field_mismatch() {
        let turn_key = trial_turn_key("session-tamper", 1);
        let original_skill = "skill-v1-original";
        let id = trial_id(&turn_key, original_skill);
        let mut snapshot = SkillTrialSnapshot::default();
        snapshot.next_ordinal = 1;
        snapshot.trials.insert(
            id.clone(),
            SkillTrialRecord {
                id,
                skill_id: "skill-v1-tampered".into(),
                turn_key,
                status: SkillTrialStatus::Pending,
                evidence_id: None,
                ordinal: 0,
            },
        );
        assert!(matches!(
            SkillTrialRegistry::from_snapshot(SkillTrialConfig::default(), snapshot),
            Err(SkillError::InvalidTrial(_))
        ));
    }

    #[test]
    fn cap_evicts_terminal_trials_but_never_pending_trials() {
        let (skills, skill_id) = active_skill_registry(&["memory.recall"]);
        let config = SkillTrialConfig {
            trial_cap: 2,
            exposure_cap: 1,
        };
        let mut registry = SkillTrialRegistry::new(config.clone()).unwrap();
        registry
            .expose("session-cap", 0, &skills, std::slice::from_ref(&skill_id))
            .unwrap();
        registry
            .resolve_episode(
                &episode(
                    "session-cap",
                    0,
                    &[("memory.recall", ToolOutcome::Succeeded)],
                    "completed",
                    'e',
                ),
                &skills,
            )
            .unwrap();
        registry
            .expose("session-cap", 1, &skills, std::slice::from_ref(&skill_id))
            .unwrap();
        registry
            .expose("session-cap", 2, &skills, std::slice::from_ref(&skill_id))
            .unwrap();
        assert_eq!(registry.snapshot().trials.len(), 2);
        assert!(registry
            .expose("session-cap", 3, &skills, std::slice::from_ref(&skill_id))
            .is_err());
        assert_eq!(registry.snapshot().trials.len(), 2);
    }
}
