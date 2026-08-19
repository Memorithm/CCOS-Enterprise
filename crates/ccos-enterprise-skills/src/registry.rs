use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{skill_fingerprint, EpisodeObservation, SkillError};

pub const SKILL_SNAPSHOT_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillStatus {
    Candidate,
    Probationary,
    Active,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkillRecord {
    pub id: String,
    pub fingerprint: String,
    pub tool_sequence: Vec<String>,
    pub status: SkillStatus,
    pub support: u64,
    pub trials_attempted: u64,
    pub trials_passed: u64,
    pub eta: f64,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkillSnapshot {
    pub schema_version: u32,
    pub skills: BTreeMap<String, SkillRecord>,
    /// Bounded FIFO of recently observed evidence IDs.
    ///
    /// In schema v1 this field was a `BTreeSet<String>`. Both representations
    /// serialize to a JSON array, so existing snapshots remain readable while
    /// the runtime can now enforce a finite retention window.
    pub observed_evidence_ids: Vec<String>,
}

impl Default for SkillSnapshot {
    fn default() -> Self {
        Self {
            schema_version: SKILL_SNAPSHOT_SCHEMA,
            skills: BTreeMap::new(),
            observed_evidence_ids: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SkillConfig {
    pub min_support: u64,
    pub candidate_trials: u64,
    pub activation_eta: f64,
    pub retire_eta: f64,
    pub evidence_cap: usize,
    pub dedup_cap: usize,
}

impl Default for SkillConfig {
    fn default() -> Self {
        Self {
            min_support: 2,
            candidate_trials: 3,
            activation_eta: 0.75,
            retire_eta: 0.40,
            evidence_cap: 32,
            dedup_cap: 4096,
        }
    }
}

impl SkillConfig {
    pub fn validate(&self) -> Result<(), SkillError> {
        if self.min_support == 0 {
            return Err(SkillError::InvalidConfig(
                "min_support must be greater than zero".into(),
            ));
        }
        if self.candidate_trials == 0 {
            return Err(SkillError::InvalidConfig(
                "candidate_trials must be greater than zero".into(),
            ));
        }
        if !(0.0..=1.0).contains(&self.activation_eta) || !self.activation_eta.is_finite() {
            return Err(SkillError::InvalidConfig(
                "activation_eta must be finite and within [0, 1]".into(),
            ));
        }
        if !(0.0..=1.0).contains(&self.retire_eta) || !self.retire_eta.is_finite() {
            return Err(SkillError::InvalidConfig(
                "retire_eta must be finite and within [0, 1]".into(),
            ));
        }
        if self.retire_eta >= self.activation_eta {
            return Err(SkillError::InvalidConfig(
                "retire_eta must be lower than activation_eta".into(),
            ));
        }
        if self.evidence_cap == 0 {
            return Err(SkillError::InvalidConfig(
                "evidence_cap must be greater than zero".into(),
            ));
        }
        if self.dedup_cap == 0 {
            return Err(SkillError::InvalidConfig(
                "dedup_cap must be greater than zero".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserveDisposition {
    Ignored,
    Duplicate,
    Created,
    Updated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObserveResult {
    pub disposition: ObserveDisposition,
    pub skill_id: Option<String>,
    pub status: Option<SkillStatus>,
}

impl ObserveResult {
    fn ignored(disposition: ObserveDisposition) -> Self {
        Self {
            disposition,
            skill_id: None,
            status: None,
        }
    }
}

pub struct SkillRegistry {
    config: SkillConfig,
    snapshot: SkillSnapshot,
}

impl SkillRegistry {
    pub fn new(config: SkillConfig) -> Result<Self, SkillError> {
        config.validate()?;
        Ok(Self {
            config,
            snapshot: SkillSnapshot::default(),
        })
    }

    pub fn from_snapshot(
        config: SkillConfig,
        mut snapshot: SkillSnapshot,
    ) -> Result<Self, SkillError> {
        config.validate()?;
        if snapshot.schema_version != SKILL_SNAPSHOT_SCHEMA {
            return Err(SkillError::UnsupportedSchema {
                found: snapshot.schema_version,
            });
        }
        validate_snapshot(&snapshot)?;

        // Configuration caps are runtime policy. When an operator lowers a
        // cap, restored state must converge immediately rather than waiting for
        // a future append that may never happen.
        for record in snapshot.skills.values_mut() {
            trim_to_cap(&mut record.evidence_ids, config.evidence_cap);
        }
        trim_to_cap(&mut snapshot.observed_evidence_ids, config.dedup_cap);

        Ok(Self { config, snapshot })
    }

    pub fn snapshot(&self) -> &SkillSnapshot {
        &self.snapshot
    }

    pub fn into_snapshot(self) -> SkillSnapshot {
        self.snapshot
    }

    pub fn get(&self, skill_id: &str) -> Option<&SkillRecord> {
        self.snapshot.skills.get(skill_id)
    }

    pub fn active(&self) -> impl Iterator<Item = &SkillRecord> {
        self.snapshot
            .skills
            .values()
            .filter(|record| record.status == SkillStatus::Active)
    }

    pub fn observe(&mut self, episode: &EpisodeObservation) -> Result<ObserveResult, SkillError> {
        if episode.tools.is_empty() {
            return Ok(ObserveResult::ignored(ObserveDisposition::Ignored));
        }

        let positive = episode.is_positive_anchor();
        let negative = episode.is_negative_trial();
        if !positive && !negative {
            return Ok(ObserveResult::ignored(ObserveDisposition::Ignored));
        }

        if self
            .snapshot
            .observed_evidence_ids
            .iter()
            .any(|id| id == &episode.evidence_id)
        {
            return Ok(ObserveResult::ignored(ObserveDisposition::Duplicate));
        }

        let fingerprint = skill_fingerprint(&episode.tools);
        let skill_id = format!("skill-v1-{fingerprint}");
        let was_present = self.snapshot.skills.contains_key(&skill_id);
        let tool_sequence: Vec<String> =
            episode.tools.iter().map(|tool| tool.name.clone()).collect();

        let record = self
            .snapshot
            .skills
            .entry(skill_id.clone())
            .or_insert_with(|| SkillRecord {
                id: skill_id.clone(),
                fingerprint: fingerprint.clone(),
                tool_sequence: tool_sequence.clone(),
                status: SkillStatus::Candidate,
                support: 0,
                trials_attempted: 0,
                trials_passed: 0,
                eta: 0.5,
                evidence_ids: Vec::new(),
            });

        if record.fingerprint != fingerprint || record.tool_sequence != tool_sequence {
            return Err(SkillError::InvalidCapture(
                "skill fingerprint collision or inconsistent tool sequence".into(),
            ));
        }

        record.trials_attempted = record.trials_attempted.saturating_add(1);
        if positive {
            record.support = record.support.saturating_add(1);
            record.trials_passed = record.trials_passed.saturating_add(1);
        }
        record.eta = posterior_eta(record.trials_passed, record.trials_attempted);
        push_bounded_evidence(
            &mut record.evidence_ids,
            &episode.evidence_id,
            self.config.evidence_cap,
        );
        advance_status(record, &self.config);

        push_bounded_evidence(
            &mut self.snapshot.observed_evidence_ids,
            &episode.evidence_id,
            self.config.dedup_cap,
        );

        Ok(ObserveResult {
            disposition: if was_present {
                ObserveDisposition::Updated
            } else {
                ObserveDisposition::Created
            },
            skill_id: Some(skill_id),
            status: Some(record.status),
        })
    }
}

fn posterior_eta(passed: u64, attempts: u64) -> f64 {
    (passed as f64 + 1.0) / (attempts as f64 + 2.0)
}

fn advance_status(record: &mut SkillRecord, config: &SkillConfig) {
    if record.status == SkillStatus::Retired {
        return;
    }

    if record.status == SkillStatus::Candidate && record.support >= config.min_support {
        record.status = SkillStatus::Probationary;
    }

    if record.trials_attempted >= config.candidate_trials {
        if record.eta < config.retire_eta {
            record.status = SkillStatus::Retired;
        } else if record.status == SkillStatus::Probationary && record.eta >= config.activation_eta
        {
            record.status = SkillStatus::Active;
        }
    }

    if record.status == SkillStatus::Active && record.eta < config.retire_eta {
        record.status = SkillStatus::Retired;
    }
}

fn push_bounded_evidence(ids: &mut Vec<String>, id: &str, cap: usize) {
    while ids.len() >= cap {
        ids.remove(0);
    }
    ids.push(id.to_string());
}

fn trim_to_cap(ids: &mut Vec<String>, cap: usize) {
    if ids.len() > cap {
        ids.drain(..ids.len() - cap);
    }
}

fn validate_snapshot(snapshot: &SkillSnapshot) -> Result<(), SkillError> {
    let mut observed = BTreeSet::new();
    for evidence_id in &snapshot.observed_evidence_ids {
        if !observed.insert(evidence_id) {
            return Err(SkillError::InvalidCapture(
                "global evidence deduplication index contains duplicates".into(),
            ));
        }
    }

    for (key, record) in &snapshot.skills {
        if key != &record.id {
            return Err(SkillError::InvalidCapture(
                "skill map key does not match record id".into(),
            ));
        }
        if record.fingerprint.len() != 64
            || !record
                .fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(SkillError::InvalidCapture(
                "skill fingerprint is not lowercase sha256".into(),
            ));
        }
        if record.tool_sequence.is_empty() {
            return Err(SkillError::InvalidCapture(
                "persisted skill has no tool sequence".into(),
            ));
        }
        if record.trials_passed > record.trials_attempted || record.support > record.trials_passed {
            return Err(SkillError::InvalidCapture(
                "persisted skill counters are inconsistent".into(),
            ));
        }
        let eta = posterior_eta(record.trials_passed, record.trials_attempted);
        if (record.eta - eta).abs() > f64::EPSILON {
            return Err(SkillError::InvalidCapture(
                "persisted skill eta does not match counters".into(),
            ));
        }
        let mut record_evidence = BTreeSet::new();
        for evidence_id in &record.evidence_ids {
            if !record_evidence.insert(evidence_id) {
                return Err(SkillError::InvalidCapture(
                    "skill evidence list contains duplicates".into(),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{EpisodeObservation, ToolObservation, ToolOutcome};

    use super::*;

    fn episode(id: &str, outcomes: &[ToolOutcome], reason: &str) -> EpisodeObservation {
        EpisodeObservation {
            evidence_id: id.into(),
            session_id: "s".into(),
            turn: 1,
            reason_kind: reason.into(),
            tools: outcomes
                .iter()
                .enumerate()
                .map(|(index, outcome)| ToolObservation {
                    name: format!("tool.{index}"),
                    call_id: format!("call-{index}"),
                    outcome: *outcome,
                })
                .collect(),
        }
    }

    #[test]
    fn promotes_only_after_support_trials_and_eta_threshold() {
        let mut registry = SkillRegistry::new(SkillConfig::default()).unwrap();
        let one = episode(
            "e1",
            &[ToolOutcome::Succeeded, ToolOutcome::Succeeded],
            "completed",
        );
        let two = episode(
            "e2",
            &[ToolOutcome::Succeeded, ToolOutcome::Succeeded],
            "completed",
        );
        let three = episode(
            "e3",
            &[ToolOutcome::Succeeded, ToolOutcome::Succeeded],
            "completed",
        );
        assert_eq!(
            registry.observe(&one).unwrap().status,
            Some(SkillStatus::Candidate)
        );
        assert_eq!(
            registry.observe(&two).unwrap().status,
            Some(SkillStatus::Probationary)
        );
        assert_eq!(
            registry.observe(&three).unwrap().status,
            Some(SkillStatus::Active)
        );
        let skill = registry.snapshot().skills.values().next().unwrap();
        assert_eq!(skill.support, 3);
        assert_eq!(skill.trials_attempted, 3);
        assert_eq!(skill.trials_passed, 3);
        assert_eq!(skill.eta, 0.8);
    }

    #[test]
    fn duplicate_evidence_is_idempotent_inside_bounded_window() {
        let mut registry = SkillRegistry::new(SkillConfig::default()).unwrap();
        let observation = episode("same", &[ToolOutcome::Succeeded], "completed");
        assert_eq!(
            registry.observe(&observation).unwrap().disposition,
            ObserveDisposition::Created
        );
        let before = registry.snapshot().clone();
        assert_eq!(
            registry.observe(&observation).unwrap().disposition,
            ObserveDisposition::Duplicate
        );
        assert_eq!(registry.snapshot(), &before);
    }

    #[test]
    fn repeated_negative_trials_retire_candidate() {
        let config = SkillConfig {
            min_support: 2,
            candidate_trials: 4,
            activation_eta: 0.75,
            retire_eta: 0.55,
            evidence_cap: 8,
            dedup_cap: 32,
        };
        let mut registry = SkillRegistry::new(config).unwrap();
        for id in ["p1", "p2"] {
            registry
                .observe(&episode(id, &[ToolOutcome::Succeeded], "completed"))
                .unwrap();
        }
        for id in ["n1", "n2"] {
            registry
                .observe(&episode(id, &[ToolOutcome::Failed], "error"))
                .unwrap();
        }
        let skill = registry.snapshot().skills.values().next().unwrap();
        assert_eq!(skill.trials_passed, 2);
        assert_eq!(skill.trials_attempted, 4);
        assert_eq!(skill.eta, 0.5);
        assert_eq!(skill.status, SkillStatus::Retired);
    }

    #[test]
    fn failed_unresolved_call_counts_as_one_negative_trial() {
        let mut registry = SkillRegistry::new(SkillConfig::default()).unwrap();
        let out = registry
            .observe(&episode("fu", &[ToolOutcome::FailedUnresolved], "error"))
            .unwrap();
        assert_eq!(out.disposition, ObserveDisposition::Created);
        let skill = registry.snapshot().skills.values().next().unwrap();
        assert_eq!(skill.support, 0);
        assert_eq!(skill.trials_attempted, 1);
        assert_eq!(skill.trials_passed, 0);
        assert_eq!(skill.eta, 1.0 / 3.0);
    }

    #[test]
    fn unresolved_call_counts_as_negative_trial() {
        let mut registry = SkillRegistry::new(SkillConfig::default()).unwrap();
        let out = registry
            .observe(&episode("u", &[ToolOutcome::Unresolved], "completed"))
            .unwrap();
        assert_eq!(out.disposition, ObserveDisposition::Created);
        let skill = registry.snapshot().skills.values().next().unwrap();
        assert_eq!(skill.support, 0);
        assert_eq!(skill.trials_attempted, 1);
        assert_eq!(skill.trials_passed, 0);
        assert_eq!(skill.eta, 1.0 / 3.0);
    }

    #[test]
    fn global_deduplication_window_is_bounded() {
        let config = SkillConfig {
            evidence_cap: 2,
            dedup_cap: 3,
            ..SkillConfig::default()
        };
        let mut registry = SkillRegistry::new(config).unwrap();
        for id in ["e1", "e2", "e3", "e4", "e5"] {
            registry
                .observe(&episode(id, &[ToolOutcome::Succeeded], "completed"))
                .unwrap();
        }
        assert_eq!(
            registry.snapshot().observed_evidence_ids,
            vec!["e3".to_string(), "e4".to_string(), "e5".to_string()]
        );
        let skill = registry.snapshot().skills.values().next().unwrap();
        assert_eq!(skill.evidence_ids, vec!["e4".to_string(), "e5".to_string()]);
    }

    #[test]
    fn restored_snapshot_is_trimmed_when_caps_decrease() {
        let mut registry = SkillRegistry::new(SkillConfig {
            evidence_cap: 8,
            dedup_cap: 8,
            ..SkillConfig::default()
        })
        .unwrap();
        for id in ["e1", "e2", "e3", "e4", "e5"] {
            registry
                .observe(&episode(id, &[ToolOutcome::Succeeded], "completed"))
                .unwrap();
        }
        let snapshot = registry.into_snapshot();
        let restored = SkillRegistry::from_snapshot(
            SkillConfig {
                evidence_cap: 2,
                dedup_cap: 3,
                ..SkillConfig::default()
            },
            snapshot,
        )
        .unwrap();
        assert_eq!(
            restored.snapshot().observed_evidence_ids,
            vec!["e3".to_string(), "e4".to_string(), "e5".to_string()]
        );
        let skill = restored.snapshot().skills.values().next().unwrap();
        assert_eq!(skill.evidence_ids, vec!["e4".to_string(), "e5".to_string()]);
    }

    #[test]
    fn neutral_non_tool_turn_is_ignored() {
        let mut registry = SkillRegistry::new(SkillConfig::default()).unwrap();
        let neutral = episode("neutral", &[], "aborted");
        assert_eq!(
            registry.observe(&neutral).unwrap().disposition,
            ObserveDisposition::Ignored
        );
        assert!(registry.snapshot().skills.is_empty());
        assert!(registry.snapshot().observed_evidence_ids.is_empty());
    }
}
