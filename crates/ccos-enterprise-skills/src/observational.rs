use std::collections::BTreeMap;

use crate::{SkillTrialRegistry, SkillTrialStatus};

/// Read-only aggregate of the post-exposure observational trial ledger for one skill.
///
/// These counters are deliberately separate from the crystallization lifecycle's
/// `trials_attempted`, `trials_passed`, and `eta`. They describe only trials created
/// after a governed skill exposure. No score, causal attribution, lifecycle decision,
/// correlation key, trial id, or evidence id is derived or exposed here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SkillObservationalSummary {
    pub total: u64,
    pub pending: u64,
    pub passed: u64,
    pub failed: u64,
    pub inconclusive: u64,
    pub not_observed: u64,
}

/// Aggregate every validated observational trial by skill id.
///
/// `SkillTrialRegistry` is accepted rather than a raw snapshot so callers cannot
/// accidentally summarize unvalidated persisted state. Skills with no observational
/// trials are absent from the returned map and can be interpreted as the default
/// all-zero summary by a read projection.
pub fn summarize_observational_trials(
    registry: &SkillTrialRegistry,
) -> BTreeMap<String, SkillObservationalSummary> {
    let mut summaries = BTreeMap::new();
    for trial in registry.snapshot().trials.values() {
        let summary = summaries
            .entry(trial.skill_id.clone())
            .or_insert_with(SkillObservationalSummary::default);
        summary.total = summary.total.saturating_add(1);
        match trial.status {
            SkillTrialStatus::Pending => summary.pending = summary.pending.saturating_add(1),
            SkillTrialStatus::Passed => summary.passed = summary.passed.saturating_add(1),
            SkillTrialStatus::Failed => summary.failed = summary.failed.saturating_add(1),
            SkillTrialStatus::Inconclusive => {
                summary.inconclusive = summary.inconclusive.saturating_add(1)
            }
            SkillTrialStatus::NotObserved => {
                summary.not_observed = summary.not_observed.saturating_add(1)
            }
        }
    }
    summaries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        EpisodeObservation, SkillConfig, SkillRegistry, SkillTrialConfig, ToolObservation,
        ToolOutcome,
    };

    fn episode(
        session_id: &str,
        turn: u64,
        tool: &str,
        outcome: ToolOutcome,
        reason_kind: &str,
        evidence_byte: char,
    ) -> EpisodeObservation {
        EpisodeObservation {
            evidence_id: evidence_byte.to_string().repeat(64),
            session_id: session_id.into(),
            turn,
            reason_kind: reason_kind.into(),
            tools: vec![ToolObservation {
                name: tool.into(),
                call_id: format!("call-{turn}"),
                outcome,
            }],
        }
    }

    fn active_recall_skill() -> (SkillRegistry, String) {
        let mut skills = SkillRegistry::new(SkillConfig::default()).unwrap();
        for (turn, evidence_byte) in [(1, '1'), (2, '2'), (3, '3')] {
            skills
                .observe(&episode(
                    "skill-source",
                    turn,
                    "memory.recall",
                    ToolOutcome::Succeeded,
                    "completed",
                    evidence_byte,
                ))
                .unwrap();
        }
        let skill_id = skills.active().next().unwrap().id.clone();
        (skills, skill_id)
    }

    #[test]
    fn summarizes_each_terminal_class_and_pending_without_scoring() {
        let (skills, skill_id) = active_recall_skill();
        let mut trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        let ids = vec![skill_id.clone()];

        for turn in 10..=14 {
            trials
                .expose("observational-session", turn, &skills, &ids)
                .unwrap();
        }

        trials
            .resolve_episode(
                &episode(
                    "observational-session",
                    10,
                    "memory.recall",
                    ToolOutcome::Succeeded,
                    "completed",
                    'a',
                ),
                &skills,
            )
            .unwrap();
        trials
            .resolve_episode(
                &episode(
                    "observational-session",
                    11,
                    "memory.recall",
                    ToolOutcome::Failed,
                    "error",
                    'b',
                ),
                &skills,
            )
            .unwrap();
        trials
            .resolve_episode(
                &episode(
                    "observational-session",
                    12,
                    "memory.recall",
                    ToolOutcome::Succeeded,
                    "unknown",
                    'c',
                ),
                &skills,
            )
            .unwrap();
        trials
            .resolve_episode(
                &episode(
                    "observational-session",
                    13,
                    "memory.timeline",
                    ToolOutcome::Succeeded,
                    "completed",
                    'd',
                ),
                &skills,
            )
            .unwrap();

        let summaries = summarize_observational_trials(&trials);
        assert_eq!(summaries.len(), 1);
        assert_eq!(
            summaries.get(&skill_id),
            Some(&SkillObservationalSummary {
                total: 5,
                pending: 1,
                passed: 1,
                failed: 1,
                inconclusive: 1,
                not_observed: 1,
            })
        );
    }

    #[test]
    fn empty_validated_registry_has_no_synthetic_observations() {
        let trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        assert!(summarize_observational_trials(&trials).is_empty());
    }

    #[test]
    fn aggregation_contains_no_raw_correlation_or_evidence_identifiers() {
        let (skills, skill_id) = active_recall_skill();
        let mut trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        trials
            .expose(
                "RAW-SESSION-MUST-NOT-LEAK",
                77,
                &skills,
                std::slice::from_ref(&skill_id),
            )
            .unwrap();
        trials
            .resolve_episode(
                &episode(
                    "RAW-SESSION-MUST-NOT-LEAK",
                    77,
                    "memory.recall",
                    ToolOutcome::Succeeded,
                    "completed",
                    'e',
                ),
                &skills,
            )
            .unwrap();

        let summaries = summarize_observational_trials(&trials);
        let debug = format!("{summaries:?}");
        assert!(debug.contains(&skill_id));
        assert!(!debug.contains("RAW-SESSION-MUST-NOT-LEAK"));
        assert!(!debug.contains(&"e".repeat(64)));
        assert!(!debug.contains("trial-v1-"));
    }
}
