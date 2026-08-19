use std::collections::{BTreeMap, BTreeSet};

use crate::SkillTrialRegistry;

/// Read-only provenance links for one skill's post-exposure observational trials.
///
/// These identifiers are audit material, not model context. `trial_ids` and
/// `evidence_ids` are already domain-separated hashes persisted by the validated
/// trial ledger. Raw session ids, turns, prompts, tool arguments/results and
/// model output are deliberately absent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SkillTrialProvenance {
    /// Trial identifiers ordered newest-first by durable trial ordinal.
    pub trial_ids: Vec<String>,
    /// Distinct terminal evidence identifiers, also ordered by most-recent
    /// linked trial. Pending trials contribute no evidence id.
    pub evidence_ids: Vec<String>,
}

/// Build a deterministic skill -> observational provenance index from a
/// validated trial registry.
///
/// This mirrors MemOS's trace/policy/episode link seam without adding a second
/// CCOS store: `SkillTrialRegistry` remains the single source of truth. Taking
/// the registry rather than a raw snapshot preserves the validation boundary
/// before audit links can be observed.
pub fn index_skill_trial_provenance(
    registry: &SkillTrialRegistry,
) -> BTreeMap<String, SkillTrialProvenance> {
    let mut grouped = BTreeMap::<String, Vec<_>>::new();
    for trial in registry.snapshot().trials.values() {
        grouped
            .entry(trial.skill_id.clone())
            .or_default()
            .push(trial);
    }

    grouped
        .into_iter()
        .map(|(skill_id, mut trials)| {
            trials.sort_by(|left, right| {
                right
                    .ordinal
                    .cmp(&left.ordinal)
                    .then_with(|| right.id.cmp(&left.id))
            });

            let trial_ids = trials.iter().map(|trial| trial.id.clone()).collect();
            let mut seen_evidence = BTreeSet::new();
            let mut evidence_ids = Vec::new();
            for trial in trials {
                let Some(evidence_id) = trial.evidence_id.as_ref() else {
                    continue;
                };
                if seen_evidence.insert(evidence_id.clone()) {
                    evidence_ids.push(evidence_id.clone());
                }
            }

            (
                skill_id,
                SkillTrialProvenance {
                    trial_ids,
                    evidence_ids,
                },
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        EpisodeObservation, SkillConfig, SkillRegistry, SkillTrialConfig, SkillTrialRegistry,
        ToolObservation, ToolOutcome,
    };

    fn episode(session: &str, turn: u64, evidence: char) -> EpisodeObservation {
        EpisodeObservation {
            evidence_id: evidence.to_string().repeat(64),
            session_id: session.into(),
            turn,
            reason_kind: "completed".into(),
            tools: vec![ToolObservation {
                name: "memory.recall".into(),
                call_id: format!("call-{turn}"),
                outcome: ToolOutcome::Succeeded,
            }],
        }
    }

    fn active_skill() -> (SkillRegistry, String) {
        let mut skills = SkillRegistry::new(SkillConfig::default()).unwrap();
        for (turn, evidence) in [(1, '1'), (2, '2'), (3, '3')] {
            skills.observe(&episode("source", turn, evidence)).unwrap();
        }
        let skill_id = skills.active().next().unwrap().id.clone();
        (skills, skill_id)
    }

    #[test]
    fn indexes_trials_newest_first_and_terminal_evidence_only() {
        let (skills, skill_id) = active_skill();
        let mut trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        let ids = vec![skill_id.clone()];
        trials.expose("observed", 10, &skills, &ids).unwrap();
        trials
            .resolve_episode(&episode("observed", 10, 'a'), &skills)
            .unwrap();
        trials.expose("observed", 11, &skills, &ids).unwrap();

        let index = index_skill_trial_provenance(&trials);
        let provenance = index.get(&skill_id).unwrap();
        assert_eq!(provenance.trial_ids.len(), 2);
        assert_eq!(provenance.evidence_ids, vec!["a".repeat(64)]);

        let snapshot = trials.snapshot();
        let newest = snapshot
            .trials
            .values()
            .max_by_key(|trial| trial.ordinal)
            .unwrap();
        let oldest = snapshot
            .trials
            .values()
            .min_by_key(|trial| trial.ordinal)
            .unwrap();
        assert_eq!(provenance.trial_ids, vec![newest.id.clone(), oldest.id.clone()]);
    }

    #[test]
    fn deduplicates_evidence_without_exposing_correlation_keys() {
        let (skills, skill_id) = active_skill();
        let mut trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        let ids = vec![skill_id.clone()];
        for turn in [20, 21] {
            trials.expose("RAW-SESSION-MUST-NOT-LEAK", turn, &skills, &ids).unwrap();
            trials
                .resolve_episode(&episode("RAW-SESSION-MUST-NOT-LEAK", turn, 'b'), &skills)
                .unwrap();
        }

        let index = index_skill_trial_provenance(&trials);
        let provenance = index.get(&skill_id).unwrap();
        assert_eq!(provenance.trial_ids.len(), 2);
        assert_eq!(provenance.evidence_ids, vec!["b".repeat(64)]);
        let debug = format!("{index:?}");
        assert!(!debug.contains("RAW-SESSION-MUST-NOT-LEAK"));
        for trial in trials.snapshot().trials.values() {
            assert!(!debug.contains(&trial.turn_key));
        }
    }

    #[test]
    fn empty_validated_registry_has_no_synthetic_links() {
        let trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        assert!(index_skill_trial_provenance(&trials).is_empty());
    }
}
