//! Deterministic read-only skill evaluation reporting (observation before
//! causality).
//!
//! The observational trial ledger is now useful enough to build operator
//! intelligence — but a post-exposure association is not automatically
//! causal. This module produces deterministic, read-only evaluation reports
//! and never feeds the counters into automatic lifecycle transitions.
//!
//! Rules honored here:
//!
//! - **never classify NotObserved as Failed**: `not_observed` is its own
//!   class with its own flag;
//! - **never hide uncertainty**: the report carries explicit
//!   `insufficient_evidence` and `drift` flags derived from the data, plus
//!   the raw counts that justify them;
//! - **never mutate lifecycle**: evaluation is a pure function of the
//!   validated ledger; there is no write path in this module;
//! - **no synthetic reasoning**: the report derives every field from the
//!   ledger counts; there is no hidden reasoning, no chain-of-thought, no
//!   LLM reflection.

use serde::{Deserialize, Serialize};

use crate::{SkillObservationalSummary, SkillTrialRegistry, SkillTrialStatus};

/// Minimum observational sample size before a report claims any confidence
/// at all. Below this, `insufficient_evidence` is set regardless of the
/// counts.
pub const MIN_EVIDENCE_SAMPLE: u64 = 3;

/// The threshold (inclusive) of contradictory evidence — failed trials —
/// that raises the `drift` flag when the sample is large enough to matter.
pub const DRIFT_FAILURE_THRESHOLD: u64 = 2;

/// The evaluation of one skill's observational trials. Deterministic,
/// read-only, and deliberately free of causal claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillEvaluation {
    pub skill_id: String,
    /// The raw counts, exactly as the validated ledger reports them.
    pub summary: SkillObservationalSummary,
    /// Whether the sample is too small to support any signal.
    pub insufficient_evidence: bool,
    /// Whether the observed failure count meets or exceeds
    /// [`DRIFT_FAILURE_THRESHOLD`] on a sufficient sample. This is a *drift
    /// signal*, not a causal claim and not a lifecycle verdict.
    pub drift: bool,
    /// `NotObserved` is never `Failed`: this flag reports the distinction
    /// explicitly so an operator cannot conflate the two.
    pub has_not_observed: bool,
    /// Terminal trials as a fraction of the total (rounded to two decimal
    /// places, saturating at 1.00). Pending trials are not failures.
    pub completion_rate: u8,
    /// Passed trials as a fraction of terminal trials. 0 when there are no
    /// terminal trials. This is an *observation*, not a posterior: no
    /// Bayesian or confidence machinery is attached unless separately
    /// documented.
    pub pass_rate_of_terminal: u8,
}

impl SkillEvaluation {
    /// Evaluate one skill's trials from the validated ledger. Returns `None`
    /// when the skill has no observational trials at all.
    pub fn from_ledger(trials: &SkillTrialRegistry, skill_id: &str) -> Option<Self> {
        let summary = crate::summarize_observational_trials(trials).remove(skill_id)?;
        Some(evaluate_summary(skill_id, summary))
    }
}

/// The pure evaluation function: a deterministic mapping from the validated
/// counts to the report. No ledger access, no clock, no randomness.
pub fn evaluate_summary(skill_id: &str, summary: SkillObservationalSummary) -> SkillEvaluation {
    let sample = summary.total;
    let terminal = summary
        .passed
        .saturating_add(summary.failed)
        .saturating_add(summary.inconclusive);
    let insufficient_evidence = sample < MIN_EVIDENCE_SAMPLE;
    let drift = !insufficient_evidence && summary.failed >= DRIFT_FAILURE_THRESHOLD;
    let has_not_observed = summary.not_observed > 0;
    // Completion rate: terminal / total, as a percentage 0..=100. Never
    // exceeds 100 by construction (terminal <= total).
    let completion_rate = if sample == 0 {
        0
    } else {
        ((terminal * 100) / sample).min(100) as u8
    };
    // Pass rate among terminal trials only. NotObserved and Pending are
    // deliberately excluded — not observing is not failing.
    let pass_rate_of_terminal = if terminal == 0 {
        0
    } else {
        ((summary.passed * 100) / terminal).min(100) as u8
    };
    SkillEvaluation {
        skill_id: skill_id.to_string(),
        summary,
        insufficient_evidence,
        drift,
        has_not_observed,
        completion_rate,
        pass_rate_of_terminal,
    }
}

/// Evaluate every skill with observational trials, in skill-id order.
pub fn evaluate_all(trials: &SkillTrialRegistry) -> Vec<SkillEvaluation> {
    let mut out: Vec<SkillEvaluation> = crate::summarize_observational_trials(trials)
        .into_iter()
        .map(|(skill_id, summary)| evaluate_summary(&skill_id, summary))
        .collect();
    out.sort_by(|left, right| left.skill_id.cmp(&right.skill_id));
    out
}

/// Whether any evaluation in the ledger raises the drift flag.
pub fn any_drift(trials: &SkillTrialRegistry) -> bool {
    evaluate_all(trials)
        .iter()
        .any(|evaluation| evaluation.drift)
}

/// A trial status is never *silently* treated as failure: this is the
/// explicit classifier the report uses, and `NotObserved` is its own class.
pub fn classify(status: SkillTrialStatus) -> &'static str {
    match status {
        SkillTrialStatus::Pending => "pending",
        SkillTrialStatus::Passed => "passed",
        SkillTrialStatus::Failed => "failed",
        SkillTrialStatus::Inconclusive => "inconclusive",
        SkillTrialStatus::NotObserved => "not_observed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        EpisodeObservation, SkillConfig, SkillRegistry, SkillTrialConfig, ToolObservation,
        ToolOutcome,
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
    fn insufficient_evidence_is_explicit_never_a_verdict() {
        let (skills, skill_id) = active_skill();
        let mut trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        // One passed trial: too little to say anything.
        trials
            .expose("s", 1, &skills, std::slice::from_ref(&skill_id))
            .unwrap();
        trials
            .resolve_episode(&episode("s", 1, 'a'), &skills)
            .unwrap();
        let evaluation = SkillEvaluation::from_ledger(&trials, &skill_id).unwrap();
        assert!(evaluation.insufficient_evidence);
        assert!(!evaluation.drift, "a small sample cannot claim drift");
        assert_eq!(evaluation.summary.passed, 1);
    }

    #[test]
    fn not_observed_is_never_failed() {
        let (skills, skill_id) = active_skill();
        let mut trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        // Expose five trials; four observe the tool, one does not.
        for turn in 1..=5 {
            trials
                .expose("s", turn, &skills, std::slice::from_ref(&skill_id))
                .unwrap();
        }
        for turn in 1..=4 {
            trials
                .resolve_episode(&episode("s", turn, 'a'), &skills)
                .unwrap();
        }
        trials
            .resolve_episode(
                &EpisodeObservation {
                    evidence_id: "b".repeat(64),
                    session_id: "s".into(),
                    turn: 5,
                    reason_kind: "completed".into(),
                    tools: vec![ToolObservation {
                        name: "memory.timeline".into(),
                        call_id: "c5".into(),
                        outcome: ToolOutcome::Succeeded,
                    }],
                },
                &skills,
            )
            .unwrap();
        let evaluation = SkillEvaluation::from_ledger(&trials, &skill_id).unwrap();
        assert!(evaluation.has_not_observed);
        assert_eq!(evaluation.summary.failed, 0);
        assert_eq!(evaluation.summary.not_observed, 1);
        assert!(
            !evaluation.drift,
            "NotObserved must never count toward drift"
        );
        assert_eq!(evaluation.summary.passed, 4);
        assert_eq!(evaluation.pass_rate_of_terminal, 100);
    }

    #[test]
    fn drift_requires_both_sample_and_failures() {
        let (skills, skill_id) = active_skill();
        let mut trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        // Three trials, two failed: sufficient sample, threshold met.
        for turn in 1..=3 {
            trials
                .expose("s", turn, &skills, std::slice::from_ref(&skill_id))
                .unwrap();
        }
        trials
            .resolve_episode(
                &EpisodeObservation {
                    evidence_id: "c".repeat(64),
                    session_id: "s".into(),
                    turn: 1,
                    reason_kind: "error".into(),
                    tools: vec![ToolObservation {
                        name: "memory.recall".into(),
                        call_id: "c1".into(),
                        outcome: ToolOutcome::Failed,
                    }],
                },
                &skills,
            )
            .unwrap();
        trials
            .resolve_episode(
                &EpisodeObservation {
                    evidence_id: "d".repeat(64),
                    session_id: "s".into(),
                    turn: 2,
                    reason_kind: "error".into(),
                    tools: vec![ToolObservation {
                        name: "memory.recall".into(),
                        call_id: "c2".into(),
                        outcome: ToolOutcome::Failed,
                    }],
                },
                &skills,
            )
            .unwrap();
        trials
            .resolve_episode(&episode("s", 3, 'e'), &skills)
            .unwrap();
        let evaluation = SkillEvaluation::from_ledger(&trials, &skill_id).unwrap();
        assert!(evaluation.drift, "two failures on a sufficient sample");
        assert!(!evaluation.insufficient_evidence);
        assert_eq!(evaluation.summary.failed, 2);
        assert_eq!(evaluation.summary.passed, 1);
        assert_eq!(evaluation.pass_rate_of_terminal, 33);
    }

    #[test]
    fn pending_never_lowers_pass_rate_and_evaluation_is_read_only() {
        let (skills, skill_id) = active_skill();
        let mut trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        // Three exposures, none resolved: all pending.
        for turn in 1..=3 {
            trials
                .expose("s", turn, &skills, std::slice::from_ref(&skill_id))
                .unwrap();
        }
        let before = trials.snapshot().clone();
        let evaluation = SkillEvaluation::from_ledger(&trials, &skill_id).unwrap();
        assert_eq!(evaluation.summary.pending, 3);
        assert_eq!(evaluation.completion_rate, 0);
        assert_eq!(evaluation.pass_rate_of_terminal, 0);
        // The ledger is untouched: evaluation is read-only.
        assert_eq!(trials.snapshot(), &before);
        // And `evaluate_all` covers every skill deterministically.
        let all = evaluate_all(&trials);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0], evaluation);
    }

    #[test]
    fn classification_keeps_not_observed_distinct() {
        assert_eq!(classify(SkillTrialStatus::NotObserved), "not_observed");
        assert_eq!(classify(SkillTrialStatus::Failed), "failed");
        assert_ne!(
            classify(SkillTrialStatus::NotObserved),
            classify(SkillTrialStatus::Failed)
        );
    }
}
