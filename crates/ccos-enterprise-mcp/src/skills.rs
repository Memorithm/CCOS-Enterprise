//! Governed read-only exposure of validated Enterprise skills.
//!
//! Skills are Enterprise-local derived state, not Core tools. This module keeps
//! the capability separate from the Core translation table and exposes only
//! records that have reached the `Active` lifecycle state. Raw evidence ids,
//! prompts, tool arguments/results, fingerprints and executable procedures are
//! intentionally absent from the wire projection.

use std::collections::BTreeMap;

use ccos_enterprise_runtime::Deployment;
use ccos_enterprise_skills::{
    summarize_observational_trials, SkillObservationalSummary, SkillRecord, SkillRegistry,
    SkillStatus, SkillTrialRegistry,
};
use serde_json::{json, Value};

pub const SKILL_READ_TOOL: &str = "memory.skills";
pub const SKILL_READ_PERMISSION: &str = "memory.read";
pub const DEFAULT_SKILL_READ_LIMIT: usize = 32;
pub const MAX_SKILL_READ_LIMIT: usize = 128;

pub fn govern_skill_catalogue(deployment: &mut Deployment) {
    deployment.govern_tool(SKILL_READ_TOOL, SKILL_READ_PERMISSION);
}

pub fn skill_permission_for(tool: &str) -> Option<&'static str> {
    (tool == SKILL_READ_TOOL).then_some(SKILL_READ_PERMISSION)
}

pub fn skill_tool_spec() -> Value {
    json!({
        "name": SKILL_READ_TOOL,
        "description": "List validated active evidence-backed skills for the authenticated tenant, including read-only post-exposure observational trial counters. Metadata only; this capability never executes a skill or returns raw captured content.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_SKILL_READ_LIMIT,
                    "description": "Maximum active skills to return."
                }
            },
            "additionalProperties": false
        }
    })
}

/// Current production projection used by the stdio server.
///
/// Keep this shape stable until the server explicitly loads the validated
/// post-exposure trial ledger. Returning synthetic zero counters here would be
/// misleading for tenants that already have observational trials.
pub fn active_skill_tool_result(
    registry: &SkillRegistry,
    arguments: &Value,
) -> Result<Value, String> {
    active_skill_tool_result_inner(registry, None, arguments)
}

/// Read-only projection that augments each Active skill with counters derived
/// from a validated post-exposure trial registry.
///
/// Accepting `SkillTrialRegistry` rather than a raw snapshot or caller-built
/// counter map preserves #61's validation boundary: arbitrary persisted bytes
/// cannot be summarized, and callers cannot inject fabricated counters. This
/// function never scores the aggregate and never mutates lifecycle state.
pub fn active_skill_tool_result_with_observational(
    registry: &SkillRegistry,
    trials: &SkillTrialRegistry,
    arguments: &Value,
) -> Result<Value, String> {
    let observational = summarize_observational_trials(trials);
    active_skill_tool_result_inner(registry, Some(&observational), arguments)
}

fn active_skill_tool_result_inner(
    registry: &SkillRegistry,
    observational: Option<&BTreeMap<String, SkillObservationalSummary>>,
    arguments: &Value,
) -> Result<Value, String> {
    let limit = skill_read_limit(arguments)?;
    let structured = project_active_skills(registry.active(), observational, limit);
    let text = serde_json::to_string(&structured)
        .map_err(|error| format!("cannot serialize active skill projection: {error}"))?;
    Ok(json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": structured
    }))
}

fn skill_read_limit(arguments: &Value) -> Result<usize, String> {
    let object = arguments
        .as_object()
        .ok_or_else(|| "memory.skills arguments must be an object".to_string())?;
    if let Some(unexpected) = object.keys().find(|key| key.as_str() != "limit") {
        return Err(format!(
            "memory.skills does not accept argument {unexpected:?}"
        ));
    }
    match object.get("limit") {
        None => Ok(DEFAULT_SKILL_READ_LIMIT),
        Some(value) => {
            let limit = value
                .as_u64()
                .ok_or_else(|| "memory.skills limit must be an integer".to_string())?;
            if limit == 0 || limit > MAX_SKILL_READ_LIMIT as u64 {
                return Err(format!(
                    "memory.skills limit must be within 1..={MAX_SKILL_READ_LIMIT}"
                ));
            }
            Ok(limit as usize)
        }
    }
}

fn project_active_skills<'a>(
    records: impl Iterator<Item = &'a SkillRecord>,
    observational: Option<&BTreeMap<String, SkillObservationalSummary>>,
    limit: usize,
) -> Value {
    let mut total_active = 0usize;
    let mut skills = Vec::new();
    for record in records {
        if record.status != SkillStatus::Active {
            continue;
        }
        total_active = total_active.saturating_add(1);
        if skills.len() < limit {
            let mut projected = json!({
                "id": record.id,
                "tool_sequence": record.tool_sequence,
                "status": "active",
                "support": record.support,
                "trials_attempted": record.trials_attempted,
                "trials_passed": record.trials_passed,
                "eta": record.eta
            });
            if let Some(observational) = observational {
                let observed = observational.get(&record.id).copied().unwrap_or_default();
                projected["observational"] = json!({
                    "total": observed.total,
                    "pending": observed.pending,
                    "passed": observed.passed,
                    "failed": observed.failed,
                    "inconclusive": observed.inconclusive,
                    "not_observed": observed.not_observed
                });
            }
            skills.push(projected);
        }
    }
    let returned = skills.len();
    json!({
        "skills": skills,
        "returned": returned,
        "total_active": total_active,
        "truncated": returned < total_active
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str, status: SkillStatus) -> SkillRecord {
        SkillRecord {
            id: id.into(),
            fingerprint: "FINGERPRINT-MUST-NOT-BE-EXPOSED".into(),
            tool_sequence: vec!["memory.recall".into()],
            status,
            support: 3,
            trials_attempted: 3,
            trials_passed: 3,
            eta: 0.8,
            evidence_ids: vec!["EVIDENCE-ID-MUST-NOT-BE-EXPOSED".into()],
        }
    }

    #[test]
    fn current_wire_projection_stays_unchanged_until_server_wiring() {
        let active = record("skill-active", SkillStatus::Active);
        let candidate = record("skill-candidate", SkillStatus::Candidate);
        let records = [&active, &candidate];
        let value = project_active_skills(records.into_iter(), None, 32);
        assert_eq!(value["returned"], 1);
        assert_eq!(value["total_active"], 1);
        assert_eq!(value["skills"][0]["id"], "skill-active");
        assert!(value["skills"][0].get("observational").is_none());
        let text = value.to_string();
        assert!(!text.contains("skill-candidate"));
        assert!(!text.contains("FINGERPRINT-MUST-NOT-BE-EXPOSED"));
        assert!(!text.contains("EVIDENCE-ID-MUST-NOT-BE-EXPOSED"));
    }

    #[test]
    fn observational_projection_exposes_exact_counts_without_private_ids() {
        let active = record("skill-active", SkillStatus::Active);
        let records = [&active];
        let observational = BTreeMap::from([(
            "skill-active".to_string(),
            SkillObservationalSummary {
                total: 6,
                pending: 1,
                passed: 2,
                failed: 1,
                inconclusive: 1,
                not_observed: 1,
            },
        )]);
        let value = project_active_skills(records.into_iter(), Some(&observational), 32);
        assert_eq!(value["skills"][0]["observational"]["total"], 6);
        assert_eq!(value["skills"][0]["observational"]["pending"], 1);
        assert_eq!(value["skills"][0]["observational"]["passed"], 2);
        assert_eq!(value["skills"][0]["observational"]["failed"], 1);
        assert_eq!(value["skills"][0]["observational"]["inconclusive"], 1);
        assert_eq!(value["skills"][0]["observational"]["not_observed"], 1);
        let text = value.to_string();
        assert!(!text.contains("trial-v1-"));
        assert!(!text.contains("turn_key"));
        assert!(!text.contains("evidence_id"));
    }

    #[test]
    fn observational_projection_uses_explicit_zero_counts_when_absent() {
        let active = record("skill-active", SkillStatus::Active);
        let records = [&active];
        let observational = BTreeMap::new();
        let value = project_active_skills(records.into_iter(), Some(&observational), 32);
        assert_eq!(
            value["skills"][0]["observational"],
            json!({
                "total": 0,
                "pending": 0,
                "passed": 0,
                "failed": 0,
                "inconclusive": 0,
                "not_observed": 0
            })
        );
    }

    #[test]
    fn input_is_bounded_and_closed() {
        assert_eq!(skill_read_limit(&json!({})).unwrap(), 32);
        assert_eq!(skill_read_limit(&json!({"limit": 1})).unwrap(), 1);
        assert_eq!(skill_read_limit(&json!({"limit": 128})).unwrap(), 128);
        for invalid in [
            json!({"limit": 0}),
            json!({"limit": 129}),
            json!({"limit": 1.5}),
            json!({"limit": "32"}),
            json!({"status": "candidate"}),
        ] {
            assert!(skill_read_limit(&invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn capability_is_read_only_and_exact() {
        assert_eq!(skill_permission_for(SKILL_READ_TOOL), Some("memory.read"));
        assert_eq!(skill_permission_for("memory.skill_execute"), None);
        let spec = skill_tool_spec();
        assert_eq!(spec["name"], SKILL_READ_TOOL);
        assert_eq!(spec["inputSchema"]["additionalProperties"], false);
    }
}
