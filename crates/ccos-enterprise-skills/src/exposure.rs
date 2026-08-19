use std::collections::BTreeSet;

use serde_json::Value;

const EPISODE_MARKER: &str = "## CCOS Episode (evidence-only)";
const TOOL_HEADER: &str = "\n## Tools\n";
const DSH_SKILL_TOOL: &str = "ccos_skills";
const ENTERPRISE_SKILL_TOOL: &str = "memory.skills";
const MAX_EXPOSED_SKILLS: usize = 128;
const SKILL_PREFIX: &str = "skill-v1-";

/// Recover only validated skill ids that were actually rendered by a successful
/// governed skill-read call in the adapter-owned DSH transcript.
///
/// This evidence is deliberately best-effort: malformed/truncated tool output
/// contributes no trial evidence instead of making the already-admitted memory
/// capture fail. Canonical L1 parsing remains authoritative for the episode
/// itself.
pub fn parse_skill_exposures(source: &str) -> Vec<String> {
    let Some(marker_at) = source.rfind(EPISODE_MARKER) else {
        return Vec::new();
    };
    let prefix = &source[..marker_at];
    let Some(tools_at) = prefix.rfind(TOOL_HEADER) else {
        return Vec::new();
    };
    let mut tools_text = &prefix[tools_at + TOOL_HEADER.len()..];
    if let Some(end) = tools_text.find("\nturn_end_reason:") {
        tools_text = &tools_text[..end];
    }

    let mut exposed = BTreeSet::new();
    let mut current_tool: Option<&str> = None;
    let mut current_output: Option<&str> = None;
    let mut failed = false;

    let finish = |tool: Option<&str>, output: Option<&str>, failed: bool, out: &mut BTreeSet<String>| {
        if failed || !matches!(tool, Some(DSH_SKILL_TOOL | ENTERPRISE_SKILL_TOOL)) {
            return;
        }
        let Some(output) = output else {
            return;
        };
        let Some(ids) = skill_ids_from_rendered_output(output) else {
            return;
        };
        if out.len().saturating_add(ids.len()) > MAX_EXPOSED_SKILLS {
            return;
        }
        out.extend(ids);
    };

    for line in tools_text.lines() {
        if let Some(rest) = line.strip_prefix("- ") {
            finish(current_tool, current_output, failed, &mut exposed);
            current_output = None;
            failed = false;
            current_tool = rest.rfind(" (").map(|open| &rest[..open]);
        } else if let Some(output) = line.strip_prefix("  output: ") {
            current_output = Some(output);
        } else if line == "  failed: true" {
            failed = true;
        }
    }
    finish(current_tool, current_output, failed, &mut exposed);
    exposed.into_iter().collect()
}

fn skill_ids_from_rendered_output(output: &str) -> Option<Vec<String>> {
    let value: Value = serde_json::from_str(output).ok()?;
    let mut payloads = Vec::new();
    collect_payloads(&value, &mut payloads);
    let mut all = BTreeSet::new();
    for payload in payloads {
        let ids = skill_ids_from_payload(&payload)?;
        if all.len().saturating_add(ids.len()) > MAX_EXPOSED_SKILLS {
            return None;
        }
        all.extend(ids);
    }
    (!all.is_empty()).then(|| all.into_iter().collect())
}

fn collect_payloads(value: &Value, out: &mut Vec<Value>) {
    match value {
        Value::Array(items) => {
            for item in items {
                if item.get("type").and_then(Value::as_str) == Some("text") {
                    if let Some(text) = item.get("text").and_then(Value::as_str) {
                        if let Ok(payload) = serde_json::from_str::<Value>(text) {
                            out.push(payload);
                        }
                    }
                }
            }
        }
        Value::Object(object) => {
            if let Some(structured) = object.get("structuredContent") {
                out.push(structured.clone());
            } else if object.contains_key("skills") {
                out.push(value.clone());
            }
        }
        Value::String(text) => {
            if let Ok(payload) = serde_json::from_str::<Value>(text) {
                out.push(payload);
            }
        }
        _ => {}
    }
}

fn skill_ids_from_payload(payload: &Value) -> Option<Vec<String>> {
    let object = payload.as_object()?;
    let skills = object.get("skills")?.as_array()?;
    if skills.is_empty() || skills.len() > MAX_EXPOSED_SKILLS {
        return None;
    }
    let returned = object.get("returned")?.as_u64()?;
    if returned != skills.len() as u64 {
        return None;
    }
    let mut ids = BTreeSet::new();
    for skill in skills {
        if skill.get("status").and_then(Value::as_str) != Some("active") {
            return None;
        }
        let id = skill.get("id")?.as_str()?;
        if !canonical_skill_id(id) || !ids.insert(id.to_string()) {
            return None;
        }
    }
    Some(ids.into_iter().collect())
}

fn canonical_skill_id(id: &str) -> bool {
    let Some(fingerprint) = id.strip_prefix(SKILL_PREFIX) else {
        return false;
    };
    fingerprint.len() == 64
        && fingerprint
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn skill(id_byte: char) -> String {
        format!("skill-v1-{}", id_byte.to_string().repeat(64))
    }

    fn capture(output: &str, failed: bool) -> String {
        format!(
            "# turn\n\n## Tools\n- ccos_skills (read-1)\n  output: {output}\n{}\n- memory.recall (call-2)\n  output: ok\nturn_end_reason: {{\"kind\":\"completed\"}}\n\n{EPISODE_MARKER}\n```json\n{{}}\n```\n",
            if failed { "  failed: true" } else { "" }
        )
    }

    #[test]
    fn extracts_only_active_ids_from_rendered_skill_result() {
        let id = skill('a');
        let text = serde_json::json!({
            "skills": [{ "id": id, "status": "active" }],
            "returned": 1,
            "total_active": 1,
            "truncated": false
        })
        .to_string();
        let output = serde_json::json!([{ "type": "text", "text": text }]).to_string();
        assert_eq!(parse_skill_exposures(&capture(&output, false)), vec![id]);
    }

    #[test]
    fn failed_truncated_or_non_active_results_are_not_evidence() {
        let id = skill('b');
        let valid_text = serde_json::json!({
            "skills": [{ "id": id, "status": "active" }],
            "returned": 1
        })
        .to_string();
        let valid = serde_json::json!([{ "type": "text", "text": valid_text }]).to_string();
        assert!(parse_skill_exposures(&capture(&valid, true)).is_empty());

        let truncated = serde_json::json!([{
            "type": "text",
            "text": "{\"skills\":[... [CCOS tool result truncated]"
        }])
        .to_string();
        assert!(parse_skill_exposures(&capture(&truncated, false)).is_empty());

        let inactive_text = serde_json::json!({
            "skills": [{ "id": skill('c'), "status": "candidate" }],
            "returned": 1
        })
        .to_string();
        let inactive = serde_json::json!([{ "type": "text", "text": inactive_text }]).to_string();
        assert!(parse_skill_exposures(&capture(&inactive, false)).is_empty());
    }

    #[test]
    fn unions_repeated_reads_without_duplicates() {
        let left = skill('d');
        let right = skill('e');
        let first = serde_json::json!([{
            "type": "text",
            "text": serde_json::json!({
                "skills": [{ "id": left, "status": "active" }],
                "returned": 1
            }).to_string()
        }])
        .to_string();
        let second = serde_json::json!([{
            "type": "text",
            "text": serde_json::json!({
                "skills": [
                    { "id": left, "status": "active" },
                    { "id": right, "status": "active" }
                ],
                "returned": 2
            }).to_string()
        }])
        .to_string();
        let source = format!(
            "# turn\n\n## Tools\n- ccos_skills (read-1)\n  output: {first}\n- ccos_skills (read-2)\n  output: {second}\nturn_end_reason: {{\"kind\":\"completed\"}}\n\n{EPISODE_MARKER}\n```json\n{{}}\n```\n"
        );
        assert_eq!(parse_skill_exposures(&source), vec![left, right]);
    }
}
