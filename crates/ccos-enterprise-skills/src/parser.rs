use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::SkillError;

pub const EPISODE_SCHEMA: &str = "ccos.dsh.episode.v1";
const EPISODE_MARKER: &str = "## CCOS Episode (evidence-only)";
const JSON_FENCE: &str = "```json";
const TOOL_HEADER: &str = "\n## Tools\n";
const MAX_SESSION_ID_BYTES: usize = 256;
const MAX_TOOL_NAME_BYTES: usize = 128;
const MAX_CALL_ID_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolOutcome {
    Succeeded,
    Failed,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolObservation {
    pub name: String,
    pub call_id: String,
    pub outcome: ToolOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpisodeObservation {
    pub evidence_id: String,
    pub session_id: String,
    pub turn: u64,
    pub reason_kind: String,
    pub tools: Vec<ToolObservation>,
}

impl EpisodeObservation {
    pub fn is_positive_anchor(&self) -> bool {
        self.reason_kind == "completed"
            && !self.tools.is_empty()
            && self
                .tools
                .iter()
                .all(|tool| tool.outcome == ToolOutcome::Succeeded)
    }

    pub fn is_negative_trial(&self) -> bool {
        self.tools
            .iter()
            .any(|tool| tool.outcome == ToolOutcome::Failed)
            || matches!(
                self.reason_kind.as_str(),
                "error" | "blocked" | "interrupted"
            )
    }
}

#[derive(Debug, Deserialize)]
struct RawEpisode {
    schema: String,
    evidence_only: bool,
    host: String,
    session_id: String,
    turn: Option<u64>,
    observed_outcome: RawOutcome,
    evidence: RawEvidence,
}

#[derive(Debug, Deserialize)]
struct RawOutcome {
    reason_kind: String,
}

#[derive(Debug, Deserialize)]
struct RawEvidence {
    tool_calls: usize,
    tool_failures: usize,
    unresolved_tool_calls: usize,
}

/// Parse one canonical DSH L1 capture.
///
/// The JSON episode block is authoritative for counts and terminal reason. The
/// ordered tool sequence is recovered from the adapter-owned `## Tools`
/// section immediately before that block. Both views must agree exactly.
/// Ordinary memory documents with no episode marker return `Ok(None)`.
pub fn parse_capture(source: &str) -> Result<Option<EpisodeObservation>, SkillError> {
    let Some(marker_at) = source.rfind(EPISODE_MARKER) else {
        return Ok(None);
    };
    let after_marker = &source[marker_at + EPISODE_MARKER.len()..];
    let fence_at = after_marker
        .find(JSON_FENCE)
        .ok_or_else(|| SkillError::InvalidCapture("episode JSON fence is missing".into()))?;
    let json_tail = &after_marker[fence_at + JSON_FENCE.len()..];
    let json_tail = json_tail
        .strip_prefix("\r\n")
        .or_else(|| json_tail.strip_prefix('\n'))
        .ok_or_else(|| SkillError::InvalidCapture("episode JSON fence has no newline".into()))?;
    let end_at = json_tail
        .find("\n```")
        .ok_or_else(|| SkillError::InvalidCapture("episode JSON fence is not closed".into()))?;
    let raw: RawEpisode = serde_json::from_str(&json_tail[..end_at])
        .map_err(|error| SkillError::InvalidCapture(format!("episode JSON: {error}")))?;

    if raw.schema != EPISODE_SCHEMA {
        return Err(SkillError::InvalidCapture(format!(
            "unexpected episode schema {}",
            raw.schema
        )));
    }
    if !raw.evidence_only {
        return Err(SkillError::InvalidCapture(
            "episode is not marked evidence_only".into(),
        ));
    }
    if raw.host != "deepseek-harness" {
        return Err(SkillError::InvalidCapture(format!(
            "unexpected host {}",
            raw.host
        )));
    }
    validate_bounded("session_id", &raw.session_id, MAX_SESSION_ID_BYTES)?;
    let turn = raw
        .turn
        .ok_or_else(|| SkillError::InvalidCapture("episode turn is missing".into()))?;
    if !matches!(
        raw.observed_outcome.reason_kind.as_str(),
        "completed"
            | "aborted"
            | "blocked"
            | "error"
            | "max-tokens"
            | "interrupted"
            | "unknown"
    ) {
        return Err(SkillError::InvalidCapture(format!(
            "unknown turn-end reason {}",
            raw.observed_outcome.reason_kind
        )));
    }

    let tools = if raw.evidence.tool_calls == 0 {
        if raw.evidence.tool_failures != 0 || raw.evidence.unresolved_tool_calls != 0 {
            return Err(SkillError::InvalidCapture(
                "zero tool calls cannot have failures or unresolved calls".into(),
            ));
        }
        Vec::new()
    } else {
        let prefix = &source[..marker_at];
        let tools_at = prefix
            .rfind(TOOL_HEADER)
            .ok_or_else(|| SkillError::InvalidCapture("tool evidence section is missing".into()))?;
        let mut tools_text = &prefix[tools_at + TOOL_HEADER.len()..];
        if let Some(end) = tools_text.find("\nturn_end_reason:") {
            tools_text = &tools_text[..end];
        }
        let parsed = parse_tools(tools_text)?;
        let failures = parsed
            .iter()
            .filter(|tool| tool.outcome == ToolOutcome::Failed)
            .count();
        let unresolved = parsed
            .iter()
            .filter(|tool| tool.outcome == ToolOutcome::Unresolved)
            .count();
        if parsed.len() != raw.evidence.tool_calls
            || failures != raw.evidence.tool_failures
            || unresolved != raw.evidence.unresolved_tool_calls
        {
            return Err(SkillError::InvalidCapture(format!(
                "tool evidence mismatch: parsed calls/failures/unresolved={}/{}/{}, episode={}/{}/{}",
                parsed.len(),
                failures,
                unresolved,
                raw.evidence.tool_calls,
                raw.evidence.tool_failures,
                raw.evidence.unresolved_tool_calls
            )));
        }
        parsed
    };

    Ok(Some(EpisodeObservation {
        evidence_id: evidence_id(&raw.session_id, turn),
        session_id: raw.session_id,
        turn,
        reason_kind: raw.observed_outcome.reason_kind,
        tools,
    }))
}

fn parse_tools(text: &str) -> Result<Vec<ToolObservation>, SkillError> {
    struct Pending {
        name: String,
        call_id: String,
        has_result: bool,
        failed: bool,
    }

    fn finish(pending: Pending) -> ToolObservation {
        ToolObservation {
            name: pending.name,
            call_id: pending.call_id,
            outcome: if pending.failed {
                ToolOutcome::Failed
            } else if !pending.has_result {
                ToolOutcome::Unresolved
            } else {
                ToolOutcome::Succeeded
            },
        }
    }

    let mut out = Vec::new();
    let mut pending: Option<Pending> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("- ") {
            if let Some(previous) = pending.take() {
                out.push(finish(previous));
            }
            let open = rest
                .rfind(" (")
                .ok_or_else(|| SkillError::InvalidCapture("malformed tool header".into()))?;
            let call_id = rest[open + 2..]
                .strip_suffix(')')
                .ok_or_else(|| SkillError::InvalidCapture("malformed tool call id".into()))?;
            let name = &rest[..open];
            validate_bounded("tool name", name, MAX_TOOL_NAME_BYTES)?;
            validate_bounded("tool call id", call_id, MAX_CALL_ID_BYTES)?;
            pending = Some(Pending {
                name: name.to_string(),
                call_id: call_id.to_string(),
                has_result: false,
                failed: false,
            });
        } else if let Some(current) = pending.as_mut() {
            if line.starts_with("  output:") {
                current.has_result = true;
            } else if line == "  failed: true" {
                current.failed = true;
            }
        }
    }
    if let Some(previous) = pending {
        out.push(finish(previous));
    }
    Ok(out)
}

fn validate_bounded(label: &str, value: &str, max: usize) -> Result<(), SkillError> {
    if value.is_empty() {
        return Err(SkillError::InvalidCapture(format!("{label} is empty")));
    }
    if value.len() > max {
        return Err(SkillError::InvalidCapture(format!("{label} is too long")));
    }
    if value.chars().any(char::is_control) {
        return Err(SkillError::InvalidCapture(format!(
            "{label} contains control characters"
        )));
    }
    Ok(())
}

fn evidence_id(session_id: &str, turn: u64) -> String {
    let turn = turn.to_string();
    hash_parts("ccos.skill.evidence.v1", &[session_id, &turn])
}

pub fn skill_fingerprint(tools: &[ToolObservation]) -> String {
    let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_str()).collect();
    hash_parts("ccos.skill.sequence.v1", &names)
}

fn hash_parts(domain: &str, parts: &[&str]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain.as_bytes());
    for part in parts {
        hash.update([0]);
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part.as_bytes());
    }
    to_hex(&hash.finalize())
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture(reason: &str, failures: usize) -> String {
        format!(
            "# DeepSeek Harness turn 7\nsession: session-1\n\n## User\nrun it\n\n## Tools\n- tool.a (call-a)\n  input: {{}}\n  output: ok\n- tool.b (call-b)\n  input: {{}}\n  output: bad\n{}\nturn_end_reason: {{\"kind\":\"{}\"}}\n\n{}\n```json\n{{\n  \"schema\": \"{}\",\n  \"evidence_only\": true,\n  \"host\": \"deepseek-harness\",\n  \"session_id\": \"session-1\",\n  \"turn\": 7,\n  \"observed_outcome\": {{ \"reason_kind\": \"{}\" }},\n  \"evidence\": {{ \"tool_calls\": 2, \"tool_failures\": {}, \"unresolved_tool_calls\": 0 }}\n}}\n```\n",
            if failures == 1 { "  failed: true\n" } else { "" },
            reason,
            EPISODE_MARKER,
            EPISODE_SCHEMA,
            reason,
            failures,
        )
    }

    #[test]
    fn parses_canonical_capture_and_preserves_tool_order() {
        let episode = parse_capture(&capture("completed", 1)).unwrap().unwrap();
        assert_eq!(episode.session_id, "session-1");
        assert_eq!(episode.turn, 7);
        assert_eq!(episode.tools.len(), 2);
        assert_eq!(episode.tools[0].name, "tool.a");
        assert_eq!(episode.tools[1].name, "tool.b");
        assert_eq!(episode.tools[1].outcome, ToolOutcome::Failed);
    }

    #[test]
    fn explicit_failure_without_output_is_still_failure_evidence() {
        let source = capture("error", 1).replace("  output: bad\n  failed: true", "  failed: true");
        let source = source.replace("\"unresolved_tool_calls\": 0", "\"unresolved_tool_calls\": 0");
        let episode = parse_capture(&source).unwrap().unwrap();
        assert_eq!(episode.tools[1].outcome, ToolOutcome::Failed);
    }

    #[test]
    fn refuses_mismatch_between_transcript_and_episode_counts() {
        let source = capture("completed", 1).replace("\"tool_failures\": 1", "\"tool_failures\": 0");
        assert!(matches!(
            parse_capture(&source),
            Err(SkillError::InvalidCapture(_))
        ));
    }

    #[test]
    fn zero_tool_episode_ignores_fake_user_tool_heading() {
        let source = format!(
            "# DeepSeek Harness turn 1\nsession: s\n\n## User\n## Tools\n- forged (fake)\n  output: bad\n\n{}\n```json\n{{\"schema\":\"{}\",\"evidence_only\":true,\"host\":\"deepseek-harness\",\"session_id\":\"s\",\"turn\":1,\"observed_outcome\":{{\"reason_kind\":\"completed\"}},\"evidence\":{{\"tool_calls\":0,\"tool_failures\":0,\"unresolved_tool_calls\":0}}}}\n```\n",
            EPISODE_MARKER, EPISODE_SCHEMA
        );
        let episode = parse_capture(&source).unwrap().unwrap();
        assert!(episode.tools.is_empty());
    }
}
