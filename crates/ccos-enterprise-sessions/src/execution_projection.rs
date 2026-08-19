//! Derived, non-authoritative views over the Enterprise execution journal.
//!
//! The append-only journal remains the sole execution source of truth. These
//! projections are rebuilt from verified journal records and can therefore be
//! discarded at any time without losing state.

use crate::execution::{
    ExecutionEvent, ExecutionJournal, JournalError, ToolRecoveryDisposition, GENESIS_HASH,
};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    /// Referenced by a message/tool before an explicit lifecycle start event.
    Observed,
    Running,
    Succeeded,
    Failed,
}

impl LifecycleState {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolState {
    NotStarted,
    OutcomeUnknown,
    Completed {
        success: bool,
        output_sha256: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolProjection {
    pub call_id: String,
    pub tool: String,
    pub turn_id: String,
    pub step_id: String,
    pub state: ToolState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepProjection {
    pub step_id: String,
    pub state: LifecycleState,
    pub explicit_start: bool,
    pub assistant_messages: usize,
    pub tool_calls: Vec<String>,
}

impl StepProjection {
    fn observed(step_id: &str) -> Self {
        Self {
            step_id: step_id.to_string(),
            state: LifecycleState::Observed,
            explicit_start: false,
            assistant_messages: 0,
            tool_calls: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnProjection {
    pub turn_id: String,
    pub state: LifecycleState,
    pub explicit_start: bool,
    pub user_messages: usize,
    pub assistant_messages: usize,
    pub steps: BTreeMap<String, StepProjection>,
}

impl TurnProjection {
    fn observed(turn_id: &str) -> Self {
        Self {
            turn_id: turn_id.to_string(),
            state: LifecycleState::Observed,
            explicit_start: false,
            user_messages: 0,
            assistant_messages: 0,
            steps: BTreeMap::new(),
        }
    }

    fn step_mut(&mut self, step_id: &str) -> &mut StepProjection {
        self.steps
            .entry(step_id.to_string())
            .or_insert_with(|| StepProjection::observed(step_id))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalState {
    Pending,
    Decided { allowed: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalProjection {
    pub approval_id: String,
    pub capability: String,
    pub state: ApprovalState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionProjection {
    pub stream_id: String,
    pub total_records: usize,
    pub head_hash: String,
    pub turns: BTreeMap<String, TurnProjection>,
    pub tools: BTreeMap<String, ToolProjection>,
    pub approvals: BTreeMap<String, ApprovalProjection>,
}

impl ExecutionProjection {
    /// Rebuild a complete view from an already-opened, integrity-verified
    /// journal. No projection state is persisted.
    pub fn from_journal(journal: &ExecutionJournal) -> Result<Self, ProjectionError> {
        let mut turns = BTreeMap::<String, TurnProjection>::new();
        let mut tool_locations = BTreeMap::<String, (String, String)>::new();
        let mut approvals = BTreeMap::<String, ApprovalProjection>::new();

        for record in journal.records() {
            match &record.event {
                ExecutionEvent::TurnStarted { turn_id } => {
                    let turn = turns
                        .entry(turn_id.clone())
                        .or_insert_with(|| TurnProjection::observed(turn_id));
                    if turn.explicit_start {
                        return Err(ProjectionError::Lifecycle(format!(
                            "turn {turn_id:?} started more than once"
                        )));
                    }
                    if turn.state.is_terminal() {
                        return Err(ProjectionError::Lifecycle(format!(
                            "turn {turn_id:?} started after it was terminal"
                        )));
                    }
                    turn.explicit_start = true;
                    turn.state = LifecycleState::Running;
                }
                ExecutionEvent::StepStarted { turn_id, step_id } => {
                    let turn = turns
                        .entry(turn_id.clone())
                        .or_insert_with(|| TurnProjection::observed(turn_id));
                    let step = turn.step_mut(step_id);
                    if step.explicit_start {
                        return Err(ProjectionError::Lifecycle(format!(
                            "step {step_id:?} in turn {turn_id:?} started more than once"
                        )));
                    }
                    if step.state.is_terminal() {
                        return Err(ProjectionError::Lifecycle(format!(
                            "step {step_id:?} in turn {turn_id:?} started after it was terminal"
                        )));
                    }
                    step.explicit_start = true;
                    step.state = LifecycleState::Running;
                }
                ExecutionEvent::UserMessage { turn_id, .. } => {
                    let turn = turns
                        .entry(turn_id.clone())
                        .or_insert_with(|| TurnProjection::observed(turn_id));
                    turn.user_messages += 1;
                }
                ExecutionEvent::AssistantMessage {
                    turn_id, step_id, ..
                } => {
                    let turn = turns
                        .entry(turn_id.clone())
                        .or_insert_with(|| TurnProjection::observed(turn_id));
                    turn.assistant_messages += 1;
                    turn.step_mut(step_id).assistant_messages += 1;
                }
                ExecutionEvent::ToolRequested {
                    turn_id,
                    step_id,
                    call_id,
                    ..
                } => {
                    if tool_locations
                        .insert(call_id.clone(), (turn_id.clone(), step_id.clone()))
                        .is_some()
                    {
                        return Err(ProjectionError::Lifecycle(format!(
                            "tool call {call_id:?} was requested more than once"
                        )));
                    }
                    let turn = turns
                        .entry(turn_id.clone())
                        .or_insert_with(|| TurnProjection::observed(turn_id));
                    let step = turn.step_mut(step_id);
                    if !step.tool_calls.iter().any(|existing| existing == call_id) {
                        step.tool_calls.push(call_id.clone());
                    }
                }
                ExecutionEvent::ApprovalAsked {
                    approval_id,
                    capability,
                } => {
                    if approvals.contains_key(approval_id) {
                        return Err(ProjectionError::Lifecycle(format!(
                            "approval {approval_id:?} was asked more than once"
                        )));
                    }
                    approvals.insert(
                        approval_id.clone(),
                        ApprovalProjection {
                            approval_id: approval_id.clone(),
                            capability: capability.clone(),
                            state: ApprovalState::Pending,
                        },
                    );
                }
                ExecutionEvent::ApprovalDecided {
                    approval_id,
                    allowed,
                } => {
                    let approval = approvals.get_mut(approval_id).ok_or_else(|| {
                        ProjectionError::Lifecycle(format!(
                            "approval {approval_id:?} was decided before it was asked"
                        ))
                    })?;
                    if !matches!(approval.state, ApprovalState::Pending) {
                        return Err(ProjectionError::Lifecycle(format!(
                            "approval {approval_id:?} was decided more than once"
                        )));
                    }
                    approval.state = ApprovalState::Decided { allowed: *allowed };
                }
                ExecutionEvent::StepFinished {
                    turn_id,
                    step_id,
                    success,
                } => {
                    let turn = turns
                        .entry(turn_id.clone())
                        .or_insert_with(|| TurnProjection::observed(turn_id));
                    let step = turn.step_mut(step_id);
                    if step.state.is_terminal() {
                        return Err(ProjectionError::Lifecycle(format!(
                            "step {step_id:?} in turn {turn_id:?} finished more than once"
                        )));
                    }
                    step.state = if *success {
                        LifecycleState::Succeeded
                    } else {
                        LifecycleState::Failed
                    };
                }
                ExecutionEvent::TurnFinished { turn_id, success } => {
                    let turn = turns
                        .entry(turn_id.clone())
                        .or_insert_with(|| TurnProjection::observed(turn_id));
                    if turn.state.is_terminal() {
                        return Err(ProjectionError::Lifecycle(format!(
                            "turn {turn_id:?} finished more than once"
                        )));
                    }
                    turn.state = if *success {
                        LifecycleState::Succeeded
                    } else {
                        LifecycleState::Failed
                    };
                }
                ExecutionEvent::HostCallCorrelated { .. }
                | ExecutionEvent::ToolStarted { .. }
                | ExecutionEvent::ToolFinished { .. } => {}
            }
        }

        let mut tools = BTreeMap::new();
        for recovered in journal.recover_tools()? {
            let (turn_id, step_id) = tool_locations.get(&recovered.call_id).ok_or_else(|| {
                ProjectionError::Lifecycle(format!(
                    "tool recovery has no request location for {:?}",
                    recovered.call_id
                ))
            })?;
            let state = match recovered.disposition {
                ToolRecoveryDisposition::NotStarted => ToolState::NotStarted,
                ToolRecoveryDisposition::OutcomeUnknown => ToolState::OutcomeUnknown,
                ToolRecoveryDisposition::Completed {
                    success,
                    output_sha256,
                } => ToolState::Completed {
                    success,
                    output_sha256,
                },
            };
            tools.insert(
                recovered.call_id.clone(),
                ToolProjection {
                    call_id: recovered.call_id,
                    tool: recovered.tool,
                    turn_id: turn_id.clone(),
                    step_id: step_id.clone(),
                    state,
                },
            );
        }

        Ok(Self {
            stream_id: journal.stream_id().to_string(),
            total_records: journal.len(),
            head_hash: journal.head_hash().to_string(),
            turns,
            tools,
            approvals,
        })
    }

    /// Calls that crossed the durable start boundary but have no durable result.
    pub fn unsafe_outcomes(&self) -> impl Iterator<Item = &ToolProjection> {
        self.tools
            .values()
            .filter(|tool| tool.state == ToolState::OutcomeUnknown)
    }

    /// Calls whose request is durable but which never crossed the start boundary.
    pub fn not_started(&self) -> impl Iterator<Item = &ToolProjection> {
        self.tools
            .values()
            .filter(|tool| tool.state == ToolState::NotStarted)
    }

    pub fn pending_approvals(&self) -> impl Iterator<Item = &ApprovalProjection> {
        self.approvals
            .values()
            .filter(|approval| approval.state == ApprovalState::Pending)
    }

    /// True means there is no call whose side-effect outcome is unknown.
    pub fn is_recovery_safe(&self) -> bool {
        self.unsafe_outcomes().next().is_none()
    }
}

impl Default for ExecutionProjection {
    fn default() -> Self {
        Self {
            stream_id: String::new(),
            total_records: 0,
            head_hash: GENESIS_HASH.to_string(),
            turns: BTreeMap::new(),
            tools: BTreeMap::new(),
            approvals: BTreeMap::new(),
        }
    }
}

#[derive(Debug)]
pub enum ProjectionError {
    Journal(JournalError),
    Lifecycle(String),
}

impl std::fmt::Display for ProjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Journal(error) => write!(f, "execution projection journal: {error}"),
            Self::Lifecycle(detail) => write!(f, "execution projection lifecycle: {detail}"),
        }
    }
}

impl std::error::Error for ProjectionError {}

impl From<JournalError> for ProjectionError {
    fn from(value: JournalError) -> Self {
        Self::Journal(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::ExecutionEvent;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(0);

    fn journal(tag: &str) -> (PathBuf, ExecutionJournal) {
        let id = NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "ccos-execution-projection-{tag}-{}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        let path = dir.join("execution.jsonl");
        let opened = ExecutionJournal::open(&path, "tenant/acme/mcp").expect("open");
        (dir, opened.journal)
    }

    fn request(call_id: &str, turn_id: &str, step_id: &str) -> ExecutionEvent {
        ExecutionEvent::ToolRequested {
            turn_id: turn_id.to_string(),
            step_id: step_id.to_string(),
            call_id: call_id.to_string(),
            tool: "recall".to_string(),
            input_sha256: "input".to_string(),
        }
    }

    #[test]
    fn projects_all_three_tool_recovery_states() {
        let (dir, mut journal) = journal("tool-states");
        journal
            .append(request("not-started", "turn", "step"))
            .expect("request");
        journal
            .append(request("unknown", "turn", "step"))
            .expect("request");
        journal
            .append(ExecutionEvent::ToolStarted {
                call_id: "unknown".to_string(),
            })
            .expect("start");
        journal
            .append(request("done", "turn", "step"))
            .expect("request");
        journal
            .append(ExecutionEvent::ToolStarted {
                call_id: "done".to_string(),
            })
            .expect("start");
        journal
            .append(ExecutionEvent::ToolFinished {
                call_id: "done".to_string(),
                success: true,
                output_sha256: "output".to_string(),
            })
            .expect("finish");

        let projection = ExecutionProjection::from_journal(&journal).expect("project");
        assert_eq!(projection.not_started().count(), 1);
        assert_eq!(projection.unsafe_outcomes().count(), 1);
        assert!(!projection.is_recovery_safe());
        assert!(matches!(
            projection.tools["done"].state,
            ToolState::Completed { success: true, .. }
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn projects_turn_step_messages_and_approval() {
        let (dir, mut journal) = journal("lifecycle");
        journal
            .append(ExecutionEvent::TurnStarted {
                turn_id: "turn-1".to_string(),
            })
            .expect("turn start");
        journal
            .append(ExecutionEvent::UserMessage {
                turn_id: "turn-1".to_string(),
                message_id: "user-1".to_string(),
                content_sha256: "user-hash".to_string(),
            })
            .expect("user");
        journal
            .append(ExecutionEvent::StepStarted {
                turn_id: "turn-1".to_string(),
                step_id: "step-1".to_string(),
            })
            .expect("step start");
        journal
            .append(ExecutionEvent::AssistantMessage {
                turn_id: "turn-1".to_string(),
                step_id: "step-1".to_string(),
                message_id: "assistant-1".to_string(),
                content_sha256: "assistant-hash".to_string(),
            })
            .expect("assistant");
        journal
            .append(ExecutionEvent::ApprovalAsked {
                approval_id: "approval-1".to_string(),
                capability: "workspace.write".to_string(),
            })
            .expect("approval asked");
        journal
            .append(ExecutionEvent::ApprovalDecided {
                approval_id: "approval-1".to_string(),
                allowed: true,
            })
            .expect("approval decided");
        journal
            .append(ExecutionEvent::StepFinished {
                turn_id: "turn-1".to_string(),
                step_id: "step-1".to_string(),
                success: true,
            })
            .expect("step finish");
        journal
            .append(ExecutionEvent::TurnFinished {
                turn_id: "turn-1".to_string(),
                success: true,
            })
            .expect("turn finish");

        let projection = ExecutionProjection::from_journal(&journal).expect("project");
        let turn = &projection.turns["turn-1"];
        assert_eq!(turn.state, LifecycleState::Succeeded);
        assert!(turn.explicit_start);
        assert_eq!(turn.user_messages, 1);
        assert_eq!(turn.assistant_messages, 1);
        assert_eq!(turn.steps["step-1"].state, LifecycleState::Succeeded);
        assert!(turn.steps["step-1"].explicit_start);
        assert_eq!(projection.pending_approvals().count(), 0);
        assert_eq!(
            projection.approvals["approval-1"].state,
            ApprovalState::Decided { allowed: true }
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn tool_only_stream_still_builds_observed_lifecycle_nodes() {
        let (dir, mut journal) = journal("tool-only");
        journal
            .append(request("call-1", "mcp-turn", "mcp-step"))
            .expect("request");
        let projection = ExecutionProjection::from_journal(&journal).expect("project");
        let turn = &projection.turns["mcp-turn"];
        assert_eq!(turn.state, LifecycleState::Observed);
        assert!(!turn.explicit_start);
        assert_eq!(turn.steps["mcp-step"].state, LifecycleState::Observed);
        assert_eq!(turn.steps["mcp-step"].tool_calls, vec!["call-1"]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn pending_approval_is_visible() {
        let (dir, mut journal) = journal("pending-approval");
        journal
            .append(ExecutionEvent::ApprovalAsked {
                approval_id: "approval-1".to_string(),
                capability: "network".to_string(),
            })
            .expect("ask");
        let projection = ExecutionProjection::from_journal(&journal).expect("project");
        let pending: Vec<_> = projection.pending_approvals().collect();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].capability, "network");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn duplicate_turn_start_is_refused() {
        let (dir, mut journal) = journal("duplicate-turn");
        for _ in 0..2 {
            journal
                .append(ExecutionEvent::TurnStarted {
                    turn_id: "turn-1".to_string(),
                })
                .expect("append");
        }
        let error = ExecutionProjection::from_journal(&journal).expect_err("duplicate");
        assert!(matches!(error, ProjectionError::Lifecycle(_)), "{error}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
