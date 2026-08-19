use ccos_enterprise_sessions::execution::{ExecutionEvent, ExecutionJournal};
use ccos_enterprise_sessions::execution_projection::{ExecutionProjection, LifecycleState};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn host_correlation_is_durable_but_projection_neutral() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "ccos-host-correlation-projection-{}-{nonce}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("scratch directory");

    let path = root.join("execution.jsonl");
    let mut journal = ExecutionJournal::open(&path, "tenant/acme/session-1")
        .expect("open execution journal")
        .journal;
    journal
        .append(ExecutionEvent::TurnStarted {
            turn_id: "turn-1".into(),
        })
        .expect("turn start");
    journal
        .append(ExecutionEvent::HostCallCorrelated {
            call_id: "attempt-1".into(),
            request_id: "request-1".into(),
            host: "deepseek-harness".into(),
            host_session_id: "dsh-session".into(),
            trace_id: "0123456789abcdef0123456789abcdef".into(),
            agent_id: "deepseek-harness-agent".into(),
            profile: "default".into(),
            turn_id: "turn-1".into(),
            step_id: "step-1".into(),
            tool_call_id: Some("tool-call-1".into()),
            tool: "memory.recall".into(),
        })
        .expect("host correlation");
    journal
        .append(ExecutionEvent::TurnFinished {
            turn_id: "turn-1".into(),
            success: true,
        })
        .expect("turn finish");

    let projection = ExecutionProjection::from_journal(&journal).expect("project journal");
    assert_eq!(projection.total_records, 3);
    assert_eq!(projection.turns["turn-1"].state, LifecycleState::Succeeded);
    assert!(projection.tools.is_empty());
    assert!(projection.approvals.is_empty());

    let _ = std::fs::remove_dir_all(root);
}
