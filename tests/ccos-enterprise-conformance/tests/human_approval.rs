//! The composed human-approval contract: RequireApproval is real product
//! behavior — unrecorded approval is denial, recorded approval authorizes
//! exactly one artifact and tenant, and the ledger survives snapshots.

use ccos_enterprise_approval::{ApprovalDecision, ApprovalRequest, ApprovalSnapshot};
use ccos_enterprise_auth::AuthStrength;
use ccos_enterprise_runtime::{actor, request, Call, Deployment, Refusal, TenantState};
use ccos_enterprise_tenancy::TenantId;

fn deployment_with_approval_gate() -> Deployment {
    let mut d = Deployment::new();
    d.add_role("operator", &["policy.admin", "memory.read", "memory.write"])
        .govern_tool("policy.set", "policy.admin")
        .govern_tool("license.revoke", "policy.admin")
        .require_approval("policy.set")
        .require_approval("license.revoke");
    let mut t = TenantState::new(10_000);
    t.allow_model("claude-opus");
    assert!(d.add_tenant("memorithm", "acme", t));
    d.assign("root", "operator");
    d
}

fn operator_call<'a>(
    root: &'a ccos_enterprise_auth::AuthenticatedActor,
    req: &'a ccos_enterprise_gateway::GatewayRequest,
) -> Call<'a> {
    Call {
        actor: root,
        request: req,
        model: "claude-opus",
        cost_tokens: 1,
        variant: None,
        justification: Some("an operator act"),
    }
}

fn operator_identity() -> ccos_enterprise_auth::AuthenticatedActor {
    actor("memorithm", "root", AuthStrength::Token)
}

fn approval(tenant: &str, action: &str, artifact: &str, at: u64) -> ApprovalRequest {
    ApprovalRequest::new(
        TenantId(tenant.into()),
        action,
        artifact,
        "ZEKRITI Tarek",
        ApprovalDecision::Approved,
        at,
        None,
        "approved by the human maintainer",
    )
    .unwrap()
}

fn artifact(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

#[test]
fn approval_gated_tool_denies_without_a_record() {
    let mut d = deployment_with_approval_gate();
    // The call passes every other gate; the approval gate is the only
    // standing barrier. A missing approval must be a refusal.
    let root = operator_identity();
    let req = request("acme", "root", "policy.set", "r-no-approval");
    let call = operator_call(&root, &req);
    assert_eq!(
        d.approval_gate(&call, &artifact(1)),
        Err(Refusal::RequiresApproval),
        "unrecorded approval is denial"
    );
    // The call is still admissible (the gate is separate from admit): an
    // operator can be told exactly which artifact needs approval.
    assert!(
        d.admit(call).is_forwarded(),
        "the governed path admits; the approval gate is the caller's second check"
    );
}

#[test]
fn recorded_approval_authorizes_exactly_one_artifact() {
    let mut d = deployment_with_approval_gate();
    d.record_approval(approval("acme", "policy.set", &artifact(2), 1_000))
        .unwrap();
    let root = operator_identity();
    let req = request("acme", "root", "policy.set", "r-approved");
    let call = operator_call(&root, &req);
    assert_eq!(d.approval_gate(&call, &artifact(2)), Ok(()));
    assert_eq!(
        d.approval_gate(&call, &artifact(3)),
        Err(Refusal::RequiresApproval),
        "a different artifact is a different approval"
    );
    // Other tenants are never authorized by an acme approval.
    let globex_req = request("globex", "root", "policy.set", "r-globex");
    let call = operator_call(&root, &globex_req);
    assert_eq!(
        d.approval_gate(&call, &artifact(2)),
        Err(Refusal::RequiresApproval)
    );
}

#[test]
fn approval_ledger_survives_a_snapshot_restore_cycle() {
    let mut d = deployment_with_approval_gate();
    d.record_approval(approval("acme", "license.revoke", &artifact(4), 1_000))
        .unwrap();
    let snapshot = d.snapshot();
    assert_eq!(snapshot.approvals.approvals.len(), 1);
    assert!(snapshot.approval_required.contains("license.revoke"));

    let restored = Deployment::restore(snapshot, &[], &[]).expect("restore");
    let root = operator_identity();
    let req = request("acme", "root", "license.revoke", "r-restored");
    let call = operator_call(&root, &req);
    assert_eq!(
        restored.approval_gate(&call, &artifact(4)),
        Ok(()),
        "the approval survives restart"
    );
    assert_eq!(
        restored.approval_gate(&call, &artifact(5)),
        Err(Refusal::RequiresApproval)
    );
}

#[test]
fn corrupt_approval_ledger_is_refused_on_restore() {
    let d = deployment_with_approval_gate();
    let mut snapshot = d.snapshot();
    let mut approvals = ApprovalSnapshot::default();
    // A record whose id does not match its fields is corruption.
    approvals.approvals.insert(
        "approval-v1-forged".into(),
        ccos_enterprise_approval::ApprovalRecord {
            id: "approval-v1-forged".into(),
            tenant: "acme".into(),
            approver: "ZEKRITI Tarek".into(),
            action: "policy.set".into(),
            artifact_hash: artifact(6),
            decision: ApprovalDecision::Approved,
            recorded_at: 1_000,
            expires_at: None,
            justification: Some("x".into()),
            schema_version: 1,
        },
    );
    snapshot.approvals = approvals;
    let err = match Deployment::restore(snapshot, &[], &[]) {
        Ok(_) => panic!("corrupt approval state must refuse restore"),
        Err(error) => error,
    };
    assert!(
        matches!(
            err,
            ccos_enterprise_runtime::RestoreError::ApprovalLedgerCorrupt { .. }
        ),
        "{err}"
    );
}

#[test]
fn approval_denial_never_bills_the_tenant() {
    let d = deployment_with_approval_gate();
    let root = operator_identity();
    let req = request("acme", "root", "policy.set", "r-no-approval-bill");
    let call = operator_call(&root, &req);
    assert_eq!(
        d.approval_gate(&call, &artifact(7)),
        Err(Refusal::RequiresApproval)
    );
    // The gate itself is free; the tenant's ledger is untouched.
    assert_eq!(d.spent("acme"), Some(0));
}
