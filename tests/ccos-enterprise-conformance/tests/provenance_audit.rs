//! The composed provenance-audit contract: tenant scoping, RBAC denial,
//! deterministic ordering, bounded output, and fail-closed behavior on the
//! governed operator path.

use std::collections::BTreeMap;

use ccos_enterprise_rbac::{Permission, Role, RoleBook};
use ccos_enterprise_runtime::{Deployment, TenantState};
use ccos_enterprise_skills::{
    EpisodeObservation, SkillConfig, SkillRegistry, SkillTrialConfig, SkillTrialRegistry,
    ToolObservation, ToolOutcome,
};
use ccos_enterprise_skills_audit::{
    audit_provenance, AuditLimits, AuditQuery, AuditSources, SKILL_AUDIT_PERMISSION,
};
use ccos_enterprise_tenancy::{TenantId, TenantScope};

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

fn operator_roles() -> RoleBook {
    let mut book = RoleBook::default();
    let mut auditor = Role {
        name: "auditor".into(),
        ..Default::default()
    };
    auditor
        .permissions
        .insert(Permission(SKILL_AUDIT_PERMISSION.to_string()));
    book.add_role(auditor);
    assert!(book.assign("operator", "auditor"));
    book
}

/// The composed contract: a tenant-scoped deployment with one crystallized
/// skill and its observational trials, plus the role book that authorizes an
/// operator.
fn composed_fixture() -> (
    Deployment,
    SkillRegistry,
    SkillTrialRegistry,
    RoleBook,
    TenantScope<()>,
) {
    let mut d = Deployment::new();
    let mut t = TenantState::new(10_000);
    t.allow_model("claude-opus");
    assert!(d.add_tenant("memorithm", "acme", t));
    let mut t = TenantState::new(10_000);
    t.allow_model("claude-opus");
    assert!(d.add_tenant("memorithm", "globex", t));

    let mut skills = SkillRegistry::new(SkillConfig::default()).unwrap();
    for (turn, evidence) in [(1, '1'), (2, '2'), (3, '3')] {
        skills
            .observe(&episode("skill-source", turn, evidence))
            .unwrap();
    }
    let skill_id = skills.active().next().unwrap().id.clone();

    let mut trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
    trials
        .expose("session-a", 10, &skills, std::slice::from_ref(&skill_id))
        .unwrap();
    trials
        .resolve_episode(&episode("session-a", 10, 'a'), &skills)
        .unwrap();
    trials
        .expose("session-a", 11, &skills, std::slice::from_ref(&skill_id))
        .unwrap();

    let scope = TenantScope::new(TenantId("acme".into()), ());
    (d, skills, trials, operator_roles(), scope)
}

#[test]
fn operator_audit_is_tenant_scoped_and_newest_first() {
    let (_d, skills, trials, roles, scope) = composed_fixture();
    let known: BTreeMap<TenantId, ()> = BTreeMap::from([
        (TenantId("acme".into()), ()),
        (TenantId("globex".into()), ()),
    ]);
    let report = audit_provenance(
        AuditQuery {
            caller: "operator",
            scope: &scope,
            limits: AuditLimits::default(),
            sources: AuditSources {
                skills: &skills,
                trials: &trials,
            },
            roles: &roles,
        },
        &known,
    )
    .expect("acme is a known tenant");
    assert_eq!(report.tenant, "acme");
    assert!(!report.empty);
    let skill = &report.skills[0];
    assert_eq!(skill.trials.len(), 2);
    let ordinals: Vec<u64> = skill.trials.iter().map(|t| t.ordinal).collect();
    assert!(ordinals.windows(2).all(|w| w[0] >= w[1]), "newest-first");
    use ccos_enterprise_skills_audit::TrialStatus;
    // Newest-first: the newest trial (turn 11) is pending, the older resolved
    // trial (turn 10) passed, and pending contributes no synthetic evidence.
    assert_eq!(skill.trials[0].status, TrialStatus::Pending);
    assert_eq!(skill.trials[0].evidence_id, None, "no synthetic evidence");
    assert_eq!(skill.trials[1].status, TrialStatus::Passed);
}

#[test]
fn cross_tenant_audit_is_refused() {
    let (_d, skills, trials, roles, _scope) = composed_fixture();
    let known: BTreeMap<TenantId, ()> = BTreeMap::from([(TenantId("acme".into()), ())]);
    let foreign = TenantScope::new(TenantId("globex".into()), ());
    let err = audit_provenance(
        AuditQuery {
            caller: "operator",
            scope: &foreign,
            limits: AuditLimits::default(),
            sources: AuditSources {
                skills: &skills,
                trials: &trials,
            },
            roles: &roles,
        },
        &known,
    )
    .expect_err("cross-tenant must be refused");
    assert!(matches!(
        err,
        ccos_enterprise_skills_audit::AuditError::UnknownTenant
    ));
}

#[test]
fn audit_denied_without_the_permission() {
    let (_d, skills, trials, _roles, scope) = composed_fixture();
    let known: BTreeMap<TenantId, ()> = BTreeMap::from([(TenantId("acme".into()), ())]);
    let locked = RoleBook::default();
    let err = audit_provenance(
        AuditQuery {
            caller: "operator",
            scope: &scope,
            limits: AuditLimits::default(),
            sources: AuditSources {
                skills: &skills,
                trials: &trials,
            },
            roles: &locked,
        },
        &known,
    )
    .expect_err("no role, no audit");
    assert!(matches!(
        err,
        ccos_enterprise_skills_audit::AuditError::PermissionDenied
    ));
}

#[test]
fn audit_refuses_a_forged_actor_without_the_role() {
    // Even a caller that knows the tenant name cannot read another tenant's
    // audit material; the role book is the only authority.
    let (_d, skills, trials, roles, scope) = composed_fixture();
    let known: BTreeMap<TenantId, ()> = BTreeMap::from([(TenantId("acme".into()), ())]);
    let err = audit_provenance(
        AuditQuery {
            caller: "mallory",
            scope: &scope,
            limits: AuditLimits::default(),
            sources: AuditSources {
                skills: &skills,
                trials: &trials,
            },
            roles: &roles,
        },
        &known,
    )
    .expect_err("mallory holds no auditor role");
    assert!(matches!(
        err,
        ccos_enterprise_skills_audit::AuditError::PermissionDenied
    ));
}

#[test]
fn bounded_audit_reports_truncation_without_hiding_counters() {
    let mut d = Deployment::new();
    let mut t = TenantState::new(10_000);
    t.allow_model("claude-opus");
    assert!(d.add_tenant("memorithm", "acme", t));
    let mut skills = SkillRegistry::new(SkillConfig::default()).unwrap();
    for (turn, evidence) in [(1, '1'), (2, '2'), (3, '3')] {
        skills
            .observe(&episode("skill-source", turn, evidence))
            .unwrap();
    }
    let skill_id = skills.active().next().unwrap().id.clone();
    let mut trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
    for turn in 0..20 {
        trials
            .expose("s", turn, &skills, std::slice::from_ref(&skill_id))
            .unwrap();
        trials
            .resolve_episode(&episode("s", turn, 'c'), &skills)
            .unwrap();
    }
    let scope = TenantScope::new(TenantId("acme".into()), ());
    let known: BTreeMap<TenantId, ()> = BTreeMap::from([(TenantId("acme".into()), ())]);
    let report = audit_provenance(
        AuditQuery {
            caller: "operator",
            scope: &scope,
            limits: AuditLimits {
                max_trials_per_skill: 5,
                max_evidence_per_skill: 5,
                max_skills: 16,
            },
            sources: AuditSources {
                skills: &skills,
                trials: &trials,
            },
            roles: &operator_roles(),
        },
        &known,
    )
    .expect("report");
    let skill = &report.skills[0];
    assert_eq!(skill.trials.len(), 5, "bounded rows");
    assert!(skill.truncated, "truncation is announced");
    assert_eq!(
        skill.observational.total, 20,
        "counters cover the whole ledger"
    );
}

#[test]
fn report_serializes_schema_versioned_without_raw_material() {
    let (_d, skills, trials, roles, scope) = composed_fixture();
    let known: BTreeMap<TenantId, ()> = BTreeMap::from([(TenantId("acme".into()), ())]);
    let report = audit_provenance(
        AuditQuery {
            caller: "operator",
            scope: &scope,
            limits: AuditLimits::default(),
            sources: AuditSources {
                skills: &skills,
                trials: &trials,
            },
            roles: &roles,
        },
        &known,
    )
    .expect("report");
    let text = serde_json::to_string(&report).unwrap();
    assert!(text.contains("ccos.enterprise.skill-audit/v1"));
    assert!(!text.contains("session-a"), "raw session id leaked");
    assert!(
        !text.contains("skill-source"),
        "raw session material leaked"
    );
    assert!(!text.contains("call-"), "raw call ids leaked");
    assert!(!text.contains("RAW"), "raw material leaked");
}
