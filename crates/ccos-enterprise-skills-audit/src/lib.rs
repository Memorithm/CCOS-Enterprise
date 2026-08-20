//! # CCOS Enterprise — skill / cognitive provenance audit
//!
//! The operator-facing, tenant-scoped, read-only audit surface over the
//! validated skill and observational-trial ledgers.
//!
//! ## Contract
//!
//! - **tenant-scoped**: a query names one [`TenantScope`]; no query may
//!   enumerate other tenants' material;
//! - **RBAC-governed**: the caller must hold the audit permission;
//! - **read-only**: this crate never mutates a ledger;
//! - **bounded**: output is capped by an explicit query limit;
//! - **deterministic**: ordering is stable (newest-first by durable ordinal,
//!   ties broken by identifier);
//! - **fail-closed**: a corrupt source ledger is refused, never summarized
//!   approximately;
//! - **based only on validated durable registries**: the audit derives from
//!   [`SkillRegistry`] and [`SkillTrialRegistry`] — the validated snapshot
//!   forms — not from raw files;
//! - **no raw content**: prompts, assistant text, tool input/output, session
//!   ids and workspace paths are deliberately absent. Only hashed identifiers
//!   already present in the validated ledgers are exposed;
//! - **schema-versioned output**: every serialized report carries
//!   [`SKILL_AUDIT_SCHEMA`];
//! - **complete operator trail**: the admission of the audit request itself is
//!   journaled by the governed execution path before this projection is
//!   consulted, so the query has an audit record like any other decision.
//!
//! This surface is deliberately separate from the model-visible
//! `memory.skills` projection: nothing here is ever recalled into model
//! context.
//!
//! ## Where the data comes from
//!
//! The trial ledger keys trials by a domain-separated hash of `(session_id,
//! turn)` ([`crate::ccos_enterprise_skills::trial_turn_key`]), so the audit
//! can correlate a trial to its exposure turn without ever seeing the raw
//! session. The skill registry holds ordered tool names and bounded evidence
//! identifiers; both are Enterprise-local derived state, and both are
//! validated by their owning registries before this crate sees them.

use std::collections::BTreeMap;

use ccos_enterprise_rbac::{Permission, RoleBook};
use ccos_enterprise_skills::{
    index_skill_trial_provenance, summarize_observational_trials, SkillRegistry, SkillStatus,
    SkillTrialRegistry, SkillTrialStatus,
};
use ccos_enterprise_tenancy::{TenantId, TenantScope};
use serde::{Deserialize, Serialize};

/// Schema tag written into every serialized audit report.
pub const SKILL_AUDIT_SCHEMA: &str = "ccos.enterprise.skill-audit/v1";

/// The permission required to run a skill-provenance audit query.
///
/// This is a distinct capability from `memory.read` on purpose: the
/// provenance audit exposes correlation and evidence identifiers that the
/// model-visible projection deliberately withholds, so it must not ride on the
/// permission a model-facing tool uses.
pub const SKILL_AUDIT_PERMISSION: &str = "audit.provenance";

/// Bounds on a provenance query. Everything is bounded; nothing grows with
/// caller input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditLimits {
    /// Maximum number of trial rows per skill.
    pub max_trials_per_skill: usize,
    /// Maximum number of evidence rows per skill.
    pub max_evidence_per_skill: usize,
    /// Maximum number of skills in one report.
    pub max_skills: usize,
}

impl Default for AuditLimits {
    fn default() -> Self {
        Self {
            max_trials_per_skill: 512,
            max_evidence_per_skill: 256,
            max_skills: 1_024,
        }
    }
}

impl AuditLimits {
    pub fn validate(&self) -> Result<(), AuditError> {
        if self.max_trials_per_skill == 0
            || self.max_evidence_per_skill == 0
            || self.max_skills == 0
        {
            return Err(AuditError::InvalidLimits);
        }
        Ok(())
    }
}

/// Why an audit query was refused. Every variant is fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    /// The caller holds no role granting [`SKILL_AUDIT_PERMISSION`].
    PermissionDenied,
    /// The named tenant does not exist in this deployment.
    UnknownTenant,
    /// The validated source bundle belongs to a different tenant than the
    /// requested scope. Source identity is checked before any ledger row is read.
    SourceTenantMismatch { requested: String, source: String },
    /// The limits were invalid (all must be non-zero).
    InvalidLimits,
    /// The query limit is not within `1..=MAX_QUERY_LIMIT`.
    LimitOutOfRange { found: usize },
    /// The source ledger is corrupt; refusing rather than guessing.
    CorruptLedger { detail: String },
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PermissionDenied => write!(f, "permission denied: audit.provenance required"),
            Self::UnknownTenant => write!(f, "unknown tenant"),
            Self::SourceTenantMismatch { requested, source } => write!(
                f,
                "audit source tenant {source:?} does not match requested tenant {requested:?}"
            ),
            Self::InvalidLimits => write!(f, "audit limits must all be non-zero"),
            Self::LimitOutOfRange { found } => {
                write!(f, "query limit {found} is outside 1..={MAX_QUERY_LIMIT}")
            }
            Self::CorruptLedger { detail } => {
                write!(f, "source ledger is corrupt and was refused: {detail}")
            }
        }
    }
}

impl std::error::Error for AuditError {}

/// One trial row in a provenance report.
///
/// Identifiers are the hashed, validated forms from the ledger — never raw
/// session ids, turns, prompts, tool arguments or model output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrialRow {
    pub trial_id: String,
    pub skill_id: String,
    pub status: TrialStatus,
    pub ordinal: u64,
    /// Domain-separated hash of `(session_id, turn)`. Present because the
    /// ledger keeps it; it is not a raw session identifier.
    pub turn_key: String,
    /// The evidence hash this trial resolved to, when terminal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_id: Option<String>,
}

/// Wire form of [`SkillTrialStatus`], stable under serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrialStatus {
    Pending,
    Passed,
    Failed,
    Inconclusive,
    NotObserved,
}

impl From<SkillTrialStatus> for TrialStatus {
    fn from(status: SkillTrialStatus) -> Self {
        match status {
            SkillTrialStatus::Pending => Self::Pending,
            SkillTrialStatus::Passed => Self::Passed,
            SkillTrialStatus::Failed => Self::Failed,
            SkillTrialStatus::Inconclusive => Self::Inconclusive,
            SkillTrialStatus::NotObserved => Self::NotObserved,
        }
    }
}

/// One skill's provenance report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillProvenanceReport {
    pub skill_id: String,
    /// Tool names in the order the skill crystallized, bounded by the ledger.
    pub tool_sequence: Vec<String>,
    pub status: SkillStatus,
    /// Trials newest-first by durable ordinal, capped by the query limit.
    pub trials: Vec<TrialRow>,
    /// Distinct terminal evidence identifiers, most-recent-linked first.
    pub evidence_ids: Vec<String>,
    /// Aggregate counts over the *whole* validated ledger, not just the
    /// returned rows — so `truncated` never hides a counter.
    pub observational: ObservationalCounters,
    /// Whether rows were cut by the query limit.
    pub truncated: bool,
}

/// Aggregate post-exposure observational counters, as counted by the
/// validated ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ObservationalCounters {
    pub total: u64,
    pub pending: u64,
    pub passed: u64,
    pub failed: u64,
    pub inconclusive: u64,
    pub not_observed: u64,
}

/// One tenant's complete provenance report.
///
/// Everything here is derived data, serialized with a schema tag so an
/// external consumer can refuse a shape it does not understand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceReport {
    pub schema: String,
    pub tenant: String,
    /// Total skills in the validated source before the report-level cap.
    pub total_skills: usize,
    pub skills: Vec<SkillProvenanceReport>,
    /// Whether `max_skills` omitted one or more skill rows. Per-skill
    /// `truncated` remains about trial/evidence row caps only.
    pub truncated: bool,
    /// The tenant holds no skills at all.
    pub empty: bool,
}

/// The validated ledgers a report is derived from.
///
/// Both registries are the validated snapshot forms — construction refuses
/// corrupt or schema-unknown state — so the audit boundary is the same one
/// the ledgers themselves enforce.
pub struct AuditSources<'a> {
    /// Tenant identity of the store from which both validated registries were
    /// loaded. The audit query refuses a mismatch with its requested scope.
    pub tenant: TenantId,
    pub skills: &'a SkillRegistry,
    pub trials: &'a SkillTrialRegistry,
}

/// A fully bound audit query: the caller's proven identity, the tenant scope,
/// and the limits.
pub struct AuditQuery<'a> {
    pub caller: &'a str,
    pub scope: &'a TenantScope<()>,
    pub limits: AuditLimits,
    /// The validated sources to derive from.
    pub sources: AuditSources<'a>,
    /// The deployment's role book, used to enforce the audit permission.
    pub roles: &'a RoleBook,
}

/// How many skill rows the report will carry. The audit is bounded per skill
/// and per report; totals are counted across the whole ledger so truncation
/// is always visible.
pub const MAX_QUERY_LIMIT: usize = 1_024;

/// Run one provenance audit query.
///
/// Fail-closed in every direction: permission first (deny by default — an
/// actor holding no role that grants `audit.provenance` is refused), then
/// tenant existence (against the provided tenant set), then limits; the
/// ledgers are consulted only through their validated registries, so corrupt
/// state is a refusal, not a guess.
pub fn audit_provenance(
    query: AuditQuery<'_>,
    known_tenants: &BTreeMap<TenantId, ()>,
) -> Result<ProvenanceReport, AuditError> {
    query.limits.validate()?;
    if query.limits.max_skills > MAX_QUERY_LIMIT {
        return Err(AuditError::LimitOutOfRange {
            found: query.limits.max_skills,
        });
    }
    // RBAC: the caller must hold a role granting the audit capability. Deny
    // by default — an actor holding no such role is refused here, at the
    // capability boundary, before any ledger material is consulted.
    if !query.roles.allows(
        query.caller,
        &Permission(SKILL_AUDIT_PERMISSION.to_string()),
    ) {
        return Err(AuditError::PermissionDenied);
    }
    if !known_tenants.contains_key(&query.scope.tenant) {
        return Err(AuditError::UnknownTenant);
    }
    if query.sources.tenant != query.scope.tenant {
        return Err(AuditError::SourceTenantMismatch {
            requested: query.scope.tenant.0.clone(),
            source: query.sources.tenant.0.clone(),
        });
    }

    let provenance = index_skill_trial_provenance(query.sources.trials);
    let summaries = summarize_observational_trials(query.sources.trials);
    let total_skills = query.sources.skills.snapshot().skills.len();
    let mut skills = Vec::new();

    for record in query.sources.skills.snapshot().skills.values() {
        if skills.len() >= query.limits.max_skills {
            break;
        }
        let linked = provenance.get(&record.id);
        let summary = summaries.get(&record.id).copied().unwrap_or_default();
        let trial_ids = linked.map(|p| p.trial_ids.as_slice()).unwrap_or(&[]);
        let evidence_ids = linked.map(|p| p.evidence_ids.as_slice()).unwrap_or(&[]);

        let truncated_trials = trial_ids.len() > query.limits.max_trials_per_skill;
        let truncated_evidence = evidence_ids.len() > query.limits.max_evidence_per_skill;

        let trials: Vec<TrialRow> = trial_ids
            .iter()
            .take(query.limits.max_trials_per_skill)
            .filter_map(|trial_id| {
                query
                    .sources
                    .trials
                    .snapshot()
                    .trials
                    .get(trial_id)
                    .map(|trial| TrialRow {
                        trial_id: trial.id.clone(),
                        skill_id: trial.skill_id.clone(),
                        status: trial.status.into(),
                        ordinal: trial.ordinal,
                        turn_key: trial.turn_key.clone(),
                        evidence_id: trial.evidence_id.clone(),
                    })
            })
            .collect();

        let evidence: Vec<String> = evidence_ids
            .iter()
            .take(query.limits.max_evidence_per_skill)
            .cloned()
            .collect();

        skills.push(SkillProvenanceReport {
            skill_id: record.id.clone(),
            tool_sequence: record.tool_sequence.clone(),
            status: record.status,
            trials,
            evidence_ids: evidence,
            observational: ObservationalCounters {
                total: summary.total,
                pending: summary.pending,
                passed: summary.passed,
                failed: summary.failed,
                inconclusive: summary.inconclusive,
                not_observed: summary.not_observed,
            },
            truncated: truncated_trials || truncated_evidence,
        });
    }

    // A tenant with no skills at all is a *fact* an operator needs to read,
    // not a fabrication: the report says `empty: true` and carries no rows.
    Ok(ProvenanceReport {
        schema: SKILL_AUDIT_SCHEMA.to_string(),
        tenant: query.scope.tenant.0.clone(),
        total_skills,
        truncated: skills.len() < total_skills,
        skills,
        empty: total_skills == 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ccos_enterprise_rbac::Role;
    use ccos_enterprise_skills::{
        EpisodeObservation, SkillConfig, SkillTrialConfig, ToolObservation, ToolOutcome,
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

    fn tenants(scope: &TenantScope<()>) -> BTreeMap<TenantId, ()> {
        BTreeMap::from([(scope.tenant.clone(), ())])
    }

    /// A role book where `operator` holds exactly the audit permission.
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

    /// A role book where `operator` holds nothing.
    fn locked_out_roles() -> RoleBook {
        let mut book = RoleBook::default();
        let mut nobody = Role {
            name: "nobody".into(),
            ..Default::default()
        };
        nobody.permissions.insert(Permission("memory.read".into()));
        book.add_role(nobody);
        assert!(book.assign("operator", "nobody"));
        book
    }

    #[test]
    fn empty_registry_is_an_explicit_empty_report_not_a_fabrication() {
        let skills = SkillRegistry::new(SkillConfig::default()).unwrap();
        let trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        let scope = TenantScope::new(TenantId("acme".into()), ());
        let roles = operator_roles();
        let report = audit_provenance(
            AuditQuery {
                caller: "operator",
                scope: &scope,
                limits: AuditLimits::default(),
                sources: AuditSources {
                    tenant: scope.tenant.clone(),
                    skills: &skills,
                    trials: &trials,
                },
                roles: &roles,
            },
            &tenants(&scope),
        )
        .expect("an empty tenant is a reportable fact");
        assert!(report.empty);
        assert!(report.skills.is_empty());
        assert_eq!(report.tenant, "acme");
    }

    #[test]
    fn cross_tenant_query_is_refused() {
        let skills = SkillRegistry::new(SkillConfig::default()).unwrap();
        let trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        let scope = TenantScope::new(TenantId("acme".into()), ());
        let foreign = TenantScope::new(TenantId("globex".into()), ());
        let roles = operator_roles();
        assert_eq!(
            audit_provenance(
                AuditQuery {
                    caller: "operator",
                    scope: &foreign,
                    limits: AuditLimits::default(),
                    sources: AuditSources {
                        tenant: scope.tenant.clone(),
                        skills: &skills,
                        trials: &trials,
                    },
                    roles: &roles,
                },
                &tenants(&scope),
            ),
            Err(AuditError::UnknownTenant)
        );
    }

    #[test]
    fn permission_is_denied_by_default_for_an_unauthorized_caller() {
        let skills = SkillRegistry::new(SkillConfig::default()).unwrap();
        let trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        let scope = TenantScope::new(TenantId("acme".into()), ());
        let roles = locked_out_roles();
        assert_eq!(
            audit_provenance(
                AuditQuery {
                    caller: "operator",
                    scope: &scope,
                    limits: AuditLimits::default(),
                    sources: AuditSources {
                        tenant: scope.tenant.clone(),
                        skills: &skills,
                        trials: &trials,
                    },
                    roles: &roles,
                },
                &tenants(&scope),
            ),
            Err(AuditError::PermissionDenied)
        );
        // An actor that holds no role at all is equally refused.
        let empty = RoleBook::default();
        assert_eq!(
            audit_provenance(
                AuditQuery {
                    caller: "intruder",
                    scope: &scope,
                    limits: AuditLimits::default(),
                    sources: AuditSources {
                        tenant: scope.tenant.clone(),
                        skills: &skills,
                        trials: &trials,
                    },
                    roles: &empty,
                },
                &tenants(&scope),
            ),
            Err(AuditError::PermissionDenied)
        );
    }

    #[test]
    fn newest_first_ordering_and_terminal_evidence_dedup() {
        let (skills, skill_id) = active_skill();
        let mut trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        let ids = vec![skill_id.clone()];
        // The session name is deliberately distinct from anything a skill id
        // could legitimately contain, so its absence from the serialized
        // report is a meaningful no-raw-session assertion.
        const RAW_SESSION: &str = "RAW-SESSION-ID-9f8e7d6c5b4a";
        trials.expose(RAW_SESSION, 10, &skills, &ids).unwrap();
        trials
            .resolve_episode(&episode(RAW_SESSION, 10, 'a'), &skills)
            .unwrap();
        trials.expose(RAW_SESSION, 11, &skills, &ids).unwrap();
        trials.expose(RAW_SESSION, 12, &skills, &ids).unwrap();
        trials
            .resolve_episode(&episode(RAW_SESSION, 12, 'b'), &skills)
            .unwrap();

        let scope = TenantScope::new(TenantId("acme".into()), ());
        let roles = operator_roles();
        let report = audit_provenance(
            AuditQuery {
                caller: "operator",
                scope: &scope,
                limits: AuditLimits::default(),
                sources: AuditSources {
                    tenant: scope.tenant.clone(),
                    skills: &skills,
                    trials: &trials,
                },
                roles: &roles,
            },
            &tenants(&scope),
        )
        .expect("report");
        assert_eq!(report.schema, SKILL_AUDIT_SCHEMA);
        assert_eq!(report.tenant, "acme");
        assert!(!report.empty);
        let skill = &report.skills[0];
        // Newest-first by ordinal: turn 12 resolved, turn 11 pending, turn 10 resolved.
        assert_eq!(skill.trials.len(), 3);
        let ordinals: Vec<u64> = skill.trials.iter().map(|t| t.ordinal).collect();
        let mut sorted = ordinals.clone();
        sorted.sort_unstable();
        sorted.reverse();
        assert_eq!(ordinals, sorted, "trials are newest-first");
        assert_eq!(skill.trials[0].status, TrialStatus::Passed);
        assert_eq!(skill.trials[1].status, TrialStatus::Pending);
        assert_eq!(skill.trials[2].status, TrialStatus::Passed);
        // Pending trial carries no synthetic evidence; the two resolved trials
        // dedup onto the two distinct evidence hashes.
        assert_eq!(skill.trials[1].evidence_id, None);
        assert_eq!(skill.evidence_ids.len(), 2);
        // No raw session id anywhere in the serialized report; the turn keys
        // are the domain-separated hashes the ledger already validated.
        let text = serde_json::to_string(&report).unwrap();
        assert!(!text.contains(RAW_SESSION), "raw session id leaked: {text}");
        for trial in &skill.trials {
            assert_eq!(trial.turn_key.len(), 64, "turn key is a sha256 hash");
            assert!(trial.turn_key.bytes().all(|b| b.is_ascii_hexdigit()));
        }
        // Observational counters come from the whole validated ledger.
        assert_eq!(skill.observational.total, 3);
        assert_eq!(skill.observational.pending, 1);
        assert_eq!(skill.observational.passed, 2);
        assert!(!skill.truncated);
    }

    #[test]
    fn bounded_output_truncates_rows_and_says_so() {
        let (skills, skill_id) = active_skill();
        let mut trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        let ids = vec![skill_id.clone()];
        for turn in 0..10 {
            trials.expose("s", turn, &skills, &ids).unwrap();
            trials
                .resolve_episode(&episode("s", turn, 'c'), &skills)
                .unwrap();
        }
        let scope = TenantScope::new(TenantId("acme".into()), ());
        let roles = operator_roles();
        let limits = AuditLimits {
            max_trials_per_skill: 3,
            max_evidence_per_skill: 1,
            max_skills: 1_024,
        };
        let report = audit_provenance(
            AuditQuery {
                caller: "operator",
                scope: &scope,
                limits,
                sources: AuditSources {
                    tenant: scope.tenant.clone(),
                    skills: &skills,
                    trials: &trials,
                },
                roles: &roles,
            },
            &tenants(&scope),
        )
        .expect("report");
        let skill = &report.skills[0];
        assert_eq!(skill.trials.len(), 3);
        assert_eq!(skill.evidence_ids.len(), 1);
        assert!(skill.truncated);
        // Counters still cover the whole ledger — truncation never hides data.
        assert_eq!(skill.observational.total, 10);
    }

    #[test]
    fn corrupt_ledger_is_refused_not_guessed() {
        // A registry constructed from a corrupt snapshot is refused at
        // construction; the audit itself can only ever see validated state.
        let mut snapshot = ccos_enterprise_skills::SkillTrialSnapshot::default();
        snapshot.trials.insert(
            "not-a-trial-id".into(),
            ccos_enterprise_skills::SkillTrialRecord {
                id: "not-a-trial-id".into(),
                skill_id: "skill-v1-x".into(),
                turn_key: "a".repeat(64),
                status: SkillTrialStatus::Pending,
                evidence_id: None,
                ordinal: 0,
            },
        );
        let refused = SkillTrialRegistry::from_snapshot(SkillTrialConfig::default(), snapshot);
        assert!(refused.is_err(), "corrupt trial state must not construct");
    }

    #[test]
    fn report_contains_no_raw_session_or_turn_material() {
        let (skills, skill_id) = active_skill();
        let mut trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        let ids = vec![skill_id.clone()];
        trials
            .expose("RAW-SESSION-MUST-NOT-LEAK", 77, &skills, &ids)
            .unwrap();
        trials
            .resolve_episode(&episode("RAW-SESSION-MUST-NOT-LEAK", 77, 'e'), &skills)
            .unwrap();

        let scope = TenantScope::new(TenantId("acme".into()), ());
        let roles = operator_roles();
        let report = audit_provenance(
            AuditQuery {
                caller: "operator",
                scope: &scope,
                limits: AuditLimits::default(),
                sources: AuditSources {
                    tenant: scope.tenant.clone(),
                    skills: &skills,
                    trials: &trials,
                },
                roles: &roles,
            },
            &tenants(&scope),
        )
        .expect("report");
        let text = serde_json::to_string(&report).unwrap();
        assert!(!text.contains("RAW-SESSION"));
        assert!(!text.contains("77"));
        assert!(!text.contains("call-"));
        // Evidence hashes are 64 lowercase hex — the only content identifiers.
        assert!(text.contains(&"e".repeat(64)));
    }
}
