//! Digest-sealed, deterministic, offline-verifiable audit exports
//! (docs/COGNITIVE_AUDIT.md).
//!
//! An export is a tenant-scoped, bounded, schema-versioned snapshot of the
//! provenance audit for one tenant, sealed with a canonical digest so a
//! recipient can verify it offline against the original ledgers. There is no
//! cross-tenant aggregate: an export names exactly one tenant and carries
//! only that tenant's material.

use std::collections::BTreeMap;

use ccos_enterprise_rbac::RoleBook;
use ccos_enterprise_skills::{SkillRegistry, SkillTrialRegistry};
use ccos_enterprise_tenancy::TenantId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{ProvenanceReport, SKILL_AUDIT_SCHEMA};

/// Schema tag of a sealed export.
pub const EXPORT_SCHEMA: &str = "ccos.enterprise.audit-export/v1";

/// One sealed audit export for one tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedExport {
    pub schema: String,
    pub tenant: String,
    /// The provenance report, serialized inside the seal.
    pub report: ProvenanceReport,
    /// sha256 (lowercase hex) over the canonical serialization of `report`.
    pub digest: String,
    /// The report's own schema tag, duplicated outside the payload only so a
    /// recipient can reject an unsupported inner shape before interpreting it.
    /// Verification requires this value and `report.schema` to agree exactly.
    pub report_schema: String,
}

impl SealedExport {
    /// Recompute the seal digest from the carried report.
    pub fn recompute_digest(&self) -> Option<String> {
        let canonical = serde_json::to_vec(&self.report).ok()?;
        Some(seal_digest(&canonical))
    }

    /// Verify the seal offline: both schema declarations must be recognized
    /// and identical, tenant scope must agree, and the digest must match the
    /// exact carried report.
    pub fn verify(&self) -> Result<(), String> {
        if self.schema != EXPORT_SCHEMA {
            return Err(format!("unrecognized export schema {:?}", self.schema));
        }
        if self.report_schema != SKILL_AUDIT_SCHEMA {
            return Err(format!(
                "unrecognized report schema {:?}",
                self.report_schema
            ));
        }
        if self.report.schema != SKILL_AUDIT_SCHEMA {
            return Err(format!(
                "unrecognized embedded report schema {:?}",
                self.report.schema
            ));
        }
        if self.report_schema != self.report.schema {
            return Err("outer and embedded report schemas disagree".into());
        }
        if self.report.tenant != self.tenant {
            return Err("export tenant does not match report tenant".into());
        }
        match self.recompute_digest() {
            Some(digest) if digest == self.digest => Ok(()),
            Some(_) => Err("export digest does not match its report".into()),
            None => Err("export report is not canonically serializable".into()),
        }
    }
}

/// Canonical seal digest over the report's canonical serialization.
fn seal_digest(report_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ccos-enterprise-audit-export-v1");
    hasher.update((report_bytes.len() as u64).to_be_bytes());
    hasher.update(report_bytes);
    let mut out = String::with_capacity(64);
    use std::fmt::Write as _;
    for byte in hasher.finalize() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The bounds of one export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportLimits {
    pub max_trials_per_skill: usize,
    pub max_evidence_per_skill: usize,
    pub max_skills: usize,
}

impl Default for ExportLimits {
    fn default() -> Self {
        Self {
            max_trials_per_skill: 512,
            max_evidence_per_skill: 256,
            max_skills: 1_024,
        }
    }
}

/// Produce a sealed, deterministic, tenant-scoped audit export.
///
/// `known_tenants` must be the deployment's authoritative tenant set. The
/// exporter deliberately does **not** manufacture that set from the requested
/// tenant: doing so would turn the existence check into a tautology. Source
/// ownership is then enforced by the audit projection's own tenant-binding
/// contract; this function never weakens it.
pub fn seal_export(
    caller: &str,
    roles: &RoleBook,
    known_tenants: &BTreeMap<TenantId, ()>,
    tenant: &TenantId,
    skills: &SkillRegistry,
    trials: &SkillTrialRegistry,
    limits: ExportLimits,
) -> Result<SealedExport, String> {
    if !known_tenants.contains_key(tenant) {
        return Err(format!(
            "cannot build audit export: unknown tenant {:?}",
            tenant.0
        ));
    }
    let report = crate::audit_provenance(
        crate::AuditQuery {
            caller,
            scope: &ccos_enterprise_tenancy::TenantScope::new(tenant.clone(), ()),
            limits: crate::AuditLimits {
                max_trials_per_skill: limits.max_trials_per_skill,
                max_evidence_per_skill: limits.max_evidence_per_skill,
                max_skills: limits.max_skills,
            },
            sources: crate::AuditSources { skills, trials },
            roles,
        },
        known_tenants,
    )
    .map_err(|error| format!("cannot build audit export: {error}"))?;

    if report.tenant != tenant.0 {
        return Err(format!(
            "export tenant {:?} does not match report tenant {:?}",
            tenant.0, report.tenant
        ));
    }
    if report.schema != SKILL_AUDIT_SCHEMA {
        return Err(format!(
            "cannot seal unsupported report schema {:?}",
            report.schema
        ));
    }
    let canonical = serde_json::to_vec(&report)
        .map_err(|error| format!("cannot serialize export report: {error}"))?;
    Ok(SealedExport {
        schema: EXPORT_SCHEMA.to_string(),
        tenant: tenant.0.clone(),
        report_schema: SKILL_AUDIT_SCHEMA.to_string(),
        digest: seal_digest(&canonical),
        report,
    })
}

/// Whether a sealed export is byte-for-byte deterministic for the same
/// authoritative tenant set and ledger inputs.
pub fn exports_are_deterministic(
    caller: &str,
    roles: &RoleBook,
    known_tenants: &BTreeMap<TenantId, ()>,
    tenant: &TenantId,
    skills: &SkillRegistry,
    trials: &SkillTrialRegistry,
    limits: ExportLimits,
) -> bool {
    match (
        seal_export(caller, roles, known_tenants, tenant, skills, trials, limits),
        seal_export(caller, roles, known_tenants, tenant, skills, trials, limits),
    ) {
        (Ok(first), Ok(second)) => first == second,
        _ => false,
    }
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

    fn fixture() -> (SkillRegistry, SkillTrialRegistry) {
        let mut skills = SkillRegistry::new(SkillConfig::default()).unwrap();
        for (turn, evidence) in [(1, '1'), (2, '2'), (3, '3')] {
            skills.observe(&episode("source", turn, evidence)).unwrap();
        }
        let skill_id = skills.active().next().unwrap().id.clone();
        let mut trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        trials
            .expose("session-x", 10, &skills, std::slice::from_ref(&skill_id))
            .unwrap();
        trials
            .resolve_episode(&episode("session-x", 10, 'a'), &skills)
            .unwrap();
        (skills, trials)
    }

    fn operator_roles() -> RoleBook {
        let mut book = RoleBook::default();
        let mut auditor = Role {
            name: "auditor".into(),
            ..Default::default()
        };
        auditor.permissions.insert(ccos_enterprise_rbac::Permission(
            crate::SKILL_AUDIT_PERMISSION.to_string(),
        ));
        book.add_role(auditor);
        assert!(book.assign("operator", "auditor"));
        book
    }

    fn tenants(tenant: &TenantId) -> BTreeMap<TenantId, ()> {
        BTreeMap::from([(tenant.clone(), ())])
    }

    #[test]
    fn export_is_sealed_verifiable_and_deterministic() {
        let tenant = TenantId("acme".into());
        let known = tenants(&tenant);
        let (skills, trials) = fixture();
        let roles = operator_roles();
        let export = seal_export(
            "operator",
            &roles,
            &known,
            &tenant,
            &skills,
            &trials,
            ExportLimits::default(),
        )
        .unwrap();
        assert_eq!(export.schema, EXPORT_SCHEMA);
        assert_eq!(export.tenant, "acme");
        assert!(export.verify().is_ok(), "seal verifies offline");
        assert!(exports_are_deterministic(
            "operator",
            &roles,
            &known,
            &tenant,
            &skills,
            &trials,
            ExportLimits::default()
        ));
        assert!(seal_export(
            "intruder",
            &RoleBook::default(),
            &known,
            &tenant,
            &skills,
            &trials,
            ExportLimits::default(),
        )
        .is_err());
    }

    #[test]
    fn nonexistent_tenant_is_refused_by_authoritative_set() {
        let acme = TenantId("acme".into());
        let globex = TenantId("globex".into());
        let known = tenants(&acme);
        let (skills, trials) = fixture();
        assert!(seal_export(
            "operator",
            &operator_roles(),
            &known,
            &globex,
            &skills,
            &trials,
            ExportLimits::default(),
        )
        .is_err());
    }

    #[test]
    fn tampered_export_fails_verification_including_inner_schema() {
        let tenant = TenantId("acme".into());
        let known = tenants(&tenant);
        let (skills, trials) = fixture();
        let roles = operator_roles();
        let make = || {
            seal_export(
                "operator",
                &roles,
                &known,
                &tenant,
                &skills,
                &trials,
                ExportLimits::default(),
            )
            .unwrap()
        };
        let mut export = make();
        export.digest = "0".repeat(64);
        assert!(export.verify().is_err(), "tampered digest is refused");

        let mut export = make();
        export.report_schema = "ccos.enterprise.skill-audit/v999".into();
        assert!(
            export.verify().is_err(),
            "unknown outer report schema is refused"
        );

        let mut export = make();
        export.report.schema = "ccos.enterprise.skill-audit/v999".into();
        export.digest = export.recompute_digest().unwrap();
        assert!(
            export.verify().is_err(),
            "an unknown embedded schema is refused even with a matching digest"
        );

        let mut export = make();
        export.report.tenant = "globex".into();
        export.digest = export.recompute_digest().unwrap();
        assert!(export.verify().is_err(), "tenant mismatch is refused");
    }

    #[test]
    fn export_contains_no_raw_session_material() {
        let tenant = TenantId("acme".into());
        let known = tenants(&tenant);
        let (skills, trials) = fixture();
        let roles = operator_roles();
        let export = seal_export(
            "operator",
            &roles,
            &known,
            &tenant,
            &skills,
            &trials,
            ExportLimits::default(),
        )
        .unwrap();
        let text = serde_json::to_string(&export).unwrap();
        assert!(!text.contains("session-x"), "raw session leaked");
        assert!(!text.contains("call-"), "raw call ids leaked");
    }

    #[test]
    fn empty_ledger_export_is_an_explicit_empty_seal() {
        let tenant = TenantId("acme".into());
        let known = tenants(&tenant);
        let skills = SkillRegistry::new(SkillConfig::default()).unwrap();
        let trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        let roles = operator_roles();
        let export = seal_export(
            "operator",
            &roles,
            &known,
            &tenant,
            &skills,
            &trials,
            ExportLimits::default(),
        )
        .unwrap();
        assert!(export.report.empty);
        assert!(export.verify().is_ok());
    }
}
