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
    /// sha256 (lowercase hex) over the canonical serialization of
    /// `report` — the offline verification digest.
    pub digest: String,
    /// The report's own schema tag, carried so a recipient can refuse an
    /// unknown shape before trusting the digest.
    pub report_schema: String,
}

impl SealedExport {
    /// Recompute the seal digest from the carried report. `None` when the
    /// report cannot be serialized canonically (which would itself be a
    /// defect in the seal).
    pub fn recompute_digest(&self) -> Option<String> {
        let canonical = serde_json::to_vec(&self.report).ok()?;
        Some(seal_digest(&canonical))
    }

    /// Verify the seal offline: the digest must match the report, and the
    /// schema must be the one this product produces.
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
/// The report is built exactly as [`crate::audit_provenance`] builds it
/// (same limits, same ordering, same RBAC gate), then sealed with the
/// canonical digest. The export is verifiable offline by any recipient
/// holding the report's schema contract.
pub fn seal_export(
    caller: &str,
    roles: &RoleBook,
    tenant: &TenantId,
    skills: &SkillRegistry,
    trials: &SkillTrialRegistry,
    limits: ExportLimits,
) -> Result<SealedExport, String> {
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
        &BTreeMap::from([(tenant.clone(), ())]),
    )
    .map_err(|error| format!("cannot build audit export: {error}"))?;

    // The report is built against the tenant set; the export is explicitly
    // tenant-scoped, so the report must match.
    if report.tenant != tenant.0 {
        return Err(format!(
            "export tenant {:?} does not match report tenant {:?}",
            tenant.0, report.tenant
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
/// ledger inputs (the property that makes exports diffable).
pub fn exports_are_deterministic(
    caller: &str,
    roles: &RoleBook,
    tenant: &TenantId,
    skills: &SkillRegistry,
    trials: &SkillTrialRegistry,
    limits: ExportLimits,
) -> bool {
    match (
        seal_export(caller, roles, tenant, skills, trials, limits),
        seal_export(caller, roles, tenant, skills, trials, limits),
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

    #[test]
    fn export_is_sealed_verifiable_and_deterministic() {
        let tenant = TenantId("acme".into());
        let (skills, trials) = fixture();
        let roles = operator_roles();
        let export = seal_export(
            "operator",
            &roles,
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
            &tenant,
            &skills,
            &trials,
            ExportLimits::default()
        ));
        // An unpermissioned caller cannot produce an export at all.
        assert!(seal_export(
            "intruder",
            &RoleBook::default(),
            &tenant,
            &skills,
            &trials,
            ExportLimits::default(),
        )
        .is_err());
    }

    #[test]
    fn tampered_export_fails_verification() {
        let tenant = TenantId("acme".into());
        let (skills, trials) = fixture();
        let roles = operator_roles();
        let mut export = seal_export(
            "operator",
            &roles,
            &tenant,
            &skills,
            &trials,
            ExportLimits::default(),
        )
        .unwrap();
        export.digest = "0".repeat(64);
        assert!(export.verify().is_err(), "tampered digest is refused");
        let mut export = seal_export(
            "operator",
            &roles,
            &tenant,
            &skills,
            &trials,
            ExportLimits::default(),
        )
        .unwrap();
        export.report_schema = "ccos.enterprise.audit-export/v999".into();
        assert!(export.verify().is_err(), "unknown schema is refused");
        let mut export = seal_export(
            "operator",
            &roles,
            &tenant,
            &skills,
            &trials,
            ExportLimits::default(),
        )
        .unwrap();
        export.report.tenant = "globex".into();
        assert!(export.verify().is_err(), "tenant mismatch is refused");
    }

    #[test]
    fn export_contains_no_raw_session_material() {
        let tenant = TenantId("acme".into());
        let (skills, trials) = fixture();
        let roles = operator_roles();
        let export = seal_export(
            "operator",
            &roles,
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
        let skills = SkillRegistry::new(SkillConfig::default()).unwrap();
        let trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        let roles = operator_roles();
        let export = seal_export(
            "operator",
            &roles,
            &tenant,
            &skills,
            &trials,
            ExportLimits::default(),
        )
        .unwrap();
        assert!(export.report.empty);
        assert!(export.verify().is_ok());
    }

    #[test]
    fn export_scope_is_exactly_the_named_tenant() {
        let tenant = TenantId("acme".into());
        let (skills, trials) = fixture();
        let roles = operator_roles();
        let export = seal_export(
            "operator",
            &roles,
            &tenant,
            &skills,
            &trials,
            ExportLimits::default(),
        )
        .unwrap();
        // The export names exactly one tenant and its material is scoped to
        // it: no cross-tenant aggregate exists anywhere in the seal.
        assert_eq!(export.tenant, "acme");
        assert_eq!(export.report.tenant, "acme");
    }
}
