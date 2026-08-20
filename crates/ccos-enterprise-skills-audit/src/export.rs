//! Digest-sealed, deterministic, offline-verifiable provenance exports.
//!
//! The exporter consumes the same [`crate::AuditQuery`] as the operator audit
//! itself. In particular, the source bundle must already have been created by
//! [`crate::AuditSources::from_stores`]; export never accepts caller-labelled
//! raw registries and therefore cannot bypass the tenant-binding boundary.

use std::collections::BTreeMap;

use ccos_enterprise_tenancy::TenantId;
use serde::{Deserialize, Serialize};

use crate::{audit_provenance, AuditQuery, ProvenanceReport, SKILL_AUDIT_SCHEMA};

/// Schema tag of a sealed provenance export.
pub const EXPORT_SCHEMA: &str = "ccos.enterprise.audit-export/v1";
const EXPORT_DIGEST_DOMAIN: &[u8] = b"ccos-enterprise-audit-export-v1";

/// One offline-verifiable export for exactly one tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedExport {
    pub schema: String,
    pub tenant: String,
    pub report_schema: String,
    pub report: ProvenanceReport,
    /// Lowercase SHA-256 over the canonical serialized report, domain-separated
    /// and length-framed by the shared Enterprise hashing helper.
    pub digest: String,
}

impl SealedExport {
    /// Recompute the digest carried by this export.
    pub fn recompute_digest(&self) -> Option<String> {
        let canonical = serde_json::to_vec(&self.report).ok()?;
        Some(ccos_enterprise_skills::framed_sha256_hex(
            EXPORT_DIGEST_DOMAIN,
            &canonical,
        ))
    }

    /// Verify this export without access to the live deployment.
    ///
    /// Verification refuses unknown schemas, an outer/inner schema mismatch,
    /// a tenant mismatch, malformed digest syntax, or changed report bytes.
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
        if self.digest.len() != 64
            || !self
                .digest
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err("export digest is not lowercase SHA-256".into());
        }
        match self.recompute_digest() {
            Some(digest) if digest == self.digest => Ok(()),
            Some(_) => Err("export digest does not match its report".into()),
            None => Err("export report is not canonically serializable".into()),
        }
    }
}

/// Produce a sealed export through the already-hardened operator audit path.
///
/// RBAC, authoritative tenant existence, source/store tenant binding, bounds,
/// corruption handling and report-level `total_skills`/`truncated` semantics
/// are inherited from [`crate::audit_provenance`]. There is no alternate audit
/// projection in this module.
pub fn seal_export(
    query: AuditQuery<'_>,
    known_tenants: &BTreeMap<TenantId, ()>,
) -> Result<SealedExport, String> {
    let report = audit_provenance(query, known_tenants)
        .map_err(|error| format!("cannot build audit export: {error}"))?;
    if report.schema != SKILL_AUDIT_SCHEMA {
        return Err(format!(
            "cannot seal unsupported report schema {:?}",
            report.schema
        ));
    }
    let tenant = report.tenant.clone();
    let canonical = serde_json::to_vec(&report)
        .map_err(|error| format!("cannot serialize export report: {error}"))?;
    let digest = ccos_enterprise_skills::framed_sha256_hex(EXPORT_DIGEST_DOMAIN, &canonical);
    Ok(SealedExport {
        schema: EXPORT_SCHEMA.to_string(),
        tenant,
        report_schema: SKILL_AUDIT_SCHEMA.to_string(),
        report,
        digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ccos_enterprise_rbac::{Permission, Role, RoleBook};
    use ccos_enterprise_skills::{
        EpisodeObservation, SkillConfig, SkillRegistry, SkillStore, SkillTrialConfig,
        SkillTrialRegistry, SkillTrialStore, ToolObservation, ToolOutcome,
    };
    use ccos_enterprise_tenancy::TenantScope;

    fn operator_roles() -> RoleBook {
        let mut book = RoleBook::default();
        let mut role = Role {
            name: "auditor".into(),
            ..Default::default()
        };
        role.permissions
            .insert(Permission(crate::SKILL_AUDIT_PERMISSION.to_string()));
        book.add_role(role);
        assert!(book.assign("operator", "auditor"));
        book
    }

    fn episode(turn: u64, evidence: char) -> EpisodeObservation {
        EpisodeObservation {
            evidence_id: evidence.to_string().repeat(64),
            session_id: "raw-session-must-not-leak".into(),
            turn,
            reason_kind: "completed".into(),
            tools: vec![ToolObservation {
                name: "memory.recall".into(),
                call_id: format!("raw-call-{turn}"),
                outcome: ToolOutcome::Succeeded,
            }],
        }
    }

    fn bound_sources<'a>(
        tenant: &str,
        skills: &'a SkillRegistry,
        trials: &'a SkillTrialRegistry,
    ) -> crate::AuditSources<'a> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir()
            .join(format!("ccos-export-source-{}-{nonce}", std::process::id()))
            .join(tenant);
        let skill_store = SkillStore::open(&root).unwrap();
        skill_store.save(skills.snapshot()).unwrap();
        let trial_store = SkillTrialStore::open(&root).unwrap();
        trial_store.save(trials.snapshot()).unwrap();
        let sources = crate::AuditSources::from_stores(
            &skill_store,
            &trial_store,
            skills,
            trials,
        )
        .unwrap();
        drop(trial_store);
        drop(skill_store);
        let _ = std::fs::remove_dir_all(root.parent().unwrap());
        sources
    }

    #[test]
    fn sealed_export_preserves_hardened_report_contract() {
        let mut skills = SkillRegistry::new(SkillConfig::default()).unwrap();
        for (turn, evidence) in [(1, '1'), (2, '2'), (3, '3')] {
            skills.observe(&episode(turn, evidence)).unwrap();
        }
        let trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        let scope = TenantScope::new(TenantId("acme".into()), ());
        let known = BTreeMap::from([(scope.tenant.clone(), ())]);
        let roles = operator_roles();
        let export = seal_export(
            AuditQuery {
                caller: "operator",
                scope: &scope,
                limits: crate::AuditLimits::default(),
                sources: bound_sources("acme", &skills, &trials),
                roles: &roles,
            },
            &known,
        )
        .unwrap();

        assert_eq!(export.tenant, "acme");
        assert_eq!(export.report.total_skills, 1);
        assert!(!export.report.truncated);
        assert!(export.verify().is_ok());
        let text = serde_json::to_string(&export).unwrap();
        assert!(!text.contains("raw-session-must-not-leak"));
        assert!(!text.contains("raw-call-"));
    }

    #[test]
    fn tenant_mismatch_is_refused_before_export_projection() {
        let skills = SkillRegistry::new(SkillConfig::default()).unwrap();
        let trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        let scope = TenantScope::new(TenantId("globex".into()), ());
        let known = BTreeMap::from([
            (TenantId("acme".into()), ()),
            (TenantId("globex".into()), ()),
        ]);
        let roles = operator_roles();
        let result = seal_export(
            AuditQuery {
                caller: "operator",
                scope: &scope,
                limits: crate::AuditLimits::default(),
                sources: bound_sources("acme", &skills, &trials),
                roles: &roles,
            },
            &known,
        );
        assert!(result
            .unwrap_err()
            .contains("does not match requested tenant"));
    }

    #[test]
    fn tampering_and_unauthorized_export_are_refused() {
        let skills = SkillRegistry::new(SkillConfig::default()).unwrap();
        let trials = SkillTrialRegistry::new(SkillTrialConfig::default()).unwrap();
        let scope = TenantScope::new(TenantId("acme".into()), ());
        let known = BTreeMap::from([(scope.tenant.clone(), ())]);
        let roles = operator_roles();
        let mut export = seal_export(
            AuditQuery {
                caller: "operator",
                scope: &scope,
                limits: crate::AuditLimits::default(),
                sources: bound_sources("acme", &skills, &trials),
                roles: &roles,
            },
            &known,
        )
        .unwrap();
        export.report.tenant = "globex".into();
        export.digest = export.recompute_digest().unwrap();
        assert!(export.verify().is_err());

        let denied = seal_export(
            AuditQuery {
                caller: "intruder",
                scope: &scope,
                limits: crate::AuditLimits::default(),
                sources: bound_sources("acme", &skills, &trials),
                roles: &RoleBook::default(),
            },
            &known,
        );
        assert!(denied.is_err());
    }
}
