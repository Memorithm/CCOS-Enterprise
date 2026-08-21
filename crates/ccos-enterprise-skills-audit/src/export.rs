//! Authenticated, deterministic, offline-verifiable provenance exports.
//!
//! The exporter consumes the same [`crate::AuditQuery`] as the operator audit
//! itself. In particular, the source bundle must already have been created by
//! [`crate::AuditSources::from_stores`]; export never accepts caller-labelled
//! raw registries and therefore cannot bypass the tenant-binding boundary.
//!
//! An export never authenticates itself. Integrity is carried by a deterministic
//! report digest, while authenticity is established only through a caller-
//! supplied [`ExportVerifier`] representing an external trust anchor.

use std::collections::BTreeMap;

use ccos_enterprise_tenancy::TenantId;
use serde::{Deserialize, Serialize};

use crate::{audit_provenance, AuditQuery, ProvenanceReport, SKILL_AUDIT_SCHEMA};

/// Schema tag of a sealed provenance export.
pub const EXPORT_SCHEMA: &str = "ccos.enterprise.audit-export/v1";
const EXPORT_DIGEST_DOMAIN: &[u8] = b"ccos-enterprise-audit-export-v1";
const MAX_AUTH_LABEL_BYTES: usize = 128;

/// Signing boundary supplied by the operator/deployment.
///
/// Production implementations should use a deployment-controlled signing key
/// (for example a hardware-backed asymmetric key). The private key is never
/// stored in, or derived from, the export itself.
pub trait ExportSigner {
    fn algorithm(&self) -> &str;
    fn key_id(&self) -> &str;
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String>;
}

/// Verification boundary supplied by the offline verifier.
///
/// The verifier is the trust anchor: an export cannot choose a different key
/// or algorithm and still pass verification because both labels must match the
/// verifier before signature verification is attempted.
pub trait ExportVerifier {
    fn algorithm(&self) -> &str;
    fn key_id(&self) -> &str;
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), String>;
}

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
    /// Operator-selected signing algorithm, authenticated by the signature.
    pub signature_algorithm: String,
    /// Stable identifier of the external verification key/trust anchor.
    pub signing_key_id: String,
    /// Lowercase hexadecimal signature bytes returned by [`ExportSigner`].
    pub signature: String,
}

#[derive(Serialize)]
struct SignedFields<'a> {
    schema: &'a str,
    tenant: &'a str,
    report_schema: &'a str,
    digest: &'a str,
    signature_algorithm: &'a str,
    signing_key_id: &'a str,
}

fn valid_auth_label(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_AUTH_LABEL_BYTES && !value.chars().any(char::is_control)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }

    if value.is_empty() || !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Some((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

impl SealedExport {
    /// Recompute the report integrity digest carried by this export.
    pub fn recompute_digest(&self) -> Option<String> {
        let canonical = serde_json::to_vec(&self.report).ok()?;
        Some(ccos_enterprise_skills::framed_sha256_hex(
            EXPORT_DIGEST_DOMAIN,
            &canonical,
        ))
    }

    fn signed_message(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&SignedFields {
            schema: &self.schema,
            tenant: &self.tenant,
            report_schema: &self.report_schema,
            digest: &self.digest,
            signature_algorithm: &self.signature_algorithm,
            signing_key_id: &self.signing_key_id,
        })
        .map_err(|error| format!("cannot serialize authenticated export fields: {error}"))
    }

    /// Verify report integrity and authenticity against an external trust
    /// anchor. There is intentionally no self-contained `verify()` method.
    pub fn verify_with(&self, verifier: &impl ExportVerifier) -> Result<(), String> {
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
            Some(digest) if digest == self.digest => {}
            Some(_) => return Err("export digest does not match its report".into()),
            None => return Err("export report is not canonically serializable".into()),
        }
        if !valid_auth_label(&self.signature_algorithm) || !valid_auth_label(&self.signing_key_id) {
            return Err("export signature metadata is invalid".into());
        }
        if verifier.algorithm() != self.signature_algorithm {
            return Err("export signature algorithm is not trusted by verifier".into());
        }
        if verifier.key_id() != self.signing_key_id {
            return Err("export signing key is not the configured trust anchor".into());
        }
        let signature = decode_hex(&self.signature)
            .ok_or_else(|| "export signature is not lowercase hex".to_string())?;
        verifier.verify(&self.signed_message()?, &signature)
    }
}

/// Produce an authenticated export through the already-hardened operator audit
/// path and a deployment-controlled signing boundary.
///
/// RBAC, authoritative tenant existence, source/store tenant binding, bounds,
/// corruption handling and report-level `total_skills`/`truncated` semantics
/// are inherited from [`crate::audit_provenance`]. There is no alternate audit
/// projection in this module.
pub fn seal_export(
    query: AuditQuery<'_>,
    known_tenants: &BTreeMap<TenantId, ()>,
    signer: &impl ExportSigner,
) -> Result<SealedExport, String> {
    if !valid_auth_label(signer.algorithm()) || !valid_auth_label(signer.key_id()) {
        return Err("export signer metadata is invalid".into());
    }
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
    let mut export = SealedExport {
        schema: EXPORT_SCHEMA.to_string(),
        tenant,
        report_schema: SKILL_AUDIT_SCHEMA.to_string(),
        report,
        digest,
        signature_algorithm: signer.algorithm().to_string(),
        signing_key_id: signer.key_id().to_string(),
        signature: String::new(),
    };
    let signature = signer.sign(&export.signed_message()?)?;
    if signature.is_empty() {
        return Err("export signer returned an empty signature".into());
    }
    export.signature = encode_hex(&signature);
    Ok(export)
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

    struct TestTrustAnchor {
        key_id: &'static str,
        secret: &'static [u8],
    }

    impl TestTrustAnchor {
        fn signature(&self, message: &[u8]) -> Vec<u8> {
            let mut material = Vec::with_capacity(self.secret.len() + message.len());
            material.extend_from_slice(self.secret);
            material.extend_from_slice(message);
            ccos_enterprise_skills::framed_sha256_hex(b"test-only-audit-export-mac", &material)
                .into_bytes()
        }
    }

    impl ExportSigner for TestTrustAnchor {
        fn algorithm(&self) -> &str {
            "test-only-mac"
        }

        fn key_id(&self) -> &str {
            self.key_id
        }

        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
            Ok(self.signature(message))
        }
    }

    impl ExportVerifier for TestTrustAnchor {
        fn algorithm(&self) -> &str {
            "test-only-mac"
        }

        fn key_id(&self) -> &str {
            self.key_id
        }

        fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), String> {
            if self.signature(message) == signature {
                Ok(())
            } else {
                Err("bad test signature".into())
            }
        }
    }

    const TRUSTED: TestTrustAnchor = TestTrustAnchor {
        key_id: "audit-key-2026",
        secret: b"trusted-test-secret",
    };

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
        let sources =
            crate::AuditSources::from_stores(&skill_store, &trial_store, skills, trials).unwrap();
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
            &TRUSTED,
        )
        .unwrap();

        assert_eq!(export.tenant, "acme");
        assert_eq!(export.report.total_skills, 1);
        assert!(!export.report.truncated);
        assert!(export.verify_with(&TRUSTED).is_ok());
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
            &TRUSTED,
        );
        assert!(result
            .unwrap_err()
            .contains("does not match requested tenant"));
    }

    #[test]
    fn tampering_wrong_trust_anchor_and_unauthorized_export_are_refused() {
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
            &TRUSTED,
        )
        .unwrap();

        export.report.tenant = "globex".into();
        export.digest = export.recompute_digest().unwrap();
        assert!(export.verify_with(&TRUSTED).is_err());

        let fresh = seal_export(
            AuditQuery {
                caller: "operator",
                scope: &scope,
                limits: crate::AuditLimits::default(),
                sources: bound_sources("acme", &skills, &trials),
                roles: &roles,
            },
            &known,
            &TRUSTED,
        )
        .unwrap();
        let untrusted = TestTrustAnchor {
            key_id: "attacker-key",
            secret: b"attacker-secret",
        };
        assert!(fresh.verify_with(&untrusted).is_err());

        let denied = seal_export(
            AuditQuery {
                caller: "intruder",
                scope: &scope,
                limits: crate::AuditLimits::default(),
                sources: bound_sources("acme", &skills, &trials),
                roles: &RoleBook::default(),
            },
            &known,
            &TRUSTED,
        );
        assert!(denied.is_err());
    }
}
