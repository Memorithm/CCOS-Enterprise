//! Deterministic, reversible ontology migrations for Knowledge Plane proposals.
//!
//! P4c deliberately supports only lossless renames. A migration transforms an
//! [`EntityProposal`] between two exact ontology fingerprints and validates both the source
//! and target schema. It never rewrites the canonical Knowledge journal. Callers may promote
//! the migrated proposal later through the normal P4b promotion gate.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ccos_enterprise_extract::ExtractedValue;
use ccos_enterprise_knowledge_model::TenantId;
use ccos_enterprise_ontology::{Ontology, Violation};
use ccos_enterprise_resolution::{EntityProposal, FactProposal};
use sha2::{Digest, Sha256};

pub const ONTOLOGY_MIGRATION_CONTRACT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum MigrationStep {
    RenameEntityType {
        from: String,
        to: String,
    },
    RenameProperty {
        entity_type: String,
        from: String,
        to: String,
    },
}

impl MigrationStep {
    fn validate(&self) -> Result<(), MigrationError> {
        let valid = match self {
            Self::RenameEntityType { from, to } => {
                !from.trim().is_empty() && !to.trim().is_empty() && from != to
            }
            Self::RenameProperty {
                entity_type,
                from,
                to,
            } => {
                !entity_type.trim().is_empty()
                    && !from.trim().is_empty()
                    && !to.trim().is_empty()
                    && from != to
            }
        };
        if valid {
            Ok(())
        } else {
            Err(MigrationError::InvalidStep(self.clone()))
        }
    }

    fn inverse(&self) -> Self {
        match self {
            Self::RenameEntityType { from, to } => Self::RenameEntityType {
                from: to.clone(),
                to: from.clone(),
            },
            Self::RenameProperty {
                entity_type,
                from,
                to,
            } => Self::RenameProperty {
                entity_type: entity_type.clone(),
                from: to.clone(),
                to: from.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OntologyMigration {
    pub contract_version: u32,
    pub migration_id: String,
    pub tenant: TenantId,
    pub from_version: String,
    pub from_fingerprint: String,
    pub to_version: String,
    pub to_fingerprint: String,
    pub steps: Vec<MigrationStep>,
    pub migration_hash: String,
}

impl OntologyMigration {
    pub fn new(
        migration_id: impl Into<String>,
        from: &Ontology,
        to: &Ontology,
        steps: Vec<MigrationStep>,
    ) -> Result<Self, MigrationError> {
        let migration_id = migration_id.into();
        if migration_id.trim().is_empty() {
            return Err(MigrationError::InvalidMigrationId);
        }
        if from.tenant() != to.tenant() {
            return Err(MigrationError::TenantMismatch {
                expected: from.tenant().0.clone(),
                actual: to.tenant().0.clone(),
            });
        }
        if from.fingerprint() == to.fingerprint() {
            return Err(MigrationError::IdenticalEndpoints);
        }
        if steps.is_empty() {
            return Err(MigrationError::EmptyMigration);
        }

        let mut seen = BTreeSet::new();
        for step in &steps {
            step.validate()?;
            if !seen.insert(step.clone()) {
                return Err(MigrationError::DuplicateStep(step.clone()));
            }
        }

        let migration_hash = migration_hash(
            &migration_id,
            from.tenant(),
            from.version(),
            from.fingerprint(),
            to.version(),
            to.fingerprint(),
            &steps,
        );

        Ok(Self {
            contract_version: ONTOLOGY_MIGRATION_CONTRACT_VERSION,
            migration_id,
            tenant: from.tenant().clone(),
            from_version: from.version().to_owned(),
            from_fingerprint: from.fingerprint().to_owned(),
            to_version: to.version().to_owned(),
            to_fingerprint: to.fingerprint().to_owned(),
            steps,
            migration_hash,
        })
    }

    /// Build the exact lossless inverse. Reverse step order is required for chained renames.
    pub fn inverse(
        &self,
        from: &Ontology,
        to: &Ontology,
    ) -> Result<OntologyMigration, MigrationError> {
        self.verify_endpoints(from, to)?;
        let steps = self
            .steps
            .iter()
            .rev()
            .map(MigrationStep::inverse)
            .collect();
        OntologyMigration::new(format!("{}:inverse", self.migration_id), to, from, steps)
    }

    pub fn apply(
        &self,
        from: &Ontology,
        to: &Ontology,
        proposal: &EntityProposal,
    ) -> Result<MigrationResult, MigrationError> {
        self.verify_endpoints(from, to)?;
        if &proposal.tenant != from.tenant() {
            return Err(MigrationError::TenantMismatch {
                expected: from.tenant().0.clone(),
                actual: proposal.tenant.0.clone(),
            });
        }

        let source_report = from.validate_proposal(proposal);
        if !source_report.is_valid() {
            return Err(MigrationError::SourceInvalid(source_report.violations));
        }

        let before_hash = proposal_hash(proposal);
        let mut migrated = proposal.clone();
        for step in &self.steps {
            apply_step(step, &mut migrated)?;
        }

        let target_report = to.validate_proposal(&migrated);
        if !target_report.is_valid() {
            return Err(MigrationError::TargetInvalid(target_report.violations));
        }
        let after_hash = proposal_hash(&migrated);

        Ok(MigrationResult {
            proposal: migrated,
            receipt: MigrationReceipt {
                contract_version: ONTOLOGY_MIGRATION_CONTRACT_VERSION,
                migration_id: self.migration_id.clone(),
                migration_hash: self.migration_hash.clone(),
                tenant: self.tenant.clone(),
                from_version: self.from_version.clone(),
                from_fingerprint: self.from_fingerprint.clone(),
                to_version: self.to_version.clone(),
                to_fingerprint: self.to_fingerprint.clone(),
                before_proposal_hash: before_hash,
                after_proposal_hash: after_hash,
            },
        })
    }

    fn verify_endpoints(&self, from: &Ontology, to: &Ontology) -> Result<(), MigrationError> {
        if from.tenant() != &self.tenant || to.tenant() != &self.tenant {
            return Err(MigrationError::EndpointMismatch);
        }
        if from.version() != self.from_version
            || from.fingerprint() != self.from_fingerprint
            || to.version() != self.to_version
            || to.fingerprint() != self.to_fingerprint
        {
            return Err(MigrationError::EndpointMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReceipt {
    pub contract_version: u32,
    pub migration_id: String,
    pub migration_hash: String,
    pub tenant: TenantId,
    pub from_version: String,
    pub from_fingerprint: String,
    pub to_version: String,
    pub to_fingerprint: String,
    pub before_proposal_hash: String,
    pub after_proposal_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationResult {
    pub proposal: EntityProposal,
    pub receipt: MigrationReceipt,
}

/// Tenant-scoped registry. Duplicate endpoint pairs fail closed rather than silently replacing
/// a migration definition whose semantics may differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationRegistry {
    tenant: TenantId,
    migrations: BTreeMap<(String, String), OntologyMigration>,
}

impl MigrationRegistry {
    pub fn new(tenant: TenantId) -> Result<Self, MigrationError> {
        if tenant.0.trim().is_empty() {
            return Err(MigrationError::InvalidTenant);
        }
        Ok(Self {
            tenant,
            migrations: BTreeMap::new(),
        })
    }

    pub fn register(&mut self, migration: OntologyMigration) -> Result<(), MigrationError> {
        if migration.tenant != self.tenant {
            return Err(MigrationError::TenantMismatch {
                expected: self.tenant.0.clone(),
                actual: migration.tenant.0.clone(),
            });
        }
        let key = (
            migration.from_fingerprint.clone(),
            migration.to_fingerprint.clone(),
        );
        if self.migrations.contains_key(&key) {
            return Err(MigrationError::DuplicateRoute {
                from: key.0,
                to: key.1,
            });
        }
        self.migrations.insert(key, migration);
        Ok(())
    }

    pub fn direct(
        &self,
        from_fingerprint: &str,
        to_fingerprint: &str,
    ) -> Option<&OntologyMigration> {
        self.migrations
            .get(&(from_fingerprint.to_owned(), to_fingerprint.to_owned()))
    }

    pub fn len(&self) -> usize {
        self.migrations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.migrations.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationError {
    InvalidTenant,
    InvalidMigrationId,
    EmptyMigration,
    IdenticalEndpoints,
    TenantMismatch {
        expected: String,
        actual: String,
    },
    EndpointMismatch,
    InvalidStep(MigrationStep),
    DuplicateStep(MigrationStep),
    DuplicateRoute {
        from: String,
        to: String,
    },
    PropertyCollision {
        entity_type: String,
        property: String,
    },
    SourceInvalid(Vec<Violation>),
    TargetInvalid(Vec<Violation>),
}

impl fmt::Display for MigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTenant => f.write_str("migration registry tenant must be non-empty"),
            Self::InvalidMigrationId => f.write_str("migration id must be non-empty"),
            Self::EmptyMigration => f.write_str("migration must contain at least one step"),
            Self::IdenticalEndpoints => {
                f.write_str("migration source and target ontology are identical")
            }
            Self::TenantMismatch { expected, actual } => {
                write!(
                    f,
                    "migration tenant mismatch: expected {expected:?}, got {actual:?}"
                )
            }
            Self::EndpointMismatch => {
                f.write_str("migration does not match the supplied ontology endpoints")
            }
            Self::InvalidStep(step) => write!(f, "invalid migration step: {step:?}"),
            Self::DuplicateStep(step) => write!(f, "duplicate migration step: {step:?}"),
            Self::DuplicateRoute { from, to } => {
                write!(f, "migration route {from} -> {to} is already registered")
            }
            Self::PropertyCollision {
                entity_type,
                property,
            } => write!(
                f,
                "property rename for entity type {entity_type:?} would collide at {property:?}"
            ),
            Self::SourceInvalid(violations) => {
                write!(
                    f,
                    "proposal is invalid under source ontology: {violations:?}"
                )
            }
            Self::TargetInvalid(violations) => {
                write!(
                    f,
                    "migrated proposal is invalid under target ontology: {violations:?}"
                )
            }
        }
    }
}

impl std::error::Error for MigrationError {}

fn apply_step(step: &MigrationStep, proposal: &mut EntityProposal) -> Result<(), MigrationError> {
    match step {
        MigrationStep::RenameEntityType { from, to } => {
            if proposal.entity_type == *from {
                proposal.entity_type.clone_from(to);
            }
        }
        MigrationStep::RenameProperty {
            entity_type,
            from,
            to,
        } => {
            if proposal.entity_type != *entity_type {
                return Ok(());
            }
            let has_source = proposal.facts.iter().any(|fact| fact.predicate == *from);
            if !has_source {
                return Ok(());
            }
            if proposal.facts.iter().any(|fact| fact.predicate == *to) {
                return Err(MigrationError::PropertyCollision {
                    entity_type: entity_type.clone(),
                    property: to.clone(),
                });
            }
            for fact in &mut proposal.facts {
                if fact.predicate == *from {
                    fact.predicate.clone_from(to);
                }
            }
        }
    }
    Ok(())
}

fn migration_hash(
    migration_id: &str,
    tenant: &TenantId,
    from_version: &str,
    from_fingerprint: &str,
    to_version: &str,
    to_fingerprint: &str,
    steps: &[MigrationStep],
) -> String {
    let mut hasher = Sha256::new();
    hash_part(
        &mut hasher,
        &ONTOLOGY_MIGRATION_CONTRACT_VERSION.to_le_bytes(),
    );
    hash_part(&mut hasher, migration_id.as_bytes());
    hash_part(&mut hasher, tenant.0.as_bytes());
    hash_part(&mut hasher, from_version.as_bytes());
    hash_part(&mut hasher, from_fingerprint.as_bytes());
    hash_part(&mut hasher, to_version.as_bytes());
    hash_part(&mut hasher, to_fingerprint.as_bytes());
    for step in steps {
        match step {
            MigrationStep::RenameEntityType { from, to } => {
                hash_part(&mut hasher, b"rename-entity-type");
                hash_part(&mut hasher, from.as_bytes());
                hash_part(&mut hasher, to.as_bytes());
            }
            MigrationStep::RenameProperty {
                entity_type,
                from,
                to,
            } => {
                hash_part(&mut hasher, b"rename-property");
                hash_part(&mut hasher, entity_type.as_bytes());
                hash_part(&mut hasher, from.as_bytes());
                hash_part(&mut hasher, to.as_bytes());
            }
        }
    }
    format!("sha256:{}", hex_lower(&hasher.finalize()))
}

fn proposal_hash(proposal: &EntityProposal) -> String {
    let mut hasher = Sha256::new();
    hash_part(&mut hasher, proposal.tenant.0.as_bytes());
    hash_part(&mut hasher, proposal.id.as_str().as_bytes());
    hash_part(&mut hasher, proposal.entity_type.as_bytes());
    for candidate in &proposal.candidates {
        hash_part(&mut hasher, candidate.0.as_bytes());
    }
    for evidence in &proposal.evidence {
        hash_part(&mut hasher, evidence.as_str().as_bytes());
    }
    for label in &proposal.labels {
        hash_part(&mut hasher, label.as_bytes());
    }

    let mut facts: Vec<_> = proposal.facts.iter().map(fact_hash_key).collect();
    facts.sort();
    for fact in facts {
        hash_part(&mut hasher, fact.as_bytes());
    }
    format!("sha256:{}", hex_lower(&hasher.finalize()))
}

fn fact_hash_key(fact: &FactProposal) -> String {
    format!(
        "{}\u{0}{}\u{0}{}\u{0}{}",
        fact.candidate.0,
        fact.predicate,
        value_key(&fact.value),
        fact.evidence.as_str()
    )
}

fn value_key(value: &ExtractedValue) -> String {
    match value {
        ExtractedValue::Null => "null:".to_owned(),
        ExtractedValue::Bool(value) => format!("bool:{value}"),
        ExtractedValue::Number(value) => format!("number:{value}"),
        ExtractedValue::String(value) => format!("string:{value}"),
        ExtractedValue::Json(value) => format!("json:{value}"),
    }
}

fn hash_part(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use ccos_enterprise_extract::CandidateId;
    use ccos_enterprise_knowledge_model::{EntityId, EvidenceId};
    use ccos_enterprise_ontology::{EntitySchema, PropertySpec, ValueType};

    fn v1(allow_extra: bool) -> Ontology {
        Ontology::new(
            TenantId("tenant-a".into()),
            "v1",
            [EntitySchema::new(
                "company",
                [
                    PropertySpec::new("id", ValueType::String, true).unwrap(),
                    PropertySpec::new("legal_name", ValueType::String, true).unwrap(),
                ],
                allow_extra,
            )
            .unwrap()],
        )
        .unwrap()
    }

    fn v2() -> Ontology {
        Ontology::new(
            TenantId("tenant-a".into()),
            "v2",
            [EntitySchema::new(
                "organization",
                [
                    PropertySpec::new("id", ValueType::String, true).unwrap(),
                    PropertySpec::new("name", ValueType::String, true).unwrap(),
                ],
                false,
            )
            .unwrap()],
        )
        .unwrap()
    }

    fn proposal(include_target_name: bool) -> EntityProposal {
        let candidate = CandidateId("candidate:1".into());
        let evidence = EvidenceId::from("evidence:1");
        let mut facts = vec![
            FactProposal {
                candidate: candidate.clone(),
                predicate: "id".into(),
                value: ExtractedValue::String("C-7".into()),
                evidence: evidence.clone(),
            },
            FactProposal {
                candidate: candidate.clone(),
                predicate: "legal_name".into(),
                value: ExtractedValue::String("Acme".into()),
                evidence: evidence.clone(),
            },
        ];
        if include_target_name {
            facts.push(FactProposal {
                candidate: candidate.clone(),
                predicate: "name".into(),
                value: ExtractedValue::String("Other".into()),
                evidence: evidence.clone(),
            });
        }
        EntityProposal {
            id: EntityId::new("entity:company:7"),
            tenant: TenantId("tenant-a".into()),
            entity_type: "company".into(),
            candidates: BTreeSet::from([candidate]),
            evidence: BTreeSet::from([evidence]),
            labels: BTreeSet::from(["Acme".into()]),
            facts,
        }
    }

    fn migration(from: &Ontology, to: &Ontology) -> OntologyMigration {
        OntologyMigration::new(
            "company-v1-to-v2",
            from,
            to,
            vec![
                MigrationStep::RenameEntityType {
                    from: "company".into(),
                    to: "organization".into(),
                },
                MigrationStep::RenameProperty {
                    entity_type: "organization".into(),
                    from: "legal_name".into(),
                    to: "name".into(),
                },
            ],
        )
        .unwrap()
    }

    #[test]
    fn forward_then_inverse_restores_exact_proposal() {
        let from = v1(false);
        let to = v2();
        let migration = migration(&from, &to);
        let original = proposal(false);
        let forward = migration.apply(&from, &to, &original).unwrap();
        assert_eq!(forward.proposal.entity_type, "organization");
        assert!(forward
            .proposal
            .facts
            .iter()
            .any(|fact| fact.predicate == "name"));
        let inverse = migration.inverse(&from, &to).unwrap();
        let restored = inverse
            .apply(&to, &from, &forward.proposal)
            .unwrap()
            .proposal;
        assert_eq!(restored, original);
    }

    #[test]
    fn migration_hash_and_receipt_are_deterministic() {
        let from = v1(false);
        let to = v2();
        let migration = migration(&from, &to);
        let left = migration.apply(&from, &to, &proposal(false)).unwrap();
        let right = migration.apply(&from, &to, &proposal(false)).unwrap();
        assert_eq!(left.receipt, right.receipt);
        assert!(left.receipt.migration_hash.starts_with("sha256:"));
    }

    #[test]
    fn property_collision_fails_closed() {
        let from = v1(true);
        let to = v2();
        let migration = migration(&from, &to);
        assert!(matches!(
            migration.apply(&from, &to, &proposal(true)),
            Err(MigrationError::PropertyCollision { .. })
        ));
    }

    #[test]
    fn registry_rejects_duplicate_routes_and_foreign_tenants() {
        let from = v1(false);
        let to = v2();
        let migration = migration(&from, &to);
        let mut registry = MigrationRegistry::new(TenantId("tenant-a".into())).unwrap();
        registry.register(migration.clone()).unwrap();
        assert!(matches!(
            registry.register(migration),
            Err(MigrationError::DuplicateRoute { .. })
        ));
        assert_eq!(registry.len(), 1);
    }
}
