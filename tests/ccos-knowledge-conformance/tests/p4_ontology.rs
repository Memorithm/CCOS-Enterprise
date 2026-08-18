use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ccos_enterprise_extract::extract;
use ccos_enterprise_ingest::{IngestLimits, KnowledgeSource, LocalTreeSource};
use ccos_enterprise_knowledge::model::TenantId;
use ccos_enterprise_ontology::{EntitySchema, Ontology, PropertySpec, ValueType};
use ccos_enterprise_resolution::{resolve_batches, IdentityNormalization, ResolutionSchema};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let ordinal = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ccos-ontology-conformance-{label}-{}-{ordinal}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn resolved_multi_source_observation_must_conform_before_future_fact_promotion() {
    let crm_dir = TestDir::new("crm");
    let erp_dir = TestDir::new("erp");
    std::fs::write(
        crm_dir.0.join("company.json"),
        br#"{"company_id":"C-7","name":"Acme","country":"FR","active":true}"#,
    )
    .unwrap();
    std::fs::write(
        erp_dir.0.join("company.json"),
        br#"{"company_id":"C-7","name":"Acme","employees":42}"#,
    )
    .unwrap();

    let ingest = |root: &PathBuf, namespace: &str| {
        LocalTreeSource::new(
            TenantId("tenant-a".into()),
            namespace,
            root,
            IngestLimits::default(),
        )
        .unwrap()
    };
    let crm = ingest(&crm_dir.0, "crm");
    let erp = ingest(&erp_dir.0, "erp");
    let crm_raw = crm.fetch(&crm.enumerate().unwrap().remove(0)).unwrap();
    let erp_raw = erp.fetch(&erp.enumerate().unwrap().remove(0)).unwrap();
    let resolved = resolve_batches(
        &[extract(&crm_raw).unwrap(), extract(&erp_raw).unwrap()],
        &ResolutionSchema::new(
            "company",
            ["company_id"],
            Some("name".into()),
            IdentityNormalization::Exact,
        )
        .unwrap(),
    )
    .unwrap();
    let proposal = resolved.proposals.values().next().unwrap();

    let ontology = Ontology::new(
        TenantId("tenant-a".into()),
        "company-v1",
        [EntitySchema::new(
            "company",
            [
                PropertySpec::new("company_id", ValueType::String, true).unwrap(),
                PropertySpec::new("name", ValueType::String, true).unwrap(),
                PropertySpec::new("country", ValueType::String, false).unwrap(),
                PropertySpec::new("active", ValueType::Bool, false).unwrap(),
                PropertySpec::new("employees", ValueType::Number, false).unwrap(),
            ],
            false,
        )
        .unwrap()],
    )
    .unwrap();

    let report = ontology.validate_proposal(proposal);
    assert!(
        report.is_valid(),
        "unexpected violations: {:?}",
        report.violations
    );
    assert!(report.ontology_fingerprint.starts_with("sha256:"));
}
