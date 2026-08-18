use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ccos_enterprise_ingest::{IngestLimits, KnowledgeSource, LocalTreeSource};
use ccos_enterprise_knowledge::model::{SourceTrust, TenantId};
use ccos_enterprise_normalize::normalize;

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let ordinal = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ccos-normalize-conformance-{label}-{}-{ordinal}",
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
fn normalization_derives_from_but_never_replaces_raw_evidence_hash() {
    let left = TestDir::new("left");
    let right = TestDir::new("right");
    std::fs::write(left.0.join("record.json"), br#"{ "b": 2, "a": 1 }"#).unwrap();
    std::fs::write(right.0.join("record.json"), br#"{"a":1,"b":2}"#).unwrap();

    let build = |root: &PathBuf| {
        LocalTreeSource::new(
            TenantId("acme".into()),
            "dataset",
            root,
            IngestLimits::default(),
        )
        .unwrap()
    };
    let left_source = build(&left.0);
    let right_source = build(&right.0);
    let left_descriptor = left_source.enumerate().unwrap().remove(0);
    let right_descriptor = right_source.enumerate().unwrap().remove(0);
    let left_raw = left_source.fetch(&left_descriptor).unwrap();
    let right_raw = right_source.fetch(&right_descriptor).unwrap();
    let left_source_record = left_raw.source_record(SourceTrust::External);
    let left_evidence = left_raw.whole_artifact_evidence();
    let left_normalized = normalize(&left_raw).unwrap();
    let right_normalized = normalize(&right_raw).unwrap();

    assert_ne!(left_raw.content_hash, right_raw.content_hash);
    assert_ne!(
        left_raw.whole_artifact_evidence().id,
        right_raw.whole_artifact_evidence().id
    );
    assert_eq!(
        left_normalized.manifest.output_content_hash,
        right_normalized.manifest.output_content_hash
    );
    assert_eq!(
        left_source_record.content_hash.as_deref(),
        Some(left_normalized.manifest.input_content_hash.as_str())
    );
    assert_eq!(left_evidence.content_hash, left_source_record.content_hash);
    assert_ne!(
        left_normalized.manifest.input_content_hash,
        left_normalized.manifest.output_content_hash
    );
}
