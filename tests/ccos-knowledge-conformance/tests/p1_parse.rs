use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ccos_enterprise_ingest::{IngestLimits, KnowledgeSource, LocalTreeSource};
use ccos_enterprise_knowledge::model::TenantId;
use ccos_enterprise_parse::{parse, ParsedUnitKind};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let ordinal = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ccos-parse-conformance-{}-{ordinal}",
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
fn parsed_unit_locator_resolves_to_original_raw_source_bytes() {
    let dir = TestDir::new();
    std::fs::write(
        dir.0.join("events.ndjson"),
        b"{\"event\":\"open\"}\r\n\r\n{\"event\":\"close\",\"id\":2}\r\n",
    )
    .unwrap();
    let source = LocalTreeSource::new(
        TenantId("acme".into()),
        "events",
        &dir.0,
        IngestLimits::default(),
    )
    .unwrap();
    let descriptor = source.enumerate().unwrap().remove(0);
    let raw = source.fetch(&descriptor).unwrap();
    let parsed = parse(&raw).unwrap();

    assert_eq!(parsed.units.len(), 2);
    assert!(parsed
        .units
        .iter()
        .all(|unit| unit.kind == ParsedUnitKind::NdjsonRecord));
    let second = &parsed.units[1];
    assert_eq!(
        second.evidence_locator(),
        format!("bytes:{}-{}", second.raw_span.start, second.raw_span.end)
    );
    assert_eq!(
        &raw.bytes[second.raw_span.start..second.raw_span.end],
        b"{\"event\":\"close\",\"id\":2}"
    );
    assert_eq!(parsed.raw_content_hash, raw.content_hash);
}
