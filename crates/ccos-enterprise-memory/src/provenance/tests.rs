use super::*;
use crate::*;
use ccos_enterprise_knowledge_model::SourceTrust;
use std::cell::Cell;
use std::io::Cursor;

struct Bytes {
    bytes: Vec<u8>,
    reads: Cell<usize>,
}
impl SourceBytes for Bytes {
    fn open(&self, _: &TenantId, _: &SourceRecord) -> Result<Box<dyn Read>, ProvenanceError> {
        self.reads.set(self.reads.get() + 1);
        Ok(Box::new(Cursor::new(self.bytes.clone())))
    }
}
fn tenant() -> TenantId {
    TenantId::validated("acme").unwrap()
}
fn id(s: &str) -> MemoryAssetId {
    MemoryAssetId::new(s).unwrap()
}
fn fixture() -> (
    GovernedMemoryProjection,
    GovernedMemoryContextAssembly,
    EvidenceCatalog,
    Bytes,
) {
    let bytes = b"prefix: precise source\r\n".to_vec();
    let digest = hash(&bytes);
    let source = SourceRecord {
        id: SourceId::new("s"),
        tenant: tenant(),
        locator: "source://declared".into(),
        content_hash: Some(digest.clone()),
        trust: SourceTrust::Untrusted,
    };
    let evidence = EvidenceRecord {
        id: EvidenceId::new("e"),
        tenant: tenant(),
        source: source.id.clone(),
        locator: Some("bytes:8-22".into()),
        content_hash: Some(digest),
    };
    let catalog = EvidenceCatalog::new(tenant(), [source], [evidence]).unwrap();
    let mut graph = MemoryLineageGraph::new();
    graph
        .register(
            MemoryAssetDescriptor::new(
                id("root"),
                MemorySpace::Tenant,
                MemoryStratum::Evidence,
                MemoryLineage::root([MemoryEvidenceRef::new("e").unwrap()]).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    graph
        .register(
            MemoryAssetDescriptor::new(
                id("derived"),
                MemorySpace::Tenant,
                MemoryStratum::Episode,
                MemoryLineage::derived([id("root")], []).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    let projection = GovernedMemoryProjection::new(
        tenant(),
        graph,
        ["root", "derived"]
            .into_iter()
            .map(|s| (id(s), MemoryTrustMetadata::unverified(1)))
            .collect(),
        MemoryLoadoutPlan::new([MemoryLoadoutBinding::new(
            MemorySpace::Tenant,
            1,
            MemoryUsageMode::Bootstrap,
        )
        .unwrap()])
        .unwrap(),
    )
    .unwrap();
    let admitted = admit_governed_recall(
        GovernedRecallGate {
            expected_tenant: &tenant(),
            projection: &projection,
            policy: GovernedRecallTrustPolicy::AnyNonQuarantined,
        },
        [GovernedMemoryObservation {
            asset_id: id("derived"),
            space: MemorySpace::Tenant,
            payload: b"a derived claim, not proven by a hash".to_vec(),
            similarity: 0.99,
        }],
    )
    .unwrap();
    let assembly = assemble_governed_bootstrap_context(
        &projection,
        admitted,
        MemoryContextBudget::new(8, 1024).unwrap(),
    )
    .unwrap();
    (
        projection,
        assembly,
        catalog,
        Bytes {
            bytes,
            reads: Cell::new(0),
        },
    )
}
#[test]
fn inherited_exact_reference_and_raw_span_are_verified_without_truth_promotion() {
    let (p, a, c, b) = fixture();
    let cited = cite_governed_context(&a, &p, &c, &b, CitationBudget::bounded(14)).unwrap();
    assert_eq!(cited.quote_bytes(), 14);
    assert_eq!(b.reads.get(), 1);
    let item = &cited.items()[0];
    assert_eq!(item.asset_id(), &id("derived"));
    assert_eq!(item.payload_sha256(), a.chunks()[0].payload_sha256_hex());
    let quote = &item.citations()[0];
    assert_eq!(quote.quote_bytes(), b"precise source");
    assert_eq!(quote.quote_hash(), hash(b"precise source"));
    assert_eq!(quote.evidence_id().as_str(), "e");
    assert_eq!(
        a.chunks()[0].trust_state(),
        MemoryValidationState::Unverified
    );
}
#[test]
fn joins_hashes_spans_and_budgets_fail_closed() {
    let (p, a, mut c, b) = fixture();
    let check = |c: &EvidenceCatalog, budget| cite_governed_context(&a, &p, c, &b, budget);
    assert_eq!(
        check(&c, CitationBudget::bounded(13)),
        Err(ProvenanceError::Limit)
    );
    for invalid in [
        "bytes:08-22",
        "bytes:8-999",
        "bytes:8-8",
        "bytes:+8-22",
        "characters:8-22",
    ] {
        c.evidence.get_mut(&EvidenceId::new("e")).unwrap().locator = Some(invalid.into());
        assert_eq!(
            check(&c, CitationBudget::bounded(100)),
            Err(ProvenanceError::InvalidSpan)
        );
    }
    c.evidence.get_mut(&EvidenceId::new("e")).unwrap().locator = Some("bytes:8-22".into());
    c.evidence
        .get_mut(&EvidenceId::new("e"))
        .unwrap()
        .content_hash = None;
    assert_eq!(
        check(&c, CitationBudget::bounded(100)),
        Err(ProvenanceError::MissingHash)
    );
    c.evidence
        .get_mut(&EvidenceId::new("e"))
        .unwrap()
        .content_hash = Some(hash(b"other"));
    assert_eq!(
        check(&c, CitationBudget::bounded(100)),
        Err(ProvenanceError::ContentMismatch)
    );
    c.evidence.clear();
    assert_eq!(
        check(&c, CitationBudget::bounded(100)),
        Err(ProvenanceError::MissingEvidence)
    );
}
#[test]
fn changed_source_and_authority_cannot_reuse_a_valid_admission() {
    let (mut p, a, mut c, mut b) = fixture();
    b.bytes[0] ^= 1;
    assert_eq!(
        cite_governed_context(&a, &p, &c, &b, CitationBudget::bounded(100)),
        Err(ProvenanceError::ContentMismatch)
    );
    b.reads.set(0);
    p.graph.invalidate(&id("root")).unwrap();
    assert_eq!(
        cite_governed_context(&a, &p, &c, &b, CitationBudget::bounded(100)),
        Err(ProvenanceError::ProjectionMismatch)
    );
    assert_eq!(b.reads.get(), 0);
    c.tenant = TenantId::validated("other").unwrap();
    assert_eq!(
        cite_governed_context(&a, &p, &c, &b, CitationBudget::bounded(100)),
        Err(ProvenanceError::TenantMismatch)
    );
    assert_eq!(b.reads.get(), 0);
}
#[test]
fn catalog_rejects_cross_tenant_and_duplicate_rows() {
    let (_, _, c, _) = fixture();
    let source = c.sources.values().next().unwrap().clone();
    assert!(EvidenceCatalog::new(tenant(), [source.clone(), source.clone()], []).is_err());
    assert!(EvidenceCatalog::new(TenantId::validated("other").unwrap(), [source], []).is_err());
    let source = c.sources.values().next().unwrap().clone();
    let e = c.evidence.values().next().unwrap().clone();
    assert!(EvidenceCatalog::new(tenant(), [source], [e.clone(), e]).is_err());
}
#[test]
fn all_resource_limits_are_enforced_and_binary_quotes_remain_exact() {
    let (p, a, mut c, mut b) = fixture();
    for mutate in [0, 1, 2, 3, 4] {
        let mut budget = CitationBudget::bounded(100);
        match mutate {
            0 => budget.max_sources = 0,
            1 => budget.max_source_bytes = 1,
            2 => budget.max_total_source_bytes = 1,
            3 => budget.max_citations = 0,
            _ => budget.max_lineage_visits = 1,
        }
        assert_eq!(
            cite_governed_context(&a, &p, &c, &b, budget),
            Err(ProvenanceError::Limit)
        );
    }
    b.bytes[8] = 255;
    let digest = hash(&b.bytes);
    c.sources.get_mut(&SourceId::new("s")).unwrap().content_hash = Some(digest.clone());
    c.evidence
        .get_mut(&EvidenceId::new("e"))
        .unwrap()
        .content_hash = Some(digest);
    let output = cite_governed_context(&a, &p, &c, &b, CitationBudget::bounded(100)).unwrap();
    assert_eq!(output.items()[0].citations()[0].quote_bytes()[0], 255);
    assert_eq!(output.items()[0].citations()[0].quote_text(), None);
}
