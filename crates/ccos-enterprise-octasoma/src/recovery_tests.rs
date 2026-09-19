use super::*;
use ccos_enterprise_memory::{
    assemble_governed_bootstrap_context, attest_governed_context, MemoryAssetDescriptor,
    MemoryAssetState, MemoryContextBudget, MemoryEvidenceRef, MemoryLineage, MemoryLineageGraph,
    MemoryLoadout, MemoryLoadoutBinding, MemoryLoadoutPlan, MemoryRecallBudget, MemorySpace,
    MemoryStratum, MemoryTrustMetadata, MemoryUsageMode, MemoryValidationState,
};
use ccos_enterprise_tenancy::TenantId;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "ccos-provider-recovery-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn tenant() -> TenantId {
    TenantId::validated("acme").unwrap()
}
fn id(value: &str) -> MemoryAssetId {
    MemoryAssetId::new(value).unwrap()
}
fn config() -> RecoveryConfig {
    RecoveryConfig {
        dimension: 4,
        simhash_bits: 64,
        per_tenant_capacity: 16,
        seed: 42,
    }
}
fn verified() -> MemoryTrustMetadata {
    MemoryTrustMetadata::new(
        MemoryValidationState::Verified,
        1,
        1,
        0,
        ["proof:fixture".into()],
    )
    .unwrap()
}
fn fixture() -> (GovernedMemoryProjection, Vec<RecoveryRecord>) {
    let mut graph = MemoryLineageGraph::new();
    let mut trust = BTreeMap::new();
    let mut records = Vec::new();
    for name in [
        "f-private",
        "e-forgotten",
        "a-live",
        "b-root",
        "d-quarantine",
        "g-unverified",
    ] {
        let space = if name == "f-private" {
            MemorySpace::project("private").unwrap()
        } else {
            MemorySpace::Tenant
        };
        graph
            .register(
                MemoryAssetDescriptor::new(
                    id(name),
                    space,
                    MemoryStratum::Evidence,
                    MemoryLineage::root([MemoryEvidenceRef::new(format!("audit:{name}")).unwrap()])
                        .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        let meta = match name {
            "d-quarantine" => MemoryTrustMetadata::new(
                MemoryValidationState::Quarantined,
                1,
                1,
                0,
                Vec::<String>::new(),
            )
            .unwrap(),
            "g-unverified" => MemoryTrustMetadata::unverified(1),
            _ => verified(),
        };
        trust.insert(id(name), meta);
        records.push(RecoveryRecord {
            asset_id: id(name),
            embedding: vec![1.0, -0.0, f32::from_bits(1), 0.0],
            payload: [name.as_bytes(), b"\0\xff"].concat(),
            forgotten: name == "e-forgotten",
        });
    }
    graph
        .register(
            MemoryAssetDescriptor::new(
                id("c-derived"),
                MemorySpace::Tenant,
                MemoryStratum::Episode,
                MemoryLineage::derived([id("b-root")], []).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    trust.insert(id("c-derived"), verified());
    records.insert(
        2,
        RecoveryRecord {
            asset_id: id("c-derived"),
            embedding: vec![1.0, 0.0, 0.0, 0.0],
            payload: b"derived".to_vec(),
            forgotten: false,
        },
    );
    graph.invalidate(&id("b-root")).unwrap();
    let plan = MemoryLoadoutPlan::new([
        MemoryLoadoutBinding::new(
            MemorySpace::Tenant,
            100,
            MemoryUsageMode::BootstrapAndOnDemand,
        )
        .unwrap(),
        MemoryLoadoutBinding::new(
            MemorySpace::project("private").unwrap(),
            10,
            MemoryUsageMode::OnDemand,
        )
        .unwrap(),
    ])
    .unwrap();
    (
        GovernedMemoryProjection::new(tenant(), graph, trust, plan).unwrap(),
        records,
    )
}
fn request(loadout: &MemoryLoadout) -> TenantScope<BudgetedMemoryRecall<'_>> {
    TenantScope::new(
        tenant(),
        BudgetedMemoryRecall {
            embedding: &[1.0, 0.0, 0.0, 0.0],
            loadout,
            budget: MemoryRecallBudget::new(16, 16, 4096).unwrap(),
        },
    )
}
fn image() -> (GovernedMemoryProjection, RecoveryImage) {
    let (authority, records) = fixture();
    let image = RecoveryImage::capture(&authority, config(), &records).unwrap();
    (authority, image)
}
fn restore(
    bytes: &[u8],
    digest: [u8; 32],
    authority: &GovernedMemoryProjection,
) -> Result<RecoveredGovernedMemory, RecoveryError> {
    restore_governed_memory(bytes, digest, authority, config())
}
fn mutated_image(
    mutator: impl FnOnce(&mut serde_json::Value),
) -> Result<RecoveredGovernedMemory, RecoveryError> {
    let (authority, image) = image();
    let mut value: serde_json::Value = serde_json::from_slice(image.as_bytes()).unwrap();
    mutator(&mut value);
    let bytes = serde_json::to_vec(&value).unwrap();
    restore(&bytes, Sha256::digest(&bytes).into(), &authority)
}

#[test]
fn backend_contract_matches_the_resolved_workspace_pin() {
    let workspace = include_str!("../../../Cargo.toml");
    assert!(workspace
        .lines()
        .any(|line| line.starts_with("octasoma =") && line.contains(BACKEND_REVISION)));
}

#[test]
fn canonical_projection_encoder_matches_existing_disk_format() {
    let dir = Directory::new();
    let (authority, _) = fixture();
    let path = ccos_enterprise_memory::save_governed_memory_projection(&dir.0, &authority).unwrap();
    assert_eq!(
        encode_governed_memory_projection(&authority).unwrap(),
        fs::read(path).unwrap()
    );
}

#[test]
fn deterministic_image_preserves_order_bits_binary_payload_and_tombstones() {
    let (authority, records) = fixture();
    let first = RecoveryImage::capture(&authority, config(), &records).unwrap();
    let second = RecoveryImage::capture(&authority, config(), &records).unwrap();
    assert_eq!(first.as_bytes(), second.as_bytes());
    assert_eq!(first.digest(), second.digest());
    let wire: WireImage = serde_json::from_slice(first.as_bytes()).unwrap();
    for (wire, source) in wire.records.iter().zip(&records) {
        assert_eq!(wire.asset_id, source.asset_id.as_str());
        assert_eq!(
            wire.embedding_bits,
            source
                .embedding
                .iter()
                .map(|v| v.to_bits())
                .collect::<Vec<_>>()
        );
        assert_eq!(wire.payload, source.payload);
        assert_eq!(wire.forgotten, source.forgotten);
    }
    let mut reordered = records.clone();
    reordered.swap(0, 1);
    assert_ne!(
        first.digest(),
        RecoveryImage::capture(&authority, config(), &reordered)
            .unwrap()
            .digest()
    );
}

#[test]
fn real_provider_reconstruction_matches_original_replay() {
    let (authority, records) = fixture();
    let image = RecoveryImage::capture(&authority, config(), &records).unwrap();
    let recovered = restore(image.as_bytes(), image.digest(), &authority).unwrap();
    let mut original = EnterpriseOctaSoma::new(4, 64, 16, 42).unwrap();
    for row in &records {
        original
            .insert_governed(TenantScope::new(
                tenant(),
                GovernedMemoryWrite {
                    asset_id: &row.asset_id,
                    space: &authority.graph.descriptor(&row.asset_id).unwrap().space,
                    embedding: &row.embedding,
                    payload: &row.payload,
                },
            ))
            .unwrap();
        if row.forgotten {
            original
                .forget_governed(TenantScope::new(tenant(), &row.asset_id))
                .unwrap();
        }
    }
    let loadout = MemoryLoadout::new([
        MemorySpace::Tenant,
        MemorySpace::project("private").unwrap(),
    ])
    .unwrap();
    let before = original.recall_governed_bounded(request(&loadout)).unwrap();
    let after = recovered
        .provider
        .recall_governed_bounded(request(&loadout))
        .unwrap();
    assert_eq!(before, after);
    assert_eq!(recovered.stored_records(), records.len());
    assert_eq!(recovered.provider.tenant_count(), 1);
    assert!(!after.iter().any(|o| o.asset_id == id("e-forgotten")));
}

#[test]
fn recovery_preserves_filtering_and_can_build_an_attested_context() {
    let (authority, image) = image();
    let recovered = restore(image.as_bytes(), image.digest(), &authority).unwrap();
    let loadout = authority.loadout.bootstrap_loadout().unwrap().unwrap();
    let admitted = recovered
        .recall(
            &authority,
            request(&loadout),
            GovernedRecallTrustPolicy::VerifiedOnly,
        )
        .unwrap();
    assert_eq!(
        admitted
            .iter()
            .map(|o| o.asset_id.as_str())
            .collect::<Vec<_>>(),
        vec!["a-live"]
    );
    assert_eq!(
        recovered.authority.projection().graph.state(&id("b-root")),
        Some(MemoryAssetState::Invalidated)
    );
    assert_eq!(
        recovered
            .authority
            .projection()
            .graph
            .state(&id("c-derived")),
        Some(MemoryAssetState::Stale)
    );
    let context = assemble_governed_bootstrap_context(
        &authority,
        admitted,
        MemoryContextBudget::new(2, 128).unwrap(),
    )
    .unwrap();
    let attested = attest_governed_context(&context);
    assert_eq!(context.len(), 1);
    assert_eq!(attested[0].asset_id, id("a-live"));
    let permissive = recovered
        .recall(
            &authority,
            request(&loadout),
            GovernedRecallTrustPolicy::AnyNonQuarantined,
        )
        .unwrap();
    assert_eq!(permissive.len(), 2);
}

#[test]
fn stale_governance_loadout_trust_and_tenant_are_rejected() {
    let (authority, image) = image();
    let recovered = restore(image.as_bytes(), image.digest(), &authority).unwrap();
    let loadout = MemoryLoadout::tenant_only();
    let mut invalidated = authority.clone();
    invalidated.graph.invalidate(&id("a-live")).unwrap();
    let mut trust_changed = authority.clone();
    trust_changed
        .trust
        .insert(id("a-live"), MemoryTrustMetadata::unverified(1));
    let mut loadout_changed = authority.clone();
    loadout_changed.loadout = MemoryLoadoutPlan::new([MemoryLoadoutBinding::new(
        MemorySpace::Tenant,
        1,
        MemoryUsageMode::Bootstrap,
    )
    .unwrap()])
    .unwrap();
    for changed in [invalidated, trust_changed, loadout_changed] {
        assert!(matches!(
            restore(image.as_bytes(), image.digest(), &changed),
            Err(RecoveryError::GovernanceMismatch)
        ));
        assert!(matches!(
            recovered.recall(
                &changed,
                request(&loadout),
                GovernedRecallTrustPolicy::AnyNonQuarantined
            ),
            Err(RecoveryError::GovernanceMismatch)
        ));
    }
    let mut other = request(&loadout);
    other.tenant = TenantId::validated("other").unwrap();
    assert!(matches!(
        recovered.recall(&authority, other, GovernedRecallTrustPolicy::VerifiedOnly),
        Err(RecoveryError::TenantMismatch)
    ));
    let mut other_authority = authority.clone();
    other_authority.tenant = TenantId::validated("other").unwrap();
    assert!(matches!(
        restore(image.as_bytes(), image.digest(), &other_authority),
        Err(RecoveryError::GovernanceMismatch)
    ));
}

#[test]
fn loadout_cannot_be_widened_by_the_query() {
    let (authority, image) = image();
    let recovered = restore(image.as_bytes(), image.digest(), &authority).unwrap();
    let loadout = MemoryLoadout::new([MemorySpace::team("not-configured").unwrap()]).unwrap();
    assert!(matches!(
        recovered.recall(
            &authority,
            request(&loadout),
            GovernedRecallTrustPolicy::VerifiedOnly
        ),
        Err(RecoveryError::Invalid(_))
    ));
}

#[test]
fn duplicate_missing_unknown_records_and_missing_trust_fail_closed() {
    let (authority, records) = fixture();
    let mut duplicate = records.clone();
    duplicate[1] = duplicate[0].clone();
    let mut unknown = records.clone();
    unknown[0].asset_id = id("unknown");
    for rows in [duplicate, unknown, records[..records.len() - 1].to_vec()] {
        assert!(RecoveryImage::capture(&authority, config(), &rows).is_err());
    }
    let mut missing_trust = authority;
    missing_trust.trust.remove(&id("a-live"));
    assert!(RecoveryImage::capture(&missing_trust, config(), &records).is_err());
}

#[test]
fn malformed_records_rejected_even_with_matching_external_digest() {
    assert!(mutated_image(|v| {
        v["records"][1] = v["records"][0].clone();
    })
    .is_err());
    assert!(mutated_image(|v| {
        v["records"].as_array_mut().unwrap().pop();
    })
    .is_err());
    assert!(mutated_image(|v| {
        v["records"][0]["asset_id"] = "unknown".into();
    })
    .is_err());
    assert!(mutated_image(|v| {
        v["records"][0]["embedding_bits"] = serde_json::json!([0]);
    })
    .is_err());
    assert!(mutated_image(|v| {
        v["records"][0]["embedding_bits"][0] = serde_json::json!(f32::NAN.to_bits());
    })
    .is_err());
}

#[test]
fn nonfinite_dimensions_and_configuration_limits_are_enforced() {
    let (authority, records) = fixture();
    for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        let mut rows = records.clone();
        rows[0].embedding[0] = value;
        assert!(RecoveryImage::capture(&authority, config(), &rows).is_err());
    }
    for bad in [
        RecoveryConfig {
            dimension: 0,
            ..config()
        },
        RecoveryConfig {
            simhash_bits: 1,
            ..config()
        },
        RecoveryConfig {
            per_tenant_capacity: 1,
            ..config()
        },
        RecoveryConfig {
            dimension: 8192,
            simhash_bits: 4096,
            ..config()
        },
    ] {
        assert!(RecoveryImage::capture(&authority, bad, &records).is_err());
    }
    let image = RecoveryImage::capture(&authority, config(), &records).unwrap();
    assert!(matches!(
        restore_governed_memory(
            image.as_bytes(),
            image.digest(),
            &authority,
            RecoveryConfig {
                seed: 43,
                ..config()
            }
        ),
        Err(RecoveryError::ConfigurationMismatch)
    ));
}

#[test]
fn finite_float_bit_patterns_roundtrip_without_json_float_coercion() {
    let (authority, mut rows) = fixture();
    rows[0].embedding = vec![f32::MIN_POSITIVE, f32::from_bits(1), -0.0, 1.0];
    let image = RecoveryImage::capture(&authority, config(), &rows).unwrap();
    let wire: WireImage = serde_json::from_slice(image.as_bytes()).unwrap();
    assert_eq!(
        wire.records[0].embedding_bits,
        rows[0]
            .embedding
            .iter()
            .map(|f| f.to_bits())
            .collect::<Vec<_>>()
    );
    assert!(restore(image.as_bytes(), image.digest(), &authority).is_ok());
}

#[test]
fn corrupt_truncated_and_changed_payloads_fail_receipt_verification() {
    let (authority, image) = image();
    let mut changed = image.as_bytes().to_vec();
    changed[0] ^= 1;
    assert!(matches!(
        restore(&changed, image.digest(), &authority),
        Err(RecoveryError::DigestMismatch)
    ));
    assert!(matches!(
        restore(&image.as_bytes()[..20], image.digest(), &authority),
        Err(RecoveryError::DigestMismatch)
    ));
    assert!(matches!(
        restore(image.as_bytes(), [0; 32], &authority),
        Err(RecoveryError::DigestMismatch)
    ));
    let malformed = b"{bad";
    assert!(matches!(
        restore(malformed, Sha256::digest(malformed).into(), &authority),
        Err(RecoveryError::Json(_))
    ));
}

#[test]
fn unknown_fields_versions_backend_and_duplicate_keys_are_rejected() {
    assert!(mutated_image(|v| {
        v["authority_override"] = true.into();
    })
    .is_err());
    assert!(mutated_image(|v| {
        v["records"][0]["space"] = "tenant".into();
    })
    .is_err());
    assert!(mutated_image(|v| {
        v["version"] = 99.into();
    })
    .is_err());
    assert!(mutated_image(|v| {
        v["backend_revision"] = "unreviewed".into();
    })
    .is_err());
    let (authority, image) = image();
    let text = std::str::from_utf8(image.as_bytes()).unwrap().replacen(
        "\"version\":1",
        "\"version\":1,\"version\":1",
        1,
    );
    assert!(matches!(
        restore(
            text.as_bytes(),
            Sha256::digest(text.as_bytes()).into(),
            &authority
        ),
        Err(RecoveryError::Json(_))
    ));
}

#[test]
fn reader_errors_and_wire_byte_limit_fail_before_rebuild() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("injected read failure"))
        }
    }
    let (authority, _) = fixture();
    assert!(matches!(
        restore_governed_memory(Broken, [0; 32], &authority, config()),
        Err(RecoveryError::Io { .. })
    ));
    assert!(matches!(
        restore_governed_memory(io::repeat(b'x'), [0; 32], &authority, config()),
        Err(RecoveryError::Limit("image bytes"))
    ));
    let mut limited = LimitedOutput(vec![0; MAX_RECOVERY_IMAGE_BYTES - 1]);
    assert!(limited.write_all(b"xx").is_err());
    assert_eq!(limited.0.len(), MAX_RECOVERY_IMAGE_BYTES - 1);
}

#[test]
fn immutable_file_roundtrip_never_overwrites_and_reports_sync_errors() {
    let dir = Directory::new();
    let (authority, image) = image();
    let path = dir.0.join("generation.json");
    image.write_new(&path).unwrap();
    let before = fs::read(&path).unwrap();
    assert!(image.write_new(&path).is_err());
    assert_eq!(before, fs::read(&path).unwrap());
    let recovered = restore_governed_memory(
        File::open(&path).unwrap(),
        image.digest(),
        &authority,
        config(),
    )
    .unwrap();
    assert_eq!(recovered.stored_records(), 7);
    assert!(image
        .write_new_with(&dir.0.join("uncertain.json"), |_| Err(io::Error::other(
            "injected parent sync failure"
        )))
        .is_err());
    assert!(!dir.0.join("missing-parent").exists());
    assert!(image
        .write_new(dir.0.join("missing-parent/image.json"))
        .is_err());
    assert!(!dir.0.join("missing-parent").exists());
}

#[cfg(unix)]
#[test]
fn dangling_destination_is_not_replaced_and_file_is_private() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = Directory::new();
    let (_, image) = image();
    let path = dir.0.join("dangling");
    symlink(dir.0.join("absent"), &path).unwrap();
    assert!(image.write_new(&path).is_err());
    assert!(fs::symlink_metadata(path).unwrap().file_type().is_symlink());
    let path = dir.0.join("private.json");
    image.write_new(&path).unwrap();
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn fresh_process_restore_probe() {
    let Some(path) = std::env::var_os("CCOS_PROVIDER_RECOVERY_PROBE_PATH") else {
        return;
    };
    let receipt = std::env::var("CCOS_PROVIDER_RECOVERY_PROBE_RECEIPT").unwrap();
    assert_eq!(receipt.len(), 64);
    let mut expected = [0u8; 32];
    for (i, byte) in expected.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&receipt[2 * i..2 * i + 2], 16).unwrap();
    }
    let (authority, _) = fixture();
    let recovered =
        restore_governed_memory(File::open(path).unwrap(), expected, &authority, config()).unwrap();
    let loadout = MemoryLoadout::tenant_only();
    let result = recovered
        .recall(
            &authority,
            request(&loadout),
            GovernedRecallTrustPolicy::VerifiedOnly,
        )
        .unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].asset_id, id("a-live"));
    assert_eq!(recovered.stored_records(), 7);
}

#[test]
fn fresh_process_reconstructs_actual_provider_from_the_durable_image() {
    let dir = Directory::new();
    let (_, image) = image();
    let path = dir.0.join("snapshot.json");
    image.write_new(&path).unwrap();
    let expected = image
        .digest()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    drop(image);
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "recovery::tests::fresh_process_restore_probe",
            "--nocapture",
        ])
        .env("CCOS_PROVIDER_RECOVERY_PROBE_PATH", &path)
        .env("CCOS_PROVIDER_RECOVERY_PROBE_RECEIPT", expected)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "probe must run one actual test"
    );
}
