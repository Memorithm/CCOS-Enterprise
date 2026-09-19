use super::*;
use ccos_enterprise_envelope::{EnvelopeError, TenantKms};
use ccos_enterprise_memory::{
    MemoryAssetDescriptor, MemoryAssetId, MemoryEvidenceRef, MemoryLineage, MemoryLineageGraph,
    MemoryLoadoutBinding, MemoryLoadoutPlan, MemorySpace, MemoryStratum, MemoryTrustMetadata,
    MemoryUsageMode,
};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::AtomicBool;

struct TestKms {
    retired: AtomicBool,
}
impl TestKms {
    fn cipher(&self, tenant: &TenantId, key: &str) -> Result<XChaCha20Poly1305, EnvelopeError> {
        if tenant.as_str() != "acme" || (key == "k1" && self.retired.load(Ordering::SeqCst)) {
            return Err(EnvelopeError::KeyService);
        }
        let material = match key {
            "k1" => [1; 32],
            "k2" => [2; 32],
            _ => return Err(EnvelopeError::KeyService),
        };
        Ok(XChaCha20Poly1305::new_from_slice(&material).unwrap())
    }
}
impl TenantKms for TestKms {
    fn wrap(
        &self,
        tenant: &TenantId,
        key_id: &str,
        binding: &[u8; 32],
        key: &[u8; 32],
    ) -> Result<Vec<u8>, EnvelopeError> {
        let mut nonce = [0; 24];
        OsRng.fill_bytes(&mut nonce);
        let mut bytes = nonce.to_vec();
        bytes.extend(
            self.cipher(tenant, key_id)?
                .encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: key,
                        aad: binding,
                    },
                )
                .unwrap(),
        );
        Ok(bytes)
    }
    fn unwrap(
        &self,
        tenant: &TenantId,
        key_id: &str,
        binding: &[u8; 32],
        wrapped: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, EnvelopeError> {
        if wrapped.len() != 72 {
            return Err(EnvelopeError::Format);
        }
        let bytes = Zeroizing::new(
            self.cipher(tenant, key_id)?
                .decrypt(
                    XNonce::from_slice(&wrapped[..24]),
                    Payload {
                        msg: &wrapped[24..],
                        aad: binding,
                    },
                )
                .map_err(|_| EnvelopeError::Authentication)?,
        );
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(&bytes);
        Ok(key)
    }
}
fn tenant() -> TenantId {
    TenantId::validated("acme").unwrap()
}
fn id() -> MemoryAssetId {
    MemoryAssetId::new("root").unwrap()
}
fn cipher(key: &str, kms: Arc<TestKms>) -> Arc<EnvelopeCipher> {
    Arc::new(
        EnvelopeCipher::new(
            tenant(),
            key.into(),
            BTreeSet::from(["k1".into(), "k2".into()]),
            kms,
        )
        .unwrap(),
    )
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "ccos-encrypted-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn initialize(root: &Path, cipher: Arc<EnvelopeCipher>) -> ProviderGenerationStore {
    let mut graph = MemoryLineageGraph::new();
    graph
        .register(
            MemoryAssetDescriptor::new(
                id(),
                MemorySpace::Tenant,
                MemoryStratum::Evidence,
                MemoryLineage::root([MemoryEvidenceRef::new("source:root").unwrap()]).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    let authority = GovernedMemoryProjection::new(
        tenant(),
        graph,
        BTreeMap::from([(id(), MemoryTrustMetadata::unverified(1))]),
        MemoryLoadoutPlan::new([MemoryLoadoutBinding::new(
            MemorySpace::Tenant,
            100,
            MemoryUsageMode::BootstrapAndOnDemand,
        )
        .unwrap()])
        .unwrap(),
    )
    .unwrap();
    ProviderGenerationStore::initialize_encrypted(
        root,
        authority,
        RecoveryConfig {
            dimension: 2,
            simhash_bits: 64,
            per_tenant_capacity: 8,
            seed: 42,
        },
        &[RecoveryRecord {
            asset_id: id(),
            embedding: vec![1.0, 0.0],
            payload: b"sensitive source bytes".to_vec(),
            forgotten: false,
        }],
        cipher,
    )
    .unwrap()
}

#[test]
fn encrypted_generation_recovery_purge_and_rotation_survive_key_retirement() {
    let dir = Directory::new();
    let kms = Arc::new(TestKms {
        retired: AtomicBool::new(false),
    });
    let c1 = cipher("k1", kms.clone());
    let c2 = cipher("k2", kms.clone());
    let store = initialize(&dir.0, c1.clone());
    let digest = store.recovered.digest();
    drop(store);
    assert!(ProviderGenerationStore::open(&dir.0, tenant()).is_err());
    let store = ProviderGenerationStore::open_encrypted(&dir.0, tenant(), c1).unwrap();
    assert_eq!(store.recovered.digest(), digest);
    assert_eq!(
        store.recovered.source_records()[0].payload,
        b"sensitive source bytes"
    );
    let authority = store.governance().clone();
    let records = store.recovered.source_records().to_vec();
    let config = store.config;
    let store = store.advance(authority, config, &records).unwrap();
    drop(store);
    let store = ProviderGenerationStore::open_encrypted(&dir.0, tenant(), c2.clone()).unwrap();
    let prepared = store.prepare_purge(&tenant(), id()).unwrap();
    let (store, purge) = store.commit_prepared_purge(prepared).unwrap();
    assert!(store.matches_purge_receipt(&purge));
    let (store, rotation) = store.rotate_encryption(&tenant()).unwrap();
    assert!(store.matches_encryption_receipt(&rotation).unwrap());
    for (path, _) in managed_artifacts(&dir.0).unwrap() {
        let bytes = fs::read(path).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(value.get("ciphertext").is_some());
        assert!(value.get("records").is_none());
        assert!(value.get("purged").is_none());
        assert!(!bytes
            .windows(b"sensitive source bytes".len())
            .any(|w| w == b"sensitive source bytes"));
    }
    drop(store);
    kms.retired.store(true, Ordering::SeqCst);
    let recovered = ProviderGenerationStore::open_encrypted(&dir.0, tenant(), c2).unwrap();
    assert!(recovered.matches_purge_receipt(&purge));
    assert!(recovered.matches_encryption_receipt(&rotation).unwrap());
}

#[test]
fn encrypted_files_cannot_move_between_artifacts_or_fall_back_to_plaintext() {
    let dir = Directory::new();
    let kms = Arc::new(TestKms {
        retired: AtomicBool::new(false),
    });
    let cipher = cipher("k1", kms);
    let store = initialize(&dir.0, cipher.clone());
    let provider = dir
        .0
        .join(PROVIDER_GENERATIONS_DIR)
        .join(provider_generation_filename(0));
    let governance = dir
        .0
        .join(GOVERNANCE_GENERATIONS_DIR)
        .join(governance_generation_filename(0));
    let valid = fs::read(&provider).unwrap();
    drop(store);
    fs::copy(&governance, &provider).unwrap();
    assert!(ProviderGenerationStore::open_encrypted(&dir.0, tenant(), cipher.clone()).is_err());
    fs::write(&provider, &valid).unwrap();
    let plain = read_artifact(
        &dir.0,
        Some(&cipher),
        &provider,
        crate::recovery::MAX_RECOVERY_IMAGE_BYTES,
    )
    .unwrap();
    fs::write(&provider, plain.as_slice()).unwrap();
    assert!(ProviderGenerationStore::open_encrypted(&dir.0, tenant(), cipher).is_err());
}

#[test]
#[ignore = "child process entry point"]
fn rotation_worker() {
    let root = PathBuf::from(std::env::var_os("CCOS_ROTATION_TEST_ROOT").unwrap());
    let c = cipher(
        "k2",
        Arc::new(TestKms {
            retired: AtomicBool::new(false),
        }),
    );
    let store = ProviderGenerationStore::open_encrypted(root, tenant(), c).unwrap();
    store.rotate_encryption(&tenant()).unwrap();
    panic!("missing crash checkpoint");
}

#[test]
fn killed_rotation_resumes_before_serving_and_allows_old_key_retirement() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    for stage in ["intent", "artifact", "complete"] {
        let dir = Directory::new();
        let kms = Arc::new(TestKms {
            retired: AtomicBool::new(false),
        });
        let store = initialize(&dir.0, cipher("k1", kms.clone()));
        let digest = store.recovered.digest();
        drop(store);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "generation::encrypted_artifacts::tests::rotation_worker",
                "--ignored",
            ])
            .env("CCOS_ROTATION_TEST_ROOT", &dir.0)
            .env("CCOS_ROTATION_TEST_STAGE", stage)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let start = Instant::now();
        while !dir.0.join("test-ready").exists() && start.elapsed() < Duration::from_secs(20) {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let ready = dir.0.join("test-ready").exists();
        let _ = child.kill();
        child.wait().unwrap();
        assert!(ready, "{stage}");
        assert!(ProviderGenerationStore::open(&dir.0, tenant()).is_err());
        let next =
            ProviderGenerationStore::open_encrypted(&dir.0, tenant(), cipher("k2", kms.clone()))
                .unwrap();
        assert_eq!(next.recovered.digest(), digest);
        drop(next);
        assert!(!dir.0.join(ROTATION_INTENT).exists());
        kms.retired.store(true, Ordering::SeqCst);
        let next =
            ProviderGenerationStore::open_encrypted(&dir.0, tenant(), cipher("k2", kms)).unwrap();
        assert_eq!(
            next.recovered.source_records()[0].payload,
            b"sensitive source bytes"
        );
    }
}

#[test]
#[ignore = "child process entry point"]
fn encrypted_purge_worker() {
    let root = PathBuf::from(std::env::var_os("CCOS_ROTATION_TEST_ROOT").unwrap());
    let c = cipher(
        "k1",
        Arc::new(TestKms {
            retired: AtomicBool::new(false),
        }),
    );
    let store = ProviderGenerationStore::open_encrypted(root, tenant(), c).unwrap();
    let prepared = store.prepare_purge(&tenant(), id()).unwrap();
    store.commit_prepared_purge(prepared).unwrap();
    panic!("missing purge checkpoint");
}

#[test]
fn encrypted_purge_rolls_forward_after_process_death() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    for stage in ["intent", "artifacts", "selector", "cleanup", "floor"] {
        let dir = Directory::new();
        let kms = Arc::new(TestKms {
            retired: AtomicBool::new(false),
        });
        drop(initialize(&dir.0, cipher("k1", kms.clone())));
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "generation::encrypted_artifacts::tests::encrypted_purge_worker",
                "--ignored",
            ])
            .env("CCOS_ROTATION_TEST_ROOT", &dir.0)
            .env("CCOS_PURGE_TEST_STAGE", stage)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let start = Instant::now();
        while !dir.0.join("test-ready").exists() && start.elapsed() < Duration::from_secs(20) {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let ready = dir.0.join("test-ready").exists();
        let _ = child.kill();
        child.wait().unwrap();
        assert!(ready, "{stage}");
        let next =
            ProviderGenerationStore::open_encrypted(&dir.0, tenant(), cipher("k1", kms)).unwrap();
        assert!(next.recovered.source_records()[0].is_physically_purged());
        assert_eq!(next.generation(), 1);
        assert_eq!(
            fs::read_dir(dir.0.join(PROVIDER_GENERATIONS_DIR))
                .unwrap()
                .count(),
            1
        );
    }
}
