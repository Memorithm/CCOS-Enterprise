//! Authenticated server seam with an isolated, in-memory remote-key-service model.
//! Vault transport is qualified separately; this fixture is never production code.
use super::*;
use ccos_enterprise_envelope::{EnvelopeCipher, EnvelopeError, TenantKms};
use ccos_enterprise_memory::{
    GovernedMemoryProjection, MemoryAssetDescriptor, MemoryAssetId, MemoryEvidenceRef,
    MemoryLineage, MemoryLineageGraph, MemoryLoadoutBinding, MemoryLoadoutPlan, MemorySpace,
    MemoryStratum, MemoryTrustMetadata, MemoryUsageMode, MemoryValidationState,
};
use ccos_enterprise_provider_adapter::{
    generation::ProviderGenerationStore,
    recovery::{RecoveryConfig, RecoveryRecord},
};
use ccos_enterprise_tenancy::TenantId;
use rand::{rngs::OsRng, RngCore};
use std::collections::BTreeSet;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use zeroize::Zeroizing;

struct StoredKey {
    label: String,
    binding: [u8; 32],
    key: Zeroizing<[u8; 32]>,
}
#[derive(Default)]
struct KeyService {
    keys: Mutex<BTreeMap<Vec<u8>, StoredKey>>,
    retired: AtomicBool,
    offline: AtomicBool,
}
impl TenantKms for KeyService {
    fn wrap(
        &self,
        tenant: &TenantId,
        key_id: &str,
        binding: &[u8; 32],
        key: &[u8; 32],
    ) -> Result<Vec<u8>, EnvelopeError> {
        if tenant.as_str() != "acme" || self.offline.load(Ordering::SeqCst) {
            return Err(EnvelopeError::KeyService);
        }
        let mut handle = vec![0; 32];
        OsRng.fill_bytes(&mut handle);
        self.keys.lock().unwrap().insert(
            handle.clone(),
            StoredKey {
                label: key_id.into(),
                binding: *binding,
                key: Zeroizing::new(*key),
            },
        );
        Ok(handle)
    }
    fn unwrap(
        &self,
        tenant: &TenantId,
        key_id: &str,
        binding: &[u8; 32],
        wrapped: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, EnvelopeError> {
        if tenant.as_str() != "acme"
            || self.offline.load(Ordering::SeqCst)
            || (key_id == "k1" && self.retired.load(Ordering::SeqCst))
        {
            return Err(EnvelopeError::KeyService);
        }
        let keys = self.keys.lock().unwrap();
        let stored = keys.get(wrapped).ok_or(EnvelopeError::KeyService)?;
        if stored.label != key_id || &stored.binding != binding {
            return Err(EnvelopeError::KeyService);
        }
        Ok(Zeroizing::new(*stored.key))
    }
}
fn cipher(active: &str, kms: Arc<KeyService>) -> Arc<EnvelopeCipher> {
    Arc::new(
        EnvelopeCipher::new(
            TenantId::validated("acme").unwrap(),
            active.into(),
            BTreeSet::from(["k1".into(), "k2".into()]),
            kms,
        )
        .unwrap(),
    )
}

#[test]
fn authenticated_encrypted_server_rotates_and_recovers_without_old_key_or_plaintext_fallback() {
    let mut config = tests::test_config("envelope-server");
    let _ = fs::remove_dir_all(&config.state_dir);
    let root = config.state_dir.join("provider");
    let kms = Arc::new(KeyService::default());
    let asset = MemoryAssetId::new("root").unwrap();
    let mut graph = MemoryLineageGraph::new();
    graph
        .register(
            MemoryAssetDescriptor::new(
                asset.clone(),
                MemorySpace::Tenant,
                MemoryStratum::Evidence,
                MemoryLineage::root([MemoryEvidenceRef::new("e:root").unwrap()]).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    let authority = GovernedMemoryProjection::new(
        TenantId::validated("acme").unwrap(),
        graph,
        BTreeMap::from([(
            asset.clone(),
            MemoryTrustMetadata::new(
                MemoryValidationState::Verified,
                1,
                1,
                0,
                ["test-proof".into()],
            )
            .unwrap(),
        )]),
        MemoryLoadoutPlan::new([MemoryLoadoutBinding::new(
            MemorySpace::Tenant,
            100,
            MemoryUsageMode::BootstrapAndOnDemand,
        )
        .unwrap()])
        .unwrap(),
    )
    .unwrap();
    drop(
        ProviderGenerationStore::initialize_encrypted(
            &root,
            authority,
            RecoveryConfig {
                dimension: 2,
                simhash_bits: 64,
                per_tenant_capacity: 8,
                seed: 42,
            },
            &[RecoveryRecord {
                asset_id: asset,
                embedding: vec![1.0, 0.0],
                payload: b"sealed memory".to_vec(),
                forgotten: false,
            }],
            cipher("k1", kms.clone()),
        )
        .unwrap(),
    );
    config.governed_memory_root = Some(root);
    config.envelope = Some(cipher("k2", kms.clone()));
    let mut server = Server::new(config.clone()).unwrap();
    let denied = server
        .handle(&tests::call(
            1,
            "alice",
            "deny-key-rotation",
            ccos_enterprise_mcp::GOVERNED_KEY_ROTATE_TOOL,
            json!({}),
        ))
        .unwrap();
    assert_eq!(denied["result"]["isError"], true);
    server.front_door.deployment_mut().add_role(
        "key-operator",
        &[ccos_enterprise_mcp::GOVERNED_KEY_ROTATE_PERMISSION],
    );
    assert!(server
        .front_door
        .deployment_mut()
        .assign("memorithm", "alice", "key-operator"));
    let rotated = server
        .handle(&tests::call(
            2,
            "alice",
            "rotate",
            ccos_enterprise_mcp::GOVERNED_KEY_ROTATE_TOOL,
            json!({}),
        ))
        .unwrap();
    assert_eq!(
        rotated["result"]["structuredContent"]["key_id"], "k2",
        "{rotated}"
    );
    let effect_file = effect_path(&config.state_dir);
    drop(server);
    let mut effect = read_effect(&effect_file).unwrap().unwrap();
    effect.state = EffectState::Succeeded;
    write_effect(&effect_file, &effect).unwrap();
    kms.retired.store(true, Ordering::SeqCst);
    let mut server = Server::new(config.clone()).unwrap();
    let context=server.handle(&tests::call(3,"alice","read-encrypted",ccos_enterprise_mcp::GOVERNED_CONTEXT_TOOL,
        json!({"embedding":[1.0,0.0],"recall_max_items":8,"recall_max_shortlist":8,"recall_max_payload_bytes":4096,"context_max_items":8,"context_max_payload_bytes":4096}))).unwrap();
    assert_eq!(
        context["result"]["structuredContent"]["items"][0]["asset_id"], "root",
        "{context}"
    );
    drop(server);
    kms.offline.store(true, Ordering::SeqCst);
    assert!(Server::new(config.clone()).is_err());
    config.envelope = None;
    assert!(Server::new(config.clone()).is_err());
    fs::remove_dir_all(config.state_dir).unwrap();
}
