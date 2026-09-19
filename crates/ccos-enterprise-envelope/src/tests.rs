use super::*;
use std::sync::Mutex;

struct TestKms {
    retired: Mutex<bool>,
}
impl TenantKms for TestKms {
    fn wrap(
        &self,
        tenant: &TenantId,
        key_id: &str,
        binding: &[u8; 32],
        key: &[u8; 32],
    ) -> Result<Vec<u8>, EnvelopeError> {
        if tenant.as_str() != "a" || (key_id == "k1" && *self.retired.lock().unwrap()) {
            return Err(EnvelopeError::KeyService);
        }
        let wrapping = if key_id == "k1" {
            [1; 32]
        } else if key_id == "k2" {
            [2; 32]
        } else {
            return Err(EnvelopeError::KeyService);
        };
        let cipher = XChaCha20Poly1305::new_from_slice(&wrapping).unwrap();
        let mut nonce = [0; 24];
        OsRng.fill_bytes(&mut nonce);
        let mut wrapped = nonce.to_vec();
        wrapped.extend(
            cipher
                .encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: key,
                        aad: binding,
                    },
                )
                .unwrap(),
        );
        Ok(wrapped)
    }
    fn unwrap(
        &self,
        tenant: &TenantId,
        key_id: &str,
        binding: &[u8; 32],
        wrapped: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, EnvelopeError> {
        if tenant.as_str() != "a"
            || (key_id == "k1" && *self.retired.lock().unwrap())
            || wrapped.len() != 72
        {
            return Err(EnvelopeError::KeyService);
        }
        let wrapping = if key_id == "k1" {
            [1; 32]
        } else if key_id == "k2" {
            [2; 32]
        } else {
            return Err(EnvelopeError::KeyService);
        };
        let cipher = XChaCha20Poly1305::new_from_slice(&wrapping).unwrap();
        let bytes = Zeroizing::new(
            cipher
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
fn cipher(tenant: &str, active: &str, kms: Arc<TestKms>) -> EnvelopeCipher {
    EnvelopeCipher::new(
        TenantId::validated(tenant).unwrap(),
        active.into(),
        BTreeSet::from(["k1".into(), "k2".into()]),
        kms,
    )
    .unwrap()
}
#[test]
fn tenant_artifact_tampering_and_plaintext_fail_closed() {
    let kms = Arc::new(TestKms {
        retired: Mutex::new(false),
    });
    let c = cipher("a", "k1", kms.clone());
    let bytes = c.seal("provider/generation-1", b"secret", 1024).unwrap();
    assert_eq!(
        c.open("provider/generation-1", &bytes, 1024)
            .unwrap()
            .as_slice(),
        b"secret"
    );
    assert!(cipher("b", "k1", kms)
        .open("provider/generation-1", &bytes, 1024)
        .is_err());
    assert!(c.open("provider/generation-2", &bytes, 1024).is_err());
    assert!(c.open("provider/generation-1", b"secret", 1024).is_err());
    assert!(c.open("provider/generation-1", &bytes, 2).is_err());
    for field in [
        "tenant",
        "key_id",
        "ciphertext",
        "wrapped_key",
        "nonce",
        "algorithm",
    ] {
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value[field] = serde_json::json!("tampered");
        assert!(c
            .open(
                "provider/generation-1",
                &serde_json::to_vec(&value).unwrap(),
                1024
            )
            .is_err());
    }
    let second = c.seal("provider/generation-1", b"secret", 1024).unwrap();
    assert_ne!(bytes, second);
}
#[test]
fn rotation_preserves_ciphertext_and_supports_old_key_retirement() {
    let kms = Arc::new(TestKms {
        retired: Mutex::new(false),
    });
    let old = cipher("a", "k1", kms.clone());
    let new = cipher("a", "k2", kms.clone());
    let bytes = old.seal("artifact", b"recovery", 1024).unwrap();
    let rotated = new.rewrap("artifact", &bytes, 1024).unwrap();
    let a: Envelope = serde_json::from_slice(&bytes).unwrap();
    let b: Envelope = serde_json::from_slice(&rotated).unwrap();
    assert_eq!(a.ciphertext, b.ciphertext);
    assert_eq!(a.nonce, b.nonce);
    assert_ne!(a.wrapped_key, b.wrapped_key);
    *kms.retired.lock().unwrap() = true;
    assert!(old.open("artifact", &bytes, 1024).is_err());
    assert_eq!(
        new.open("artifact", &rotated, 1024).unwrap().as_slice(),
        b"recovery"
    );
    assert_eq!(new.rewrap("artifact", &rotated, 1024).unwrap(), rotated);
}
