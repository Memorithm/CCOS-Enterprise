//! Tenant-bound envelope encryption. KMS selection is independently configured,
//! never inferred from an envelope's untrusted key label. No default key exists.

use base64::{engine::general_purpose::STANDARD, Engine};
use ccos_enterprise_tenancy::TenantId;
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::Arc;
use zeroize::Zeroizing;

pub mod vault;

const VERSION: u32 = 1;
const ALGORITHM: &str = "XChaCha20Poly1305";
const MAX_WRAPPED_KEY: usize = 64 * 1024;
const MAX_HEADER: usize = 128 * 1024;

/// Errors intentionally omit plaintext, credentials and KMS response bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    Configuration,
    Format,
    Authentication,
    KeyService,
    Entropy,
    Limit,
}
impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tenant envelope {:?}", self)
    }
}
impl std::error::Error for EnvelopeError {}

/// Implementations must enforce their independently provisioned tenant/key map.
/// `binding` is non-secret authenticated context, identical on wrap and unwrap.
/// Production providers must not return raw KMS errors containing secrets.
pub trait TenantKms: Send + Sync {
    fn wrap(
        &self,
        tenant: &TenantId,
        key_id: &str,
        binding: &[u8; 32],
        key: &[u8; 32],
    ) -> Result<Vec<u8>, EnvelopeError>;
    fn unwrap(
        &self,
        tenant: &TenantId,
        key_id: &str,
        binding: &[u8; 32],
        wrapped: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, EnvelopeError>;
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    algorithm: String,
    tenant: String,
    key_id: String,
    wrapped_key: String,
    nonce: String,
    ciphertext: String,
}

type DecryptedEnvelope = (Zeroizing<Vec<u8>>, Zeroizing<[u8; 32]>);

/// Immutable configuration for one tenant. Explicit read keys allow a staged
/// rotation; the active key is always used for new writes and rewrapping.
pub struct EnvelopeCipher {
    tenant: TenantId,
    active_key: String,
    read_keys: BTreeSet<String>,
    kms: Arc<dyn TenantKms>,
}

impl std::fmt::Debug for EnvelopeCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvelopeCipher")
            .field("tenant", &self.tenant)
            .field("active_key", &self.active_key)
            .finish_non_exhaustive()
    }
}

impl EnvelopeCipher {
    pub fn new(
        tenant: TenantId,
        active_key: String,
        read_keys: BTreeSet<String>,
        kms: Arc<dyn TenantKms>,
    ) -> Result<Self, EnvelopeError> {
        if TenantId::validated(tenant.as_str()).as_ref() != Some(&tenant)
            || !valid_key_id(&active_key)
            || !read_keys.contains(&active_key)
            || read_keys.len() > 64
            || read_keys.iter().any(|k| !valid_key_id(k))
        {
            return Err(EnvelopeError::Configuration);
        }
        Ok(Self {
            tenant,
            active_key,
            read_keys,
            kms,
        })
    }
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }
    pub fn active_key(&self) -> &str {
        &self.active_key
    }

    pub fn encoded_limit(plaintext_limit: usize) -> Result<usize, EnvelopeError> {
        plaintext_limit
            .checked_add(18)
            .and_then(|n| n.checked_mul(4))
            .map(|n| n / 3)
            .and_then(|n| n.checked_add(MAX_HEADER))
            .ok_or(EnvelopeError::Limit)
    }

    fn aad(&self, artifact: &str) -> Result<Vec<u8>, EnvelopeError> {
        if artifact.is_empty()
            || artifact.len() > 512
            || artifact.starts_with('/')
            || artifact
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || artifact
                .bytes()
                .any(|b| !b.is_ascii_alphanumeric() && !b"-._/".contains(&b))
        {
            return Err(EnvelopeError::Configuration);
        }
        serde_json::to_vec(&(
            "ccos-enterprise-envelope",
            VERSION,
            ALGORITHM,
            self.tenant.as_str(),
            artifact,
        ))
        .map_err(|_| EnvelopeError::Format)
    }

    pub fn seal(
        &self,
        artifact: &str,
        plaintext: &[u8],
        limit: usize,
    ) -> Result<Vec<u8>, EnvelopeError> {
        if plaintext.len() > limit {
            return Err(EnvelopeError::Limit);
        }
        let aad = self.aad(artifact)?;
        let binding = Sha256::digest(&aad).into();
        let mut key = Zeroizing::new([0u8; 32]);
        let mut nonce = [0u8; 24];
        OsRng
            .try_fill_bytes(key.as_mut())
            .map_err(|_| EnvelopeError::Entropy)?;
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| EnvelopeError::Entropy)?;
        let wrapped = self
            .kms
            .wrap(&self.tenant, &self.active_key, &binding, &key)?;
        if wrapped.is_empty() || wrapped.len() > MAX_WRAPPED_KEY {
            return Err(EnvelopeError::Limit);
        }
        let cipher =
            XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| EnvelopeError::Format)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| EnvelopeError::Authentication)?;
        let envelope = Envelope {
            version: VERSION,
            algorithm: ALGORITHM.into(),
            tenant: self.tenant.as_str().into(),
            key_id: self.active_key.clone(),
            wrapped_key: STANDARD.encode(wrapped),
            nonce: STANDARD.encode(nonce),
            ciphertext: STANDARD.encode(ciphertext),
        };
        serde_json::to_vec(&envelope).map_err(|_| EnvelopeError::Format)
    }

    fn parse(&self, bytes: &[u8], limit: usize) -> Result<Envelope, EnvelopeError> {
        if bytes.len() > Self::encoded_limit(limit)? {
            return Err(EnvelopeError::Limit);
        }
        let e: Envelope = serde_json::from_slice(bytes).map_err(|_| EnvelopeError::Format)?;
        if e.version != VERSION
            || e.algorithm != ALGORITHM
            || e.tenant != self.tenant.as_str()
            || !self.read_keys.contains(&e.key_id)
            || e.wrapped_key.len() > MAX_WRAPPED_KEY * 4 / 3 + 4
            || e.nonce.len() != 32
        {
            return Err(EnvelopeError::Authentication);
        }
        Ok(e)
    }

    fn decrypt(
        &self,
        artifact: &str,
        e: &Envelope,
        limit: usize,
    ) -> Result<DecryptedEnvelope, EnvelopeError> {
        let aad = self.aad(artifact)?;
        let binding = Sha256::digest(&aad).into();
        let nonce = STANDARD
            .decode(&e.nonce)
            .map_err(|_| EnvelopeError::Format)?;
        if nonce.len() != 24 {
            return Err(EnvelopeError::Format);
        }
        let ciphertext = STANDARD
            .decode(&e.ciphertext)
            .map_err(|_| EnvelopeError::Format)?;
        if ciphertext.len() < 16 || ciphertext.len() - 16 > limit {
            return Err(EnvelopeError::Limit);
        }
        let wrapped = STANDARD
            .decode(&e.wrapped_key)
            .map_err(|_| EnvelopeError::Format)?;
        if wrapped.is_empty() || wrapped.len() > MAX_WRAPPED_KEY {
            return Err(EnvelopeError::Limit);
        }
        let key = self
            .kms
            .unwrap(&self.tenant, &e.key_id, &binding, &wrapped)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| EnvelopeError::Format)?;
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| EnvelopeError::Authentication)?;
        Ok((Zeroizing::new(plaintext), key))
    }

    pub fn open(
        &self,
        artifact: &str,
        bytes: &[u8],
        limit: usize,
    ) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
        let e = self.parse(bytes, limit)?;
        Ok(self.decrypt(artifact, &e, limit)?.0)
    }

    /// Authenticate before rewrapping. Ciphertext/nonce and plaintext receipts
    /// remain stable; only the KMS envelope changes. No key is written to disk.
    pub fn rewrap(
        &self,
        artifact: &str,
        bytes: &[u8],
        limit: usize,
    ) -> Result<Vec<u8>, EnvelopeError> {
        let mut e = self.parse(bytes, limit)?;
        let (_plaintext, key) = self.decrypt(artifact, &e, limit)?;
        if e.key_id == self.active_key {
            return Ok(bytes.to_vec());
        }
        let binding = Sha256::digest(self.aad(artifact)?).into();
        let wrapped = self
            .kms
            .wrap(&self.tenant, &self.active_key, &binding, &key)?;
        if wrapped.is_empty() || wrapped.len() > MAX_WRAPPED_KEY {
            return Err(EnvelopeError::Limit);
        }
        e.key_id = self.active_key.clone();
        e.wrapped_key = STANDARD.encode(wrapped);
        serde_json::to_vec(&e).map_err(|_| EnvelopeError::Format)
    }

    pub fn uses_active_key(&self, bytes: &[u8], limit: usize) -> Result<bool, EnvelopeError> {
        Ok(self.parse(bytes, limit)?.key_id == self.active_key)
    }
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._:@/".contains(&b))
}

#[cfg(test)]
mod tests;
