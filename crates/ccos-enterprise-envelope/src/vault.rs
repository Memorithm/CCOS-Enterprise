//! Explicitly configured Vault Transit adapter. This client cannot create,
//! delete, rotate or export a Vault KEK. Operators provision tenant keys/ACLs.
use super::*;
use reqwest::{blocking::Client, header::HeaderValue, redirect::Policy, Url};
use std::collections::BTreeMap;
use std::io::Read;
use std::time::Duration;
use zeroize::Zeroize;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultKey {
    pub name: String,
    pub version: u32,
}

pub struct VaultTransitKms {
    client: Client,
    address: Url,
    mount: String,
    token: Zeroizing<String>,
    keys: BTreeMap<(String, String), VaultKey>,
}

#[derive(Deserialize)]
struct Response {
    data: ResponseData,
}
#[derive(Deserialize)]
struct ResponseData {
    #[serde(default)]
    plaintext: Option<String>,
    #[serde(default)]
    ciphertext: Option<String>,
}
impl Drop for ResponseData {
    fn drop(&mut self) {
        if let Some(value) = &mut self.plaintext {
            value.zeroize();
        }
    }
}

impl VaultTransitKms {
    /// HTTPS with normal certificate/hostname validation; no redirects or proxy
    /// inheritance. Key paths and versions come from operator configuration.
    pub fn new(
        address: &str,
        mount: String,
        token: Zeroizing<String>,
        keys: BTreeMap<(String, String), VaultKey>,
    ) -> Result<Self, EnvelopeError> {
        Self::build(address, mount, token, keys, false)
    }

    fn build(
        address: &str,
        mount: String,
        token: Zeroizing<String>,
        keys: BTreeMap<(String, String), VaultKey>,
        test_loopback: bool,
    ) -> Result<Self, EnvelopeError> {
        let address = Url::parse(address).map_err(|_| EnvelopeError::Configuration)?;
        let loopback = matches!(address.host_str(), Some("127.0.0.1" | "[::1]"));
        if (address.scheme() != "https"
            && !(test_loopback && loopback && address.scheme() == "http"))
            || !address.username().is_empty()
            || address.password().is_some()
            || address.query().is_some()
            || address.fragment().is_some()
            || address.path() != "/"
            || !segment(&mount)
            || token.is_empty()
            || token.len() > 8192
            || keys.is_empty()
            || keys.len() > 64
        {
            return Err(EnvelopeError::Configuration);
        }
        HeaderValue::from_str(&token).map_err(|_| EnvelopeError::Configuration)?;
        let mut owners = BTreeMap::new();
        for ((tenant, key_id), key) in &keys {
            if TenantId::validated(tenant).is_none()
                || !valid_key_id(key_id)
                || !segment(&key.name)
                || key.version == 0
            {
                return Err(EnvelopeError::Configuration);
            }
            if owners
                .insert(&key.name, tenant)
                .is_some_and(|previous| previous != tenant)
            {
                return Err(EnvelopeError::Configuration);
            }
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .redirect(Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| EnvelopeError::Configuration)?;
        Ok(Self {
            client,
            address,
            mount,
            token,
            keys,
        })
    }

    fn configured(&self, tenant: &TenantId, key_id: &str) -> Result<&VaultKey, EnvelopeError> {
        self.keys
            .get(&(tenant.as_str().into(), key_id.into()))
            .ok_or(EnvelopeError::KeyService)
    }

    fn post(
        &self,
        operation: &str,
        name: &str,
        mut body: serde_json::Value,
    ) -> Result<Response, EnvelopeError> {
        let url = self
            .address
            .join(&format!("v1/{}/{operation}/{name}", self.mount))
            .map_err(|_| EnvelopeError::Configuration)?;
        let request = Zeroizing::new(serde_json::to_vec(&body).map_err(|_| EnvelopeError::Format)?);
        if let Some(serde_json::Value::String(value)) = body.get_mut("plaintext") {
            value.zeroize();
        }
        let mut token =
            HeaderValue::from_str(&self.token).map_err(|_| EnvelopeError::Configuration)?;
        token.set_sensitive(true);
        let response = self
            .client
            .post(url)
            .header("X-Vault-Token", token)
            .header("Content-Type", "application/json")
            .body(request.to_vec())
            .send()
            .map_err(|_| EnvelopeError::KeyService)?;
        if !response.status().is_success() {
            return Err(EnvelopeError::KeyService);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        response
            .take((MAX_HEADER + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| EnvelopeError::KeyService)?;
        if bytes.len() > MAX_HEADER {
            return Err(EnvelopeError::Limit);
        }
        serde_json::from_slice(&bytes).map_err(|_| EnvelopeError::KeyService)
    }
}

impl TenantKms for VaultTransitKms {
    fn wrap(
        &self,
        tenant: &TenantId,
        key_id: &str,
        binding: &[u8; 32],
        key: &[u8; 32],
    ) -> Result<Vec<u8>, EnvelopeError> {
        let configured = self.configured(tenant, key_id)?;
        let mut response = self.post(
            "encrypt",
            &configured.name,
            serde_json::json!({
                "plaintext": STANDARD.encode(key), "context": STANDARD.encode(binding),
                "associated_data": STANDARD.encode(binding), "key_version": configured.version,
            }),
        )?;
        let wrapped = response
            .data
            .ciphertext
            .take()
            .ok_or(EnvelopeError::KeyService)?;
        if !wrapped.starts_with(&format!("vault:v{}:", configured.version))
            || wrapped.len() > MAX_WRAPPED_KEY
        {
            return Err(EnvelopeError::KeyService);
        }
        Ok(wrapped.into_bytes())
    }

    fn unwrap(
        &self,
        tenant: &TenantId,
        key_id: &str,
        binding: &[u8; 32],
        wrapped: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, EnvelopeError> {
        let configured = self.configured(tenant, key_id)?;
        let wrapped = std::str::from_utf8(wrapped).map_err(|_| EnvelopeError::Format)?;
        if wrapped.len() > MAX_WRAPPED_KEY
            || !wrapped.starts_with(&format!("vault:v{}:", configured.version))
        {
            return Err(EnvelopeError::KeyService);
        }
        let response = self.post("decrypt", &configured.name, serde_json::json!({
            "ciphertext": wrapped, "context": STANDARD.encode(binding), "associated_data": STANDARD.encode(binding),
        }))?;
        let plaintext = response
            .data
            .plaintext
            .as_deref()
            .ok_or(EnvelopeError::KeyService)?;
        let decoded = Zeroizing::new(
            STANDARD
                .decode(plaintext)
                .map_err(|_| EnvelopeError::KeyService)?,
        );
        if decoded.len() != 32 {
            return Err(EnvelopeError::KeyService);
        }
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(&decoded);
        Ok(key)
    }
}

fn segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfiguration {
    vault_address: String,
    mount: String,
    token_file: std::path::PathBuf,
    active_key: String,
    keys: Vec<KeyConfiguration>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyConfiguration {
    id: String,
    name: String,
    version: u32,
}

/// Load operator configuration and a separate restricted token file. No token
/// defaults, HTTP override, automatic key creation or plaintext fallback exists.
pub fn from_config_file(
    tenant: TenantId,
    path: &std::path::Path,
) -> Result<Arc<EnvelopeCipher>, EnvelopeError> {
    let bytes = bounded_file(path, MAX_HEADER)?;
    let config: FileConfiguration =
        serde_json::from_slice(&bytes).map_err(|_| EnvelopeError::Configuration)?;
    if !config.token_file.is_absolute() {
        return Err(EnvelopeError::Configuration);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::symlink_metadata(&config.token_file)
            .map_err(|_| EnvelopeError::Configuration)?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(EnvelopeError::Configuration);
        }
    }
    let token_bytes = bounded_file(&config.token_file, 8192)?;
    let token = Zeroizing::new(
        std::str::from_utf8(&token_bytes)
            .map_err(|_| EnvelopeError::Configuration)?
            .trim()
            .to_owned(),
    );
    let mut keys = BTreeMap::new();
    let mut read_keys = BTreeSet::new();
    for key in config.keys {
        if !read_keys.insert(key.id.clone()) {
            return Err(EnvelopeError::Configuration);
        }
        keys.insert(
            (tenant.as_str().into(), key.id),
            VaultKey {
                name: key.name,
                version: key.version,
            },
        );
    }
    let kms = Arc::new(VaultTransitKms::new(
        &config.vault_address,
        config.mount,
        token,
        keys,
    )?);
    Ok(Arc::new(EnvelopeCipher::new(
        tenant,
        config.active_key,
        read_keys,
        kms,
    )?))
}

fn bounded_file(path: &std::path::Path, limit: usize) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| EnvelopeError::Configuration)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(EnvelopeError::Configuration);
    }
    let file = std::fs::File::open(path).map_err(|_| EnvelopeError::Configuration)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| EnvelopeError::Configuration)?;
    if bytes.len() > limit {
        return Err(EnvelopeError::Limit);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn qualification_enabled() -> bool {
        std::env::var_os("CCOS_VAULT_QUALIFICATION").is_some()
    }

    fn qualification_value(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
    }

    fn admin_request(
        client: &Client,
        method: reqwest::Method,
        address: &str,
        root_token: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> reqwest::blocking::Response {
        let request = client
            .request(method, format!("{address}/v1/{path}"))
            .header("X-Vault-Token", root_token);
        let response = match body {
            Some(body) => request
                .header("Content-Type", "application/json")
                .body(serde_json::to_vec(&body).expect("qualification request body")),
            None => request,
        }
        .send()
        .unwrap_or_else(|_| panic!("Vault request failed for {path}"));
        response
    }

    fn successful_json(response: reqwest::blocking::Response) -> serde_json::Value {
        assert!(
            response.status().is_success(),
            "Vault returned status {}",
            response.status()
        );
        let mut bytes = Vec::new();
        response
            .take((MAX_HEADER + 1) as u64)
            .read_to_end(&mut bytes)
            .expect("qualification response read");
        assert!(
            bytes.len() <= MAX_HEADER,
            "qualification response too large"
        );
        serde_json::from_slice(&bytes).expect("bounded qualification response")
    }

    fn create_service_token(
        client: &Client,
        address: &str,
        root_token: &str,
        ttl: &str,
        renewable: bool,
        display_name: &str,
    ) -> String {
        let response = successful_json(admin_request(
            client,
            reqwest::Method::POST,
            address,
            root_token,
            "auth/token/create-orphan",
            Some(serde_json::json!({
                "policies": ["ccos-acme-service"],
                "ttl": ttl,
                "explicit_max_ttl": if renewable { "120s" } else { ttl },
                "renewable": renewable,
                "no_default_policy": true,
                "display_name": display_name,
            })),
        ));
        response["auth"]["client_token"]
            .as_str()
            .expect("service token")
            .to_owned()
    }

    fn qualification_kms(
        address: &str,
        token: String,
        versions: &[(&str, u32)],
    ) -> Arc<VaultTransitKms> {
        let keys = versions
            .iter()
            .map(|(id, version)| {
                (
                    ("acme".into(), (*id).into()),
                    VaultKey {
                        name: "ccos-acme".into(),
                        version: *version,
                    },
                )
            })
            .collect();
        Arc::new(
            VaultTransitKms::build(address, "transit".into(), Zeroizing::new(token), keys, true)
                .expect("loopback qualification client"),
        )
    }

    fn qualification_cipher(
        kms: Arc<VaultTransitKms>,
        active: &str,
        reads: &[&str],
    ) -> EnvelopeCipher {
        EnvelopeCipher::new(
            TenantId::validated("acme").expect("tenant"),
            active.into(),
            reads.iter().map(|key| (*key).to_owned()).collect(),
            kms,
        )
        .expect("qualification cipher")
    }

    #[test]
    #[ignore = "requires an explicitly provisioned, ephemeral real Vault server"]
    fn live_vault_active_qualification() {
        if !qualification_enabled() {
            return;
        }
        let address = qualification_value("VAULT_ADDR")
            .trim_end_matches('/')
            .to_owned();
        let root_token = qualification_value("VAULT_TOKEN");
        let expected_version = qualification_value("CCOS_VAULT_VERSION");
        let output = std::path::PathBuf::from(qualification_value("CCOS_VAULT_ACTIVE_RESULT"));
        assert!(
            address.starts_with("http://127.0.0.1:"),
            "qualification Vault must be loopback-only"
        );

        let admin = Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(Policy::none())
            .no_proxy()
            .build()
            .expect("admin client");
        let health = successful_json(admin_request(
            &admin,
            reqwest::Method::GET,
            &address,
            &root_token,
            "sys/health",
            None,
        ));
        assert_eq!(health["version"].as_str(), Some(expected_version.as_str()));

        let enable = admin_request(
            &admin,
            reqwest::Method::POST,
            &address,
            &root_token,
            "sys/mounts/transit",
            Some(serde_json::json!({"type": "transit"})),
        );
        assert!(enable.status().is_success());
        for key in ["ccos-acme", "ccos-other"] {
            let response = admin_request(
                &admin,
                reqwest::Method::POST,
                &address,
                &root_token,
                &format!("transit/keys/{key}"),
                Some(serde_json::json!({
                    "type": "aes256-gcm96",
                    "derived": true,
                    "exportable": false,
                    "allow_plaintext_backup": false,
                })),
            );
            assert!(response.status().is_success());
        }
        let policy = r#"
path "transit/encrypt/ccos-acme" { capabilities = ["update"] }
path "transit/decrypt/ccos-acme" { capabilities = ["update"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }
"#;
        let policy_response = admin_request(
            &admin,
            reqwest::Method::PUT,
            &address,
            &root_token,
            "sys/policies/acl/ccos-acme-service",
            Some(serde_json::json!({"policy": policy})),
        );
        assert!(policy_response.status().is_success());

        let service_token = create_service_token(
            &admin,
            &address,
            &root_token,
            "30s",
            true,
            "ccos-qualification-renewable",
        );
        let service = Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(Policy::none())
            .no_proxy()
            .build()
            .expect("service client");
        let renewal = successful_json(
            service
                .post(format!("{address}/v1/auth/token/renew-self"))
                .header("X-Vault-Token", &service_token)
                .header("Content-Type", "application/json")
                .body(
                    serde_json::to_vec(&serde_json::json!({"increment": "45s"}))
                        .expect("renewal body"),
                )
                .send()
                .expect("renew self"),
        );
        assert_eq!(renewal["auth"]["renewable"].as_bool(), Some(true));
        assert!(renewal["auth"]["lease_duration"]
            .as_u64()
            .is_some_and(|ttl| ttl >= 30));

        let denied_other = service
            .post(format!("{address}/v1/transit/encrypt/ccos-other"))
            .header("X-Vault-Token", &service_token)
            .header("Content-Type", "application/json")
            .body(
                serde_json::to_vec(&serde_json::json!({
                    "plaintext": STANDARD.encode([0u8; 32]),
                    "context": STANDARD.encode([0u8; 32]),
                }))
                .expect("cross-key body"),
            )
            .send()
            .expect("forbidden other-key request");
        assert_eq!(denied_other.status(), reqwest::StatusCode::FORBIDDEN);
        let denied_rotate = service
            .post(format!("{address}/v1/transit/keys/ccos-acme/rotate"))
            .header("X-Vault-Token", &service_token)
            .header("Content-Type", "application/json")
            .body(b"{}".to_vec())
            .send()
            .expect("forbidden rotate request");
        assert_eq!(denied_rotate.status(), reqwest::StatusCode::FORBIDDEN);

        let cipher_v1 = qualification_cipher(
            qualification_kms(&address, service_token.clone(), &[("acme-v1", 1)]),
            "acme-v1",
            &["acme-v1"],
        );
        let backup_plaintext = b"qualified-backup-generation";
        let backup_v1 = cipher_v1
            .seal("backups/generation-1.json", backup_plaintext, 4096)
            .expect("seal v1 backup");
        assert_eq!(
            cipher_v1
                .open("backups/generation-1.json", &backup_v1, 4096)
                .expect("restore v1 backup")
                .as_slice(),
            backup_plaintext
        );

        let rotated = admin_request(
            &admin,
            reqwest::Method::POST,
            &address,
            &root_token,
            "transit/keys/ccos-acme/rotate",
            Some(serde_json::json!({})),
        );
        assert!(rotated.status().is_success());
        let key_state = successful_json(admin_request(
            &admin,
            reqwest::Method::GET,
            &address,
            &root_token,
            "transit/keys/ccos-acme",
            None,
        ));
        assert_eq!(key_state["data"]["latest_version"].as_u64(), Some(2));

        let cipher_v2 = qualification_cipher(
            qualification_kms(
                &address,
                service_token.clone(),
                &[("acme-v1", 1), ("acme-v2", 2)],
            ),
            "acme-v2",
            &["acme-v1", "acme-v2"],
        );
        assert_eq!(
            cipher_v2
                .open("backups/generation-1.json", &backup_v1, 4096)
                .expect("old backup readable before retirement")
                .as_slice(),
            backup_plaintext
        );
        let backup_v2 = cipher_v2
            .rewrap("backups/generation-1.json", &backup_v1, 4096)
            .expect("rewrap backup to v2");
        assert!(cipher_v2
            .uses_active_key(&backup_v2, 4096)
            .expect("active key marker"));
        assert_eq!(
            cipher_v2
                .open("backups/generation-1.json", &backup_v2, 4096)
                .expect("restored rewrapped backup")
                .as_slice(),
            backup_plaintext
        );

        let retired = admin_request(
            &admin,
            reqwest::Method::POST,
            &address,
            &root_token,
            "transit/keys/ccos-acme/config",
            Some(serde_json::json!({"min_decryption_version": 2})),
        );
        assert!(retired.status().is_success());
        assert!(matches!(
            cipher_v2.open("backups/generation-1.json", &backup_v1, 4096),
            Err(EnvelopeError::KeyService)
        ));
        assert_eq!(
            cipher_v2
                .open("backups/generation-1.json", &backup_v2, 4096)
                .expect("v2 remains restorable")
                .as_slice(),
            backup_plaintext
        );

        let short_token = create_service_token(
            &admin,
            &address,
            &root_token,
            "2s",
            false,
            "ccos-qualification-expiring",
        );
        let short_cipher = qualification_cipher(
            qualification_kms(&address, short_token, &[("acme-v2", 2)]),
            "acme-v2",
            &["acme-v2"],
        );
        short_cipher
            .seal("state/pre-expiry.json", b"before-expiry", 4096)
            .expect("short token initially works");
        std::thread::sleep(Duration::from_secs(3));
        assert!(matches!(
            short_cipher.seal("state/post-expiry.json", b"after-expiry", 4096),
            Err(EnvelopeError::KeyService)
        ));

        let result = serde_json::json!({
            "schema": "ccos-vault-qualification-active.v1",
            "vault_version": expected_version,
            "vault_address_class": "http_loopback_ephemeral",
            "transit_algorithm": "aes256-gcm96-derived",
            "checks": {
                "real_vault_health": true,
                "least_privilege_named_key_acl": true,
                "cross_key_encrypt_denied": true,
                "service_key_rotation_denied": true,
                "renewable_token_renewed": true,
                "nonrenewable_token_expired_fail_closed": true,
                "transit_rotation_to_v2": true,
                "old_backup_restored_before_retirement": true,
                "backup_rewrapped_and_restored_after_rotation": true,
                "v1_refused_after_min_decryption_version_2": true,
                "v2_restored_after_retirement": true
            },
            "limits": [
                "ephemeral single-node development server",
                "loopback HTTP isolates Vault semantics from separately tested production TLS enforcement",
                "no HSM, IAM, HA, seal, FIPS or production deployment qualification"
            ]
        });
        std::fs::write(
            output,
            serde_json::to_vec_pretty(&result).expect("qualification result"),
        )
        .expect("write qualification result");
    }

    #[test]
    #[ignore = "requires the qualification Vault process to have been stopped"]
    fn live_vault_outage_fails_closed() {
        if !qualification_enabled() {
            return;
        }
        let address = qualification_value("VAULT_ADDR")
            .trim_end_matches('/')
            .to_owned();
        let output = std::path::PathBuf::from(qualification_value("CCOS_VAULT_OUTAGE_RESULT"));
        let unavailable_credential = String::from_utf8(vec![b'x'; 32]).expect("ASCII credential");
        let cipher = qualification_cipher(
            qualification_kms(&address, unavailable_credential, &[("acme-v2", 2)]),
            "acme-v2",
            &["acme-v2"],
        );
        assert!(matches!(
            cipher.seal("state/outage.json", b"must-not-persist", 4096),
            Err(EnvelopeError::KeyService)
        ));
        let result = serde_json::json!({
            "schema": "ccos-vault-qualification-outage.v1",
            "checks": {"stopped_real_vault_fails_closed": true}
        });
        std::fs::write(
            output,
            serde_json::to_vec_pretty(&result).expect("outage result"),
        )
        .expect("write outage result");
    }

    #[test]
    fn network_configuration_rejects_http_paths_and_shared_tenant_keys() {
        let keys = BTreeMap::from([(
            ("a".into(), "k1".into()),
            VaultKey {
                name: "tenant-a".into(),
                version: 1,
            },
        )]);
        for address in [
            "http://example.com",
            "https://user:password@example.com",
            "https://example.com/prefix",
            "https://example.com?token=x",
        ] {
            assert!(VaultTransitKms::new(
                address,
                "transit".into(),
                Zeroizing::new("test-token".into()),
                keys.clone()
            )
            .is_err());
        }
        let mut shared = keys;
        shared.insert(
            ("b".into(), "k1".into()),
            VaultKey {
                name: "tenant-a".into(),
                version: 2,
            },
        );
        assert!(VaultTransitKms::new(
            "https://example.com",
            "transit".into(),
            Zeroizing::new("test-token".into()),
            shared
        )
        .is_err());
    }

    #[test]
    fn transit_transport_binds_key_version_tenant_and_authenticated_context() {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let binding = [9u8; 32];
        let secret = [7u8; 32];
        let worker = std::thread::spawn(move || {
            for operation in ["encrypt", "decrypt"] {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut first = String::new();
                reader.read_line(&mut first).unwrap();
                assert_eq!(
                    first.trim(),
                    format!("POST /v1/transit/{operation}/tenant-a HTTP/1.1")
                );
                let mut length = 0;
                let mut token = false;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = v.trim().parse::<usize>().unwrap();
                    }
                    if line.trim() == "x-vault-token: fixture-token" {
                        token = true;
                    }
                }
                assert!(token);
                assert!(length < 8192);
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(body["associated_data"], STANDARD.encode(binding));
                assert_eq!(body["context"], STANDARD.encode(binding));
                let response = if operation == "encrypt" {
                    assert_eq!(body["key_version"], 2);
                    assert_eq!(body["plaintext"], STANDARD.encode(secret));
                    serde_json::json!({"data":{"ciphertext":"vault:v2:fixture-wrapped"}})
                } else {
                    assert_eq!(body["ciphertext"], "vault:v2:fixture-wrapped");
                    serde_json::json!({"data":{"plaintext":STANDARD.encode(secret)}})
                }
                .to_string();
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",response.len(),response).unwrap();
            }
        });
        let keys = BTreeMap::from([(
            ("a".into(), "k2".into()),
            VaultKey {
                name: "tenant-a".into(),
                version: 2,
            },
        )]);
        let kms = VaultTransitKms::build(
            &address,
            "transit".into(),
            Zeroizing::new("fixture-token".into()),
            keys,
            true,
        )
        .unwrap();
        let tenant = TenantId::validated("a").unwrap();
        let wrapped = kms.wrap(&tenant, "k2", &binding, &secret).unwrap();
        assert_eq!(
            *kms.unwrap(&tenant, "k2", &binding, &wrapped).unwrap(),
            secret
        );
        assert!(kms
            .unwrap(&TenantId::validated("b").unwrap(), "k2", &binding, &wrapped)
            .is_err());
        assert!(kms
            .unwrap(&tenant, "k2", &binding, b"vault:v1:old")
            .is_err());
        worker.join().unwrap();
    }
}
