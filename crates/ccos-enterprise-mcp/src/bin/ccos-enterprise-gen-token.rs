//! Provision a CCOS Enterprise identity: resolve an ed25519 issuer seed, sign
//! one identity token, and emit a ready-to-load environment file.
//!
//! ## Security contract enforced by this tool
//!
//! - **No default signing key.** The seed comes from `CCOS_ISSUER_SEED_HEX`
//!   (64 hex characters) or the `--seed` flag; absent both, a fresh key is
//!   drawn from the operating system CSPRNG. A deterministic, publicly-known
//!   default would let anyone forge identity tokens for every deployment
//!   provisioned with it.
//! - **An unpersisted seed is an unrecoverable deployment.** When this tool
//!   generates a seed itself, it refuses to finish until `--seed-out` names a
//!   file that will hold it; silently discarding the only copy of a signing
//!   key is worse than refusing to run.
//! - **Owner-only secrets, no clobbering.** Output files are created fresh
//!   with mode `0600`. An existing file — including a planted symlink — makes
//!   the tool fail instead of writing secret material through it.
//! - **No panics on hostile input.** Malformed flags, oversized identifiers
//!   and bad hex are diagnostics with a non-zero exit, never an abort.

use std::fs::{OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use ccos_enterprise_auth::{
    is_canonical_identity, issue_identity_token, IdentityClaims, IDENTITY_TOKEN_VERSION,
};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;

/// Identity tokens are capped at twelve hours by the verifier; asking for
/// more would be refused at admission, so the provisioner never issues one.
const TOKEN_LIFETIME_SECS: u64 = 12 * 60 * 60;

const USAGE: &str = "\
usage: ccos-enterprise-gen-token [flags]

flags:
  --out PATH           environment file to write (default: ./ccos-enterprise.env)
  --seed-out PATH      also persist the signing seed here (required when the
                       seed is generated rather than supplied)
  --seed HEX           explicit 64-hex-char signing seed (or env
                       CCOS_ISSUER_SEED_HEX)
  --org ID             organization (default: memorithm)
  --actor ID           actor (default: soulsystem)
  --audience AUD       deployment audience (default: ccos-enterprise-tarek)
  --tenant ID          tenant (default: tarek)
  --kid ID             issuer key id (default: ccos-issuer-1)
  --model NAME         allowed model (default: soulsystem)
  --budget N           token budget (default: 1000000)
  --call-cost N        cost per governed call (default: 1)
  --state-dir DIR      Enterprise state directory
                       (default: /var/lib/ccos-enterprise)
";

struct Options {
    org: String,
    actor: String,
    audience: String,
    tenant: String,
    model: String,
    kid: String,
    token_budget: u64,
    call_cost_tokens: u64,
    state_dir: PathBuf,
    out: PathBuf,
    seed_out: Option<PathBuf>,
    seed_hex: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            org: "memorithm".into(),
            actor: "soulsystem".into(),
            audience: "ccos-enterprise-tarek".into(),
            tenant: "tarek".into(),
            model: "soulsystem".into(),
            kid: "ccos-issuer-1".into(),
            token_budget: 1_000_000,
            call_cost_tokens: 1,
            state_dir: PathBuf::from("/var/lib/ccos-enterprise"),
            out: PathBuf::from("ccos-enterprise.env"),
            seed_out: None,
            seed_hex: None,
        }
    }
}

fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut options = Options::default();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        let mut value = || -> Result<String, String> {
            index += 1;
            args.get(index)
                .cloned()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| format!("{flag} requires a value"))
        };
        match flag {
            "--help" | "-h" => return Err(USAGE.to_string()),
            "--out" => options.out = PathBuf::from(value()?),
            "--seed-out" => options.seed_out = Some(PathBuf::from(value()?)),
            "--seed" => options.seed_hex = Some(value()?),
            "--org" => options.org = value()?,
            "--actor" => options.actor = value()?,
            "--audience" => options.audience = value()?,
            "--tenant" => options.tenant = value()?,
            "--kid" => options.kid = value()?,
            "--model" => options.model = value()?,
            "--budget" => {
                options.token_budget = parse_positive(&value()?, "--budget")?;
            }
            "--call-cost" => {
                options.call_cost_tokens = parse_positive(&value()?, "--call-cost")?;
            }
            "--state-dir" => options.state_dir = PathBuf::from(value()?),
            other => return Err(format!("unknown flag {other:?}\n{USAGE}")),
        }
        index += 1;
    }
    Ok(options)
}

fn parse_positive(raw: &str, flag: &str) -> Result<u64, String> {
    raw.parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("{flag} must be a positive integer, got {raw:?}"))
}

fn validate(options: &Options) -> Result<(), String> {
    for (label, value) in [
        ("--org", &options.org),
        ("--actor", &options.actor),
        ("--tenant", &options.tenant),
        ("--kid", &options.kid),
    ] {
        if !is_canonical_identity(value) {
            return Err(format!(
                "{label} {value:?} is not a canonical identifier \
                 (lowercase ASCII letters, digits, '_' or '-', starting with a letter or digit)"
            ));
        }
    }
    if options.audience.is_empty() || options.audience.len() > 128 {
        return Err("--audience must be between 1 and 128 characters".into());
    }
    if options.model.is_empty() || options.model.len() > 256 {
        return Err("--model must be between 1 and 256 characters".into());
    }
    Ok(())
}

fn decode_seed_hex(value: &str) -> Result<[u8; 32], String> {
    let trimmed = value.trim();
    if trimmed.len() != 64 || !trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("the signing seed must be exactly 64 hexadecimal characters (32 bytes)".into());
    }
    let mut seed = [0u8; 32];
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&trimmed[index * 2..index * 2 + 2], 16)
            .map_err(|_| "the signing seed is not valid hexadecimal".to_string())?;
    }
    Ok(seed)
}

fn unix_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock is before the Unix epoch".to_string())
}

fn unique_jti(now: u64) -> String {
    let mut suffix = [0u8; 4];
    OsRng.fill_bytes(&mut suffix);
    format!("prod-{now}-{}", hex(&suffix))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Create a fresh owner-only file and durably write `contents` into it.
///
/// `create_new` refuses to follow an existing entry out of the way — including
/// a symlink an attacker planted at the output path — so secret material is
/// never redirected nor revealed through pre-existing permissions.
fn write_secret_file(path: &Path, contents: &str) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            format!(
                "cannot create {} (an existing file must be removed first): {error}",
                path.display()
            )
        })?;
    file.set_permissions(Permissions::from_mode(0o600))
        .map_err(|error| format!("cannot restrict permissions on {}: {error}", path.display()))?;
    file.write_all(contents.as_bytes())
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("cannot flush {}: {error}", path.display()))
}

fn run(args: Vec<String>) -> Result<String, String> {
    let options = parse_options(&args)?;
    validate(&options)?;

    let supplied_seed = options
        .seed_hex
        .clone()
        .or_else(|| std::env::var("CCOS_ISSUER_SEED_HEX").ok());
    let generated = supplied_seed.is_none();
    let seed = match supplied_seed.as_deref() {
        Some(hex_value) => decode_seed_hex(hex_value)?,
        None => {
            let mut raw = [0u8; 32];
            OsRng.fill_bytes(&mut raw);
            raw
        }
    };

    if generated && options.seed_out.is_none() {
        return Err(
            "no signing seed was supplied, so one was generated — but --seed-out is missing. \
             Refusing to discard the only copy of a signing key: pass --seed-out PATH to \
             persist the generated seed, or supply CCOS_ISSUER_SEED_HEX yourself."
                .into(),
        );
    }

    let signing = SigningKey::from_bytes(&seed);
    let verifying_hex = hex(signing.verifying_key().to_bytes().as_slice());

    let now = unix_now()?;
    let claims = IdentityClaims {
        version: IDENTITY_TOKEN_VERSION,
        jti: unique_jti(now),
        org: options.org.clone(),
        actor: options.actor.clone(),
        audience: options.audience.clone(),
        issued_at: now,
        expires_at: now
            .checked_add(TOKEN_LIFETIME_SECS)
            .ok_or("token expiry overflowed")?,
        not_before: None,
    };
    let token = issue_identity_token(&seed, &options.kid, &claims)
        .map_err(|error| format!("cannot issue the identity token: {error}"))?;

    let env_file = format!(
        "# CCOS Enterprise — identity and configuration (generated at unix time {now})\n\
         CCOS_ENTERPRISE_TENANT={tenant}\n\
         CCOS_ENTERPRISE_AUDIENCE={audience}\n\
         CCOS_ENTERPRISE_ISSUER_KID={kid}\n\
         CCOS_ENTERPRISE_ISSUER_PUBLIC_KEY_HEX={public_key}\n\
         CCOS_ENTERPRISE_IDENTITY_TOKEN={token}\n\
         CCOS_ENTERPRISE_MODEL={model}\n\
         CCOS_ENTERPRISE_TOKEN_BUDGET={budget}\n\
         CCOS_ENTERPRISE_CALL_COST_TOKENS={call_cost}\n\
         CCOS_ENTERPRISE_STATE_DIR={state_dir}\n",
        tenant = options.tenant,
        audience = options.audience,
        kid = options.kid,
        public_key = verifying_hex,
        token = token,
        model = options.model,
        budget = options.token_budget,
        call_cost = options.call_cost_tokens,
        state_dir = options.state_dir.display(),
    );
    write_secret_file(&options.out, &env_file)?;

    if let Some(seed_out) = &options.seed_out {
        write_secret_file(seed_out, &format!("{}\n", hex(seed.as_slice())))?;
    }

    Ok(format!(
        "provisioned org={} actor={} tenant={} kid={}\n  env file: {} (mode 0600)\n  public key: {}\n  token: {}…\n  expires_at: {}",
        options.org,
        options.actor,
        options.tenant,
        options.kid,
        options.out.display(),
        verifying_hex,
        &token[..token.len().min(24)],
        claims.expires_at,
    ))
}

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(summary) => {
            println!("{summary}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ccos-enterprise-gen-token: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_hex_is_exact_and_bounded() {
        assert_eq!(decode_seed_hex(&"ab".repeat(32)).unwrap(), [0xab; 32]);
        assert!(decode_seed_hex("00").is_err());
        assert!(decode_seed_hex(&"zz".repeat(32)).is_err());
        assert!(decode_seed_hex(&"aa".repeat(33)).is_err());
        assert_eq!(
            decode_seed_hex(&format!("{} ", "ab".repeat(32))).unwrap(),
            [0xab; 32]
        );
    }

    #[test]
    fn generated_jti_is_unique_and_canonical() {
        let a = unique_jti(1_000);
        let b = unique_jti(1_000);
        assert_ne!(a, b, "jti collisions would make revocation ambiguous");
        for jti in [a, b] {
            assert!(is_canonical_identity(&jti), "{jti:?} is not canonical");
            assert!(jti.starts_with("prod-1000-"));
        }
    }

    #[test]
    fn option_parsing_rejects_hostile_input_without_panicking() {
        assert!(parse_options(&["--budget".into(), "abc".into()]).is_err());
        assert!(parse_options(&["--budget".into(), "0".into()]).is_err());
        assert!(parse_options(&["--org".into()]).is_err());
        assert!(parse_options(&["--nope".to_string()]).is_err());

        let parsed = parse_options(&[
            "--out".into(),
            "/tmp/x.env".into(),
            "--budget".into(),
            "42".into(),
        ])
        .unwrap();
        assert_eq!(parsed.out, PathBuf::from("/tmp/x.env"));
        assert_eq!(parsed.token_budget, 42);
    }

    #[test]
    fn validation_refuses_non_canonical_identifiers() {
        let mut options = Options::default();
        assert!(validate(&options).is_ok());
        options.org = "Memorithm".into();
        assert!(validate(&options).is_err());
        options = Options::default();
        options.tenant = "-rf".into();
        assert!(validate(&options).is_err());
        options = Options::default();
        options.model = String::new();
        assert!(validate(&options).is_err());
    }

    #[test]
    fn secret_files_are_owner_only_and_never_overwrite() {
        let root = std::env::temp_dir().join(format!("gen-token-test-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("secret.env");

        write_secret_file(&path, "one\n").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "secrets must be owner-only");

        // A second write must fail rather than silently rotate a live secret.
        assert!(write_secret_file(&path, "two\n").is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "one\n");

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn end_to_end_provisioning_produces_a_verifiable_token() {
        let root = std::env::temp_dir().join(format!("gen-token-e2e-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let env_path = root.join("ccos-enterprise.env");
        let seed_path = root.join("issuer.seed");

        let summary = run(vec![
            "--out".into(),
            env_path.to_string_lossy().into_owned(),
            "--seed-out".into(),
            seed_path.to_string_lossy().into_owned(),
            "--org".into(),
            "acme".into(),
            "--actor".into(),
            "agent-7".into(),
            "--audience".into(),
            "test-aud".into(),
            "--tenant".into(),
            "acme".into(),
            "--kid".into(),
            "issuer-a".into(),
            "--model".into(),
            "deepseek-harness".into(),
            "--budget".into(),
            "10".into(),
            "--state-dir".into(),
            root.to_string_lossy().into_owned(),
        ])
        .unwrap();
        assert!(summary.contains("acme"));

        let env_text = std::fs::read_to_string(&env_path).unwrap();
        let token = env_text
            .lines()
            .find_map(|line| line.strip_prefix("CCOS_ENTERPRISE_IDENTITY_TOKEN="))
            .expect("env file carries the identity token");
        let public_key_hex = env_text
            .lines()
            .find_map(|line| line.strip_prefix("CCOS_ENTERPRISE_ISSUER_PUBLIC_KEY_HEX="))
            .expect("env file carries the issuer public key");

        // Verify the minted token the way the MCP server will.
        use ccos_enterprise_auth::{AuthStrength, Authenticator, TokenAuthenticator};
        let mut key_bytes = [0u8; 32];
        for (index, byte) in key_bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&public_key_hex[index * 2..index * 2 + 2], 16).unwrap();
        }
        let mut verifier = TokenAuthenticator::new("test-aud", AuthStrength::Token);
        assert!(verifier.add_issuer(
            "issuer-a",
            ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).unwrap()
        ));
        let now = unix_now().unwrap();
        let identity = verifier
            .authenticate(token, now)
            .expect("minted token verifies");
        assert_eq!(identity.org().0, "acme");
        assert_eq!(identity.actor().0, "agent-7");

        let seed_text = std::fs::read_to_string(&seed_path)
            .unwrap()
            .trim()
            .to_string();
        assert_eq!(seed_text.len(), 64, "persisted seed is 64 hex characters");
        assert_eq!(
            decode_seed_hex(&seed_text).unwrap(),
            decode_seed_hex(seed_text.trim()).unwrap()
        );

        std::fs::remove_dir_all(&root).unwrap();
    }
}
