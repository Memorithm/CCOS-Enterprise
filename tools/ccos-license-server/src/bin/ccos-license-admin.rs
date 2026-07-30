//! The vendor's vault CLI — sells seats, re-arms lost ones, revokes bad ones.
//!
//! ```sh
//! ccos-license-admin --vault vault.json new --licensee "Acme Corp" --days 365 [--label invoice-42]
//! ccos-license-admin --vault vault.json list
//! ccos-license-admin --vault vault.json rearm  <CODE or key>
//! ccos-license-admin --vault vault.json revoke <CODE or key>
//! ccos-license-admin --vault vault.json migrate
//! ```
//!
//! `new` prints the claim code **once** — the vault stores only its
//! second-degree hash (the *vault key*, also printed: the safe handle `list`,
//! `rearm` and `revoke` work with), so a lost code cannot be recovered, only
//! re-armed (`rearm` resets a claimed entry so the same code can be redeemed
//! again, e.g. after a machine died) or replaced. `migrate` upgrades a v1
//! vault (keyed by the wire-level code hash) to the v2 keying in place. No
//! signing seed is needed here: tokens are signed by the counter at claim
//! time, so this CLI can run anywhere the vault file lives.

use ccos_license_server::{Entry, Status, Vault, VAULT_SCHEMA, VAULT_SCHEMA_V1};
use std::path::{Path, PathBuf};
use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut vault_path: Option<PathBuf> = None;
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--vault" => {
                i += 1;
                vault_path = args.get(i).map(PathBuf::from);
            }
            other => rest.push(other.to_string()),
        }
        i += 1;
    }
    let command = rest.first().map(String::as_str).unwrap_or("");
    // `manifest` signs a release file and never touches the vault; every other
    // subcommand operates on it.
    if command == "manifest" {
        return cmd_manifest(&rest[1..]);
    }
    let Some(vault_path) = vault_path else {
        usage("--vault <vault.json> is required");
    };
    match command {
        "new" => cmd_new(&vault_path, &rest[1..]),
        "list" => cmd_list(&vault_path),
        "rearm" => cmd_flip(&vault_path, rest.get(1), Flip::Rearm),
        "revoke" => cmd_flip(&vault_path, rest.get(1), Flip::Revoke),
        "migrate" => cmd_migrate(&vault_path),
        _ => usage("expected a subcommand: new | list | rearm | revoke | migrate | manifest"),
    }
}

/// `manifest --version V --binary PATH --url URL [--tier pro] [--out FILE]` —
/// publish-side half of `ccos update`: hash the release artifact, sign the
/// manifest with the vendor seed (`CCOS_LICENSE_SIGNING_SEED`, same trust root
/// as license tokens), and write the one-line `release.manifest` to upload
/// next to the artifact. No vault involved.
fn cmd_manifest(args: &[String]) {
    let mut version: Option<String> = None;
    let mut binary: Option<PathBuf> = None;
    let mut url: Option<String> = None;
    let mut tier = "pro".to_string();
    let mut out = PathBuf::from("release.manifest");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--version" => {
                i += 1;
                version = args.get(i).cloned();
            }
            "--binary" => {
                i += 1;
                binary = args.get(i).map(PathBuf::from);
            }
            "--url" => {
                i += 1;
                url = args.get(i).cloned();
            }
            "--tier" => {
                i += 1;
                tier = args.get(i).cloned().unwrap_or(tier);
            }
            "--out" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    out = PathBuf::from(v);
                }
            }
            other => usage(&format!("unknown argument to manifest: {other}")),
        }
        i += 1;
    }
    let (Some(version), Some(binary), Some(url)) = (version, binary, url) else {
        usage("manifest requires --version V --binary PATH --url URL");
    };
    let Some(seed) = std::env::var("CCOS_LICENSE_SIGNING_SEED")
        .ok()
        .as_deref()
        .and_then(ccos_license_server::parse_seed)
    else {
        eprintln!("error: CCOS_LICENSE_SIGNING_SEED is unset or not 64 hex chars");
        exit(2)
    };
    let bytes = match std::fs::read(&binary) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read artifact {}: {e}", binary.display());
            exit(1)
        }
    };
    let sha256 = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&bytes);
        format!("{:x}", h.finalize())
    };
    let manifest = ccos_enterprise_governance::release::ReleaseManifest {
        version: version.clone(),
        released_unix: ccos_core::license::now_unix(),
        sha256: sha256.clone(),
        url: url.clone(),
        tier,
    };
    let line = ccos_enterprise_governance::release::sign_manifest(&seed, &manifest);
    if let Err(e) = ccos_core::util::write_durable(&out, format!("{line}\n").as_bytes()) {
        eprintln!("error: cannot write {}: {e}", out.display());
        exit(1)
    }
    println!("signed release manifest → {}", out.display());
    println!("  version   {version}");
    println!("  artifact  {} ({} bytes)", binary.display(), bytes.len());
    println!("  sha256    {sha256}");
    println!("  url       {url}");
    println!(
        "\nupload BOTH files (artifact at that url + {} as release.manifest);",
        out.display()
    );
    println!("customers run: ccos update --from <releases-host>");
}

fn usage(msg: &str) -> ! {
    eprintln!(
        "error: {msg}\n\nusage:\n  ccos-license-admin --vault <vault.json> new --licensee NAME \
         [--days N] [--label L]\n  ccos-license-admin --vault <vault.json> list\n  \
         ccos-license-admin --vault <vault.json> rearm  <CODE or vault key>\n  \
         ccos-license-admin --vault <vault.json> revoke <CODE or vault key>\n  \
         ccos-license-admin --vault <vault.json> migrate\n  \
         CCOS_LICENSE_SIGNING_SEED=<64-hex> ccos-license-admin manifest \
         --version V --binary PATH --url URL [--tier pro] [--out release.manifest]"
    );
    exit(2)
}

/// Load the vault, or start a fresh one for `new` when the file is absent.
fn load_or_new(path: &Path, create: bool) -> Vault {
    match Vault::load(path) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && create => Vault::new(),
        Err(e) => {
            eprintln!("error: cannot load vault {}: {e}", path.display());
            exit(1)
        }
    }
}

fn save_or_die(vault: &Vault, path: &Path) {
    if let Err(e) = vault.save(path) {
        eprintln!("error: cannot save vault {}: {e}", path.display());
        exit(1)
    }
}

fn cmd_new(vault_path: &Path, args: &[String]) {
    let mut licensee: Option<String> = None;
    let mut days: Option<u64> = None;
    let mut label: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--licensee" => {
                i += 1;
                licensee = args.get(i).cloned();
            }
            "--days" => {
                i += 1;
                days = args.get(i).and_then(|v| v.parse().ok());
                if days.is_none() {
                    usage("--days expects a positive integer");
                }
            }
            "--label" => {
                i += 1;
                label = args.get(i).cloned();
            }
            other => usage(&format!("unknown argument to new: {other}")),
        }
        i += 1;
    }
    let Some(licensee) = licensee else {
        usage("new requires --licensee NAME (an invoice reference works too)");
    };
    if days == Some(0) {
        usage("--days 0 would mint a seat that expires at the instant of claim");
    }

    let mut vault = load_or_new(vault_path, true);
    let entropy: [u8; 16] = rand::random();
    let code = ccos_enterprise_governance::claim::code_from_entropy(&entropy);
    let hash = ccos_enterprise_governance::claim::code_hash(&code);
    let key = ccos_enterprise_governance::claim::vault_key(&hash);
    vault.entries.insert(
        key.clone(),
        Entry {
            licensee: licensee.clone(),
            label,
            days,
            status: Status::Unclaimed,
            created_unix: ccos_core::license::now_unix(),
            claimed_unix: None,
            exp_unix: None,
            machine: None,
        },
    );
    save_or_die(&vault, vault_path);

    println!("claim code (shown ONCE — the vault stores only a second-degree hash):\n");
    println!("    {code}\n");
    println!("  licensee   {licensee}");
    match days {
        Some(d) => println!("  duration   {d} days from the moment of claim"),
        None => println!("  duration   perpetual"),
    }
    println!("  vault key  {key}");
    println!("  vault      {}", vault_path.display());
    println!("\nhand the code to the customer; they run:");
    println!("    ccos license claim {code} --from https://licensing.memorithm.fr");
}

/// First 12 chars of an identifier for display — never panics on a short or
/// hand-edited value.
fn short(id: &str) -> &str {
    &id[..12.min(id.len())]
}

fn cmd_list(vault_path: &Path) {
    let vault = load_or_new(vault_path, false);
    if vault.entries.is_empty() {
        println!("vault {} is empty", vault_path.display());
        return;
    }
    println!(
        "{:<14} {:<10} {:<22} {:<11} {:<11} machine",
        "vault-key", "status", "licensee", "days", "claimed"
    );
    for (key, e) in &vault.entries {
        println!(
            "{:<14} {:<10} {:<22} {:<11} {:<11} {}",
            short(key),
            match e.status {
                Status::Unclaimed => "unclaimed",
                Status::Claimed => "claimed",
                Status::Revoked => "revoked",
            },
            e.licensee,
            e.days.map_or("perpetual".to_string(), |d| d.to_string()),
            e.claimed_unix.map_or("-".to_string(), |t| t.to_string()),
            e.machine.as_deref().map_or("-", short),
        );
    }
}

enum Flip {
    Rearm,
    Revoke,
}

fn cmd_flip(vault_path: &Path, code_or_key: Option<&String>, flip: Flip) {
    let Some(input) = code_or_key else {
        usage("expected a claim CODE or its 64-hex vault key");
    };
    let mut vault = load_or_new(vault_path, false);
    // Accept the code itself (canonicalized, hashed, then keyed), the vault
    // key straight out of `list`/`new`, or — for continuity with pre-v2
    // notes — the wire-level code hash, from which the key derives.
    let key = if ccos_enterprise_governance::claim::is_sha256_hex(input) {
        if vault.entries.contains_key(input.as_str()) {
            input.clone()
        } else {
            ccos_enterprise_governance::claim::vault_key(input)
        }
    } else {
        match ccos_enterprise_governance::claim::canonical_code(input) {
            Some(code) => ccos_enterprise_governance::claim::vault_key(
                &ccos_enterprise_governance::claim::code_hash(&code),
            ),
            None => usage("that is neither a claim code nor a 64-hex vault key"),
        }
    };
    let Some(entry) = vault.entries.get_mut(&key) else {
        eprintln!("error: no entry under {}…", short(&key));
        exit(1)
    };
    match flip {
        Flip::Rearm => {
            entry.status = Status::Unclaimed;
            entry.claimed_unix = None;
            entry.exp_unix = None;
            entry.machine = None;
            println!(
                "re-armed {}… — the same code can be claimed again (fresh expiry at claim)",
                short(&key)
            );
        }
        Flip::Revoke => {
            entry.status = Status::Revoked;
            println!(
                "revoked {}… — the counter now refuses this code",
                short(&key)
            );
        }
    }
    save_or_die(&vault, vault_path);
}

/// Upgrade a v1 vault (entries keyed by the wire-level `sha256(code)`) to the
/// v2 keying (`vault_key(sha256(code))`) in place. Lossless and idempotent:
/// v2 keys derive deterministically from v1 keys, and an already-v2 vault is
/// left untouched.
fn cmd_migrate(vault_path: &Path) {
    let vault = match Vault::load_any_schema(vault_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: cannot load vault {}: {e}", vault_path.display());
            exit(1)
        }
    };
    if vault.schema == VAULT_SCHEMA {
        println!(
            "vault {} is already {VAULT_SCHEMA} — nothing to do",
            vault_path.display()
        );
        return;
    }
    if vault.schema != VAULT_SCHEMA_V1 {
        eprintln!(
            "error: vault schema is '{}' — migrate only upgrades '{VAULT_SCHEMA_V1}'",
            vault.schema
        );
        exit(1)
    }
    let mut upgraded = Vault::new();
    let count = vault.entries.len();
    for (wire_hash, entry) in vault.entries {
        upgraded.entries.insert(
            ccos_enterprise_governance::claim::vault_key(&wire_hash),
            entry,
        );
    }
    save_or_die(&upgraded, vault_path);
    println!(
        "migrated {} ({count} entr{}) to {VAULT_SCHEMA} — codes and seats unchanged",
        vault_path.display(),
        if count == 1 { "y" } else { "ies" }
    );
}
