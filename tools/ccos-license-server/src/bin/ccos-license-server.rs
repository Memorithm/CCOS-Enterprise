//! The claim counter daemon. See the crate docs and `docs/LICENSING_SERVER.md`.
//!
//! ```sh
//! CCOS_LICENSE_SIGNING_SEED=<64-hex> \
//!   ccos-license-server --vault /var/lib/ccos-licenses/vault.json [--listen 127.0.0.1:8471]
//! ```
//!
//! Listens on loopback by default — TLS and the public hostname
//! (e.g. `licensing.memorithm.fr`) are the reverse proxy's job.

use ccos_license_server::{parse_seed, serve, Counter, TokenBucket, Vault};
use std::net::TcpListener;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut vault_path: Option<PathBuf> = None;
    let mut listen = "127.0.0.1:8471".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--vault" => {
                i += 1;
                vault_path = args.get(i).map(PathBuf::from);
            }
            "--listen" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    listen = v.clone();
                }
            }
            "-h" | "--help" => {
                eprintln!(
                    "usage: CCOS_LICENSE_SIGNING_SEED=<64-hex> ccos-license-server \
                     --vault <vault.json> [--listen 127.0.0.1:8471]"
                );
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    // Fail closed on every missing precondition — a counter that starts
    // half-configured would refuse every claim anyway, so say why up front.
    let Some(vault_path) = vault_path else {
        eprintln!("error: --vault <vault.json> is required (create codes with ccos-license-admin)");
        std::process::exit(2);
    };
    let seed = match std::env::var("CCOS_LICENSE_SIGNING_SEED")
        .ok()
        .as_deref()
        .and_then(parse_seed)
    {
        Some(s) => s,
        None => {
            eprintln!(
                "error: CCOS_LICENSE_SIGNING_SEED is unset or not 64 hex chars — the counter \
                 signs tokens at claim time and cannot run without the seed"
            );
            std::process::exit(2);
        }
    };
    let vault = match Vault::load(&vault_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "error: cannot load vault {} ({e}) — create it with \
                 `ccos-license-admin --vault <path> new …`",
                vault_path.display()
            );
            std::process::exit(2);
        }
    };
    let listener = match TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: cannot listen on {listen}: {e}");
            std::process::exit(2);
        }
    };

    let unclaimed = vault
        .entries
        .values()
        .filter(|e| e.status == ccos_license_server::Status::Unclaimed)
        .count();
    eprintln!(
        "[counter] listening on {listen} — vault {} ({} entries, {unclaimed} unclaimed). \
         POST /claim, GET /healthz. TLS belongs to the reverse proxy.",
        vault_path.display(),
        vault.entries.len()
    );

    // ~30 claims/min sustained, small burst: brute force on 100-bit codes is
    // absurd at any rate; this just keeps a misbehaving client from spinning.
    let counter = Counter {
        vault,
        vault_path,
        seed,
        bucket: TokenBucket::new(10.0, 0.5),
    };
    if let Err(e) = serve(listener, counter) {
        eprintln!("[counter] fatal: {e}");
        std::process::exit(1);
    }
}
