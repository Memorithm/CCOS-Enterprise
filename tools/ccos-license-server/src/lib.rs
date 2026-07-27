//! The vendor-side **claim counter** for CCOS Pro licenses.
//!
//! One small server, one small truth: a **claim code is a bearer secret whose
//! single-use property is a server-side state flip**, not a property of the
//! code itself. The vault maps `sha256(code) → entry`; a claim atomically flips
//! `unclaimed → claimed`, signs an **annual, single-seat** token binding the
//! caller's opaque machine fingerprint, persists the flip durably, and only
//! then discloses the token. Re-claiming from the *same* machine re-issues the
//! same license (self-service recovery of a lost token — the expiry is stored,
//! never extended); any other machine gets an announced refusal.
//!
//! What this server can and cannot do, by construction:
//! - it never sees a claim code (only hashes arrive) — a stolen vault holds
//!   nothing redeemable;
//! - it never learns hardware identity (fingerprints are opaque hashes);
//! - a compromised counter can refuse service or issue tokens for codes it
//!   holds, but every issued token is verified by the client against the
//!   public key baked into the client's binary, and runtime verification
//!   ([`ccos_core::license`]) stays fully offline — the counter is a fulfillment
//!   convenience, never a runtime dependency. See `docs/LICENSING_SERVER.md`
//!   for the deployment runbook and the honest threat model (the signing seed
//!   lives in this process's environment; rotate the keypair at a release if
//!   it is ever exposed).

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Vault schema tag, bumped on any breaking shape change.
pub const VAULT_SCHEMA: &str = "ccos.license.vault/v1";

/// Hard caps on what we will read from a socket — the whole request is two
/// hashes in a small JSON body, so anything bigger is not a client.
const MAX_HEAD: usize = 8 * 1024;
const MAX_BODY: usize = 4 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

// ── The vault ────────────────────────────────────────────────────────

/// Lifecycle of a claim code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Unclaimed,
    Claimed,
    Revoked,
}

/// One sold seat: everything the counter knows about a code. Note what is
/// absent — the code itself (only its hash keys the entry) and any hardware
/// identity (the machine field is the client's opaque fingerprint).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// Licensee name carried into the signed token (an invoice reference works
    /// as well as a company name — the counter does not need to know who).
    pub licensee: String,
    /// Free-form vendor note (invoice id, contract ref). Never signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// License duration in days from the moment of claim; `None` = perpetual.
    pub days: Option<u64>,
    pub status: Status,
    pub created_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_unix: Option<u64>,
    /// Expiry fixed at first claim (`now + days`); re-issues reuse it verbatim
    /// so a re-claim can never extend a license.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp_unix: Option<u64>,
    /// The opaque machine fingerprint the seat is bound to (set at first claim).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
}

/// The durably-persisted code ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    pub schema: String,
    /// `sha256(code) → entry`.
    pub entries: BTreeMap<String, Entry>,
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

/// Why a claim was refused — each maps to one announced HTTP status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// No entry under that code hash.
    UnknownCode,
    /// Claimed by a different machine (the single-seat property).
    SeatTaken,
    /// The vendor revoked the code.
    Revoked,
}

impl Vault {
    pub fn new() -> Self {
        Self {
            schema: VAULT_SCHEMA.to_string(),
            entries: BTreeMap::new(),
        }
    }

    /// Load from `path`; a missing file is an explicit error (the admin CLI
    /// creates vaults — the server never conjures one into being).
    pub fn load(path: &Path) -> io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        serde_json::from_str(&text)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("vault: {e}")))
    }

    /// Write durably (atomic rename + fsync — the flip must survive a crash
    /// *before* the token is disclosed).
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let pretty = serde_json::to_string_pretty(self).expect("vault serializes");
        ccos_core::util::write_durable(path, format!("{pretty}\n").as_bytes())
    }

    /// The claim state machine (pure — persistence and signing are the
    /// caller's). Returns the expiry to sign for, or the refusal.
    pub fn claim(
        &mut self,
        code_hash: &str,
        machine: &str,
        now: u64,
    ) -> Result<(String, Option<u64>), Refusal> {
        let entry = self
            .entries
            .get_mut(code_hash)
            .ok_or(Refusal::UnknownCode)?;
        match entry.status {
            Status::Revoked => Err(Refusal::Revoked),
            Status::Claimed => {
                // Same machine → idempotent re-issue with the stored expiry
                // (lost-token self-service; never an extension). Anything else
                // is the single-seat refusal.
                if entry.machine.as_deref() == Some(machine) {
                    Ok((entry.licensee.clone(), entry.exp_unix))
                } else {
                    Err(Refusal::SeatTaken)
                }
            }
            Status::Unclaimed => {
                let exp = entry.days.map(|d| now + d * 86_400);
                entry.status = Status::Claimed;
                entry.claimed_unix = Some(now);
                entry.exp_unix = exp;
                entry.machine = Some(machine.to_string());
                Ok((entry.licensee.clone(), exp))
            }
        }
    }
}

// ── The counter (vault + signing + persistence + rate limit) ─────────

/// A coarse global token bucket — with 100-bit codes the limiter only needs to
/// make brute force absurd, not fair-share per client (TLS/proxy IPs are not
/// trustworthy identity anyway).
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    per_second: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(capacity: f64, per_second: f64) -> Self {
        Self {
            capacity,
            tokens: capacity,
            per_second,
            last: Instant::now(),
        }
    }

    pub fn allow(&mut self) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * self.per_second)
            .min(self.capacity);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// The claim counter: everything [`serve`] needs across requests.
pub struct Counter {
    pub vault: Vault,
    pub vault_path: PathBuf,
    /// ed25519 signing seed (the ONE secret this process holds — from the
    /// environment, never from the vault).
    pub seed: [u8; 32],
    pub bucket: TokenBucket,
}

impl Counter {
    /// Handle one parsed request → `(http status, JSON body)`. Pure except for
    /// the durable vault write on a successful state flip — which happens
    /// **before** the token is disclosed, and is rolled back from disk if the
    /// write fails (never hand out a token the ledger did not record).
    pub fn handle(&mut self, method: &str, path: &str, body: &str, now: u64) -> (u16, String) {
        match (method, path) {
            ("GET", "/healthz") => (200, r#"{"ok":true}"#.to_string()),
            ("POST", ccos_enterprise_governance::claim::CLAIM_PATH) => self.handle_claim(body, now),
            ("POST", _) | ("GET", _) => (404, err_body("no such endpoint")),
            _ => (405, err_body("method not allowed")),
        }
    }

    fn handle_claim(&mut self, body: &str, now: u64) -> (u16, String) {
        if !self.bucket.allow() {
            return (429, err_body("rate limited — try again shortly"));
        }
        let Ok(req) = serde_json::from_str::<ccos_enterprise_governance::claim::ClaimRequest>(body)
        else {
            return (400, err_body("malformed claim request"));
        };
        if req.schema != ccos_enterprise_governance::claim::CLAIM_SCHEMA
            || !ccos_enterprise_governance::claim::is_sha256_hex(&req.code_hash)
            || !ccos_enterprise_governance::claim::is_sha256_hex(&req.machine)
        {
            return (400, err_body("malformed claim request"));
        }
        let before = self.vault.clone();
        match self.vault.claim(&req.code_hash, &req.machine, now) {
            Ok((licensee, exp)) => {
                if let Err(e) = self.vault.save(&self.vault_path) {
                    // Roll back in memory: the ledger on disk is the truth.
                    self.vault = before;
                    eprintln!("[counter] persist FAILED, claim refused: {e}");
                    return (500, err_body("persistence failure — nothing was issued"));
                }
                let token = ccos_enterprise_governance::vendor::sign_token_bound(
                    &self.seed,
                    &licensee,
                    exp,
                    Some(&req.machine),
                );
                eprintln!(
                    "[counter] issued: code={}… licensee={licensee} exp={exp:?}",
                    &req.code_hash[..12]
                );
                (
                    200,
                    serde_json::to_string(&ccos_enterprise_governance::claim::ClaimOk { token })
                        .expect("response serializes"),
                )
            }
            Err(Refusal::UnknownCode) => {
                eprintln!("[counter] unknown code: {}…", &req.code_hash[..12]);
                (404, err_body("unknown claim code"))
            }
            Err(Refusal::SeatTaken) => {
                eprintln!("[counter] seat taken: {}…", &req.code_hash[..12]);
                (
                    410,
                    err_body(
                        "this code was already claimed on another machine (single-seat). \
                         Contact the vendor to re-arm it.",
                    ),
                )
            }
            Err(Refusal::Revoked) => {
                eprintln!("[counter] revoked code: {}…", &req.code_hash[..12]);
                (410, err_body("this code was revoked by the vendor"))
            }
        }
    }
}

fn err_body(msg: &str) -> String {
    serde_json::to_string(&ccos_enterprise_governance::claim::ClaimErr {
        error: msg.to_string(),
    })
    .expect("error serializes")
}

// ── The zero-framework HTTP/1.1 loop ─────────────────────────────────

/// Serve claims forever on `listener`. Connections are handled sequentially
/// with hard read/write timeouts — at one small request per *sale*, latency
/// fairness is not a design pressure, and no thread pool means no thread-pool
/// bugs. TLS is the reverse proxy's job.
pub fn serve(listener: TcpListener, mut counter: Counter) -> io::Result<()> {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        let (status, body) = match read_request(&mut stream) {
            Some((method, path, body)) => {
                counter.handle(&method, &path, &body, ccos_core::license::now_unix())
            }
            None => (400, err_body("malformed request")),
        };
        let _ = write_response(&mut stream, status, &body);
    }
    Ok(())
}

/// Parse one HTTP/1.1 request off the socket: request line, `Content-Length`,
/// body. `None` on anything oversized or malformed — we answer 400 and move on.
fn read_request(stream: &mut TcpStream) -> Option<(String, String, String)> {
    let mut head = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    // Read byte-wise until the blank line; the head is tiny and bounded.
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEAD {
            return None;
        }
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return None,
        }
    }
    let head = String::from_utf8_lossy(&head);
    let mut lines = head.lines();
    let mut request_line = lines.next()?.split_whitespace();
    let method = request_line.next()?.to_string();
    let path = request_line.next()?.to_string();
    let content_length: usize = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0);
    if content_length > MAX_BODY {
        return None;
    }
    let mut body = vec![0u8; content_length];
    stream.read_exact(&mut body).ok()?;
    Some((method, path, String::from_utf8_lossy(&body).into_owned()))
}

fn write_response(stream: &mut TcpStream, status: u16, body: &str) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        410 => "Gone",
        429 => "Too Many Requests",
        _ => "Internal Server Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// Parse a 64-hex signing seed (the `CCOS_LICENSE_SIGNING_SEED` format shared
/// with the `license_sign` example) into key bytes.
pub fn parse_seed(hex: &str) -> Option<[u8; 32]> {
    ccos_core::util::from_hex32(hex.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000_000;
    const SEED: [u8; 32] = [7u8; 32];

    fn vault_with_code() -> (Vault, String) {
        let code = ccos_enterprise_governance::claim::code_from_entropy(&[42; 16]);
        let hash = ccos_enterprise_governance::claim::code_hash(&code);
        let mut vault = Vault::new();
        vault.entries.insert(
            hash.clone(),
            Entry {
                licensee: "Acme Corp".into(),
                label: Some("invoice-001".into()),
                days: Some(365),
                status: Status::Unclaimed,
                created_unix: NOW - 100,
                claimed_unix: None,
                exp_unix: None,
                machine: None,
            },
        );
        (vault, hash)
    }

    fn fp(id: &str) -> String {
        ccos_enterprise_governance::claim::machine_fingerprint_of(id)
    }

    #[test]
    fn claim_state_machine_single_use_reissue_and_refusals() {
        let (mut vault, hash) = vault_with_code();

        // Unknown code.
        assert_eq!(
            vault.claim("0".repeat(64).as_str(), &fp("m1"), NOW),
            Err(Refusal::UnknownCode)
        );
        // First claim: expiry fixed at now + 365d, machine recorded.
        let (licensee, exp) = vault.claim(&hash, &fp("m1"), NOW).expect("issues");
        assert_eq!(licensee, "Acme Corp");
        assert_eq!(exp, Some(NOW + 365 * 86_400));
        let e = &vault.entries[&hash];
        assert_eq!(e.status, Status::Claimed);
        assert_eq!(e.machine.as_deref(), Some(fp("m1").as_str()));

        // Same machine, later: idempotent re-issue with the SAME expiry.
        let (_, exp2) = vault
            .claim(&hash, &fp("m1"), NOW + 5_000)
            .expect("reissues");
        assert_eq!(exp2, exp, "a re-claim never extends the license");

        // Different machine: the single-seat refusal.
        assert_eq!(vault.claim(&hash, &fp("m2"), NOW), Err(Refusal::SeatTaken));

        // Revocation wins over everything.
        vault.entries.get_mut(&hash).unwrap().status = Status::Revoked;
        assert_eq!(vault.claim(&hash, &fp("m1"), NOW), Err(Refusal::Revoked));
    }

    #[test]
    fn perpetual_codes_issue_tokens_without_expiry() {
        let (mut vault, hash) = vault_with_code();
        vault.entries.get_mut(&hash).unwrap().days = None;
        let (_, exp) = vault.claim(&hash, &fp("m1"), NOW).unwrap();
        assert_eq!(exp, None);
    }

    fn counter(vault: Vault, dir: &Path) -> Counter {
        Counter {
            vault,
            vault_path: dir.join("vault.json"),
            seed: SEED,
            bucket: TokenBucket::new(100.0, 100.0),
        }
    }

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ccos-counter-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn claim_body(hash: &str, machine: &str) -> String {
        serde_json::to_string(&ccos_enterprise_governance::claim::ClaimRequest {
            schema: ccos_enterprise_governance::claim::CLAIM_SCHEMA.into(),
            code_hash: hash.into(),
            machine: machine.into(),
        })
        .unwrap()
    }

    #[test]
    fn handler_issues_a_verifiable_bound_token_and_persists_the_flip() {
        use ed25519_dalek::SigningKey;
        let dir = tmp("issue");
        let (vault, hash) = vault_with_code();
        let mut c = counter(vault, &dir);

        let (status, body) = c.handle("POST", "/claim", &claim_body(&hash, &fp("m1")), NOW);
        assert_eq!(status, 200, "{body}");
        let ok: ccos_enterprise_governance::claim::ClaimOk = serde_json::from_str(&body).unwrap();

        // The issued token verifies against the seed's public half and carries
        // the machine binding + expiry the vault fixed.
        let pk = SigningKey::from_bytes(&SEED).verifying_key().to_bytes();
        let v = ccos_core::license::Ed25519Verifier::with_public_key(&pk);
        use ccos_core::license::LicenseVerifier;
        let lic = v.verify(ok.token.as_bytes(), NOW).expect("verifies");
        assert_eq!(lic.licensee, "Acme Corp");
        assert_eq!(lic.machine.as_deref(), Some(fp("m1").as_str()));
        assert!(lic.machine_ok(Some(&fp("m1"))));
        assert!(!lic.machine_ok(Some(&fp("m2"))));
        assert_eq!(lic.expires_at, Some(NOW + 365 * 86_400));

        // The flip reached disk before the token was disclosed.
        let on_disk = Vault::load(&dir.join("vault.json")).unwrap();
        assert_eq!(on_disk.entries[&hash].status, Status::Claimed);

        // Second machine → 410; same machine → 200 re-issue.
        let (status, _) = c.handle("POST", "/claim", &claim_body(&hash, &fp("m2")), NOW);
        assert_eq!(status, 410);
        let (status, _) = c.handle("POST", "/claim", &claim_body(&hash, &fp("m1")), NOW + 10);
        assert_eq!(status, 200);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn handler_refuses_malformed_unknown_and_over_rate() {
        let dir = tmp("refuse");
        let (vault, hash) = vault_with_code();
        let mut c = counter(vault, &dir);

        assert_eq!(c.handle("POST", "/claim", "not json", NOW).0, 400);
        assert_eq!(
            c.handle("POST", "/claim", &claim_body("zz", &fp("m")), NOW)
                .0,
            400,
            "non-hex code hash is malformed"
        );
        let unknown = "0".repeat(64);
        assert_eq!(
            c.handle("POST", "/claim", &claim_body(&unknown, &fp("m")), NOW)
                .0,
            404
        );
        assert_eq!(c.handle("GET", "/healthz", "", NOW).0, 200);
        assert_eq!(c.handle("GET", "/nope", "", NOW).0, 404);
        assert_eq!(c.handle("DELETE", "/claim", "", NOW).0, 405);

        // Exhaust the bucket → 429, and the code is still claimable after.
        c.bucket = TokenBucket::new(1.0, 0.000001);
        assert_eq!(
            c.handle("POST", "/claim", &claim_body(&hash, &fp("m")), NOW)
                .0,
            200
        );
        assert_eq!(
            c.handle("POST", "/claim", &claim_body(&hash, &fp("m")), NOW)
                .0,
            429
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn end_to_end_over_a_real_socket() {
        let dir = tmp("socket");
        let (vault, hash) = vault_with_code();
        let c = counter(vault, &dir);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || serve(listener, c));

        let body = claim_body(&hash, &fp("m1"));
        let mut stream = TcpStream::connect(addr).unwrap();
        write!(
            stream,
            "POST /claim HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("\"token\":"), "{response}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
