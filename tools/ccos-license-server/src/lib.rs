//! The vendor-side **claim counter** for CCOS Pro licenses.
//!
//! One small server, one small truth: a **claim code is a bearer secret whose
//! single-use property is a server-side state flip**, not a property of the
//! code itself. The vault maps `vault_key(sha256(code)) → entry` — the key is
//! a *second*, domain-separated hash over the wire value (see
//! [`ccos_enterprise_governance::claim::vault_key`]); a claim re-derives the
//! key from the received hash, atomically flips `unclaimed → claimed`, signs
//! an **annual, single-seat** token binding the caller's opaque machine
//! fingerprint, persists the flip durably, and only then discloses the token.
//! Re-claiming from the *same* machine re-issues the same license
//! (self-service recovery of a lost token — the expiry is stored, never
//! extended); any other machine gets an announced refusal.
//!
//! What this server can and cannot do, by construction:
//! - it never sees a claim code (only hashes arrive), and the vault stores
//!   only second-degree hashes — a stolen vault holds nothing redeemable,
//!   neither codes nor wire hashes the `/claim` endpoint would accept;
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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use serde::{de, Deserialize, Deserializer, Serialize};

/// Vault schema tag, bumped on any breaking shape change. v2: entries are
/// keyed by `vault_key(code_hash)` (a second, domain-separated hash) instead
/// of the wire-level `code_hash`, so vault contents cannot be replayed at the
/// claim endpoint. `ccos-license-admin migrate` upgrades a v1 file in place.
pub const VAULT_SCHEMA: &str = "ccos.license.vault/v2";

/// The v1 schema tag ([`VAULT_SCHEMA`]'s predecessor) — recognized only by
/// `ccos-license-admin migrate`; the server refuses it (fail closed).
pub const VAULT_SCHEMA_V1: &str = "ccos.license.vault/v1";

/// Hard caps on what we will read from a socket — the whole request is two
/// hashes in a small JSON body, so anything bigger is not a client.
const MAX_HEAD: usize = 8 * 1024;
const MAX_BODY: usize = 4 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// How many connections may be in flight at once. A read timeout bounds how
/// long *one* connection blocks; it does not bound how long the *queue*
/// waits, so a strictly sequential loop lets a single socket that sends
/// nothing hold up every paying customer for the full timeout. Connections
/// are therefore handled concurrently, and beyond this many in flight the
/// counter sheds load with an announced 503 rather than queueing silently.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 64;
/// Ceiling on one whole request (head + body), whatever the drip rate — the
/// per-read timeout alone would let a client that sends one byte every few
/// seconds hold this sequential server for hours.
const REQUEST_DEADLINE: Duration = Duration::from_secs(10);

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
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// Licensee name carried into the signed token (an invoice reference works
    /// as well as a company name — the counter does not need to know who).
    pub licensee: String,
    /// Free-form vendor note (invoice id, contract ref). Never signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// License duration in days from the moment of claim; `null` = perpetual.
    ///
    /// The field must be **present** in the file. Serde defaults every
    /// `Option<T>` to `None` when a field is missing, so an entry that simply
    /// omitted `days` used to sell a perpetual license — the most expensive
    /// default in the product, reachable by deleting one line. `null` still
    /// means perpetual; saying nothing at all no longer does.
    #[serde(deserialize_with = "required_days")]
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
#[serde(deny_unknown_fields)]
pub struct Vault {
    pub schema: String,
    /// `vault_key(sha256(code)) → entry` — see
    /// [`ccos_enterprise_governance::claim::vault_key`].
    #[serde(deserialize_with = "unique_entries")]
    pub entries: BTreeMap<String, Entry>,
}

/// Deserialize `days`, refusing a **missing** field while still accepting an
/// explicit `null`.
///
/// `Option<u64>` alone cannot express this: serde's derive fills a missing
/// `Option` field with `None` and never calls a deserializer at all. Naming
/// one is what turns absence back into an error.
fn required_days<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    Option::<u64>::deserialize(d)
}

/// Deserialize the entry map, refusing a **duplicate key** instead of letting
/// the last one win.
///
/// `serde_json` into a `BTreeMap` overwrites silently, so appending a second
/// entry under a key that was already there un-revokes a revoked code — with
/// no error, no warning and nothing in the file to show two ever existed. JSON
/// permits duplicate names; a ledger does not.
fn unique_entries<'de, D: Deserializer<'de>>(d: D) -> Result<BTreeMap<String, Entry>, D::Error> {
    struct Unique;

    impl<'de> de::Visitor<'de> for Unique {
        type Value = BTreeMap<String, Entry>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a map of vault keys to entries, each key appearing once")
        }

        fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut out = BTreeMap::new();
            while let Some((key, entry)) = map.next_entry::<String, Entry>()? {
                if out.insert(key.clone(), entry).is_some() {
                    return Err(de::Error::custom(format!(
                        "vault key {key:?} appears twice — the later entry would \
                         silently replace the earlier one, which is how a revoked \
                         code comes back to life"
                    )));
                }
            }
            Ok(out)
        }
    }

    d.deserialize_map(Unique)
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
    /// The entry exists but is not one the counter can honour, and acting on
    /// it would cost the customer their seat. Carries the reason so an
    /// operator can find the line.
    ///
    /// This is the **vendor's** fault, not the caller's, which is why it is a
    /// distinct refusal rather than folded into `UnknownCode`: a 404 would
    /// tell a paying customer their code does not exist, and tell the vendor
    /// nothing at all.
    Unserviceable(String),
}

impl Entry {
    /// Whether this entry is one the counter can honour, and if not, why.
    ///
    /// A vault is money. Every rule here exists because its absence let a file
    /// that loaded cleanly cost a customer their seat or hand one away:
    ///
    /// * **`days: 0`** flipped the code to `Claimed`, burned the single seat
    ///   and signed a token whose entire validity window was the claim
    ///   instant. Every later re-claim re-issued the same dead expiry, so the
    ///   protocol had no recovery path — only vault surgery. The admin CLI
    ///   already refuses `--days 0`; this is the other way in.
    /// * **`Claimed` with no owner** answered `SeatTaken` to every machine
    ///   *including the customer's*, forever. `machine` is
    ///   `#[serde(default)]`, so a hand edit, a partial restore or a migration
    ///   that dropped a field produced it silently. `Some("")` is the same
    ///   trap over the wire, since no client can present the empty owner.
    /// * **`Unclaimed` carrying an owner or an expiry** is a state the claim
    ///   machine cannot produce, so it is a state nothing downstream reasons
    ///   about correctly.
    ///
    /// Returning the reason rather than a bool is deliberate: an operator
    /// whose server refuses to start needs to know which line of a
    /// hundred-thousand-line file to look at.
    pub fn validate(&self, key: &str) -> Result<(), String> {
        use ccos_enterprise_governance::claim::is_sha256_hex;

        if !is_sha256_hex(key) {
            return Err(format!(
                "vault key {key:?} is not a 64-character lowercase sha256 hex digest"
            ));
        }
        if self.licensee.trim().is_empty() {
            return Err(format!("entry {key}: licensee is empty"));
        }
        if self.days == Some(0) {
            return Err(format!(
                "entry {key}: days is 0 — claiming it would burn the seat and \
                 issue a license that expires at the instant of claim, with no \
                 recovery path. Write null for a perpetual license."
            ));
        }
        if let Some(exp) = self.exp_unix {
            if exp <= self.created_unix {
                return Err(format!(
                    "entry {key}: exp_unix {exp} is not after created_unix {} — \
                     the license was over before it was sold",
                    self.created_unix
                ));
            }
        }
        match self.status {
            Status::Claimed => {
                match self.machine.as_deref() {
                    None => {
                        return Err(format!(
                            "entry {key}: claimed with no machine — it would answer \
                             SeatTaken to every machine including the customer's, \
                             forever"
                        ))
                    }
                    Some(m) if !is_sha256_hex(m) => {
                        return Err(format!(
                            "entry {key}: machine {m:?} is not a fingerprint any \
                             client could present, so the seat is unreachable"
                        ))
                    }
                    Some(_) => {}
                }
                if self.claimed_unix.is_none() {
                    return Err(format!(
                        "entry {key}: claimed with no claimed_unix — the flip is \
                         not dateable, so the trail cannot say when the seat went"
                    ));
                }
            }
            Status::Unclaimed => {
                for (what, present) in [
                    ("machine", self.machine.is_some()),
                    ("claimed_unix", self.claimed_unix.is_some()),
                    ("exp_unix", self.exp_unix.is_some()),
                ] {
                    if present {
                        return Err(format!(
                            "entry {key}: unclaimed but carries {what} — a state the \
                             claim machine cannot produce"
                        ));
                    }
                }
            }
            // A revoked seat may or may not have been claimed first, so the
            // only rule is the one that always holds: an owner it does carry
            // must be one a client could have presented.
            Status::Revoked => {
                if let Some(m) = self.machine.as_deref() {
                    if !is_sha256_hex(m) {
                        return Err(format!("entry {key}: machine {m:?} is not a fingerprint"));
                    }
                }
            }
        }
        Ok(())
    }
}

impl Vault {
    pub fn new() -> Self {
        Self {
            schema: VAULT_SCHEMA.to_string(),
            entries: BTreeMap::new(),
        }
    }

    /// Load from `path`; a missing file is an explicit error (the admin CLI
    /// creates vaults — the server never conjures one into being), and so is
    /// any schema other than [`VAULT_SCHEMA`] (fail closed: under an older
    /// schema the keys mean something else, and silently missing every lookup
    /// would refuse real customers while looking healthy).
    pub fn load(path: &Path) -> io::Result<Self> {
        let vault = Self::load_any_schema(path)?;
        if vault.schema != VAULT_SCHEMA {
            let hint = if vault.schema == VAULT_SCHEMA_V1 {
                " — upgrade it with `ccos-license-admin --vault <path> migrate`"
            } else {
                ""
            };
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "vault schema is '{}', this build expects '{VAULT_SCHEMA}'{hint}",
                    vault.schema
                ),
            ));
        }
        Ok(vault)
    }

    /// Load without the schema gate — for `ccos-license-admin migrate`, which
    /// exists precisely to read the previous schema. Everything else goes
    /// through [`Vault::load`].
    pub fn load_any_schema(path: &Path) -> io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let vault: Self = serde_json::from_str(&text)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("vault: {e}")))?;
        // Every read path in the product goes through here, `migrate`
        // included: a migration that carried a dead seat forward would launder
        // it into the new schema.
        vault.validate()?;
        Ok(vault)
    }

    /// Check every entry ([`Entry::validate`]). Fails on the **first** bad
    /// one, naming it.
    ///
    /// Whole-file refusal is the existing posture and is kept: there is no
    /// per-entry quarantine, so one bad line stops the counter serving anyone.
    /// That blast radius is a separate, still-open finding — what changes here
    /// is only *which* files are bad, and a file holding a dead seat now is.
    pub fn validate(&self) -> io::Result<()> {
        for (key, entry) in &self.entries {
            entry
                .validate(key)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("vault: {e}")))?;
        }
        Ok(())
    }

    /// Write durably (atomic rename + fsync — the flip must survive a crash
    /// *before* the token is disclosed).
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let pretty = serde_json::to_string_pretty(self).expect("vault serializes");
        ccos_core::util::write_durable(path, format!("{pretty}\n").as_bytes())
    }

    /// The claim state machine (pure — persistence and signing are the
    /// caller's). Takes the **wire-level** `code_hash` and re-derives the
    /// vault key from it. Returns the expiry to sign for, or the refusal.
    pub fn claim(
        &mut self,
        code_hash: &str,
        machine: &str,
        now: u64,
    ) -> Result<(String, Option<u64>), Refusal> {
        let key = ccos_enterprise_governance::claim::vault_key(code_hash);
        let entry = self.entries.get_mut(&key).ok_or(Refusal::UnknownCode)?;
        match entry.status {
            // Checked before validation on purpose: a revoked code's answer
            // does not depend on the rest of the entry, nothing is issued and
            // nothing burns, so a malformed field must not turn an accurate,
            // actionable 410 into a 500.
            Status::Revoked => Err(Refusal::Revoked),
            Status::Claimed => {
                // Everything below either issues a token or refuses the seat's
                // own owner, and both are irreversible from the customer's
                // side. `Vault::load` runs the same check over the whole file,
                // but a vault can also be built in memory — and the two states
                // this catches cost a seat the instant the machine acts on
                // them: a `Claimed` entry with no owner answers SeatTaken to
                // everyone including the customer, forever.
                if let Err(why) = entry.validate(&key) {
                    return Err(Refusal::Unserviceable(why));
                }
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
                // The flip below burns the single seat. `days: 0` used to make
                // that flip issue a license whose entire validity window was
                // the claim instant, with no recovery path but vault surgery.
                if let Err(why) = entry.validate(&key) {
                    return Err(Refusal::Unserviceable(why));
                }
                // Saturating: a vendor-side `days` typo must not wrap the
                // expiry into the past (which release-mode `+` would allow).
                let exp = entry
                    .days
                    .map(|d| now.saturating_add(d.saturating_mul(86_400)));
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

/// How the vault file looked when this process last read or wrote it:
/// modification time and length. Used to notice an out-of-band edit.
pub type VaultFingerprint = (SystemTime, u64);

/// The claim counter: everything [`serve`] needs across requests.
pub struct Counter {
    pub vault: Vault,
    pub vault_path: PathBuf,
    /// ed25519 signing seed (the ONE secret this process holds — from the
    /// environment, never from the vault).
    pub seed: [u8; 32],
    pub bucket: TokenBucket,
    /// The vault file as this process last saw it. `None` re-reads on the
    /// next claim. See [`Counter::refresh_vault`].
    pub vault_seen: Option<VaultFingerprint>,
}

/// Read the vault file's fingerprint. An unreadable file yields `None`, which
/// forces a reload attempt rather than silently trusting memory.
fn fingerprint(path: &Path) -> Option<VaultFingerprint> {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.modified().ok()?, meta.len()))
}

impl Counter {
    /// Re-read the vault when the file on disk is no longer the one this
    /// process last read or wrote.
    ///
    /// The daemon holds the ledger in memory and writes the whole map back on
    /// every claim, so without this an out-of-band edit is not merely ignored
    /// — it is **destroyed** by the next claim. That is not a hypothetical
    /// path: `docs/LICENSING_SERVER.md` instructs the operator to manage codes
    /// with `ccos-license-admin` and upload `vault.json` over SFTP. Against a
    /// long-lived daemon that made `revoke` a no-op (the revoked code kept
    /// selling, and the sale erased the revocation) and made every seat sold
    /// while the daemon was up disappear at the next claim.
    ///
    /// Cheap by design: a `stat` per claim, and a re-read only when the
    /// fingerprint actually moved. Two caveats worth stating plainly — an
    /// edit that preserves both length and modification time is missed (file
    /// timestamps are coarse), and this closes the *stale-read* window, not
    /// the write race: an upload landing between this refresh and the save
    /// below is still lost. Concurrent editing of a live vault needs file
    /// locking, which is a larger change than this repair.
    pub fn refresh_vault(&mut self) -> io::Result<()> {
        let Some(current) = fingerprint(&self.vault_path) else {
            // No file to adopt. The daemon refuses to start without a
            // loadable vault, so in production this means the ledger was
            // removed underneath a running process; the in-memory copy is
            // then the only truth left and the next save restores it. Not a
            // reason to refuse a paying customer.
            return Ok(());
        };
        if Some(current) == self.vault_seen {
            return Ok(());
        }
        self.vault = Vault::load(&self.vault_path)?;
        self.vault_seen = fingerprint(&self.vault_path);
        Ok(())
    }

    /// Persist the ledger and remember the file we just wrote, so the next
    /// [`Counter::refresh_vault`] does not mistake our own write for an
    /// out-of-band edit.
    fn save_vault(&mut self) -> io::Result<()> {
        self.vault.save(&self.vault_path)?;
        self.vault_seen = fingerprint(&self.vault_path);
        Ok(())
    }
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
        // Adopt any out-of-band edit BEFORE deciding, so a revocation applied
        // while this process was running is honoured instead of overwritten.
        // Fail closed: a ledger we cannot re-read is one we must not flip.
        if let Err(e) = self.refresh_vault() {
            eprintln!("[counter] vault reload FAILED, claim refused: {e}");
            return (500, err_body("ledger unavailable — nothing was issued"));
        }
        let before = self.vault.clone();
        match self.vault.claim(&req.code_hash, &req.machine, now) {
            Ok((licensee, exp)) => {
                if let Err(e) = self.save_vault() {
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
            // 500, not 4xx: the caller did nothing wrong and retrying will not
            // help until the vendor fixes the entry. The reason goes to the
            // operator's log, never over the wire — it names an internal state
            // an unauthenticated caller has no business learning.
            Err(Refusal::Unserviceable(why)) => {
                eprintln!(
                    "[counter] UNSERVICEABLE entry for {}…: {why}",
                    &req.code_hash[..12]
                );
                (
                    500,
                    err_body(
                        "this code cannot be served — the vendor has been notified. \
                         Nothing was issued and your seat was not consumed.",
                    ),
                )
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

/// Serve claims forever on `listener`, one thread per connection, at most
/// [`MAX_CONCURRENT_CONNECTIONS`] in flight.
///
/// This loop used to be strictly sequential, on the reasoning that at one
/// small request per *sale* latency fairness is not a design pressure. That
/// reasoning is wrong against a hostile client, and measurably so: a single
/// socket that completes the handshake and then sends **zero bytes** made an
/// honest `GET /healthz` wait 5.15 s, because one connection was the whole of
/// the counter's capacity. The per-read timeout and the whole-request deadline
/// bound how long *one* connection blocks; neither bounds how long the queue
/// behind it waits, and the attacker pays nothing — no bytes, no completion,
/// and no rate-limit token, since the bucket is only consulted once a request
/// has parsed.
///
/// So: connections are served concurrently, the ledger is shared behind a
/// mutex (only claims take it, and only briefly), and past the cap the
/// counter sheds load with an announced 503 instead of queueing silently.
/// A slow client now costs one thread and its own latency, not everyone's.
/// TLS is still the reverse proxy's job.
pub fn serve(listener: TcpListener, counter: Counter) -> io::Result<()> {
    let counter = Arc::new(Mutex::new(counter));
    let in_flight = Arc::new(AtomicUsize::new(0));

    for stream in listener.incoming() {
        let Ok(mut stream) = stream else {
            // Transient accept failure (EMFILE, ECONNABORTED, …): don't spin
            // hot on the error — breathe, then keep serving.
            std::thread::sleep(Duration::from_millis(50));
            continue;
        };
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));

        if in_flight.load(Ordering::Acquire) >= MAX_CONCURRENT_CONNECTIONS {
            // Announced refusal beats an unbounded thread count. Writing it
            // is itself bounded by the write timeout set above.
            let _ = write_response(
                &mut stream,
                503,
                &err_body("counter busy — try again shortly"),
            );
            continue;
        }

        in_flight.fetch_add(1, Ordering::AcqRel);
        let counter = Arc::clone(&counter);
        let flight = Arc::clone(&in_flight);
        let spawned = std::thread::Builder::new()
            .name("ccos-claim".into())
            .spawn(move || {
                // Decrement even if the body panics, so one bad connection
                // cannot permanently consume a slot.
                let _guard = InFlightGuard(&flight);
                let deadline = Instant::now() + REQUEST_DEADLINE;
                let (status, body) = match read_request(&mut stream, deadline) {
                    Some((method, path, body)) => {
                        let now = ccos_core::license::now_unix();
                        match counter.lock() {
                            Ok(mut c) => c.handle(&method, &path, &body, now),
                            // A poisoned mutex means an earlier claim panicked
                            // mid-flip: refuse rather than trust the ledger.
                            Err(_) => (500, err_body("counter unavailable")),
                        }
                    }
                    None => (400, err_body("malformed request")),
                };
                let _ = write_response(&mut stream, status, &body);
            });
        if spawned.is_err() {
            // Out of threads: give the slot back and shed this connection.
            in_flight.fetch_sub(1, Ordering::AcqRel);
        }
    }
    Ok(())
}

/// Releases an in-flight slot on drop, panic included.
struct InFlightGuard<'a>(&'a AtomicUsize);

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Parse one HTTP/1.1 request off the socket: request line, `Content-Length`,
/// body. `None` on anything oversized, malformed, or still incomplete at
/// `deadline` — we answer 400 and move on. The deadline is what bounds a
/// drip-feeding client: per-read timeouts alone never fire as long as bytes
/// keep trickling in.
fn read_request(stream: &mut TcpStream, deadline: Instant) -> Option<(String, String, String)> {
    let mut head = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    // Read byte-wise until the blank line; the head is tiny and bounded.
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEAD || Instant::now() >= deadline {
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
    // Content-Length, strictly. The previous `.parse().ok().unwrap_or(0)`
    // could not tell "no header" from "header we could not read", so
    // `Content-Length: abc` and a value one past `u64::MAX` both silently
    // became zero and were answered 200 — a request smuggling primitive the
    // moment anything sits in front of this server. A header that is present
    // must be exactly one header and exactly a decimal number.
    let mut lengths = lines
        .filter_map(|l| l.split_once(':'))
        .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.trim());
    let content_length: usize = match (lengths.next(), lengths.next()) {
        (None, _) => 0,
        // Two Content-Length headers: the classic desync. Refuse outright
        // rather than pick one and hope the proxy picked the same.
        (Some(_), Some(_)) => return None,
        (Some(v), None) => {
            if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            v.parse().ok()?
        }
    };
    if content_length > MAX_BODY {
        return None;
    }
    let mut body = vec![0u8; content_length];
    let mut read = 0;
    while read < body.len() {
        if Instant::now() >= deadline {
            return None;
        }
        match stream.read(&mut body[read..]) {
            Ok(0) => return None, // EOF before the announced length
            Ok(n) => read += n,
            Err(_) => return None,
        }
    }
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

    /// A vault holding one unclaimed seat; returns the **wire-level** code
    /// hash (what a client sends) — the vault itself is keyed one hash
    /// further, by `vault_key(hash)`.
    fn vault_with_code() -> (Vault, String) {
        let code = ccos_enterprise_governance::claim::code_from_entropy(&[42; 16]);
        let hash = ccos_enterprise_governance::claim::code_hash(&code);
        let mut vault = Vault::new();
        vault.entries.insert(
            ccos_enterprise_governance::claim::vault_key(&hash),
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
        let key = ccos_enterprise_governance::claim::vault_key(&hash);

        // Unknown code.
        assert_eq!(
            vault.claim("0".repeat(64).as_str(), &fp("m1"), NOW),
            Err(Refusal::UnknownCode)
        );
        // First claim: expiry fixed at now + 365d, machine recorded.
        let (licensee, exp) = vault.claim(&hash, &fp("m1"), NOW).expect("issues");
        assert_eq!(licensee, "Acme Corp");
        assert_eq!(exp, Some(NOW + 365 * 86_400));
        let e = &vault.entries[&key];
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
        vault.entries.get_mut(&key).unwrap().status = Status::Revoked;
        assert_eq!(vault.claim(&hash, &fp("m1"), NOW), Err(Refusal::Revoked));
    }

    #[test]
    fn a_stolen_vault_key_cannot_be_replayed_as_a_claim() {
        // THE property the v2 vault exists for: presenting a vault KEY (what
        // a leaked vault.json contains) at the wire is an unknown code — only
        // the wire-level code hash, which the vault does not store, redeems.
        let (mut vault, hash) = vault_with_code();
        let leaked_key = vault.entries.keys().next().unwrap().clone();
        assert_ne!(leaked_key, hash, "the vault never stores the wire hash");
        assert_eq!(
            vault.claim(&leaked_key, &fp("thief"), NOW),
            Err(Refusal::UnknownCode),
            "vault contents are not redeemable"
        );
        // The honest wire hash still redeems.
        assert!(vault.claim(&hash, &fp("m1"), NOW).is_ok());
    }

    #[test]
    fn absurd_day_counts_saturate_instead_of_wrapping_into_the_past() {
        let (mut vault, hash) = vault_with_code();
        let key = ccos_enterprise_governance::claim::vault_key(&hash);
        vault.entries.get_mut(&key).unwrap().days = Some(u64::MAX / 4);
        let (_, exp) = vault.claim(&hash, &fp("m1"), NOW).expect("issues");
        let exp = exp.expect("an expiry exists");
        assert!(exp >= NOW, "never earlier than the claim instant");
        assert_eq!(exp, u64::MAX, "saturated, not wrapped");
    }

    #[test]
    fn perpetual_codes_issue_tokens_without_expiry() {
        let (mut vault, hash) = vault_with_code();
        let key = ccos_enterprise_governance::claim::vault_key(&hash);
        vault.entries.get_mut(&key).unwrap().days = None;
        let (_, exp) = vault.claim(&hash, &fp("m1"), NOW).unwrap();
        assert_eq!(exp, None);
    }

    fn counter(vault: Vault, dir: &Path) -> Counter {
        Counter {
            vault,
            vault_path: dir.join("vault.json"),
            seed: SEED,
            bucket: TokenBucket::new(100.0, 100.0),
            vault_seen: None,
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
        let key = ccos_enterprise_governance::claim::vault_key(&hash);
        assert_eq!(on_disk.entries[&key].status, Status::Claimed);

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
    fn vault_schema_gate_fails_closed() {
        let dir = tmp("schema");
        let path = dir.join("vault.json");
        let mut v = Vault::new();
        v.schema = VAULT_SCHEMA_V1.into();
        v.save(&path).unwrap();
        let err = Vault::load(&path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("migrate"),
            "the v1 refusal points at the fix: {err}"
        );
        // The migration path can still read it.
        assert_eq!(
            Vault::load_any_schema(&path).unwrap().schema,
            VAULT_SCHEMA_V1
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn drip_feeding_client_is_cut_at_the_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            // One byte every 20 ms — each read succeeds, so per-read timeouts
            // never fire; only the whole-request deadline can end this.
            for _ in 0..100 {
                if s.write_all(b"X").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let (mut stream, _) = listener.accept().unwrap();
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let started = Instant::now();
        let out = read_request(&mut stream, Instant::now() + Duration::from_millis(300));
        assert!(out.is_none(), "an unfinished request is refused");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "cut at the deadline, not at the drip rate: {:?}",
            started.elapsed()
        );
        drop(stream);
        let _ = client.join();
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
