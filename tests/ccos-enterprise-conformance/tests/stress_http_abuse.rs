//! # Hostile stress of the claim counter's HTTP/1.1 loop
//!
//! `ccos_license_server::serve` (`tools/ccos-license-server/src/lib.rs:430`)
//! is the only network surface the CCOS product exposes, it is unauthenticated
//! by construction (a claim code *is* the credential, and it never travels),
//! and it is the checkout counter: if it is down, nobody can activate a
//! purchase. Its own module doc and `docs/LICENSING_SERVER.md` make three
//! availability promises that this file attacks with a real `TcpListener` on
//! `127.0.0.1:0` and real hostile clients:
//!
//! > "Connections are handled sequentially with per-read timeouts **and a
//! > whole-request deadline**, so a drip-feeding client cannot park the queue."
//! > — `docs/LICENSING_SERVER.md`, Deployment
//!
//! > "A slow client now costs one thread and its own latency, not everyone's."
//! > — `lib.rs:428`
//!
//! > "`revoke` makes the counter refuse the code" — `docs/LICENSING_SERVER.md`
//!
//! Everything asserted below is the product's **current, real** behaviour.
//! Where that behaviour is still a defect the assertion pins the defect and
//! the comment names it; where a defect has been **repaired** the assertion
//! pins the repair, so a regression fails loudly here instead of silently
//! changing the commercial posture. Nothing here is weakened to pass, and the
//! finding numbers below are the ones the original report used — repaired
//! findings keep their number under "What was repaired" so every per-test
//! citation stays valid.
//!
//! ## What held
//!
//! * **Nothing this file could send made the counter stop serving.** Every
//!   single attack — 16 KiB header floods, `u64::MAX` content lengths, JSON
//!   nesting bombs, invalid UTF-8 in the request line, bodies that overrun
//!   their announcement, 64 abrupt resets, 64 simultaneous idle sockets, 32-way
//!   claim races — is followed by a survivor probe, and the counter answered
//!   every one. No panic, no poisoned state, no leaked descriptor, no wedged
//!   loop.
//! * **Memory is genuinely bounded.** `content_length > MAX_BODY` is checked
//!   *before* `vec![0u8; content_length]` (`lib.rs:541-544`), so the largest
//!   allocation an attacker can force per request is 4 KiB, and the head is
//!   capped at 8 KiB. A head of exactly `MAX_HEAD` is still served; 8 193
//!   bytes is refused. Concurrency is bounded the same way: at most
//!   `MAX_CONCURRENT_CONNECTIONS` = 64 threads are in flight (`lib.rs:60`,
//!   `444-453`) and the 65th connection is shed with an announced `503`, not
//!   queued silently and not spawned.
//! * **The single-seat property survives a 32-way race.** 32 threads from 32
//!   different machines racing the *same* code on the *same* counter produce
//!   exactly one `200` and 31 `410`s, one machine fingerprint in the ledger,
//!   and one signed token. Since the concurrency repair those 32 claims really
//!   are in flight together, and the property holds because the ledger is
//!   shared behind a mutex (`lib.rs:431`, `468`), the flip is persisted before
//!   the token is disclosed, and the ledger is the arbiter. 32 threads from the
//!   *same* machine get 32 **byte-identical** tokens.
//! * **The rate limiter never burns a seat.** `handle_claim` checks the bucket
//!   *before* it parses or touches the vault (`lib.rs:335`), so a `429` leaves
//!   the code exactly as claimable as it was, and it claims cleanly once the
//!   bucket refills.
//! * **There is no keep-alive, ever**, which is what keeps the remaining
//!   `Content-Length` sloppiness below (finding 3) from being a
//!   request-smuggling vulnerability behind the documented nginx/Caddy reverse
//!   proxy.
//! * **Nothing from the request is reflected into the response.** Status,
//!   reason phrase and body are all drawn from fixed strings; there is no
//!   header-injection or response-splitting surface.
//!
//! ## What was repaired
//!
//! 1. **AVAILABILITY — one connection is no longer all of the counter's
//!    capacity.** *Was:* the loop was strictly sequential, so a client that
//!    completed the TCP handshake and then sent **zero bytes** parked every
//!    paying customer for `IO_TIMEOUT` = 5 s, and one that dripped a byte every
//!    20 ms parked them for `REQUEST_DEADLINE` = 10 s. Measured end to end by
//!    this file at the time: an honest `GET /healthz` issued 250 ms behind one
//!    silent socket waited **5.0 s**; one issued behind a slowloris waited
//!    **10.0 s**; three idle sockets cost **15 s**, so a single host holding
//!    the default 128-deep accept backlog open and idle bought ~10 minutes of
//!    total outage per round, forever, from one IP, with zero payload — and the
//!    attacker paid nothing, not even a rate-limit token (the bucket is only
//!    consulted once a request parses, `lib.rs:335`). *Now:* `serve` runs one
//!    thread per connection with at most `MAX_CONCURRENT_CONNECTIONS` = 64 in
//!    flight and an announced `503` past the cap (`lib.rs:430-483`). The same
//!    attacks, measured the same way, now cost the honest client single-digit
//!    **milliseconds**, and the attacker's socket sits parked paying its own
//!    timeout alone. The runbook sentence quoted above is finally true, though
//!    its *mechanism* is now stale: connections are no longer handled
//!    sequentially (`docs/LICENSING_SERVER.md:104` still says they are).
//!    -> [`one_silent_socket_no_longer_parks_any_paying_customer`],
//!    [`a_slowloris_is_cut_at_the_deadline_and_no_longer_parks_the_queue`],
//!    [`idle_attacker_sockets_no_longer_add_up_to_an_outage`],
//!    [`past_the_concurrency_cap_the_counter_sheds_load_with_an_announced_503`]
//!
//! 3a. **SPEC — an unparseable or duplicated `Content-Length` is now refused.**
//!    *Was:* the parser ended in `.parse().ok().unwrap_or(0)`, so
//!    `Content-Length: -1`, `abc`, an empty value and `99999999999999999999999`
//!    all meant "no body" and the request was **served** where RFC 9112 §6.3
//!    requires a 400 — and the absurdity inverted, `u64::MAX` being refused
//!    (it fits `usize` and exceeds `MAX_BODY`) while `u64::MAX + 1` returned
//!    **200 OK**. Two `Content-Length` headers were not refused either; the
//!    **first** won, so `0` followed by `113` read no body at all. Both are
//!    halves of a classic front-end/back-end desync. *Now:* absent means 0, and
//!    a header that is present must be exactly **one** header whose value is
//!    entirely ASCII digits and fits a `usize` (`lib.rs:519-540`); anything
//!    else is `400 malformed request` before a body is read. `+113` is refused
//!    too — RFC 9112 §6.3 allows only DIGIT.
//!    -> [`an_unparseable_content_length_is_now_refused_not_served_as_bodyless`],
//!    [`duplicate_content_lengths_are_now_refused_but_hidden_ones_are_still_invisible`]
//!
//! 5. **CORRECTNESS — a running counter now adopts vault edits instead of
//!    erasing them.** *Was:* `serve` took the `Counter` by value and never
//!    re-read `vault.json`; every successful claim wrote that memory over the
//!    file. The runbook tells vendors to sell, re-arm and revoke seats with
//!    `ccos-license-admin --vault <the same file>` and states that `revoke`
//!    "makes the counter refuse the code" — the CLI itself prints "revoked …
//!    — the counter now refuses this code". Against a running daemon all of
//!    that was false: a revoked code was still **sold** (`200` + a valid signed
//!    token), that very claim **erased** the revocation, and a seat sold while
//!    the daemon was up was unclaimable (`404`) and then **deleted** from the
//!    file. Money moved the wrong way in both directions. *Now:* `Counter`
//!    carries a `vault_seen` fingerprint (`lib.rs:266`) and `refresh_vault`
//!    (`lib.rs:296`) re-reads the file at the start of every claim whenever it
//!    no longer matches what this process last read or wrote, so a revocation
//!    applied mid-run is honoured (`410`), a seat sold mid-run is claimable,
//!    and both survive the next claim's write-back. A ledger that cannot be
//!    re-read fails closed with `500` instead of being overwritten from memory;
//!    a *missing* file is not an error and memory is kept.
//!    -> [`a_running_counter_now_adopts_every_vault_edit_made_while_it_ran`],
//!    [`an_unreadable_ledger_is_now_refused_not_overwritten_from_memory`]
//!
//! ## What is still broken
//!
//! 2. **AVAILABILITY — 240 bytes lock out every paying customer, and 12
//!    bytes/second holds the lockout forever.** The token bucket is **global**
//!    (`lib.rs:218-220` calls this deliberate) and is charged *before* the
//!    request is understood: `lib.rs:335` runs ahead of the `serde_json` parse
//!    at `lib.rs:338`, so a request that is not a claim at all still spends a
//!    token. The cheapest one is `POST /claim HTTP/1.1\r\n\r\n` — **24
//!    bytes**, no headers, no body. The shipped parameters are burst 10 /
//!    0.5 per second (`bin/ccos-license-server.rs:100`), so ten of them
//!    (240 bytes, ~7 ms measured) empty the bucket, after which a real
//!    customer's correct claim gets `429` — asserted here — and one junk
//!    request every two seconds keeps it empty indefinitely. There is no
//!    per-peer accounting, no proof-of-work, and no separate budget for
//!    requests that turn out to be well-formed. `/healthz` is not rate limited
//!    at all, so every monitor reports the counter perfectly healthy
//!    throughout — also asserted here.
//!    -> [`ten_junk_requests_lock_out_every_paying_customer`]
//!
//! 3. **SPEC — a `Content-Length` this parser cannot *see* is still silently
//!    no body.** The value is now validated strictly (repair 3a above), but
//!    header *framing* is not: the name is compared verbatim against a
//!    `split_once(':')`, so `Content-Length : 113` is invisible here and
//!    visible to a lenient front end; `str::lines` does not end a line at a
//!    bare CR, so a header hidden behind one is absorbed into the previous
//!    value; and an obs-fold continuation (RFC 9112 §5.2) is never unfolded.
//!    `Transfer-Encoding: chunked` is ignored outright — not 501'd, as RFC
//!    9112 §6.1 requires — so a chunked claim is silently a bodyless claim,
//!    and with both headers present `Content-Length` wins, which is precisely
//!    backwards from §6.3. Each of these is one half of a classic
//!    front-end/back-end desync, and the *only* thing that keeps them from
//!    being request smuggling behind the documented nginx/Caddy reverse proxy
//!    is that this server never reuses a connection.
//!    -> [`duplicate_content_lengths_are_now_refused_but_hidden_ones_are_still_invisible`],
//!    [`transfer_encoding_chunked_is_ignored_not_refused`],
//!    [`no_connection_is_ever_reused_which_is_what_defuses_the_desync`]
//!
//! 4. **SPEC — `HEAD` is unroutable and every `405` lies about it.** The match
//!    at `lib.rs:326-331` accepts only `GET` and `POST`, so `HEAD /healthz` —
//!    the request every load balancer and uptime monitor sends first — is
//!    `405 Method Not Allowed`, **with a response body**, which RFC 9110
//!    §9.3.2 forbids for `HEAD` under any status. No `405` carries the `Allow`
//!    header RFC 9110 §15.5.6 says a server **MUST** generate. And the method
//!    is checked before the path, so `GET /claim` is `404 Not Found` (the path
//!    the whole product is built around) while `DELETE /nope` is `405 Method
//!    Not Allowed` (a path that does not exist) — exactly backwards.
//!    -> [`method_path_matrix_is_exactly_the_documented_statuses`],
//!    [`head_responses_carry_a_body_and_no_405_carries_allow`]
//!
//! 6. **SPEC — the request line is never validated.** `lib.rs:515-518` takes
//!    the first two whitespace-separated tokens of the first line and drops
//!    the rest, so there is no method-token charset check, no request-target
//!    form check and no HTTP-version check at all: `GET /healthz` with no
//!    version, with `HTTP/9.9`, tab-separated, or with trailing junk are all
//!    served identically, and a stray *header* line arriving where the request
//!    line belongs is **routed** — `: no method` becomes method `:`, target
//!    `no`, and gets a `405` rather than a `400`. Every outcome is fail-closed,
//!    so this is looseness rather than a hole, but it is the layer that is
//!    supposed to reject a malformed message before anything downstream sees
//!    it.
//!    -> [`garbage_methods_and_absurd_targets_are_classified_never_executed`],
//!    [`requests_without_a_request_line_are_refused_not_guessed`]
//!
//! 7. **ROBUSTNESS — one byte-at-a-time `read(2)` per header byte.**
//!    `lib.rs:509` reads the head into a 1-byte buffer, so an 8 KiB header
//!    flood costs 8 192 syscalls before it is refused, and a well-formed
//!    request costs one syscall per byte of its head. It is a constant factor,
//!    not an exhaustion vector on its own; it used to multiply every parked
//!    second in finding 1, and since that repair it costs only the connection
//!    that sends the bytes.
//!    -> [`a_header_flood_is_refused_at_max_head`]
//!
//! 8. **SPEC — the shed `503` is announced badly.** New with the concurrency
//!    repair, and found by the test that guards it. The shed path
//!    (`lib.rs:444-453`) writes the refusal and drops the stream **without
//!    ever reading the request**, so a caller that sent one leaves bytes in
//!    the receive queue, the close becomes an RST, and the announced body
//!    `{"error":"counter busy — try again shortly"}` is destroyed in flight —
//!    on loopback that is the common case, and the caller sees a truncated
//!    `503` that some HTTP clients report as a network error rather than as a
//!    refusal. The body is only observable intact by a client that sent
//!    nothing. And `write_response` has no `503` arm (`lib.rs:560-568`), so
//!    the status line reads `503 Internal Server Error`: the status is right,
//!    the phrase says the counter crashed when what happened is that it
//!    protected itself. Neither costs a sale — the caller is told to retry
//!    either way — but a load shedder that cannot deliver its own reason is
//!    one an operator will misdiagnose.
//!    -> [`past_the_concurrency_cap_the_counter_sheds_load_with_an_announced_503`]
//!
//! Run the whole file: `cargo test -p ccos-enterprise-conformance --test
//! stress_http_abuse` — 23 tests, ~10 s wall-clock in debug and in release,
//! dominated by the two *per-connection* bounds that are supposed to fire: the
//! slowloris deadline (10 s) and the truncated-body read timeout (5 s). Both
//! now cost only the attacker's own connection, which is why the three
//! parking measurements no longer add anything: they resolve in
//! milliseconds. Nothing here is `#[ignore]`d — the linearity proof used to be
//! 15 s of deliberate outage and is now sub-second, because the outage is
//! gone.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use ccos_enterprise_governance::b64url;
use ccos_enterprise_governance::claim::{
    code_from_entropy, code_hash, machine_fingerprint_of, vault_key, ClaimRequest, CLAIM_SCHEMA,
};
use ccos_license_server::{
    serve, Counter, Entry, Status, TokenBucket, Vault, MAX_CONCURRENT_CONNECTIONS,
};

// ── The counter's own private constants, mirrored ────────────────────
//
// These are `const` (not `pub`) in `tools/ccos-license-server/src/lib.rs`, so
// they cannot be imported. Mirroring them here is deliberate: if someone
// retunes the server, the boundary tests below fail and force the numbers in
// this file's report to be re-derived rather than silently going stale.
// `MAX_CONCURRENT_CONNECTIONS` is the exception: the concurrency repair made
// it `pub`, so it is imported above and this file cannot drift from it.

/// `lib.rs:51` — the head is refused at or beyond this many bytes.
const MAX_HEAD: usize = 8 * 1024;
/// `lib.rs:52` — an announced body larger than this is refused before it is
/// allocated.
const MAX_BODY: usize = 4 * 1024;
/// `lib.rs:53` — per-read socket timeout. This is what a *silent* client costs
/// **its own connection**; since the concurrency repair it costs nobody else.
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// `lib.rs:64` — whole-request deadline. This is what a *dripping* client costs
/// its own connection.
const REQUEST_DEADLINE: Duration = Duration::from_secs(10);
/// `bin/ccos-license-server.rs:100` — the shipped bucket: burst 10, 30/min.
const SHIPPED_BURST: f64 = 10.0;
const SHIPPED_PER_SECOND: f64 = 0.5;

/// What "served promptly" means for an honest client that is queued behind an
/// attacker: one fifth of the per-read timeout, i.e. a full second, which is
/// ~300x the measured unobstructed latency and still far below the 5 s the
/// same request used to take. Deliberately generous — the property under test
/// is "the honest client does not wait for the attacker's timeout", and a
/// tight bound would be measuring the CI machine's scheduler instead.
const PROMPT: Duration = Duration::from_millis(1_000);

/// How long a *client* in this file waits before giving up. Deliberately far
/// beyond every server-side bound, so a hang is always attributable to the
/// server and never to the test.
const CLIENT_PATIENCE: Duration = Duration::from_secs(45);

// ── Deterministic fixtures — no RNG, no wall clock in any assertion ──

/// The counter's ed25519 signing seed for this file.
const SEED: [u8; 32] = [0x3C; 32];
const DAY: u64 = 86_400;
/// Codes seeded into every counter this file spawns.
const CODES: u32 = 8;
/// A code index deliberately outside [`CODES`] — the "sold while the daemon
/// was running" seat.
const SOLD_LATE: u32 = 4_242;

/// 16 bytes of *deterministic* entropy for code `i` (splitmix64). The vendor's
/// entropy source is the only randomness in the real protocol; there is none
/// at all here, so every number this file reports is reproducible.
fn entropy(i: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut x = 0x9E37_79B9_7F4A_7C15u64 ^ u64::from(i).wrapping_mul(0xD1B5_4A32_D192_ED03);
    for chunk in out.chunks_mut(8) {
        x ^= x >> 30;
        x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x ^= x >> 27;
        x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
        x ^= x >> 31;
        chunk.copy_from_slice(&x.to_le_bytes());
    }
    out
}

/// The **wire** hash of code `i` — what a client sends, what redeems a seat.
fn wire(i: u32) -> String {
    code_hash(&code_from_entropy(&entropy(i)))
}

/// The **vault key** of code `i` — what `vault.json` contains.
fn key(i: u32) -> String {
    vault_key(&wire(i))
}

/// Machine fingerprint of host `m`.
fn fp(m: u32) -> String {
    machine_fingerprint_of(&format!("machine-{m:04}"))
}

fn unclaimed(licensee: &str) -> Entry {
    Entry {
        licensee: licensee.to_string(),
        label: Some("invoice-http-abuse".into()),
        days: Some(365),
        status: Status::Unclaimed,
        created_unix: 1_700_000_000,
        claimed_unix: None,
        exp_unix: None,
        machine: None,
    }
}

fn claim_body(code_hash: &str, machine: &str) -> String {
    serde_json::to_string(&ClaimRequest {
        schema: CLAIM_SCHEMA.to_string(),
        code_hash: code_hash.to_string(),
        machine: machine.to_string(),
    })
    .expect("request serializes")
}

/// Decode a `sign_token_bound` token and verify its ed25519 signature against
/// [`SEED`]'s public half — independently of the product's own verifier, so a
/// bug in that verifier cannot hide a bug here.
fn verified_payload(token: &str) -> serde_json::Value {
    use ed25519_dalek::{Signature, SigningKey, Verifier};
    let (payload_b64, sig_b64) = token.rsplit_once('.').expect("token is payload.sig");
    let sig_bytes = b64url::decode(sig_b64).expect("signature decodes");
    let sig = Signature::from_slice(&sig_bytes).expect("signature is 64 bytes");
    let vk = SigningKey::from_bytes(&SEED).verifying_key();
    vk.verify(payload_b64.as_bytes(), &sig)
        .expect("the counter's token verifies against its own seed");
    let json = b64url::decode(payload_b64).expect("payload decodes");
    serde_json::from_slice(&json).expect("payload is JSON")
}

// ── The hostile client ───────────────────────────────────────────────

/// One request/response exchange, including how it failed and how long the
/// *client* waited. Every field matters to an availability test: a reset
/// connection and a `400` are both acceptable answers to an abusive request,
/// but a 45-second wait is not.
#[derive(Debug)]
struct Reply {
    raw: String,
    io_error: Option<io::ErrorKind>,
    elapsed: Duration,
}

impl Reply {
    /// The status code, if a status line arrived at all.
    fn status(&self) -> Option<u16> {
        self.raw
            .strip_prefix("HTTP/1.1 ")?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    }

    /// The response body (everything past the header terminator).
    fn body(&self) -> &str {
        self.raw.split_once("\r\n\r\n").map_or("", |(_, b)| b)
    }

    /// A response header's value, lowercased-name lookup.
    fn header(&self, name: &str) -> Option<&str> {
        let head = self.raw.split_once("\r\n\r\n").map_or("", |(h, _)| h);
        head.lines()
            .skip(1)
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim())
    }

    /// The `error` field of an announced refusal — the counter distinguishes
    /// "the HTTP framing was rejected" (`malformed request`, written by
    /// `serve` at `lib.rs:475`) from "the framing was accepted and the claim
    /// JSON was rejected" (`malformed claim request`, `lib.rs:340`). Which one
    /// comes back proves which code path an abusive request reached. Since the
    /// `Content-Length` repair this distinction is what separates a value the
    /// framer refused from one it read as zero.
    fn error(&self) -> Option<String> {
        serde_json::from_str::<serde_json::Value>(self.body())
            .ok()?
            .get("error")?
            .as_str()
            .map(str::to_string)
    }

    /// The issued token, for a `200` claim.
    fn token(&self) -> Option<String> {
        serde_json::from_str::<serde_json::Value>(self.body())
            .ok()?
            .get("token")?
            .as_str()
            .map(str::to_string)
    }

    /// How many HTTP status lines came back on this connection. Anything
    /// above 1 would mean the loop answered a pipelined request.
    fn responses(&self) -> usize {
        self.raw.matches("HTTP/1.1 ").count()
    }

    /// An abusive request is allowed exactly two answers: an announced `400`,
    /// or a dead connection. It is never allowed to hang, and never allowed
    /// to succeed.
    #[track_caller]
    fn assert_refused(&self, what: &str) {
        let reset = matches!(
            self.io_error,
            Some(io::ErrorKind::ConnectionReset)
                | Some(io::ErrorKind::BrokenPipe)
                | Some(io::ErrorKind::ConnectionAborted)
        );
        assert!(
            self.status() == Some(400) || (self.status().is_none() && reset),
            "{what}: expected an announced 400 or a dead connection, got \
             status={:?} io_error={:?} raw={:?}",
            self.status(),
            self.io_error,
            self.raw
        );
        assert!(
            self.elapsed < CLIENT_PATIENCE,
            "{what}: the client gave up waiting — the loop hung"
        );
    }
}

/// Speak raw bytes at the counter and read whatever comes back until EOF.
///
/// Deliberately tolerant: a server that closes a socket with unread bytes
/// still in its receive queue makes the kernel send RST, which can destroy a
/// response that was already in flight. Every abusive request in this file can
/// therefore legitimately end in `ConnectionReset` instead of a `400`, and
/// [`Reply::assert_refused`] accepts both — asserting one specific outcome
/// would be asserting a race, not a property.
fn speak(addr: SocketAddr, request: &[u8]) -> Reply {
    let started = Instant::now();
    let mut io_error: Option<io::ErrorKind> = None;
    let mut bytes = Vec::new();
    match TcpStream::connect(addr) {
        Ok(mut s) => {
            let _ = s.set_read_timeout(Some(CLIENT_PATIENCE));
            let _ = s.set_write_timeout(Some(CLIENT_PATIENCE));
            if let Err(e) = s.write_all(request) {
                io_error = Some(e.kind());
            }
            if let Err(e) = s.read_to_end(&mut bytes) {
                if io_error.is_none() {
                    io_error = Some(e.kind());
                }
            }
        }
        Err(e) => io_error = Some(e.kind()),
    }
    Reply {
        raw: String::from_utf8_lossy(&bytes).into_owned(),
        io_error,
        elapsed: started.elapsed(),
    }
}

/// Send only a request **head** and read the whole answer before anything
/// else goes down the socket.
///
/// This is the deterministic way to ask "how did the framer read your
/// `Content-Length`?". If the counter framed the message as bodyless it
/// answers within milliseconds and closes with an empty receive queue, so the
/// answer arrives whole. If it believed the announced length it blocks in the
/// body loop until `IO_TIMEOUT` and answers `malformed request` instead. The
/// two outcomes differ in status, in error string *and* in latency, and
/// neither can be destroyed by the RST that an unread body tail would provoke
/// — sending the body and racing the reset is how this measurement goes flaky.
fn speak_head_only(addr: SocketAddr, head: &str) -> Reply {
    assert!(head.ends_with("\r\n\r\n"), "a head ends in the terminator");
    speak(addr, head.as_bytes())
}

fn get_request(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: counter.invalid\r\n\r\n").into_bytes()
}

fn post_claim(body: &str) -> Vec<u8> {
    format!(
        "POST /claim HTTP/1.1\r\nHost: counter.invalid\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

// ── The counter under attack ─────────────────────────────────────────

/// A live counter: a real `TcpListener` on loopback, a real vault on disk, and
/// `serve` running on its own thread exactly as the daemon runs it.
struct Counterparty {
    addr: SocketAddr,
    vault_path: PathBuf,
}

impl Counterparty {
    fn send(&self, request: &[u8]) -> Reply {
        speak(self.addr, request)
    }

    fn healthz(&self) -> Reply {
        self.send(&get_request("/healthz"))
    }

    /// A correct, well-formed claim of code `i` from machine `m`.
    fn claim(&self, i: u32, m: u32) -> Reply {
        self.send(&post_claim(&claim_body(&wire(i), &fp(m))))
    }

    fn on_disk(&self) -> Vault {
        Vault::load(&self.vault_path).expect("the ledger is loadable")
    }

    /// The invariant every attack in this file ends with: the counter is still
    /// serving. A single wedged request would fail this everywhere at once.
    #[track_caller]
    fn assert_still_serving(&self, after: &str) {
        let probe = self.healthz();
        assert_eq!(
            probe.status(),
            Some(200),
            "the counter stopped serving after {after}: {probe:?}"
        );
        assert_eq!(probe.body(), r#"{"ok":true}"#, "after {after}");
    }
}

/// Spawn a counter with `CODES` unclaimed seats and the given bucket.
///
/// `serve` never returns, so the thread is deliberately detached and lives
/// until the test binary exits — exactly the daemon's lifecycle, and the only
/// way to observe what a *long-lived* process does with its ledger: it used to
/// hold the startup snapshot in memory forever and write it back over every
/// out-of-band edit (former finding 5), and it now re-reads the file whenever
/// the file changed underneath it.
fn counter(tag: &str, burst: f64, per_second: f64) -> Counterparty {
    let dir = std::env::temp_dir().join(format!(
        "ccos-http-abuse-{tag}-{pid}",
        pid = std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let vault_path = dir.join("vault.json");

    let mut vault = Vault::new();
    for i in 0..CODES {
        vault
            .entries
            .insert(key(i), unclaimed(&format!("Customer {i:02}")));
    }
    vault.save(&vault_path).expect("seed the ledger");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let counter = Counter {
        vault,
        vault_path: vault_path.clone(),
        seed: SEED,
        bucket: TokenBucket::new(burst, per_second),
        vault_seen: None,
        persist_writes: 0,
    };
    std::thread::spawn(move || {
        let _ = serve(listener, counter);
    });

    let party = Counterparty { addr, vault_path };
    // Do not start measuring anything until the accept loop is demonstrably
    // running: `bind` happens before `spawn`, so a connect would otherwise
    // succeed against the backlog and mis-attribute the scheduler's latency.
    party.assert_still_serving("startup");
    party
}

// ═════════════════════════════════════════════════════════════════════
// §1  Malformed framing: what the parser accepts, refuses, and guesses
// ═════════════════════════════════════════════════════════════════════

/// A request with no request line at all, and the near-misses around it.
///
/// All refused — but note the last case: RFC 9112 §2.2 says a server SHOULD
/// ignore at least one empty line received before the request line (it is the
/// documented workaround for buggy clients that append CRLF to a previous
/// request). This one refuses it, because `head.lines().next()` returns the
/// empty line and `split_whitespace().next()?` then bails (`lib.rs:516`).
/// Fail-closed, so it is a deviation rather than a hole — pinned so a
/// deliberate change is visible.
#[test]
fn requests_without_a_request_line_are_refused_not_guessed() {
    let c = counter("noline", 1e6, 1e6);

    for (what, bytes) in [
        ("the bare terminator", &b"\r\n\r\n"[..]),
        ("a blank request line", &b" \r\n\r\n"[..]),
        ("only a method", &b"GET\r\n\r\n"[..]),
        ("only a method and a trailing space", &b"GET \r\n\r\n"[..]),
        (
            "a leading empty line RFC 9112 says to tolerate",
            &b"\r\nGET /healthz HTTP/1.1\r\n\r\n"[..],
        ),
    ] {
        let reply = c.send(bytes);
        reply.assert_refused(what);
        assert_eq!(
            reply.error().as_deref(),
            Some("malformed request"),
            "{what}: refused by the framer, not by the claim parser"
        );
    }

    c.assert_still_serving("six headless requests");
}

/// Garbage methods and absurd request targets are classified, never executed.
///
/// Routing is **path-first** (`lib.rs`), which is the RFC-shaped pairing:
/// an unknown path is `404 Not Found` whatever nonsense method arrives with
/// it, while a known endpoint answers `405 Method Not Allowed` for methods
/// it does not serve. `GET /claim` is therefore a `405`, not the inverted
/// `404` this suite used to pin.
///
/// The request line itself is still not validated: the parser takes the
/// first two whitespace-separated tokens of the first line and ignores
/// everything after them. So there is no method-token charset check, no
/// request-target form check and no HTTP-version check — `GET /healthz` with
/// no version, with `HTTP/9.9`, tab-separated or with trailing junk are all
/// served identically, and a stray header line arriving first is routed as
/// `(method, target) = (":", "no")`. All fail-closed, all pinned.
#[test]
fn garbage_methods_and_absurd_targets_are_classified_never_executed() {
    let c = counter("garbage", 1e6, 1e6);

    let long_path = format!("/{}", "a".repeat(4_000));
    let long_method = "M".repeat(4_000);
    for (what, request, expect) in [
        // Path-first: /nope does not exist, so even a nonsense method is 404.
        ("a nonsense method", "WOPBOPALOOBOP /nope HTTP/1.1", 404u16),
        ("a lowercase get", "get /healthz HTTP/1.1", 405),
        (
            "a 4 000-byte method",
            &format!("{long_method} /healthz HTTP/1.1"),
            405,
        ),
        (
            "a 4 000-byte path",
            &format!("GET {long_path} HTTP/1.1"),
            404,
        ),
        // RFC 9112 §3.2.2: an origin server MUST accept absolute-form. This
        // one 404s it, because the target is compared as an opaque string.
        (
            "absolute-form",
            "GET http://counter.invalid/healthz HTTP/1.1",
            404,
        ),
        // No HTTP version at all: the version token is never read, so this is
        // served as if it were HTTP/1.1.
        ("no version token", "GET /healthz", 200),
        ("an invented version", "GET /healthz HTTP/9.9", 200),
        ("tab-separated request line", "GET\t/healthz\tHTTP/1.1", 200),
        (
            "many spaces in the request line",
            "GET    /healthz    HTTP/1.1",
            200,
        ),
        (
            "trailing junk after the version",
            "GET /healthz HTTP/1.1 AND MORE",
            200,
        ),
        // A header line arriving where the request line belongs is routed as
        // `(method, target) = (":", "no")` rather than refused; the target
        // does not exist, so path-first routing answers 404.
        ("a stray header line, routed", ": no method", 404),
        (
            "a Content-Length as a request line",
            "Content-Length: 5",
            404,
        ),
    ] {
        let reply = c.send(format!("{request}\r\n\r\n").as_bytes());
        assert_eq!(
            reply.status(),
            Some(expect),
            "{what}: {request:?} -> {reply:?}"
        );
    }

    // Invalid UTF-8 in the request line is replaced, not rejected, by
    // `String::from_utf8_lossy` (`lib.rs:514`) — the method becomes U+FFFD
    // and lands on 405. It must not panic and must not be `GET`.
    let mut invalid = Vec::from(&b"\xff\xfe\x80 /healthz HTTP/1.1\r\n\r\n"[..]);
    let reply = c.send(&invalid);
    assert_eq!(reply.status(), Some(405), "invalid UTF-8 method: {reply:?}");
    // ...and in the path.
    invalid = Vec::from(&b"GET /\xc3\x28\xf0\x9f HTTP/1.1\r\n\r\n"[..]);
    let reply = c.send(&invalid);
    assert_eq!(reply.status(), Some(404), "invalid UTF-8 path: {reply:?}");

    c.assert_still_serving("eleven garbage request lines");
}

/// **REGRESSION GUARD (repaired finding 3a).** Every `Content-Length` the
/// parser could not turn into a `usize` **used to** be silently taken to mean
/// zero — the old framer ended in `.parse().ok() … .unwrap_or(0)`, which could
/// not tell "no header" from "header I could not read" — so the request was
/// **served** rather than refused, where RFC 9112 §6.3 requires a 400.
///
/// What that cost, in the three directions this test measured at the time:
/// * `GET /healthz` with `Content-Length: -1` and a body returned **200 OK**;
/// * `POST /claim` with `Content-Length: -1` was answered `malformed claim
///   request` **without ever waiting for the announced body**, so a customer
///   behind a proxy that rewrites lengths was told their *code* was malformed
///   when it was the framing that had been mangled;
/// * and the absurdity inverted: `u64::MAX` was refused (it fits `usize` and
///   exceeds `MAX_BODY`) while `u64::MAX + 1` — one larger, more absurd — was
///   *accepted*, because it overflowed the parse into zero.
///
/// Behind the documented nginx/Caddy reverse proxy that is one half of a
/// request-smuggling primitive: the proxy frames a body this server frames
/// away. The framer is now strict (`lib.rs:519-540`) — absent means 0, present
/// means exactly one header whose value is entirely ASCII digits and fits a
/// `usize`, anything else is `400 malformed request` before a byte of body is
/// read. Every input below is the one that used to be served; all of them are
/// now refused, the inversion is closed in both directions, and no seat moves.
#[test]
fn an_unparseable_content_length_is_now_refused_not_served_as_bodyless() {
    let c = counter("clength", 1e6, 1e6);
    let body = claim_body(&wire(0), &fp(1));

    // Refused by the *framer*, not served as bodyless — and refused without
    // waiting one millisecond for the body that was announced.
    for value in [
        "-1",
        "-4096",
        "abc",
        "",
        " ",
        "0x10",
        "1e3",
        "4096bytes",
        "18446744073709551616",              // u64::MAX + 1
        "999999999999999999999999999999999", // ~2^110
    ] {
        let reply = speak_head_only(
            c.addr,
            &format!("GET /healthz HTTP/1.1\r\nContent-Length: {value}\r\n\r\n"),
        );
        assert_eq!(
            reply.status(),
            Some(400),
            "Content-Length: {value:?} must be refused, never served as a \
             healthy bodyless GET"
        );
        assert_eq!(
            reply.error().as_deref(),
            Some("malformed request"),
            "Content-Length: {value:?} is refused by the framer, before routing"
        );
        assert!(
            reply.elapsed < Duration::from_secs(1),
            "Content-Length: {value:?} — the refusal must not cost a wait for \
             the announced body ({:?})",
            reply.elapsed
        );
    }

    // The same value on the endpoint that matters. The claim parser is never
    // reached now, so the customer is told the *request* was malformed rather
    // than being told their code was.
    let reply = speak_head_only(c.addr, "POST /claim HTTP/1.1\r\nContent-Length: -1\r\n\r\n");
    assert_eq!(reply.status(), Some(400));
    assert_eq!(
        reply.error().as_deref(),
        Some("malformed request"),
        "the framer refused it; the claim parser never saw an empty body"
    );
    assert!(
        reply.elapsed < Duration::from_secs(1),
        "{:?}",
        reply.elapsed
    );
    // Nothing was sold, which was true before the repair and must stay true.
    assert_eq!(
        c.on_disk().entries[&key(0)].status,
        Status::Unclaimed,
        "a length the parser could not read must never move the ledger"
    );

    // Refused for the other reason: these *do* parse and exceed MAX_BODY.
    for value in [
        format!("{}", MAX_BODY + 1),
        format!("{}", u32::MAX),
        format!("{}", u64::MAX),
    ] {
        let reply = speak_head_only(
            c.addr,
            &format!("GET /healthz HTTP/1.1\r\nContent-Length: {value}\r\n\r\n"),
        );
        reply.assert_refused(&format!("Content-Length: {value}"));
    }

    // The inversion, stated as the same pair of assertions with the outcome
    // flipped: the absurd value is no longer the one that gets served.
    let refused = speak_head_only(
        c.addr,
        &format!(
            "GET /healthz HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            u64::MAX
        ),
    );
    let one_larger = speak_head_only(
        c.addr,
        "GET /healthz HTTP/1.1\r\nContent-Length: 18446744073709551616\r\n\r\n",
    );
    assert_eq!(refused.status(), Some(400), "u64::MAX is refused");
    assert_eq!(
        one_larger.status(),
        Some(400),
        "u64::MAX + 1 is refused too — the inversion is closed"
    );

    // A `+` sign used to be accepted, because Rust's integer parser takes it
    // and the old framer asked nothing else; RFC 9112 §6.3 allows only DIGIT.
    // The head alone is now refused...
    let plus_head = format!(
        "POST /claim HTTP/1.1\r\nContent-Length: +{}\r\n\r\n",
        body.len()
    );
    let reply = speak_head_only(c.addr, &plus_head);
    assert_eq!(reply.status(), Some(400), "`+N` is not a length: {reply:?}");
    assert_eq!(reply.error().as_deref(), Some("malformed request"));
    // ...and so is the whole request that used to sell the seat. (Sent as one
    // burst, so the unread body may cost the response an RST — `assert_refused`
    // accepts either announced refusal; the ledger below is unambiguous.)
    let reply = c.send(format!("{plus_head}{body}").as_bytes());
    reply.assert_refused("`+N` as a Content-Length");
    assert!(reply.token().is_none(), "and it did not sell the seat");
    assert_eq!(
        c.on_disk().entries[&key(0)].status,
        Status::Unclaimed,
        "a non-DIGIT length must never reach the claim parser"
    );

    c.assert_still_serving("the content-length matrix");
}

/// **REGRESSION GUARD (repaired finding 3a) + still-open finding 3.** Two
/// `Content-Length` headers **used to** be accepted and the **first** one won
/// (the old framer used `.find`), where RFC 9112 §6.3 requires rejecting the
/// message unless every value is identical. That is the classic CL.CL desync:
/// a front end that takes the *last* value and a back end that takes the
/// *first* disagree about where the message ends. Both orders were asserted,
/// and `Content-Length: 0` followed by the real length read no body at all
/// while the real length followed by `0` sold a seat.
///
/// The framer now refuses the message outright when a second `Content-Length`
/// is present (`lib.rs:533`), in either order — asserted first below.
///
/// **The rest of this test still pins a defect.** Three shapes hide the header
/// from *this* parser while a lenient front end sees it, and those are
/// unchanged: the name is compared verbatim so `Content-Length : N` is
/// invisible, `str::lines` does not end a line at a bare CR, and an obs-fold
/// continuation is never unfolded. All three are still framed as bodyless
/// here, which is still one half of a desync — see finding 3.
///
/// Which value framed the message is read off the answer, not guessed:
/// `malformed request` means the framer refused, `malformed claim request`
/// means it accepted the message as bodyless and the claim parser saw nothing,
/// and a non-zero length would have blocked in the body loop until
/// `IO_TIMEOUT`. The latency assertions are the proof that none of them did.
#[test]
fn duplicate_and_hidden_content_lengths_are_all_refused() {
    let c = counter("dupclen", 1e6, 1e6);
    let body = claim_body(&wire(0), &fp(1));

    // REPAIRED: a second Content-Length is refused by the framer itself.
    for (what, head) in [
        (
            "two Content-Lengths, 0 first",
            format!(
                "POST /claim HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: {}\r\n\r\n",
                body.len()
            ),
        ),
        (
            "two Content-Lengths, the real length first",
            format!(
                "POST /claim HTTP/1.1\r\nContent-Length: {}\r\nContent-Length: 0\r\n\r\n",
                body.len()
            ),
        ),
        (
            "two identical Content-Lengths",
            "POST /claim HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n".to_string(),
        ),
    ] {
        let reply = speak_head_only(c.addr, &head);
        assert_eq!(reply.status(), Some(400), "{what}: {reply:?}");
        assert_eq!(
            reply.error().as_deref(),
            Some("malformed request"),
            "{what}: refused by the framer, so no parser downstream can \
             disagree with it about where this message ends"
        );
        assert!(
            reply.elapsed < Duration::from_secs(1),
            "{what}: the counter waited for a body it should not have seen ({:?})",
            reply.elapsed
        );
    }

    // REPAIRED as well: each of these used to hide the header from this
    // parser while showing it to a lenient one. Now every variant is
    // refused at the framing layer — whitespace before the colon, a bare CR
    // inside the header block, and obs-fold continuations are all framing
    // ambiguity, and ambiguity is answered with 400 rather than a guess.
    for (what, head) in [
        (
            "a space before the colon hides the header",
            format!(
                "POST /claim HTTP/1.1\r\nContent-Length : {}\r\n\r\n",
                body.len()
            ),
        ),
        (
            "`str::lines` does not end a line at a bare CR",
            format!(
                "POST /claim HTTP/1.1\r\nX-Pad: pad\rContent-Length: {}\r\n\r\n",
                body.len()
            ),
        ),
        (
            "an obs-fold continuation line (RFC 9112 §5.2 deprecates it)",
            format!(
                "POST /claim HTTP/1.1\r\nX-Pad: pad\r\n Content-Length: {}\r\n\r\n",
                body.len()
            ),
        ),
    ] {
        let reply = speak_head_only(c.addr, &head);
        assert_eq!(reply.status(), Some(400), "{what}: {reply:?}");
        assert_eq!(
            reply.error().as_deref(),
            Some("malformed request"),
            "{what}: refused by the framer — no parser downstream can \
             disagree about where this message ends"
        );
        assert!(
            reply.elapsed < Duration::from_secs(1),
            "{what}: the counter waited for a body it should not have seen ({:?})",
            reply.elapsed
        );
    }
    assert_eq!(
        c.on_disk().entries[&key(0)].status,
        Status::Unclaimed,
        "and no seat moved"
    );

    // The order that used to *sell*: first = the real length, so the trailing
    // declaration was ignored, the body was read whole and the claim was
    // honoured. Sent as one burst with the body attached, exactly as before —
    // the unread body may cost the response an RST, so `assert_refused` takes
    // either announced refusal and the ledger below is the unambiguous half.
    let reply = c.send(
        format!(
            "POST /claim HTTP/1.1\r\nContent-Length: {}\r\nContent-Length: 0\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    );
    reply.assert_refused("two Content-Lengths with the body attached");
    assert!(
        reply.token().is_none(),
        "a CL.CL message must never sell a seat: {reply:?}"
    );
    assert_eq!(
        c.on_disk().entries[&key(0)].status,
        Status::Unclaimed,
        "the seat the CL.CL desync used to sell is still unclaimed"
    );

    c.assert_still_serving("duplicate and hidden content lengths");
}

/// **REPAIRED (finding 3).** `Transfer-Encoding` is now refused at the
/// framing layer, exactly as RFC 9112 §6.1 requires of a server that cannot
/// decode it. Neither chunked alone nor the TE+CL pair can reach a handler,
/// so no front end can disagree with this server about where a message ends.
#[test]
fn transfer_encoding_is_refused_not_negotiated() {
    let c = counter("chunked", 1e6, 1e6);
    let body = claim_body(&wire(0), &fp(1));

    // Chunked alone: refused by the framer before any handler runs.
    let reply = speak_head_only(
        c.addr,
        "POST /claim HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
    );
    assert_eq!(reply.status(), Some(400));
    assert_eq!(
        reply.error().as_deref(),
        Some("malformed request"),
        "chunked framing is a framer refusal, not an empty claim"
    );
    assert!(
        reply.elapsed < Duration::from_secs(1),
        "it never waited for a single chunk: {:?}",
        reply.elapsed
    );
    assert_eq!(c.on_disk().entries[&key(0)].status, Status::Unclaimed);

    // With both headers present, the message is still refused: TE.CL is
    // precisely the disagreement RFC 9112 §6.3 exists to prevent.
    let both = format!(
        "POST /claim HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let reply = c.send(both.as_bytes());
    assert!(
        reply.status() == Some(400) || reply.token().is_none(),
        "TE+CL must never sell a seat: {reply:?}"
    );
    assert_eq!(
        c.on_disk().entries[&key(0)].status,
        Status::Unclaimed,
        "the seat the TE.CL pair used to sell is unclaimed"
    );

    c.assert_still_serving("chunked framing");
}

/// A `Content-Length` larger than the bytes actually sent holds **its own
/// connection** for the full `IO_TIMEOUT`: the body loop blocks in `read`
/// until the per-read timeout fires (`lib.rs:546-555`). This is the "does the
/// per-read bound work" test, and the answer is yes.
///
/// Under the sequential loop (former finding 1) those five seconds were five
/// seconds of the counter's *entire capacity*, bought for a 90-byte request.
/// They are now five seconds of one thread out of
/// `MAX_CONCURRENT_CONNECTIONS`, and every other customer is served meanwhile
/// — which is what [`one_silent_socket_no_longer_parks_any_paying_customer`]
/// measures directly.
#[test]
fn a_short_body_under_a_long_content_length_is_cut_at_the_io_timeout() {
    let c = counter("shortbody", 1e6, 1e6);
    let body = claim_body(&wire(0), &fp(1));

    let started = Instant::now();
    let mut s = TcpStream::connect(c.addr).expect("connect");
    s.set_read_timeout(Some(CLIENT_PATIENCE)).expect("timeout");
    // Announce the whole body, send half of it, then go quiet without closing:
    // an EOF would end the read immediately (`Ok(0)` at `lib.rs:551`), so the
    // hostile move is to stay connected and silent.
    write!(
        s,
        "POST /claim HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
        body.len() + 1_000,
        &body[..body.len() / 2]
    )
    .expect("write");
    let mut raw = Vec::new();
    let read = s.read_to_end(&mut raw);
    let elapsed = started.elapsed();
    let reply = Reply {
        raw: String::from_utf8_lossy(&raw).into_owned(),
        io_error: read.err().map(|e| e.kind()),
        elapsed,
    };

    reply.assert_refused("a body shorter than its announcement");
    assert!(
        elapsed >= IO_TIMEOUT - Duration::from_millis(500),
        "it was cut before the per-read timeout could have fired: {elapsed:?}"
    );
    assert!(
        elapsed < IO_TIMEOUT + REQUEST_DEADLINE,
        "the loop hung past every documented bound: {elapsed:?}"
    );
    // The half body never reached the claim parser and no seat moved.
    assert_eq!(c.on_disk().entries[&key(0)].status, Status::Unclaimed);
    c.assert_still_serving("a truncated body");
}

/// Bytes past the announced length are never a second request, and the
/// counter never reads them. Asserted twice: written in one burst (where the
/// unread tail makes the kernel reset the connection, so the answer may be
/// lost) and written after the response has been fully read (where the
/// outcome is unambiguous).
#[test]
fn bytes_beyond_the_announced_length_are_never_a_second_request() {
    let c = counter("overrun", 1e6, 1e6);
    let body = claim_body(&wire(0), &fp(1));

    // One burst: head + announced body + a whole extra request.
    let smuggled = format!(
        "POST /claim HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}GET /healthz HTTP/1.1\r\n\r\n",
        body.len()
    );
    let reply = c.send(smuggled.as_bytes());
    assert!(
        reply.responses() <= 1,
        "the smuggled request was answered too: {reply:?}"
    );
    if let Some(status) = reply.status() {
        assert_eq!(status, 200, "the first request was honoured: {reply:?}");
    }

    // The unambiguous version: claim code 1, read the whole answer, *then*
    // write a second request down the same socket.
    let body1 = claim_body(&wire(1), &fp(1));
    let mut s = TcpStream::connect(c.addr).expect("connect");
    s.set_read_timeout(Some(CLIENT_PATIENCE)).expect("timeout");
    s.write_all(&post_claim(&body1)).expect("write first");
    let mut raw = Vec::new();
    s.read_to_end(&mut raw)
        .expect("the first answer arrives whole");
    let first = String::from_utf8_lossy(&raw).into_owned();
    assert!(first.starts_with("HTTP/1.1 200"), "{first}");
    assert_eq!(first.matches("HTTP/1.1 ").count(), 1);
    assert_eq!(
        first
            .split_once("\r\n\r\n")
            .map(|(h, _)| h.contains("Connection: close")),
        Some(true),
        "every response announces the close"
    );

    // The socket is already closed by the server; a second request on it is
    // never answered.
    let _ = s.write_all(&get_request("/healthz"));
    let mut more = Vec::new();
    let _ = s.read_to_end(&mut more);
    assert!(
        more.is_empty(),
        "a second request on a used connection got an answer: {more:?}"
    );

    c.assert_still_serving("two smuggling attempts");
}

/// **DEFECT (finding 3, mitigation).** The `Content-Length` repair closed two
/// of the framing disagreements (an unreadable value and a duplicated header
/// are now refused outright), but three remain: a header this parser cannot
/// *see* — hidden behind a space before the colon, behind a bare CR, or behind
/// an obs-fold continuation — plus `Transfer-Encoding` being ignored rather
/// than 501'd. The reason none of those is a request-smuggling vulnerability
/// behind the documented reverse proxy is *only* that the loop never reuses a
/// connection: it writes `Connection: close`, drops the stream, and moves on.
/// Pinned as an explicit invariant, because the day someone adds keep-alive to
/// speed up the counter, finding 3's remaining disagreements become
/// exploitable in the same commit.
#[test]
fn no_connection_is_ever_reused_which_is_what_defuses_the_desync() {
    let c = counter("noalive", 1e6, 1e6);

    let mut s = TcpStream::connect(c.addr).expect("connect");
    s.set_read_timeout(Some(CLIENT_PATIENCE)).expect("timeout");
    // An explicit keep-alive request, which HTTP/1.1 makes the default anyway.
    s.write_all(b"GET /healthz HTTP/1.1\r\nConnection: keep-alive\r\n\r\n")
        .expect("write");
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).expect("answered");
    let text = String::from_utf8_lossy(&raw);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(
        text.contains("Connection: close"),
        "keep-alive was requested and refused: {text}"
    );
    // read_to_end returning means the server sent FIN: the connection is over
    // after exactly one exchange, regardless of what the client asked for.
    assert_eq!(text.matches("HTTP/1.1 ").count(), 1);

    c.assert_still_serving("a keep-alive request");
}

/// **DEFECT (finding 7).** The head is refused at `MAX_HEAD`, and the boundary
/// is exact — but it is reached one `read(2)` syscall per byte
/// (`lib.rs:509`), so refusing a flood costs 8 192 syscalls. Since the
/// concurrency repair those syscalls are spent on the flooder's own thread.
#[test]
fn a_header_flood_is_refused_at_max_head() {
    let c = counter("headflood", 1e6, 1e6);

    // Exactly MAX_HEAD bytes, ending in the terminator: still served.
    let prefix = "GET /healthz HTTP/1.1\r\nX-Pad: ";
    let pad = MAX_HEAD - prefix.len() - 4;
    let exact = format!("{prefix}{}\r\n\r\n", "P".repeat(pad));
    assert_eq!(exact.len(), MAX_HEAD);
    let reply = c.send(exact.as_bytes());
    assert_eq!(
        reply.status(),
        Some(200),
        "a head of exactly MAX_HEAD is served: {reply:?}"
    );

    // One byte more: refused.
    let over = format!("{prefix}{}\r\n\r\n", "P".repeat(pad + 1));
    assert_eq!(over.len(), MAX_HEAD + 1);
    c.send(over.as_bytes()).assert_refused("MAX_HEAD + 1");

    // A real flood: 16 KiB of many small headers, and 16 KiB of one enormous
    // one. Both refused, neither allocated beyond the cap.
    let many: String = (0..800)
        .map(|i| format!("X-Flood-{i:04}: {}\r\n", "f".repeat(10)))
        .collect();
    c.send(format!("GET /healthz HTTP/1.1\r\n{many}\r\n").as_bytes())
        .assert_refused("800 headers");
    let huge = format!(
        "GET /healthz HTTP/1.1\r\nX-Huge: {}\r\n\r\n",
        "H".repeat(16 * 1024)
    );
    c.send(huge.as_bytes()).assert_refused("a 16 KiB header");

    // A head that never terminates but stays under MAX_HEAD, with the client
    // closing its write side: EOF ends it immediately rather than costing a
    // timeout — the *polite* attacker is the cheap one for the server.
    let started = Instant::now();
    let mut s = TcpStream::connect(c.addr).expect("connect");
    s.set_read_timeout(Some(CLIENT_PATIENCE)).expect("timeout");
    s.write_all(b"GET /healthz HTTP/1.1\r\nX-Unterminated: yes\r\n")
        .expect("write");
    s.shutdown(Shutdown::Write).expect("half close");
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    assert!(
        started.elapsed() < IO_TIMEOUT,
        "an EOF should end the head immediately, not cost a timeout: {:?}",
        started.elapsed()
    );

    c.assert_still_serving("four header floods");
}

/// A `POST /claim` with no body, an empty body, and every shape of body that
/// is not a claim. All `400`, none of them a panic, none of them a seat.
#[test]
fn hostile_claim_bodies_are_refused_without_moving_the_ledger() {
    let c = counter("badbody", 1e6, 1e6);
    let good = claim_body(&wire(0), &fp(1));

    // No Content-Length header at all on a POST: framed as bodyless.
    let reply = c.send(b"POST /claim HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(reply.status(), Some(400));
    assert_eq!(reply.error().as_deref(), Some("malformed claim request"));

    let nesting_bomb = format!("{}1{}", "[".repeat(1_800), "]".repeat(1_800));
    let hostile: Vec<(&str, String)> = vec![
        ("empty", String::new()),
        ("whitespace", "   \n\t  ".into()),
        ("not json", "not json at all".into()),
        ("json null", "null".into()),
        ("json array", "[1,2,3]".into()),
        ("empty object", "{}".into()),
        (
            "wrong schema",
            claim_body(&wire(0), &fp(1)).replace("v1", "v2"),
        ),
        (
            "uppercase hex",
            good.replace(&wire(0), &wire(0).to_uppercase()),
        ),
        ("short hash", claim_body("abc", &fp(1))),
        ("64 non-hex chars", claim_body(&"z".repeat(64), &fp(1))),
        ("machine not a hash", claim_body(&wire(0), "my-laptop")),
        (
            "null bytes",
            "{\"schema\":\"\0\",\"code_hash\":\"\0\"}".to_string(),
        ),
        // A 1 800-deep nesting bomb inside MAX_BODY: serde_json's recursion
        // limit refuses it long before the stack notices.
        ("a nesting bomb", nesting_bomb),
        // Exactly MAX_BODY of junk — the largest body the parser will read.
        ("MAX_BODY of junk", "j".repeat(MAX_BODY)),
    ];
    for (what, body) in &hostile {
        assert!(body.len() <= MAX_BODY, "{what} is not a body-sized attack");
        let reply = c.send(&post_claim(body));
        assert_eq!(reply.status(), Some(400), "{what}: {reply:?}");
        assert_eq!(
            reply.error().as_deref(),
            Some("malformed claim request"),
            "{what} reached the claim parser and was refused there"
        );
    }

    // Invalid UTF-8 in the body is replaced, not rejected — and the resulting
    // JSON is not a claim.
    let mut request = Vec::from(&b"POST /claim HTTP/1.1\r\nContent-Length: 8\r\n\r\n"[..]);
    request.extend_from_slice(&[0xff, 0xfe, 0x00, 0x80, 0xc3, 0x28, 0xed, 0xa0]);
    let reply = c.send(&request);
    assert_eq!(reply.status(), Some(400), "invalid UTF-8 body: {reply:?}");

    // Not one of the fifteen touched the ledger.
    let ledger = c.on_disk();
    for i in 0..CODES {
        assert_eq!(
            ledger.entries[&key(i)].status,
            Status::Unclaimed,
            "code {i} moved on a malformed request"
        );
        assert!(ledger.entries[&key(i)].machine.is_none());
    }
    c.assert_still_serving("fifteen hostile claim bodies");
}

// ═════════════════════════════════════════════════════════════════════
// §2  Availability: what one connection costs everybody else
// ═════════════════════════════════════════════════════════════════════

/// **REGRESSION GUARD (repaired finding 1).** The cheapest denial the product
/// ever had: complete a TCP handshake and send **nothing**. `read_request`
/// blocks in `read` until `IO_TIMEOUT` (`lib.rs:505-513`), and because the
/// loop was strictly sequential that used to be five seconds during which
/// *every* paying customer's claim waited. Zero bytes sent, zero rate-limit
/// tokens consumed (the bucket is only reached by a request that parsed), zero
/// completions needed — and the cost was linear in attacker sockets.
///
/// `serve` now runs one thread per connection (`lib.rs:430-483`), so the
/// silent socket pays its own `IO_TIMEOUT` alone. The measurement is unchanged
/// — the honest client's own end-to-end latency, not the server's internals —
/// and it is printed, because the number *is* the finding: a `POST /claim`
/// issued 250 ms behind a silent socket used to take 5.0 s and must now take
/// milliseconds. Both halves are asserted: the honest client is served
/// promptly, and the attacker's socket has still been answered nothing at that
/// instant, i.e. it is parked on its own timeout rather than on everyone's.
#[test]
fn one_silent_socket_no_longer_parks_any_paying_customer() {
    let c = counter("silent", 1e6, 1e6);

    // Baseline: an unobstructed request.
    let quick = c.healthz();
    assert_eq!(quick.status(), Some(200));
    assert!(
        quick.elapsed < PROMPT,
        "baseline latency should be sub-second: {:?}",
        quick.elapsed
    );

    // The attack: one socket, zero bytes, held open.
    let mut idle = TcpStream::connect(c.addr).expect("connect");
    // Give the loop time to accept it and block on the first read.
    std::thread::sleep(Duration::from_millis(250));

    let honest = c.claim(0, 1);
    assert_eq!(honest.status(), Some(200), "{honest:?}");
    println!(
        "[http-abuse] 1 silent socket, 0 bytes sent -> honest claim answered in \
         {:?} (was IO_TIMEOUT = {IO_TIMEOUT:?} under the sequential loop)",
        honest.elapsed
    );
    assert!(
        honest.elapsed < PROMPT,
        "a silent socket must cost only itself; the honest client waited {:?}, \
         which is the parked-queue defect (it used to be IO_TIMEOUT = {IO_TIMEOUT:?})",
        honest.elapsed
    );

    // ...and the attacker is still sitting there with nothing back, paying its
    // own IO_TIMEOUT on its own thread. A read that times out (or would block)
    // proves the connection is still open and still unanswered; EOF or bytes
    // would mean it had already been dealt with, and the measurement above
    // would then not be the one described.
    idle.set_read_timeout(Some(Duration::from_millis(50)))
        .expect("timeout");
    let mut peek = [0u8; 1];
    let parked = idle.read(&mut peek);
    assert!(
        matches!(
            &parked,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut
        ),
        "the silent socket should still be parked and unanswered while the \
         honest client is served, got {parked:?}"
    );
    drop(idle);

    // The seat really was sold — promptly, and with no corruption anywhere.
    let token = honest.token().expect("a token was issued");
    let payload = verified_payload(&token);
    assert_eq!(payload["machine"], serde_json::json!(fp(1)));
    assert_eq!(c.on_disk().entries[&key(0)].status, Status::Claimed);
    c.assert_still_serving("a silent socket");
}

/// **REGRESSION GUARD (repaired finding 1).** The documented defence — "a
/// drip-feeding client cannot park the queue" — used to be only half true. The
/// `REQUEST_DEADLINE` did fire: a client sending one byte every 20 ms is cut
/// after ten seconds instead of the hours the per-read timeout alone would
/// allow. But it was cut *after* ten seconds of parking the only worker there
/// was, so the queue **had** been parked; the deadline merely bounded each
/// parking, and a second dripper started the clock again.
///
/// Both halves are now asserted, measured exactly as before:
/// * the dripper is still cut at `REQUEST_DEADLINE` and never served — the
///   per-connection bound still works and is still the thing that stops a
///   drip from lasting hours;
/// * and another client's correct claim is answered in **milliseconds** while
///   the dripper is still dripping, not after the deadline fires. The honest
///   client's latency is printed, because that number is the whole finding:
///   it used to be 10.0 s.
#[test]
fn a_slowloris_is_cut_at_the_deadline_and_no_longer_parks_the_queue() {
    let c = counter("slowloris", 1e6, 1e6);

    let addr = c.addr;
    let drip = std::thread::spawn(move || {
        let mut s = TcpStream::connect(addr).expect("connect");
        s.set_write_timeout(Some(CLIENT_PATIENCE)).expect("timeout");
        let started = Instant::now();
        let mut sent = 0usize;
        // One byte every 20 ms. Each read on the server side succeeds, so the
        // per-read timeout can never fire; only the whole-request deadline
        // can end this. 'X' never completes a head.
        for _ in 0..900 {
            if s.write_all(b"X").is_err() {
                break;
            }
            sent += 1;
            if started.elapsed() > REQUEST_DEADLINE + Duration::from_secs(5) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
        (
            started.elapsed(),
            sent,
            String::from_utf8_lossy(&raw).into_owned(),
        )
    });

    // Let the loop accept the dripper and start reading.
    std::thread::sleep(Duration::from_millis(250));

    // The key availability assertion: another client's correct claim is
    // answered *while the dripper is still dripping*, with a real seat.
    let honest = c.claim(0, 1);
    assert_eq!(honest.status(), Some(200), "{honest:?}");
    let payload = verified_payload(&honest.token().expect("token"));
    assert_eq!(payload["machine"], serde_json::json!(fp(1)));
    assert_eq!(payload["licensee"], serde_json::json!("Customer 00"));

    // ...and it did not wait for the deadline, which is the repair.
    println!(
        "[http-abuse] 1 slowloris (1 byte / 20 ms) -> honest claim answered in \
         {:?} (was REQUEST_DEADLINE = {REQUEST_DEADLINE:?} under the sequential loop)",
        honest.elapsed
    );
    assert!(
        honest.elapsed < PROMPT,
        "the dripper parked the queue again: the honest client waited {:?}, \
         and the drip was still running (it used to wait REQUEST_DEADLINE = \
         {REQUEST_DEADLINE:?})",
        honest.elapsed
    );

    let (drip_elapsed, sent, answer) = drip.join().expect("drip thread");
    assert!(
        drip_elapsed >= REQUEST_DEADLINE - Duration::from_secs(2),
        "the dripper was cut too early to be the deadline: {drip_elapsed:?}"
    );
    assert!(
        drip_elapsed < REQUEST_DEADLINE + IO_TIMEOUT + Duration::from_secs(5),
        "the dripper was never cut: {drip_elapsed:?}"
    );
    assert!(
        sent < MAX_HEAD,
        "the dripper hit MAX_HEAD instead of the deadline ({sent} bytes) — \
         this test would then be measuring the wrong bound"
    );
    assert!(
        answer.is_empty() || answer.starts_with("HTTP/1.1 400"),
        "an unfinished request is refused, never served: {answer:?}"
    );

    c.assert_still_serving("a slowloris");
}

/// **REGRESSION GUARD (repaired finding 1, exhaustion half).** The denial used
/// to be linear in attacker sockets, and the attacker paid nothing per socket:
/// three idle connections cost fifteen seconds of total outage, so the default
/// 128-deep accept backlog extrapolated to ~10 minutes per round from a single
/// IP with zero payload, forever.
///
/// Same three idle sockets, same measurement, opposite bound: the honest
/// client is served promptly and the extrapolation is now ~0. This test used
/// to be `#[ignore]`d because running it meant 16 s of deliberate outage;
/// there is no outage left to schedule around, so it runs with the rest.
#[test]
fn idle_attacker_sockets_no_longer_add_up_to_an_outage() {
    let c = counter("linear", 1e6, 1e6);

    let mut idle = Vec::new();
    for _ in 0..3 {
        idle.push(TcpStream::connect(c.addr).expect("connect"));
        // Connect one at a time so the accept order is the connect order.
        std::thread::sleep(Duration::from_millis(100));
    }
    let honest = c.healthz();
    assert_eq!(honest.status(), Some(200));
    let per_socket = honest.elapsed.as_secs_f64() / 3.0;
    println!(
        "[http-abuse] 3 idle sockets, 0 bytes sent -> honest client waited {:?} \
         ({:.2} ms per socket); 128-deep backlog extrapolates to {:.2} seconds \
         (was 5 s per socket, i.e. ~10 minutes, under the sequential loop)",
        honest.elapsed,
        per_socket * 1_000.0,
        per_socket * 128.0
    );
    assert!(
        honest.elapsed < PROMPT,
        "three idle sockets cost the honest client {:?} — the denial is linear \
         in attacker sockets again (it used to be {:?})",
        honest.elapsed,
        IO_TIMEOUT * 3
    );
    drop(idle);
    c.assert_still_serving("three idle sockets");
}

/// **REGRESSION GUARD (repaired findings 1 and 8).** One thread per
/// connection is not free either, so the repair came with a cap:
/// `MAX_CONCURRENT_CONNECTIONS` = 64 in flight (`lib.rs:60`), and past it the
/// counter answers an announced `503` instead of queueing silently or
/// spawning without limit. That ceiling is the reason unbounded concurrency
/// is not simply a different exhaustion vector, so it is pinned here: 64
/// idle sockets are accepted, the 65th caller is **told** the counter is
/// busy within milliseconds rather than being parked, and capacity returns
/// on its own as soon as the idle sockets go away.
///
/// Both former warts on the shed path are fixed and pinned in their
/// corrected form (finding 8):
/// * the refusal is written and the connection's input drained briefly — off
///   the accept loop — so a caller that sent request bytes still receives
///   its announced JSON instead of an RST-truncated reply;
/// * the status line reads `503 Service Unavailable`: load shedding is
///   named as what it is.
#[test]
fn past_the_concurrency_cap_the_counter_sheds_load_with_an_announced_503() {
    let c = counter("shed", 1e6, 1e6);

    // Fill every slot with sockets that will never send a byte.
    let idle: Vec<TcpStream> = (0..MAX_CONCURRENT_CONNECTIONS)
        .map(|_| TcpStream::connect(c.addr).expect("connect"))
        .collect();
    assert_eq!(idle.len(), 64, "the shipped cap, mirrored from the server");

    // Poll a real request until the accept loop has taken all 64 and the cap
    // is in force. A clean 200 means there was still a slot; anything else
    // means the caller was shed. Every probe must be answered promptly
    // whichever side of the cap it lands on — being parked is the one outcome
    // that is never allowed, and it is the outcome the repair removed.
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut capped = false;
    while !capped && Instant::now() < deadline {
        let probe = c.healthz();
        assert!(
            probe.elapsed < PROMPT,
            "a probe at the cap was parked for {:?} instead of being answered",
            probe.elapsed
        );
        match probe.status() {
            Some(200) => std::thread::sleep(Duration::from_millis(50)),
            // 503, or a status line the RST truncated away — either way this
            // caller was shed, not served and not parked.
            _ => {
                assert!(
                    probe.body() != r#"{"ok":true}"#,
                    "a shed caller must never be served: {probe:?}"
                );
                capped = true;
            }
        }
    }
    assert!(
        capped,
        "64 idle sockets must fill the cap and shed the 65th caller"
    );

    // The announced refusal, read whole. `speak` with an empty request sends
    // nothing, so there is nothing unread for the close to turn into an RST.
    let shed = speak(c.addr, b"");
    assert!(
        shed.elapsed < PROMPT,
        "the shed answer must be immediate: {:?}",
        shed.elapsed
    );
    assert_eq!(shed.status(), Some(503), "{shed:?}");
    assert_eq!(
        shed.error().as_deref(),
        Some("counter busy — try again shortly"),
        "load shedding is announced, not silent: {shed:?}"
    );
    // REPAIRED (finding 8): the reason phrase names the outcome — load
    // shedding, not a crash.
    assert!(
        shed.raw.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
        "the 503 reason phrase must say Service Unavailable: {:?}",
        shed.raw
    );

    // Capacity comes back on its own: the idle sockets EOF, their threads
    // finish, and the slots are released.
    drop(idle);
    let deadline = Instant::now() + IO_TIMEOUT + Duration::from_secs(5);
    while Instant::now() < deadline && c.healthz().status() != Some(200) {
        std::thread::sleep(Duration::from_millis(50));
    }
    c.assert_still_serving("64 simultaneous idle sockets");
}

/// Abrupt clients — connect and reset, half-close mid-head, reset after the
/// head — cost the counter nothing and leak nothing. 64 of them in a row do
/// not wedge the loop, exhaust descriptors, or corrupt the ledger.
#[test]
fn sixty_four_abrupt_clients_do_not_wedge_the_loop() {
    let c = counter("abrupt", 1e6, 1e6);

    for i in 0..64 {
        let mut s = TcpStream::connect(c.addr).expect("connect");
        match i % 4 {
            0 => {} // connect and drop
            1 => {
                let _ = s.write_all(b"GET /heal");
            }
            2 => {
                let _ = s.write_all(b"POST /claim HTTP/1.1\r\nContent-Length: 4096\r\n\r\nxx");
                let _ = s.shutdown(Shutdown::Write);
            }
            _ => {
                let _ = s.write_all(b"GET /healthz HTTP/1.1\r\n\r\n");
                let _ = s.shutdown(Shutdown::Both);
            }
        }
        drop(s);
    }

    // All 64 are EOF-terminated, so none of them cost a timeout: the whole
    // burst must clear in well under one IO_TIMEOUT.
    let after = c.healthz();
    assert_eq!(after.status(), Some(200), "{after:?}");
    assert!(
        after.elapsed < IO_TIMEOUT,
        "the abrupt burst parked the loop: {:?}",
        after.elapsed
    );
    assert_eq!(c.on_disk().entries.len(), CODES as usize);
    c.assert_still_serving("64 abrupt clients");
}

// ═════════════════════════════════════════════════════════════════════
// §3  The method x path matrix
// ═════════════════════════════════════════════════════════════════════

/// The documented status codes, asserted exhaustively over
/// `{GET, POST, PUT, DELETE, HEAD} x {/healthz, //claim, /claim/, /CLAIM,
/// /nope}` plus `/claim` itself.
///
/// **DEFECT (finding 4).** The match is on `(method, path)` with method
/// first (`lib.rs:325-332`), so:
/// * `POST /healthz` is `404` although the path exists and only the method is
///   wrong — RFC 9110 §15.5.6 wants `405`;
/// * `GET /claim` is `404` for the same reason, on the endpoint the entire
///   product is built around;
/// * `DELETE /nope` is `405` although the path does not exist — the pairing is
///   exactly inverted;
/// * `HEAD` is `405` everywhere, so the health check every load balancer sends
///   first cannot reach `/healthz`.
///
/// Path matching is exact and case-sensitive, which is correct: `//claim`,
/// `/claim/` and `/CLAIM` are all `404`, so no normalization bug can smuggle a
/// claim through a front end's path rewriting.
/// **REPAIRED (finding 5).** The routing matrix is path-first now:
///
/// * an unknown path is `404` for every method — a prober no longer learns
///   which methods exist from a path that does not;
/// * `/healthz` and `/claim` answer `405` with the mandatory `Allow` header
///   for any method they do not serve.
///
/// Path matching is exact and case-sensitive, which is correct: `//claim`,
/// `/claim/` and `/CLAIM` are all `404`, so no normalization bug can smuggle a
/// claim through a front end's path rewriting.
#[test]
fn method_path_matrix_is_exactly_the_documented_statuses() {
    let c = counter("matrix", 1e6, 1e6);

    const PATHS: [&str; 5] = ["/healthz", "//claim", "/claim/", "/CLAIM", "/nope"];
    for method in ["GET", "POST", "PUT", "DELETE", "HEAD"] {
        for path in PATHS {
            let expect = match (method, path) {
                ("GET", "/healthz") | ("HEAD", "/healthz") => 200,
                // Known endpoint, wrong method.
                (_, "/healthz") => 405,
                // Unknown paths: 404 for every method, whatever it is.
                _ => 404,
            };
            let reply = c.send(format!("{method} {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes());
            assert_eq!(reply.status(), Some(expect), "{method} {path} -> {reply:?}");
        }
    }

    // /claim itself: only POST routes. Every other method is a 405 that
    // names what is allowed, and the unknown paths above stay 404 even for
    // the exotic verbs.
    for (method, expect) in [
        ("GET", 405u16),
        ("PUT", 405),
        ("DELETE", 405),
        ("HEAD", 405),
        ("PATCH", 405),
        ("OPTIONS", 405),
        ("TRACE", 405),
        ("CONNECT", 405),
    ] {
        let reply = c.send(format!("{method} /claim HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes());
        assert_eq!(reply.status(), Some(expect), "{method} /claim -> {reply:?}");
        assert_eq!(
            reply.header("allow"),
            Some("GET, POST"),
            "{method} /claim must name the allowed methods"
        );
    }

    // A query string is part of the opaque target, so it 404s. Fail-closed,
    // but it means `/claim?retry=1` is not the claim endpoint.
    let reply = c.send(b"POST /claim?retry=1 HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(reply.status(), Some(404), "{reply:?}");

    // Every announced status carries the documented JSON error shape, and the
    // 200 carries the documented health body.
    assert_eq!(c.healthz().body(), r#"{"ok":true}"#);
    let reply = c.send(&get_request("/nope"));
    assert_eq!(reply.error().as_deref(), Some("no such endpoint"));
    let reply = c.send(b"DELETE /nope HTTP/1.1\r\n\r\n");
    assert_eq!(reply.error().as_deref(), Some("no such endpoint"));

    c.assert_still_serving("the 34-cell method/path matrix");
}

/// **REPAIRED (finding 4).** Both former violations are fixed and pinned in
/// their corrected form:
///
/// * a `HEAD` request is answered as `GET` with the body suppressed —
///   RFC 9110 §9.3.2 — while `Content-Length` still announces the entity a
///   `GET` would have returned;
/// * every `405` carries the `Allow` header RFC 9110 §15.5.6 requires.
#[test]
fn head_is_bodyless_and_every_405_names_allow() {
    let c = counter("headbody", 1e6, 1e6);

    let reply = c.send(b"HEAD /healthz HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(reply.status(), Some(200), "HEAD reaches the health check");
    assert_eq!(reply.body(), "", "a HEAD response must carry no body");
    assert_eq!(
        reply
            .header("content-length")
            .and_then(|v| v.parse::<usize>().ok()),
        Some(r#"{"ok":true}"#.len()),
        "the length header still describes what GET would return"
    );

    for method in ["PUT", "DELETE", "OPTIONS"] {
        let reply = c.send(format!("{method} /healthz HTTP/1.1\r\n\r\n").as_bytes());
        assert_eq!(reply.status(), Some(405));
        assert_eq!(
            reply.header("allow"),
            Some("GET, POST"),
            "{method}: a 405 must name the allowed methods"
        );
    }

    // What the responses do carry: a fixed content type, a length, and the
    // close. Nothing from the request is echoed anywhere — there is no
    // response-splitting surface even with CR/LF-looking paths.
    let reply = c.send(b"GET /nope%0d%0aX-Injected:+yes HTTP/1.1\r\n\r\n");
    assert_eq!(reply.status(), Some(404));
    assert_eq!(reply.header("x-injected"), None);
    assert_eq!(reply.header("content-type"), Some("application/json"));
    assert!(!reply.body().contains("Injected"), "{reply:?}");

    c.assert_still_serving("HEAD and 405 shapes");
}

// ═════════════════════════════════════════════════════════════════════
// §4  The rate limiter
// ═════════════════════════════════════════════════════════════════════

/// The one thing the limiter must never do: burn a seat. `handle_claim`
/// consults the bucket at `lib.rs:335`, before the body is parsed and before
/// the vault is touched, so a `429` cannot move the ledger — and the code
/// claims cleanly once the bucket refills.
///
/// The refill is measured against the bucket's own rate (0.5/s, the shipped
/// value), not against a guess: one token every two seconds.
#[test]
fn a_rate_limited_claim_never_burns_the_seat_it_refused() {
    let c = counter("nonburn", 1.0, SHIPPED_PER_SECOND);

    // The single token buys one request; spend it on an unrelated code.
    let first = c.claim(1, 9);
    assert_eq!(first.status(), Some(200), "{first:?}");

    // The victim's correct claim now hits an empty bucket, three times.
    for attempt in 0..3 {
        let refused = c.claim(0, 1);
        assert_eq!(
            refused.status(),
            Some(429),
            "attempt {attempt}: {refused:?}"
        );
        assert_eq!(
            refused.error().as_deref(),
            Some("rate limited — try again shortly")
        );
        assert!(refused.token().is_none(), "a 429 never carries a token");
    }

    // The seat is untouched: not claimed, not bound, not expiring.
    let entry = c.on_disk().entries[&key(0)].clone();
    assert_eq!(entry.status, Status::Unclaimed, "a 429 burned the seat");
    assert!(entry.machine.is_none());
    assert!(entry.claimed_unix.is_none());
    assert!(entry.exp_unix.is_none());

    // One token refills in 1/0.5 = 2 s. After that the same code claims, and
    // the token binds the machine that was refused.
    std::thread::sleep(Duration::from_millis(2_100));
    let ok = c.claim(0, 1);
    assert_eq!(ok.status(), Some(200), "the refilled bucket serves: {ok:?}");
    let payload = verified_payload(&ok.token().expect("token"));
    assert_eq!(payload["machine"], serde_json::json!(fp(1)));
    assert_eq!(payload["licensee"], serde_json::json!("Customer 00"));
    assert_eq!(c.on_disk().entries[&key(0)].status, Status::Claimed);

    c.assert_still_serving("a rate-limit round trip");
}

/// **REPAIRED (finding 2).** The bucket used to be charged *before* the
/// request was understood, so ten junk requests emptied the shipped burst and
/// every paying customer got `429` — a ~12-bytes-per-second total lockout
/// while `/healthz` stayed green. Now the bucket guards the expensive,
/// brute-force-relevant work: only requests **shaped like claims** spend it.
/// Junk is refused as malformed without touching the shared budget, so the
/// same attack no longer reaches a single customer.
#[test]
fn ten_junk_requests_no_longer_lock_out_any_paying_customer() {
    let c = counter("lockout", SHIPPED_BURST, SHIPPED_PER_SECOND);

    // The cheapest request that used to charge a token: no headers, no body.
    let junk = b"POST /claim HTTP/1.1\r\n\r\n";
    assert_eq!(junk.len(), 24, "the attacker's whole cost, in bytes");

    let started = Instant::now();
    for i in 0..(SHIPPED_BURST as u32 + 5) {
        let reply = c.send(junk);
        assert_eq!(
            reply.status(),
            Some(400),
            "junk request {i} must be refused as malformed: {reply:?}"
        );
        assert_eq!(reply.error().as_deref(), Some("malformed claim request"));
    }
    let drain = started.elapsed();
    assert!(
        drain < Duration::from_secs(2),
        "refusing junk took {drain:?} — this measurement is not the one described"
    );

    // The bucket was never touched by any of that junk, so a paying
    // customer's correct claim goes straight through.
    let customer = c.claim(0, 1);
    assert_eq!(
        customer.status(),
        Some(200),
        "a paying customer's correct claim is served despite the junk flood: {customer:?}"
    );
    assert!(customer.token().is_some(), "the sale completed");
    assert_eq!(c.on_disk().entries[&key(0)].status, Status::Claimed);

    // /healthz stays green throughout, as before.
    for _ in 0..20 {
        assert_eq!(c.healthz().status(), Some(200));
    }

    c.assert_still_serving("a junk flood");
}

// ═════════════════════════════════════════════════════════════════════
// §5  Concurrency: 32 clients racing one seat
// ═════════════════════════════════════════════════════════════════════

/// 32 threads race the same code from 32 **different** machines. Exactly one
/// `200`, 31 `410`s, one machine fingerprint in the ledger, and the issued
/// token binds that machine and nobody else.
///
/// This is the single-seat property under the only concurrency the product can
/// actually experience. It used to hold because the accept loop was
/// sequential, so the 32 claims could not overlap at all; since the
/// concurrency repair they genuinely do overlap, and it holds because the
/// ledger is shared behind a mutex (`lib.rs:431`, `468`), the flip is
/// persisted before the token is disclosed, and the ledger is the arbiter.
#[test]
fn thirty_two_machines_race_one_code_and_exactly_one_seat_is_sold() {
    let c = counter("race32", 1e6, 1e6);

    let mut results: Vec<(u32, u16, Option<String>)> = Vec::new();
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..32u32)
            .map(|m| {
                let c = &c;
                scope.spawn(move || {
                    let reply = c.claim(0, m);
                    (m, reply.status().unwrap_or(0), reply.token())
                })
            })
            .collect();
        for h in handles {
            results.push(h.join().expect("client thread"));
        }
    });

    let winners: Vec<&(u32, u16, Option<String>)> =
        results.iter().filter(|(_, s, _)| *s == 200).collect();
    let refused = results.iter().filter(|(_, s, _)| *s == 410).count();
    assert_eq!(
        winners.len(),
        1,
        "exactly one machine may hold the seat, got {winners:?}"
    );
    assert_eq!(refused, 31, "everyone else gets the single-seat refusal");
    assert!(
        results.iter().all(|(_, s, _)| *s == 200 || *s == 410),
        "no third outcome exists: {results:?}"
    );

    // No two machines got a token.
    let tokens: Vec<&String> = results.iter().filter_map(|(_, _, t)| t.as_ref()).collect();
    assert_eq!(tokens.len(), 1, "a second token was issued: {tokens:?}");

    // The ledger and the token agree on who owns the seat.
    let (winner, _, token) = winners[0];
    let entry = c.on_disk().entries[&key(0)].clone();
    assert_eq!(entry.status, Status::Claimed);
    assert_eq!(entry.machine.as_deref(), Some(fp(*winner).as_str()));
    let payload = verified_payload(token.as_ref().expect("the winner's token"));
    assert_eq!(payload["machine"], serde_json::json!(fp(*winner)));
    assert_eq!(
        payload["exp"].as_u64(),
        entry.exp_unix,
        "the signed expiry is the one the ledger recorded"
    );
    assert_eq!(
        entry.exp_unix.unwrap() - entry.claimed_unix.unwrap(),
        365 * DAY,
        "an annual seat"
    );

    // Every other seat is untouched.
    let ledger = c.on_disk();
    for i in 1..CODES {
        assert_eq!(ledger.entries[&key(i)].status, Status::Unclaimed);
    }
    c.assert_still_serving("a 32-way race");
}

/// 32 threads race the same code from the **same** machine — the lost-token
/// recovery path under concurrency. All 32 succeed, and all 32 tokens are
/// **byte-identical**, because the expiry is fixed at the first claim and
/// re-issues reuse it verbatim (`lib.rs:195`) and ed25519 signing is
/// deterministic. There is never any ambiguity about which of a customer's
/// tokens is the real one.
#[test]
fn thirty_two_reclaims_from_one_machine_yield_one_identical_token() {
    let c = counter("reissue32", 1e6, 1e6);

    let mut tokens: Vec<String> = Vec::new();
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..32u32)
            .map(|_| {
                let c = &c;
                scope.spawn(move || {
                    let reply = c.claim(0, 7);
                    (reply.status().unwrap_or(0), reply.token())
                })
            })
            .collect();
        for h in handles {
            let (status, token) = h.join().expect("client thread");
            assert_eq!(status, 200, "a same-machine re-claim must always issue");
            tokens.push(token.expect("every 200 carries a token"));
        }
    });

    assert_eq!(tokens.len(), 32);
    assert!(
        tokens.windows(2).all(|w| w[0] == w[1]),
        "32 concurrent re-issues produced more than one distinct token"
    );
    let payload = verified_payload(&tokens[0]);
    assert_eq!(payload["machine"], serde_json::json!(fp(7)));

    // One machine, one expiry, no extension anywhere in the race.
    let entry = c.on_disk().entries[&key(0)].clone();
    assert_eq!(entry.machine.as_deref(), Some(fp(7).as_str()));
    assert_eq!(payload["exp"].as_u64(), entry.exp_unix);

    // And a 33rd claim from a different machine is still refused.
    let intruder = c.claim(0, 8);
    assert_eq!(intruder.status(), Some(410), "{intruder:?}");
    assert_eq!(
        c.on_disk().entries[&key(0)].machine.as_deref(),
        Some(fp(7).as_str())
    );
    c.assert_still_serving("32 concurrent re-issues");
}

// ═════════════════════════════════════════════════════════════════════
// §6  The loop's state model: what a running counter does to its ledger
// ═════════════════════════════════════════════════════════════════════

/// **REGRESSION GUARD (repaired finding 5).** `serve` used to take the
/// `Counter` by value and never re-read `vault.json`, while every successful
/// claim wrote the in-memory ledger over the file. The runbook tells vendors
/// to manage seats with `ccos-license-admin --vault <the same file>` *while
/// the daemon runs*, and the CLI prints "revoked … — the counter now refuses
/// this code" (`bin/ccos-license-admin.rs:322`).
///
/// Against a running counter all three of those used to be false, and this
/// test measured it end to end over HTTP: a seat **sold** mid-run was
/// unclaimable (`404`), a code **revoked** mid-run was still **sold** (`200`
/// with a valid signed token), and that claim then **erased** both edits from
/// the file — the revocation became `claimed` and the newly sold seat
/// disappeared entirely. Money moved the wrong way in both directions and the
/// ledger ended up disagreeing with what the vendor had been told happened.
///
/// `Counter::refresh_vault` (`lib.rs:296`) now re-reads the file at the start
/// of every claim whenever its fingerprint no longer matches what this process
/// last read or wrote. Same edits, same requests, opposite outcomes:
/// 1. the seat sold while the daemon ran **is** claimable, with a token that
///    verifies and carries the licensee the vendor typed at the CLI;
/// 2. the code revoked while the daemon ran is **refused** (`410`), and no
///    token is issued;
/// 3. both edits **survive** the write-back that used to destroy them.
#[test]
fn a_running_counter_now_adopts_every_vault_edit_made_while_it_ran() {
    let c = counter("liveedit", 1e6, 1e6);

    // The vendor, at the CLI, exactly as the runbook documents: revoke a bad
    // code and sell a new seat, both against the live vault file.
    let mut edited = c.on_disk();
    edited
        .entries
        .get_mut(&key(1))
        .expect("code 1 exists")
        .status = Status::Revoked;
    edited
        .entries
        .insert(key(SOLD_LATE), unclaimed("Customer Sold While Running"));
    edited
        .save(&c.vault_path)
        .expect("the CLI writes the vault");
    // The file now says what the vendor believes.
    let believed = c.on_disk();
    assert_eq!(believed.entries[&key(1)].status, Status::Revoked);
    assert!(believed.entries.contains_key(&key(SOLD_LATE)));

    // 1. The seat sold while the daemon ran is a real seat.
    let sold_late = c.claim(SOLD_LATE, 3);
    assert_eq!(
        sold_late.status(),
        Some(200),
        "a seat sold against a running counter must be claimable: {sold_late:?}"
    );
    let payload = verified_payload(&sold_late.token().expect("token"));
    assert_eq!(payload["machine"], serde_json::json!(fp(3)));
    assert_eq!(
        payload["licensee"],
        serde_json::json!("Customer Sold While Running"),
        "the token carries what the vendor typed at the CLI, not the startup snapshot"
    );

    // 2. The revoked code is refused — which is exactly what the CLI promised
    //    the vendor when it printed "the counter now refuses this code".
    let revoked = c.claim(1, 4);
    assert_eq!(
        revoked.status(),
        Some(410),
        "a code revoked mid-run must be refused, not sold: {revoked:?}"
    );
    assert_eq!(
        revoked.error().as_deref(),
        Some("this code was revoked by the vendor")
    );
    assert!(revoked.token().is_none(), "a revoked code issues nothing");

    // 3. Neither edit was erased by the claim that ran after it.
    let after = c.on_disk();
    assert_eq!(
        after.entries[&key(1)].status,
        Status::Revoked,
        "the revocation survived the next claim's write-back"
    );
    assert_eq!(
        after.entries[&key(SOLD_LATE)].status,
        Status::Claimed,
        "the seat sold while the daemon ran was honoured and recorded"
    );
    assert_eq!(
        after.entries[&key(SOLD_LATE)].machine.as_deref(),
        Some(fp(3).as_str())
    );
    assert_eq!(
        after.entries.len(),
        CODES as usize + 1,
        "the ledger is the vendor's file plus the seat that was just sold, \
         not the daemon's startup snapshot"
    );

    c.assert_still_serving("a live vault edit");
}

/// **REGRESSION GUARD (repaired finding 5) + the mechanism from the other
/// side.** The counter's ledger is memory and the file is a projection of it,
/// rewritten in full on every successful claim — including an idempotent
/// re-issue that changes nothing. That much is unchanged, and it is why every
/// repeat claim costs a full serialize + `fsync` of every seat the vendor has
/// ever sold: the write amplification measured at scale in
/// `stress_vault_scale.rs`, reachable here by an unauthenticated repeat
/// request over the network.
///
/// What changed is what happens when the projection and the file disagree.
/// This test used to corrupt the file to unparseable garbage, re-claim from
/// the machine that already owns the seat, and observe that the counter
/// **overwrote** the garbage with its own memory and answered `200` — a
/// running daemon silently repairing a file it had no business trusting its
/// memory over. Now the reload is attempted first and fails closed
/// (`lib.rs:351-354`): the claim is refused `500`, nothing is issued, and the
/// operator's file is left exactly as it was found for them to look at.
///
/// The rewrite-from-memory path is then shown on the case the repair
/// deliberately kept: a *missing* file is not an error (`lib.rs:297-304`), so
/// memory is still the last truth standing and the next claim restores the
/// whole ledger from it.
#[test]
fn an_unreadable_ledger_is_now_refused_not_overwritten_from_memory() {
    let c = counter("rewrite", 1e6, 1e6);

    let first = c.claim(0, 5);
    assert_eq!(first.status(), Some(200), "{first:?}");
    let token = first.token().expect("token");

    // The disk is now garbage. Nothing about the claim state changed.
    let garbage = b"{ not a vault at all";
    std::fs::write(&c.vault_path, garbage).expect("corrupt the file");
    assert!(
        Vault::load(&c.vault_path).is_err(),
        "the ledger really is unreadable now"
    );

    // An idempotent re-issue: same code, same machine, no state change — and
    // it is refused, because the ledger it would have to write over cannot be
    // read.
    let again = c.claim(0, 5);
    assert_eq!(
        again.status(),
        Some(500),
        "an unreadable ledger must fail closed: {again:?}"
    );
    assert_eq!(
        again.error().as_deref(),
        Some("ledger unavailable — nothing was issued")
    );
    assert!(again.token().is_none(), "and it issued nothing");
    assert_eq!(
        std::fs::read(&c.vault_path).expect("the file is still there"),
        garbage,
        "the operator's file was left untouched, not overwritten from memory"
    );

    // The one case the repair deliberately keeps: no file at all is not an
    // error, so the daemon's memory is the last truth standing...
    std::fs::remove_file(&c.vault_path).expect("remove the ledger");
    let again = c.claim(0, 5);
    assert_eq!(again.status(), Some(200), "{again:?}");
    assert_eq!(
        again.token().as_deref(),
        Some(token.as_str()),
        "a re-issue is byte-identical — the expiry is stored, never extended"
    );

    // ...and that claim rewrote the entire ledger, all CODES entries of it.
    let restored = c.on_disk();
    assert_eq!(restored.entries.len(), CODES as usize);
    assert_eq!(restored.entries[&key(0)].status, Status::Claimed);
    assert_eq!(
        restored.entries[&key(0)].machine.as_deref(),
        Some(fp(5).as_str())
    );
    for i in 1..CODES {
        assert_eq!(restored.entries[&key(i)].status, Status::Unclaimed);
    }

    c.assert_still_serving("a ledger rewrite");
}
