# The CCOS Licensing Server (claim counter)

The vendor-side half of CCOS Pro licensing: a **claim counter** that turns
one-time claim codes into signed, annual, single-seat license tokens. Two
interchangeable implementations ship in `tools/ccos-license-server/`, speaking
the same wire protocol against the same vault format:

- **`ccos-license-server`** — a zero-framework Rust HTTP/1.1 daemon
  (`src/lib.rs`, `src/bin/ccos-license-server.rs`);
- **`claim.php`** — a single-file PHP variant for classic shared hosting
  (`php/claim.php`), byte-identical token output, proven by
  `php claim.php selftest`.

Runtime license *verification* never touches either: the `ccos` binary checks
tokens offline against the public key baked into it
(`ccos_core::license`). The counter is a fulfillment convenience, not a
runtime dependency — if it is down, existing licenses keep working.

## The protocol (`ccos.claim/v1`)

```
client                                counter
  |  POST /claim                        |
  |  { schema: "ccos.claim/v1",        |
  |    code_hash: sha256(code),        |   look up vault_key(code_hash)
  |    machine:   sha256(machine-id) } |   flip unclaimed → claimed
  |                                    |   persist durably, THEN sign
  |  200 { token }  /  4xx { error }   |
```

- The **code never leaves the customer's host** — only its domain-separated
  hash (`ccos-claim-code-v1|…`) does.
- The **machine identity never leaves the host** either — the fingerprint is
  `sha256("ccos-machine-v1|" + machine-id)`, opaque to the vendor.
- The signed token binds `licensee`, optional `exp`, and the fingerprint;
  the client verifies it against its baked-in public key before installing.

Refusals are announced, never silent:

| Status | Meaning |
| ------ | ------- |
| `400` | malformed request (framing, schema, non-hex fields, bad JSON) |
| `404` | unknown path, or unknown code — nothing under that hash |
| `405` | known endpoint, wrong method — the response names `Allow: GET, POST` |
| `410` | seat taken on another machine, or code revoked |
| `429` | global claim rate limit (~30 claims/min — 100-bit codes need no more) |
| `500` | counter misconfigured or persistence failed — **nothing was issued** |
| `503` | all connection slots busy — load shedding, retry shortly |

Framing and rate-limiting rules that matter behind a reverse proxy:

- **The framer is strict so no front end can disagree with it.** A request
  carrying `Transfer-Encoding`, a second or hidden `Content-Length` (space
  before the colon, bare CR, obs-fold continuation) is refused `400`
  without reaching a handler. One request per connection, `Connection:
  close` always: there is no keep-alive to desync.
- **Only well-shaped claims spend rate-limit tokens.** Malformed requests
  are answered without touching the shared budget, so a flood of one-line
  junk cannot lock paying customers out while `/healthz` stays green.
  Fairness *between* legitimate sources is the proxy's job — give each
  upstream client its own small queue so one noisy customer cannot consume
  the shared claim budget. Reference shapes:

  ```nginx
  # nginx: per-source claim budget in front of the global counter bucket
  limit_req_zone $binary_remote_addr zone=claim_per_client:10m rate=6r/m;
  location = /claim {
      limit_req zone=claim_per_client burst=3 nodelay;
      proxy_pass http://127.0.0.1:8471;
  }
  location / { proxy_pass http://127.0.0.1:8471; }
  ```

  ```caddyfile
  # Caddy (rate_limit module): same idea, one small queue per source IP
  claim.example.com {
      route {
          rate_limit { zone claim_per_client { key {remote_host} events 3 window 30s } }
          reverse_proxy 127.0.0.1:8471
      }
  }
  ```

  The counter itself stays single-bucket on purpose: it cannot see real
  client addresses through the proxy, and inventing trust for
  `X-Forwarded-For` would hand attackers a spoofable identity.
- Routing is path-first: an unknown path is `404` for every method; a known
  endpoint answers `405` with `Allow`. `HEAD /healthz` is served as `GET`
  with the body suppressed (RFC 9110 §9.3.2).

Re-claiming from the **same** machine re-issues the same license with the
**stored** expiry (lost-token self-service; never an extension). Any other
machine gets the single-seat `410` until the vendor re-arms the code.

## The vault (`ccos.license.vault/v2`)

`vault.json` is the only state: a map of **vault keys** to seat entries plus
a schema tag. The key is a *second*, domain-separated hash over the wire
value — `vault_key = sha256("ccos-vault-key-v1|" + code_hash)` — so the file
holds nothing redeemable at any layer:

- not the claim codes (behind two hashes);
- not the wire-level `code_hash` the endpoint accepts (behind one);
- no hardware identity (fingerprints are opaque hashes);
- no key material (the signing seed lives elsewhere — see below).

Writes are durable (temp sibling + atomic rename + fsync in Rust; lock +
temp + rename in PHP) and happen **before** the token is disclosed: a flip
the ledger did not record can never hand out a token.

Both implementations refuse a vault whose schema tag they do not expect
(fail closed). Upgrade a v1 vault (keyed by the wire hash) in place with:

```sh
ccos-license-admin --vault vault.json migrate
```

## Selling and managing seats (`ccos-license-admin`)

```sh
ccos-license-admin --vault vault.json new --licensee "Acme Corp" --days 365 [--label invoice-42]
ccos-license-admin --vault vault.json list
ccos-license-admin --vault vault.json rearm  <CODE or vault key>
ccos-license-admin --vault vault.json revoke <CODE or vault key>
ccos-license-admin --vault vault.json migrate
```

`new` prints the claim code **once** and stores only its vault key; a lost
code cannot be recovered, only re-armed or replaced. `rearm` resets a claimed
entry (machine died, hardware replaced) so the same code redeems again with a
fresh expiry fixed at the new claim. `revoke` makes the counter refuse the
code. No signing seed is needed for any vault operation — the CLI can run
anywhere the file lives.

## Deployment — daemon

```sh
CCOS_LICENSE_SIGNING_SEED=<64-hex> \
  ccos-license-server --vault /var/lib/ccos-licenses/vault.json [--listen 127.0.0.1:8471]
```

- Listens on **loopback** by default; TLS and the public hostname are the
  reverse proxy's job (Caddy/nginx). A claim code must never transit in
  clear.
- The **signing seed** is the one secret the process holds, from the
  environment only — never from the vault, never on disk next to it.
- Connections are handled sequentially with per-read timeouts **and a
  whole-request deadline**, so a drip-feeding client cannot park the queue.
- The global token bucket (burst 10, ~30/min sustained) exists to make brute
  force absurd, not to be fair — 100-bit codes do the heavy lifting.

## Deployment — shared hosting (PHP)

The counter's state lives in `vault.json`, not in a process, so a
script-per-request PHP host is a sound deployment (see the header of
`php/claim.php`):

1. upload `claim.php` into the webroot (e.g. `www/claim.php`);
2. put `vault.json` and `seed.hex` (the 64-hex seed, one line) in a sibling
   of the webroot — **outside** the served tree, default `../ccos-license/`;
3. copy `webroot.htaccess` next to `claim.php` as `.htaccess` (forces HTTPS,
   maps `/claim` to the script, disables caching) and, as a seatbelt,
   `ccos-license.htaccess` into the state directory as `.htaccess`;
4. manage codes locally with `ccos-license-admin` and upload `vault.json`
   over SFTP — avoid uploading while a customer is mid-claim;
5. prove the install with `php claim.php selftest` (CLI) — it asserts token
   byte-identity against a Rust-generated vector.

`GET` serves a small human claim form; `POST` with JSON is the API the
`ccos license claim` CLI speaks; both share the state machine.

## Updates: signed release manifests

Releases are two static files on any web space: the artifact and a one-line
signed manifest (`ccos-release.<b64url(payload)>.<b64url(sig)>`) produced by:

```sh
CCOS_LICENSE_SIGNING_SEED=<64-hex> ccos-license-admin manifest \
  --version 0.5.0 --binary ./ccos --url https://releases.example/ccos-0.5.0
```

`ccos update` verifies the manifest against the **same baked-in vendor key**
as licenses before downloading anything; the scheme tag is signed, so tokens
and manifests can never impersonate each other
(`ccos-enterprise-governance::release`). Offline revocation lists
(`ccosrev1.…`, `ccos-enterprise-governance::vendor`) ride the same trust
root.

## Threat model, honestly

| Compromise | Blast radius |
| ---------- | ------------ |
| **Stolen `vault.json`** | Nothing redeemable — keys are second-degree hashes; the thief learns licensee names/labels and seat states only. |
| **Compromised counter (read/write)** | Can refuse service; can burn or re-arm seats it holds; **cannot mint or tamper** — clients verify tokens against the baked-in public key, and the runtime never calls home. |
| **Stolen signing seed** | Can mint valid tokens and manifests. Rotate the keypair at the next release (new baked-in key), revoke known-bad artifacts via signed revocation lists. The seed therefore lives only in the daemon's environment / `seed.hex` outside the webroot, never in the repo, never in the vault. |
| **Hijacked release mirror** | Serves nothing installable — manifests are vendor-signed, artifact hash is signed into them. |
| **Brute force on codes** | 100 bits of entropy behind a global rate limit; the arithmetic does not close. |
