# Tenant envelope encryption, rotation and recovery

The governed provider can be explicitly provisioned and reopened in encrypted
mode. Provider images, canonical governance, selector, purge intent/floor and
rotation intent are encrypted before any temporary or final file is written.
The existing plaintext API remains available for explicitly plaintext stores;
neither mode automatically accepts the other. No default key or migration by
guessing is provided.

## Cryptographic and authority boundary

`ccos-enterprise-envelope` uses RustCrypto XChaCha20Poly1305 with a fresh OS-random
256-bit data key and 192-bit nonce for each newly sealed artifact. It binds the
format, algorithm, independently configured tenant and canonical relative
artifact name as AEAD associated data. The encrypted data key accompanies the
ciphertext; a `TenantKms` implementation wraps it using the same binding digest.
This follows envelope encryption's separate data-key/key-encryption-key roles.
See [RustCrypto 0.10.1](https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/)
and the [AWS envelope pattern](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html).
This implementation does not claim FIPS certification or implement AWS KMS.

The configured tenant and allowed key IDs precede KMS access. Labels inside an
envelope cannot select arbitrary key services, endpoints or tenant keys. Unknown
versions, changed tenant/path, invalid tags, truncated or oversized envelopes,
unavailable keys and plaintext substitution fail closed. Decrypted bytes still
pass the existing governance/image/configuration checks before provider recovery.
Checksums, key possession, semantic similarity and trust labels do not prove truth.

Data keys and temporary decrypted buffers use `Zeroizing`. The provider must
retain usable plaintext in memory while serving, and TLS/allocator/runtime copies
are not a forensic memory-erasure guarantee. An already-open owner can continue
reading its reconstructed memory during a KMS outage; new storage operations and
recovery requiring KMS fail. Revoking serving access remains an admission/session
operation in addition to key retirement.

## Vault Transit connector

`VaultTransitKms` implements explicit-version encrypt/decrypt against provisioned
tenant keys using both `context` and `associated_data`. It validates the returned
`vault:vN:` prefix against the configured immutable key version. One Vault key
name cannot be mapped to different tenants by one connector. Its HTTPS client
uses certificate/hostname verification, no redirects, no inherited proxy,
bounded responses and finite timeouts. Errors omit credentials and response
bodies. The client has no create/export/delete/rotate-KEK operation.
See the [Vault Transit API](https://developer.hashicorp.com/vault/api-docs/secret/transit).

Operators provision appropriate AEAD Transit keys and least-privilege key ACLs,
with encryption upsert disabled or no create capability. The tenant service needs
encrypt/decrypt on its named keys only. KMS administration and key retirement
remain separate operator actions. Vault tokens require an external renewal
process; this connector reads its restricted token file when configured.

For stdio, set `CCOS_ENTERPRISE_ENVELOPE_CONFIG` to a regular JSON file alongside
the existing explicit provider-root configuration. For example, these **key
references** contain no key material or credential:

```json
{
  "vault_address": "https://vault.example.org",
  "mount": "transit",
  "token_file": "/run/secrets/ccos-vault-token",
  "active_key": "acme-v2",
  "keys": [
    {"id": "acme-v1", "name": "ccos-acme", "version": 1},
    {"id": "acme-v2", "name": "ccos-acme", "version": 2}
  ]
}
```

The token file must be absolute, regular, bounded, and inaccessible to group/other
on Unix (for example mode 0600). Key IDs are immutable references: introducing a
new Vault version requires a new ID, retaining old read IDs until rotation and
backup reconciliation are complete. The expected tenant comes from the service
configuration and signed identity, not this file or an MCP argument.

Provision with `ProviderGenerationStore::initialize_encrypted`; reopen with
`open_encrypted`. Both require a configured `Arc<EnvelopeCipher>`. Existing
plaintext roots require an explicit offline migration to a fresh encrypted root
and separate handling of the old plaintext copies. No production keys or Vault
deployment are created by repository tests.

## Governed rotation and crash protocol

`memory.keys.rotate` accepts an empty object and requires its own
`memory.keys.rotate` permission through `Deployment::admit`. Default read/write
roles do not receive it. The target key is the operator-configured active key.
This rotates the stored envelopes to an already provisioned KEK version; it does
not rotate or destroy the external Vault key.

Under the exclusive generation lock, the consumed owner first publishes an
encrypted rotation intent. Every managed artifact is authenticated and its data
key rewrapped to the target key, replacing that file by synchronized temporary
file and rename. Ciphertext, nonce and plaintext generation receipts remain
unchanged. Retired generations and purge metadata are included. Known temporary
envelope files are removed before completion. Unknown files, symlinks and corrupt
orphans fail closed and require operator repair rather than silent omission.

After process death, open reads the encrypted intent and completes rewrapping
before returning an owner. During rotation both old and new key versions must
remain available. A receipt is returned after reopen; MCP Succeeded receipts
also authenticate the artifact set and key reference before settlement. An
ambiguous Started effect retains the existing explicit reconciliation requirement.

After a verified complete rotation and independent backup reconciliation,
operators can retire the old KMS version. Retiring it early may make recovery
impossible. Rotation is not erasure of backups, a distributed transaction, or
protection against restoration of the entire tenant root with old usable keys.
The [purge floor](GOVERNED_PHYSICAL_PURGE.md) still needs to be retained on restore.

## Qualification and limits

Tests cover tenant/path/ciphertext/key/version substitution, forbidden plaintext
fallback, explicit read keys, restricted network configuration, the Vault HTTP
contract against a local protocol fixture, encrypted generation and purge
recovery, and reads after simulated old-key retirement. Actual child processes
are killed during rotation (intent, partial artifact set, completion) and at all
five encrypted purge boundaries. The authenticated server test exercises distinct
permission denial, rotation, Succeeded settlement, context after restart, KMS
outage and missing-encryption configuration. Production Vault/HSM/IAM integration
is **not** established by the local protocol/key-service fixtures.

This covers the governed provider root, not Core workspaces, original sources,
Enterprise audit/effect journals or external backups. Tenant/key labels, relative
filenames, sizes and generation counts remain visible. Envelope JSON increases
disk size and transient memory; A09's plaintext measurement is not an encrypted
performance result. AEAD protection does not authorize raw OctaSoma access, change
Core semantics or promote observations into canonical truth.

```sh
cargo test -p ccos-enterprise-envelope --locked
cargo test -p ccos-enterprise-octasoma --lib generation::encrypted_artifacts --locked
cargo test -p ccos-enterprise-mcp --bin ccos-enterprise-mcp-server kms_server_tests --locked
```

## TLS dependency and redistribution

The locked Rustls version is 0.23.45, which fixes RUSTSEC-2026-0285.
The certificate data in webpki-roots 1.0.9 uses CDLA-Permissive-2.0; its
exception in cargo-deny is limited to that exact package and version. Include
[the complete license](licenses/webpki-roots-1.0.9.txt) when redistributing
binaries that embed this data. Other license and advisory gates remain active.
