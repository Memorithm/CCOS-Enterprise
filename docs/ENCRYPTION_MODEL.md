# Encryption Model

- **At rest**: CCPS envelopes (Core) are the sealed unit; Enterprise adds
  per-tenant key separation at the storage layer (deployment-managed KMS).
- **In transit**: TLS terminated at the reverse proxy; internal listeners are
  loopback-only (same posture as the license server).
- **Key management**: build-time public-key baking (Core `build.rs` keyring);
  private vendor keys exist only in issuance tooling (`ccos-enterprise-governance::vendor`).
- **No home-grown crypto**: ed25519 / SLH-DSA via `ccos-core`'s verifier; the
  all-zero placeholder key verifies nothing (fail-closed).
