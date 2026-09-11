# Encryption Model

- **At rest**: CCPS envelopes (Core) are the sealed unit. Per-tenant KMS
  wrapping at the Enterprise storage layer is **not implemented** in this
  tree; tenant isolation today is path/key namespacing plus admission gates,
  not a distinct wrapping key per tenant. Do not read this document as a
  claim that a KMS is already wired.
- **In transit**: TLS terminated at the reverse proxy; internal listeners are
  loopback-only (same posture as the license server).
- **Key management**: build-time public-key baking (Core `build.rs` keyring);
  private vendor keys exist only in issuance tooling (`ccos-enterprise-governance::vendor`).
- **No home-grown crypto**: ed25519 / SLH-DSA via `ccos-core`'s verifier; the
  all-zero placeholder key verifies nothing (fail-closed).
