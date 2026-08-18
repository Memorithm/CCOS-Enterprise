# CCOS Enterprise ↔ DeepSeek Harness adapter

This package is the native Cordis/DeepSeek Harness edge adapter for CCOS Enterprise.
It keeps DeepSeek-specific types out of CCOS Core and sends memory operations
through the Enterprise MCP boundary.

Target host: DeepSeek Harness `0.1.x` (initial validation target: `0.1.0-rc.7`).

## Invariants

- DSH remains authoritative for its turn waterfall; recall happens only after
  `next()` accepts/redacts the direct-user input.
- Recalled text is untrusted historical context, never system authority.
- Recall is fail-open and hard-capped at 3000 ms.
- Tenant and actor are mandatory and are never inferred from the workspace.
- Capture enters a durable local outbox before MCP delivery.
- DSH-native shell/code capabilities do not become CCOS capabilities.

## Enterprise stdio transport

The adapter launches `ccos-enterprise-mcp-server`. The server binds one verified
principal to one tenant and sends every call through `GovernedMcp`.

Admitted writes are acknowledged only after the tenant Core checkpoint and the
Enterprise deployment ledger are durable. The ledger preserves budget, replay
and audit state across child-process restarts. A small durable effect marker
closes the crash window between Core and the ledger: known successes are settled
without re-running Core, known failures stay retryable, and an ambiguous started
effect fails closed.

MCP `isError: true` is never an acknowledgement. The JavaScript client rejects
it so a failed capture remains in the outbox; the Rust server also treats Core
`isError: true` as a backend failure before write checkpoint/settlement and rolls
back the admission reservation and charge.

Host correlation travels under `_meta.ccos`; those fields are claims to validate,
not proof of identity.

## Lifecycle

```text
agent/pre-step
  -> next()
  -> memory.recall
  -> append untrusted context

turn/end
  -> durable outbox
  -> memory.ingest
  -> governed admission
  -> tenant Core checkpoint
  -> Enterprise ledger commit
  -> outbox delete only after success
```

## Development

```bash
cd adapters/deepseek-harness
npm run check
npm test
```

The Rust transport is covered by workspace fmt, clippy, debug/release tests and
security workflows.
