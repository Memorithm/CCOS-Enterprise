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
- Model-visible CCOS tools are a fixed read-only allowlist; writes remain owned
  by the adapter capture path and Enterprise governance.

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

## Native governed tools

When `toolsEnabled` is true, the adapter asks the Enterprise server for its live
`tools/list` and registers only these read capabilities in DSH:

| DSH name | Enterprise capability |
| --- | --- |
| `ccos_recall` | `memory.recall` |
| `ccos_recall_what_if` | `memory.recall_what_if` |
| `ccos_get` | `memory.get` |
| `ccos_stats` | `memory.stats` |
| `ccos_timeline` | `memory.timeline` |
| `ccos_verify` | `memory.verify` |
| `ccos_context_retrieve` | `context.retrieve` |
| `ccos_causal_blame` | `ccos.causal_blame` |
| `ccos_causal_flash` | `ccos.causal_flash` |
| `ccos_drift_cause` | `ccos.drift_cause` |
| `ccos_retrodict_belief` | `ccos.retrodict_belief` |

Input schemas and descriptions come from the live governed catalogue, so a Core
schema change cannot silently drift from the adapter copy. Missing expected
capabilities roll back the partial DSH tool generation.

No `memory.ingest`, `memory.page_fault`, `memory.sync`, causal mutation,
`shell.*`, `code.execute`, repository modification, patching or self-modification
capability is registered.

Native CCOS reads use DSH's exclusive scheduling by default. `ccos_recall` is
hard-capped at 3000 ms; other reads default to 60 seconds and are capped at five
minutes. Model-facing result text defaults to 6000 characters and is capped at
20000, while the canonical MCP result remains available to the execution path.
Each call is correlated with tenant, actor, DSH session, active turn/step and
`tool_call_id`.

If live tool discovery fails and `failOnStartupError` is false, automatic
recall/capture remain active while the native tool surface stays unavailable.

## Lifecycle

```text
agent/pre-step
  -> next()
  -> memory.recall
  -> append untrusted context

native ccos_* call
  -> live Enterprise schema
  -> DSH turn/step/tool_call correlation
  -> governed read capability

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
