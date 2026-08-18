# CCOS Enterprise ↔ DeepSeek Harness adapter

This package is the native Cordis/DeepSeek Harness edge adapter for CCOS Enterprise.
It deliberately keeps DeepSeek-specific types out of CCOS Core and sends every
memory operation through the Enterprise MCP boundary.

Target host: DeepSeek Harness `0.1.x` (initial validation target: `0.1.0-rc.7`).

## Security invariants

- DeepSeek Harness remains the authority for its own turn waterfall. The adapter
  calls `next()` first and only recalls from the accepted/redacted direct-user
  message.
- Recalled CCOS text is appended as a source-labelled plugin user message inside
  `<ccos_context trust="untrusted-memory">`; it is never a system instruction.
- Recall is optional and fail-open. Its foreground deadline is configurable but
  hard-capped at 3000 ms.
- Tenant and actor are mandatory. They are never inferred from a workspace,
  process username, session id, or model output.
- Capture is written to a local durable outbox before the MCP write is attempted.
  The outbox key includes tenant + DSH session + turn, preventing cross-tenant
  collisions when hosts reuse local ids.
- CCOS authorization remains fail-closed at the Enterprise server. This adapter
  does not turn DSH-native shell/code tools into CCOS capabilities.

## Transport

The adapter owns a dependency-free MCP stdio client. By default it launches:

```text
ccos-enterprise-mcp-server
```

The server-side executable is the corresponding Enterprise transport boundary;
it is intentionally separate from this DSH package so the adapter can be tested
without linking Rust into the host process.

Every `tools/call` carries host correlation data under MCP `_meta.ccos`:

```text
tenant_id, actor_id, agent_id, host,
dsh_profile, dsh_session_id, turn_id, step_id,
request_id, trace_id, model, workspace
```

The server must treat these as claims to validate, not as proof of identity.

## Lifecycle

```text
agent/pre-step
  -> await next()                 # DSH policy remains authoritative
  -> memory.recall                # first step only, fail-open
  -> append untrusted context

session/event
  -> collect direct user / assistant / tool events
  -> turn/end
  -> fsync + rename durable outbox entry
  -> memory.ingest
  -> delete outbox entry only after MCP success
```

## Development

No npm install is needed for the adapter tests:

```bash
cd adapters/deepseek-harness
npm run check
npm test
```
