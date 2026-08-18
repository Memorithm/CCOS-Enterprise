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

Build the server from the Enterprise workspace with:

```bash
cargo build --release -p ccos-enterprise-mcp --bin ccos-enterprise-mcp-server
```

The server is a one-principal, one-tenant process boundary. It verifies a signed
CCOS identity token at startup and again on every `tools/call`, provisions only
the configured tenant, and sends the resulting call through `GovernedMcp` before
Core can execute it. A governed write is acknowledged only after the tenant Core
session checkpoints successfully.

The server requires these environment variables:

```text
CCOS_ENTERPRISE_AUDIENCE
CCOS_ENTERPRISE_ISSUER_KID
CCOS_ENTERPRISE_ISSUER_PUBLIC_KEY_HEX   # 32-byte Ed25519 public key, 64 hex chars
CCOS_ENTERPRISE_IDENTITY_TOKEN          # ccosid1.ed25519...
CCOS_ENTERPRISE_TENANT
CCOS_ENTERPRISE_ACTOR                   # adapter correlation claim; must match token actor
CCOS_ENTERPRISE_MODEL
CCOS_ENTERPRISE_TOKEN_BUDGET
CCOS_ENTERPRISE_STATE_DIR
```

Optional:

```text
CCOS_ENTERPRISE_CALL_COST_TOKENS        # default 1 per governed MCP call
```

`tenantId`, `actorId`, and `model` in the Cordis plugin config override the
corresponding environment values for the adapter-side correlation metadata. A
mismatch never widens authority: the server rejects it because the signed token
and server tenant configuration remain authoritative.

Every `tools/call` carries host correlation data under MCP `_meta.ccos`:

```text
tenant_id, actor_id, agent_id, host,
dsh_profile, dsh_session_id, turn_id, step_id,
request_id, trace_id, model, workspace
```

Those fields are claims to validate, not proof of identity.

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
  -> GovernedMcp admission
  -> Core tenant checkpoint
  -> delete outbox entry only after MCP success
```

## Development

No npm install is needed for the adapter tests:

```bash
cd adapters/deepseek-harness
npm run check
npm test
```

The Rust transport is covered by the normal workspace formatting, clippy, test,
and release-test workflows.
