# DeepSeek Harness Integration

Profile: `DeepSeek Harness → CCOS Enterprise → CCOS Core`.

DeepSeek Harness is a host, not a Core dependency. The integration lives under
`adapters/deepseek-harness/` and is loaded as a native DSH Cordis plugin through
its `dsh.bundle.patch` package metadata.

## Boundary

The adapter may request only Enterprise catalogue capabilities. Automatic recall
uses `memory.recall`; automatic turn capture uses `memory.ingest`. The Enterprise
front door remains responsible for authentication, tenant ownership, RBAC,
model governance, budget, replay and audit before translating to Core names.

DSH-native capabilities such as shell execution or code execution do not become
Enterprise capabilities merely because the host can perform them. Existing
Enterprise exclusions (`shell.*`, `code.execute`, `repository.modify`,
`patch.*`, `self.*`, Research/RSI namespaces) remain unchanged.

## Identity and correlation

A DSH call is correlated with tenant, actor, agent, DSH profile/session/turn/step,
request id and trace id. Tenant and actor are explicit configuration inputs and
must be verified at the Enterprise transport; session ids alone are never a
security boundary.

## Recall policy

`agent/pre-step` is a waterfall hook. The adapter waits for downstream `next()`
first. A rejected turn is never recalled. If downstream policy rewrites or
redacts the user message, only the accepted post-policy text becomes the recall
query.

Recall is fail-open because memory context is an optional enhancement. The
configured foreground timeout is clamped to a hard 3000 ms product ceiling.
Returned text is injected as untrusted historical evidence, never as system
policy.

## Capture policy

`session/event` is consumed as an append-only structured event stream. At
`turn/end`, the adapter serializes the accepted user text, assistant text and
tool call/result summaries into a DSH turn document. Before any MCP ingest is
attempted, the capture is fsynced to a local outbox and atomically renamed into
place. An entry is removed only after an acknowledged Enterprise MCP call.

This closes the crash window present in best-effort detached capture designs:
a host crash can leave a pending outbox item, but it cannot make an acknowledged
capture disappear from the adapter without a durable local record.

## DSH compatibility target

The initial target is DeepSeek Harness `0.1.0-rc.7`. The adapter intentionally
uses the public Cordis lifecycle shapes exercised by DSH (`agent/pre-step`,
`session/event`, `systemPrompt.section`) and a standard MCP stdio transport.
