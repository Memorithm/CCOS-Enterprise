# Hermes Agent Integration

Profile: `Hermes Agent → CCOS Enterprise → CCOS Core`.

- Hermes connects at the Enterprise gateway (authenticated MCP), never directly
  at experimental namespaces.
- Tenant and actor are resolved per session; every tool call is policy-gated
  and audit-correlated by request id.
- Core tools exposed: `memory.*`, `context.*`, `policy.*`, `audit.*`,
  `system.health` class. Forbidden: `rsi.*`, `forge.*`, `patch.*`, `shell.*`,
  `code.execute`, `repository.modify`, `self.*`.
- Contract tests (CI) pin the tool catalogue so a Core upgrade cannot widen
  the surface silently.
