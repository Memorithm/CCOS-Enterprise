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
  the surface silently
  (`tests/ccos-enterprise-conformance/tests/boundary_contract.rs`).

## Tool naming

Enterprise names tools by **capability class** — `memory.`, `context.`,
`policy.`, `audit.`, plus the single tool `system.health` — not by provenance.
Two reasons:

- the prefix is what the authorization layer keys on (`memory.recall` requires
  `memory.read`); a single vendor-wide prefix carries no authorization signal
  and would need a separate mapping table anyway;
- the refused side of the boundary is already class-named (`shell.`, `patch.`,
  `self.`, …), so a class-named exposed side keeps the boundary symmetric and
  readable.

`ccos.` is accepted as an **alias** for the catalogue the gateway shipped with,
so anything already speaking it keeps working; class names are canonical for
anything new.

Core exposes bare `recall` / `ingest` over its own MCP server, so the gateway is
deliberately a **translation boundary** rather than a pass-through. That is
precisely what lets Enterprise pin its surface: a new tool appearing in Core
does not appear at the Enterprise front door until someone adds it to the
catalogue, on purpose.

## Deny by default

The gateway is an **allowlist** (`ccos_enterprise_gateway::classify`), matching
the posture of every other gate in the product — unknown roles grant nothing,
unlisted models are denied. A tool traverses only if it is in
`ALLOWED_PREFIXES` or `ALLOWED_TOOLS`.

Refusals are distinguishable on purpose, because an operator reading an audit
trail needs to tell them apart:

| Refusal | Meaning |
| --- | --- |
| `outside the Enterprise boundary` | a capability the product must never carry (`FORBIDDEN_PREFIXES` / `FORBIDDEN_TOOLS`), checked first |
| `not in the Enterprise catalogue` | merely unlisted — perhaps a Core tool nobody has exposed yet. Refused just as firmly, but an omission rather than a violation |
