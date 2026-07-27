# OpenClaw Integration

Profile: `OpenClaw → CCOS Enterprise → CCOS Core`.

- OpenClaw's recall contract (`ccos.recall` params, `get`, `sync`) is honored
  through Core's aligned MCP surface; Enterprise adds tenant scoping and RBAC
  on top.
- Workspace sync bundles are tenant-namespaced; signed-sync identities are
  mapped to Enterprise actors.
- Same forbidden-namespace list as Hermes (gateway-level, not config-level).
