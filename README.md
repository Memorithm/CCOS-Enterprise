# CCOS Enterprise

> Secure, governed, multi-tenant deployment of
> [CCOS Core](https://github.com/Memorithm/CCOS-Core).

CCOS Enterprise adds the organizational layer around the stable cognitive
kernel — authentication, RBAC, multi-tenancy with memory isolation, quotas and
budgets, model governance, encryption, backup/restore, observability, and
vendor licensing — **without ever duplicating Core**: it depends on an exact
`ccos-core` revision (currently a development path dependency, pinned to a
git `rev` before any release; never `branch = "main"`).

## Product boundary

- **Never** contains or depends on: `ccos-rsi`, `forge-core`, `ccos-forge`,
  recursive self-improvement, autonomous patch promotion, generated-code
  execution, self-modification, or CCOS Research Lab.
- Research namespaces (`rsi.*`, `forge.*`, `slha.*`, `octa.*`) are rejected at
  the gateway (`ccos-enterprise-gateway`).
- Advanced Q-Page variants are **policy-activated per tenant**
  (`ccos-enterprise-qpages`); Core's standard primitives are untouched.

## Crates

| Crate | Role |
|---|---|
| `ccos-enterprise-auth` | actor/org identity, authentication strength |
| `ccos-enterprise-rbac` | roles, permissions, deterministic grant checks |
| `ccos-enterprise-tenancy` | tenant boundaries, typed isolation scopes |
| `ccos-enterprise-policy` | quotas, budgets, model/tool allowlists |
| `ccos-enterprise-gateway` | secure MCP front door, namespace boundary |
| `ccos-enterprise-observability` | bounded metrics registries, audit correlation |
| `ccos-enterprise-backup` | backup manifests, restore gates |
| `ccos-enterprise-governance` | license claim protocol, signed release-manifest verification, vendor issuance, offline revocation |
| `ccos-enterprise-qpages` | advanced Q-Page variant registry (policy-gated) |
| `ccos-enterprise-admin` | administrative action validation + audit |
| `tools/ccos-license-server` | vendor claim counter (HTTP/1.1) + vault admin CLI + PHP shared-hosting flow |

Sole human maintainer: **ZEKRITI Tarek** (see GOVERNANCE.md).
