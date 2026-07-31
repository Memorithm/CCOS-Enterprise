# CCOS Enterprise

> Secure, governed, multi-tenant deployment of
> [CCOS Core](https://github.com/Memorithm/CCOS-Core).

CCOS Enterprise adds the organizational layer around the stable cognitive
kernel — authentication, RBAC, multi-tenancy with memory isolation, quotas and
budgets, model governance, backup/restore, observability, and vendor licensing
— **without ever duplicating Core**.

Core lives here too, under `core/`, as one member of one workspace. That is
co-location, not duplication: there is exactly **one** `ccos-core` in the
tree, and CI asserts the count rather than grepping for copied function names.
Before this, Enterprise reached Core through a `../CCOS-Core` sibling
dependency the manifest itself marked temporary, which CI had to satisfy by
checking out a second repository and symlinking it into place — two histories,
two lockfiles, and no way to land a change that spanned the boundary in one
commit. One workspace means `cargo test` covers both, and a Core change and
its Enterprise consequence are reviewed together or not at all.

The product boundary below is unchanged, and is now enforced on the
**dependency graph** rather than by repository separation — a stronger check,
since a crate cannot satisfy it merely by living somewhere else.

## Product boundary

- **Never** contains or depends on: `ccos-rsi`, `forge-core`, `ccos-forge`,
  recursive self-improvement, autonomous patch promotion, generated-code
  execution, self-modification, or CCOS Research Lab.
- The gateway (`ccos-enterprise-gateway`) is an **allowlist**: a tool traverses
  only if it is in the exposed catalogue (`memory.*`, `context.*`, `policy.*`,
  `audit.*`, `system.health`; `ccos.*` accepted as an alias). Research
  namespaces (`rsi.*`, `forge.*`, `slha.*`, `octa.*`) and the capabilities the
  profile refuses outright (`patch.*`, `shell.*`, `self.*`, `code.execute`,
  `repository.modify`) are rejected ahead of it, and no privilege reaches past
  either — see `docs/HERMES_INTEGRATION.md`.
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
| `tests/ccos-enterprise-conformance` | the composed product path end to end: governed request admission, tenant isolation, the Hermes tool-catalogue contract, adversarial scenarios |

Sole human maintainer: **ZEKRITI Tarek** (see GOVERNANCE.md).
