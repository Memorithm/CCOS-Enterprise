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

The product boundary below is enforced on the **dependency graph** rather than
by repository separation. OctaSoma is an explicit Enterprise dependency through
one governed adapter; it does not become a dependency of `ccos-core`.

### How an improvement travels between the three products

Because Core was brought in with `git subtree` and not copied, the sharing is
a command rather than a manual port:

```sh
git subtree pull --prefix=core <core-remote> main   # take an upstream Core improvement
git subtree push --prefix=core <core-remote> <branch>  # send one back upstream
```

This is what makes the three products independent *and* mutually beneficial at
the same time. Enterprise's kernel can change without asking upstream Core's
permission, and upstream Core can change without breaking Enterprise, because
neither is resolving the other at build time. An improvement crosses when
somebody decides it should — which is the point, not a limitation. The cost is
the honest one: a subtree that has diverged makes the next pull a merge, and
that merge is where the decision gets made.

## Product boundary

There are three products, and they are independent of one another: **CCOS
Core**, **CCOS Enterprise**, **CCOS Research Lab**. An improvement made in one
is carried to the others deliberately; a fundamental change to one does not
reach them. (`CCOS` and `CCOS_EXTENDED` are archived and are not part of the
lineup — where their names survive in a source comment it is provenance for
code that came from them, not a live dependency.)

- **Never** contains or depends on: `ccos-rsi`, `forge-core`, `ccos-forge`,
  recursive self-improvement, autonomous patch promotion, generated-code
  execution, self-modification, or CCOS Research Lab.
- **OctaSoma is allowed only through `ccos-enterprise-octasoma`.** That adapter
  owns tenant isolation and quota enforcement and depends on canonical OctaSoma,
  which in turn consumes targeted SciRust crates. Neither OctaSoma nor SciRust
  acquires an edge back into Enterprise or Core.
- Core still ships opt-in features of its own. Enterprise takes Core at
  `default-features = false` and **CI never sweeps Core's feature matrix**: the
  product enables premium memory through the dedicated Enterprise adapter, not
  by silently activating unrelated Core features. Core's own suite still runs,
  at default features.
- The gateway (`ccos-enterprise-gateway`) is an **allowlist**: a tool traverses
  only if it is in the exposed catalogue (`memory.*`, `context.*`, `policy.*`,
  `audit.*`, `system.health`; `ccos.*` accepted as an alias). Research/raw
  namespaces (`rsi.*`, `forge.*`, `slha.*`, `octa.*`) and the capabilities the
  profile refuses outright (`patch.*`, `shell.*`, `self.*`, `code.execute`,
  `repository.modify`) are rejected ahead of it, and no privilege reaches past
  either — see `docs/HERMES_INTEGRATION.md`.
- Advanced Q-Page variants are **policy-activated per tenant**
  (`ccos-enterprise-qpages`); Core's standard primitives are untouched.

See `docs/OCTASOMA_INTEGRATION.md` for the memory-specific authority,
isolation, persistence and determinism contract.

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
| `ccos-enterprise-skills` | evidence-backed skill crystallization + observational trial ledger (validated, hashed-only) |
| `ccos-enterprise-skills-audit` | operator-only, tenant-scoped, read-only skill/trial/evidence provenance audit (`audit.provenance`) |
| `ccos-enterprise-admin` | administrative action validation + audit |
| `ccos-enterprise-octasoma` | tenant-isolated semantic/episodic memory adapter; OctaSoma observations remain non-authoritative |
| `tools/ccos-license-server` | vendor claim counter (HTTP/1.1) + vault admin CLI + PHP shared-hosting flow |
| `tests/ccos-enterprise-conformance` | the composed product path end to end: governed request admission, tenant isolation, the Hermes tool-catalogue contract, adversarial scenarios |

Sole human maintainer: **ZEKRITI Tarek** (see GOVERNANCE.md).
