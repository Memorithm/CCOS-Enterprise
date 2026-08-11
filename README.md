# CCOS Enterprise

> Secure, governed, multi-tenant deployment of
> [CCOS Core](https://github.com/Memorithm/CCOS-Core).

CCOS Enterprise adds the organizational layer around the stable cognitive
kernel — authentication, RBAC, multi-tenancy with memory isolation, quotas and
budgets, model governance, backup/restore, observability, governed semantic /
episodic memory, and vendor licensing — **without ever duplicating Core**.

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
by repository separation. The key invariant is directional: `ccos-core` stays
independent of product/research memory engines, while Enterprise may compose
approved external engines behind Enterprise-owned governance adapters.

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

- **Core never contains or depends on** `octasoma`, SciRust, `ccos-rsi`,
  `forge-core`, `ccos-forge`, recursive self-improvement, autonomous patch
  promotion, generated-code execution, self-modification, or CCOS Research Lab.
- **Enterprise may depend on canonical OctaSoma** through an Enterprise-owned,
  governed adapter. That adapter is responsible for tenant/workspace/agent
  isolation, RBAC, quotas, lifecycle/retention, backup/restore, provenance and
  audit. OctaSoma results are observations supplied to Core contracts; they do
  not acquire authority merely because Enterprise selected the backend.
- OctaSoma is **not** added to the `core/` subtree, to any Core feature, or to
  the Core dependency graph. The dependency direction is Enterprise →
  OctaSoma → targeted SciRust crates. Core remains below and independent of
  that graph.
- Research-only components (`ccos-rsi`, Forge, autonomous patch promotion,
  generated-code execution, self-modification) remain forbidden in Enterprise.
  Their presence in Research Lab does not make them Enterprise dependencies.
- The gateway (`ccos-enterprise-gateway`) is an **allowlist**: a tool traverses
  only if it is in the exposed catalogue (`memory.*`, `context.*`, `policy.*`,
  `audit.*`, `system.health`; `ccos.*` accepted as an alias). Research
  namespaces (`rsi.*`, `forge.*`, `slha.*`) and the capabilities the profile
  refuses outright (`patch.*`, `shell.*`, `self.*`, `code.execute`,
  `repository.modify`) are rejected ahead of it. An OctaSoma-backed memory
  implementation is exposed through the governed `memory.*` contract rather
  than by publishing an unauthenticated raw `octa.*` surface.
- Advanced Q-Page variants are **policy-activated per tenant**
  (`ccos-enterprise-qpages`); Core's standard primitives are untouched.

## Planned OctaSoma adapter

`ccos-enterprise-octasoma` is the product-side integration point. Its intended
responsibilities are deliberately narrower than OctaSoma itself:

1. translate Enterprise tenancy/scope into opaque Core memory scopes;
2. apply authorization, quotas, retention and lifecycle policy before writes or
   recalls;
3. attach auditable provenance and store-generation identifiers;
4. expose OctaSoma recall as non-authoritative memory observations;
5. make backup/restore and deletion semantics Enterprise-governed;
6. keep the raw OctaSoma MCP server outside the authenticated Enterprise trust
   boundary.

The crate will be added only after the neutral memory ports in CCOS Core are
available in the Enterprise `core/` subtree. This ordering prevents an adapter
from inventing a parallel Core API merely to get ahead of the kernel contract.

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
| `ccos-enterprise-octasoma` *(planned)* | governed semantic/episodic memory adapter; never part of Core |
| `tools/ccos-license-server` | vendor claim counter (HTTP/1.1) + vault admin CLI + PHP shared-hosting flow |
| `tests/ccos-enterprise-conformance` | the composed product path end to end: governed request admission, tenant isolation, the Hermes tool-catalogue contract, adversarial scenarios |

Sole human maintainer: **ZEKRITI Tarek** (see GOVERNANCE.md).
