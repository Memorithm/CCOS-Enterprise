# Contributing to CCOS Enterprise

CCOS Enterprise is the governed, multi-tenant deployment layer around
[CCOS Core](https://github.com/Memorithm/CCOS-Core). It holds itself to the
same bar as Core: deterministic behaviour, enforced invariants, and a green
CI. This guide gets you productive quickly.

- [Local setup](#local-setup)
- [The development loop](#the-development-loop)
- [What CI checks](#what-ci-checks)
- [Coding conventions](#coding-conventions)
- [Non-negotiable boundaries](#non-negotiable-boundaries)
- [Branches & commits](#branches--commits)
- [Pull-request checklist](#pull-request-checklist)

## Local setup

You need the Rust toolchain pinned by `rust-toolchain.toml` (rustup reads it
automatically) **and a sibling checkout of CCOS Core** — during development
the workspace depends on `ccos-core` by path (charter §29; pinned to an exact
git `rev` before any release, never a branch):

```bash
git clone https://github.com/Memorithm/CCOS-Core CCOS-Core
git clone https://github.com/Memorithm/CCOS-Enterprise CCOS-Enterprise
cd CCOS-Enterprise
scripts/install-git-hooks.sh   # author-policy hooks (see Branches & commits)
cargo build --workspace --all-features
cargo test  --workspace --all-features
```

No system dependencies, no network, no GPU: every test runs fully offline.
The only optional extra is a PHP ≥ 8.0 CLI with `sodium` if you touch the
shared-hosting counter (`tools/ccos-license-server/php/claim.php` — verify
with `php claim.php selftest`).

## The development loop

Run these before every push — they mirror `ci-fast.yml` exactly, so if they
pass locally CI will too:

```bash
cargo fmt --all                                            # format (CI runs --check)
cargo clippy --workspace --all-features -- -D warnings     # lint; warnings are errors
cargo test --workspace --all-features                      # the full suite
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
scripts/check-author-policy.sh HEAD                        # the single-author policy
```

Touching the licensing stack (`ccos-enterprise-governance`,
`tools/ccos-license-server`)? Also prove the cross-implementation contract:

```bash
cargo test -p ccos-enterprise-governance --all-features
cargo test -p ccos-license-server
php tools/ccos-license-server/php/claim.php selftest
```

## What CI checks

| Workflow | When | What |
| -------- | ---- | ---- |
| `ci-fast.yml` | every push/PR | author policy, Enterprise boundary greps, `fmt`, `clippy -D warnings`, full test suite (release) |
| `ci-full.yml` | push/PR + nightly | per-crate contract tests (gateway, RBAC/tenancy/policy, governance wire formats, license server), Core-dependency conformance, MSRV |
| `ci-security.yml` | push/PR + weekly | `cargo deny` (advisories/licenses/sources), gitleaks, forbidden-capability scan (charter §4.2) |
| `ci-nightly.yml` | nightly | full tests, author policy over the whole history, docs build |
| `ci-release.yml` | manual | release gates — exact Core `rev` required, full checks, compatibility matrix artifact. CI never publishes (charter §45) |

## Coding conventions

- **Format with `rustfmt`** (default settings). No manual alignment the
  formatter would undo.
- **Zero clippy warnings.** Prefer iterators, avoid needless clones and
  allocations, and don't `#[allow(...)]` without a one-line reason.
- **Document public items.** Every public module/type/fn carries a rustdoc
  line; `RUSTDOCFLAGS="-D warnings" cargo doc` must pass, so intra-doc links
  must resolve.
- **Avoid panics on the library path.** Return `Result`/`Option`; reserve
  `unwrap`/`expect` for tests or genuinely-impossible cases (with a comment).
- **Keep determinism.** Iterate `BTreeMap`/`BTreeSet` (not hash maps) whenever
  order reaches output, audit logs, or wire formats.
- **Fail closed.** A gate that cannot decide (unknown schema, missing key,
  unclassifiable request) refuses — with an announced, specific error.
- **Wire formats are contracts.** Anything serialized across a boundary
  (claim protocol, vault, tokens, manifests, revocation lists) gets a schema
  tag, a bump discipline, and tests pinning byte-exact vectors — including
  the PHP counter's selftest when the licensing wire is involved.

## Non-negotiable boundaries

These are enforced by CI greps and tests; don't regress them.

| Boundary | Lives in |
| -------- | -------- |
| No dependency on `ccos-rsi`, `forge-core`, `ccos-forge`, Research Lab | `ci-fast.yml` boundary step, `cargo tree` scan |
| Research namespaces (`rsi.*`, `forge.*`, `slha.*`, `octa.*`) rejected at the gateway | `ccos-enterprise-gateway::classify` + tests |
| Core is depended on, never copied | `ci-full.yml` conformance job |
| Advanced Q-Pages are policy-activated per tenant, never imposed | `ccos-enterprise-qpages::QPageRegistry` + tests |
| A stolen license vault redeems nothing | `vault_key` double-hash keying, Rust + PHP tests |
| Single human contributor | `scripts/check-author-policy.sh`, `.githooks/` |

## Branches & commits

- Work on a feature branch; keep `main` green.
- Write imperative, scoped commit subjects (`gateway: reject non-canonical
  tool names`), with a body explaining *why* when it isn't obvious.
- Keep formatting-only churn out of logic commits.
- **Author policy (§43):** every commit is authored and committed by
  ZEKRITI Tarek — no other identities, no contribution trailers. CI checks
  every PR range and the whole history nightly;
  `scripts/install-git-hooks.sh` installs the local hooks that catch a
  violation before it leaves your machine.
- **Merging a pull request:** use a **merge commit** (the "Create a merge
  commit" button) or merge locally. Merge commits are exempt from the
  identity rules — GitHub stamps them with the clicking account and
  `GitHub <noreply@github.com>`, which nobody can set to the maintainer —
  but their *message* is still scanned. **Squash merge from the web UI
  fails the policy** by design: it produces an ordinary commit committed by
  `GitHub`. Squash locally if you want a single commit. A pull-request body
  containing an AI-attribution footer must never become a commit message.

## Pull-request checklist

- [ ] `cargo fmt --all -- --check` clean
- [ ] `cargo clippy --workspace --all-features -- -D warnings` clean
- [ ] `cargo test --workspace --all-features` green (new behaviour arrives
      with its tests — failing-first where practical, charter §41)
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
      --all-features` clean
- [ ] `php tools/ccos-license-server/php/claim.php selftest` green if the
      licensing wire changed
- [ ] Docs updated (`README.md`, `docs/`) for any user-facing or structural
      change
- [ ] Boundaries preserved (see the table above); determinism preserved
