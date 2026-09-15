# CI qualification contract

Audit follow-up B02/B03/B04, 15 September 2026.

## Producer failure is not a clean dependency graph

The old negative pipelines could treat a failed `cargo tree` or scanner as an
absence of forbidden matches. `scripts/ci-guards.sh` separates those outcomes.
`require_clean_output PATTERN COMMAND [ARG...]` requires a zero producer status
and nonempty output before invoking the scanner. The producer's error status and
stderr are preserved. `require_no_matches COMMAND [ARG...]` understands grep's
contract: 0 means a forbidden match (failure), 1 means no match (success), other
statuses remain failures. Output is captured in an exclusive temporary file and
cleaned up on exit. There is no eval or early grep -q pipeline close.

```bash
python3 scripts/test-ci-guards.py
source scripts/ci-guards.sh
require_clean_output 'research-lab|ccos-forge|ccos-rsi' \
  cargo tree --locked --workspace --color never
```

Fourteen stdlib-only regressions cover clean/forbidden output, empty successful
producers, partial failed producers, scanner errors, missing tools/input,
conditional callers, argument boundaries, stderr, cleanup and large output.
The same helpers are suitable for Core without importing Enterprise runtime code;
the consumer's actual boundary rules must remain repository-specific.

## The committed lockfile is the input

Fast and full jobs validate `cargo metadata --locked` before dependency graph
commands. Subsequent resolving/build/test commands use `--locked`. A final
`git diff --exit-code HEAD -- Cargo.lock` rejects an implicit local repair.
This does not pin OS images, remote action tags or every external tool.

## Toolchain coverage is explicit

Fast formatting, lint, release/default workspace and identity-feature tests keep
the existing effective 1.89.0 baseline, now explicitly selected with
`RUSTUP_TOOLCHAIN`. Full contracts and MSRV use the same explicit baseline.
A separate current-stable job selects stable, logs the actual compiler/Cargo,
compiles the Enterprise all-features graph and runs memory/MCP all-feature tests.
It is not a claim of stable coverage for every optional Core feature or every
lint. No existing contract or identity-feature test is dropped.

Rust project documentation, consulted 15 September 2026:
https://doc.rust-lang.org/cargo/commands/cargo-tree.html
https://rust-lang.github.io/rustup/overrides.html

The latest full qualification must be read from exact-head checks; a successful
preparation workflow, or an older ancestor, is not final merge evidence.
