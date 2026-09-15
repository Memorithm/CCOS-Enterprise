# Knowledge and Decision journal load errors

Follow-up to the remaining A01 read-boundary observation in the September
2026 audit. This is not a second repair of the already-fixed torn-tail append
bug, and it does not change JSONL framing or claim crash-atomic batches.

Both `KnowledgeStore::load` and `DecisionStore::load` now attempt `File::open`
directly. Only the OS `NotFound` result keeps the existing empty-state
behavior, including a missing parent directory. Every other open/read error
is returned as `StoreError::Io` with the exact journal path and original
cause. No directory or file is created by load, and read-only loading does
not repair an interrupted final record. Writer locking and repair remain
in `open`; append validation and poisoning semantics are unchanged.

Five filesystem regression cases are applied to each store: absent input
without creation, valid empty file, a non-directory root, a directory at the
journal filename, and a Unix symlink loop. The non-directory-root case is
run before the fix to demonstrate the actual empty-state error, then both
suites must pass after the repair. No privileged permission-denial test,
power-cut experiment or real deployment access is claimed.

The operating-system treatment of symbolic links is preserved. A dangling
link that makes `File::open` return `NotFound` still follows the documented
empty-read behavior; this is not a filesystem sandbox or mandatory-presence
policy. Served governance projections have a distinct mandatory-state API.

```bash
cargo +1.89.0 test -p ccos-enterprise-knowledge-store --locked
cargo +1.89.0 test -p ccos-enterprise-decision-store --locked
```

Source: Memorithm/CCOS-Enterprise baseline
`72e22014c6711cb85fd31b4fb3d087477f50bd0f`, both journal modules reviewed
15 September 2026. Rust standard library `Path::exists` documentation,
consulted 15 September 2026, explains that metadata errors are coerced to
false: https://doc.rust-lang.org/std/path/struct.Path.html#method.exists
