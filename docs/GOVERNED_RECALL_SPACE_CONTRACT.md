# Canonical memory-space admission

Follow-up to audit A08/B01, 15 September 2026.

`admit_governed_recall` must compare each returned observation's space with the
canonical descriptor for its asset ID. Membership in a requested loadout only
checks the provider's declared label; it does not authorize moving an asset
between spaces. The canonical comparison happens before inactive-lineage and
trust-policy filtering. Unknown assets, space mismatches and missing trust for
active assets are explicit errors, not defaults. An error returns no partial
admitted prefix. Same-space inactive assets retain the existing filtered behavior.

Both `assemble_served_governed_context` and `assemble_attested_served_context`
use this common gate. Attestation retains its independent descriptor-space check.
The new error is `GovernedRecallGateError::ProviderReturnedMismatchedSpace` and
carries the asset ID, expected space and observed space. Consumers exhaustively
matching the public error enum must handle the added variant.

## Executable qualification

```bash
cargo test -p ccos-enterprise-mcp --test governed_space_boundary --locked
cargo test -p ccos-enterprise-memory --locked
```

The seven integration tests cover provider relabeling, inactive lineage, missing
trust and all three trust policies, no partial-prefix return, both composition
variants, both spaces authorized in one loadout, and unchanged valid composition.
They use an adversarial provider double. They do not assert that the real
OctaSoma adapter has returned inconsistent observations or that a network leak
was exploited.

This is a library-boundary repair. It does not authenticate tenants, bind payload
bytes cryptographically, make admission types unforgeable or finish the durable
stdio server lifecycle in issues #135/#136.

## Reconciled delivery baseline

The earlier September 15 audit froze Enterprise at `fe94d534`. GitHub main was
subsequently read at `a9cbd8a0e371f96ad7b522145e2ca636b7e2c6c5`, where #150 has
already synchronized strict BEIR input validation and repaired the local
serde/serde_json lockfile edges. These are not outstanding delivery tasks.
The source-of-truth BEIR revision remains recorded in `core/UPSTREAM_CCOS_BEIR.json`.

Sources: Memorithm/CCOS-Enterprise at the above main revision, files
`crates/ccos-enterprise-memory/src/governed_recall.rs`,
`crates/ccos-enterprise-mcp/src/served_context.rs`, and PR #150.
Qualification results belong to the exact-head PR checks, not this static contract.
