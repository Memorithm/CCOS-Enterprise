# CCOS Core lineage and selective synchronization

`core/` is a reviewed embedded lineage of `Memorithm/CCOS-Core`; it is not an
unqualified mirror. Enterprise-specific adapters and product policy remain in
this repository, while general Core fixes are promoted deliberately.

The machine-readable authority is `core/UPSTREAM_CCOS_CORE.json`. It records:

- the exact initial import commit and tree;
- the later metadata-only sync commit and tree;
- the exact upstream commit and tree most recently reviewed;
- every byte-identical imported file and SHA-256 digest;
- Enterprise overlays required to compose the imported files; and
- the complete path inventory and disposition of the reviewed upstream diff.

## Verification

Run the offline contract before every Core-related change:

```sh
python3 scripts/core_sync.py verify
python3 scripts/test_core_sync.py
```

The verifier rejects missing or modified exact files, missing overlay markers,
unsafe manifest paths, duplicate dispositions and any upstream diff path that
has not been classified. CI runs this contract in both the fast and security
workflows. The normal Rust workspace tests additionally exercise the imported
persistence and scanner regressions embedded in the Core source files.

## Reviewing and applying an upstream slice

Use a clean local checkout of `Memorithm/CCOS-Core`. The tool never fetches a
repository or trusts a moving branch:

```sh
python3 scripts/core_sync.py audit --upstream /path/to/CCOS-Core
python3 scripts/core_sync.py sync --upstream /path/to/CCOS-Core
python3 scripts/core_sync.py sync --upstream /path/to/CCOS-Core --apply
```

`audit` proves the recorded commit and tree, reconstructs the complete security
diff, and checks each exact-file digest against the recorded commit. `sync`
without `--apply` is a dry gate. The explicit apply mode copies only the
allowlisted exact files; it never overwrites an Enterprise overlay or expands
the reviewed scope.

To advance the lineage, review the upstream range, update every path disposition
and digest in the manifest, then run Core and Enterprise compatibility tests on
the exact candidate head. General Core changes should be upstreamed to Core
first; Enterprise dependencies must never flow back into Core.

## Current reviewed slice

The current slice imports MEM-02/MEM-03 durable bounded persistence, MEM-04
descriptor-confined bounded workspace scanning, and the backend-neutral memory
port contract. Core-only CI, product documentation, memory-accounting changes,
fuzz metadata and author-policy changes remain owned and validated by Core.
Enterprise preserves its separate OctaSoma feature and governed product gates.
