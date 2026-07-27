# Tenant Memory Isolation

- Memory roots are tenant-scoped (`TenantScope`); there is no global memory pool.
- Cross-tenant leakage tests (CI): a recall under tenant A must return zero
  tenant-B nodes, under fuzzed adversarial queries.
- Snapshots/journals carry the tenant scope in their manifest; restore
  validates scope before applying.
- Isolation is enforced at the storage boundary, not the application
  boundary (defense in depth).
