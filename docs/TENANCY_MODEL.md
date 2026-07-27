# Tenancy Model

- `TenantId` is the outermost data boundary: memory roots, quotas, policies,
  backups and audit trails are tenant-scoped (`TenantScope<T>`).
- No shared caches keyed without tenant: rescoping is explicit and auditable.
- Tenant lifecycle (create/suspend/delete) is an administrative action
  requiring justification (`ccos-enterprise-admin`).
- Cross-tenant federation is opt-in per Q-Page variant policy
  (`MultiTenantFederated`, inactive by default).
