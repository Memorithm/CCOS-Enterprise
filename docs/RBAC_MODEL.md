# RBAC Model

- `Permission` names a governed capability (MCP tool class, admin action, data class).
- `Role` is an ordered permission set; `RoleBook` maps actors to roles.
- Deny by default: unknown roles cannot be assigned; unlisted permissions deny.
- ABAC: deferred until a concrete tenant requirement justifies it (charter §4.2).
