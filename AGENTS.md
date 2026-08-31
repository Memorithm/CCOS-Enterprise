# CCOS Enterprise Agent Bootstrap Contract

Before autonomous coding, Core synchronization, authentication/RBAC/tenancy changes, backup/restore work, governed adapter changes, PR creation, or merge decisions, read:

```bash
git fetch origin agent/ecosystem-roadmap && \
git show origin/agent/ecosystem-roadmap:.agent/CCOS_ENTERPRISE_ECOSYSTEM_ROADMAP.yaml
```

If the roadmap cannot be fetched or read, fail closed for major Core-sync, authorization, tenancy, governance, external-adapter, or merge decisions. Read-only diagnosis is allowed.

CCOS Enterprise is the governed multi-tenant layer around CCOS Core. Do not duplicate Core or allow Enterprise dependencies to backflow into it. Record exact Core lineage for deliberate subtree/sync operations and test both sides.

Research Lab RSI/Forge/generated-code semantics are outside the Enterprise boundary. Raw research, shell, patch, self-modification and code-execution capabilities must not become reachable merely because an adapter exists.

Tenant identity, authorization, quota and audit gates precede external adapter access. Required CI must be green on the exact PR head before merge.

Reread the roadmap at every session start, before Core sync/security/tenancy/backup/gateway changes, before external adapters, and before relevant PR/merge decisions.

Do not merge the roadmap itself into `main` unless the user explicitly requests it.
