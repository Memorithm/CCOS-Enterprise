# CCOS Enterprise repository agent instructions

Before repository changes, fetch and read the persistent off-main product/ecosystem roadmap:

```bash
git fetch origin agent/ecosystem-roadmap && \
git show origin/agent/ecosystem-roadmap:.agent/CCOS_ENTERPRISE_ECOSYSTEM_ROADMAP.yaml
```

Treat root `AGENTS.md` as mandatory bootstrap policy. If the roadmap is unavailable, fail closed for major Core-sync, authorization, tenancy, governance, external-adapter, or merge decisions.

Preserve exact Core lineage, no dependency backflow, tenant isolation, governed adapter boundaries, and the separation from CCOS Research Lab experimentation.
