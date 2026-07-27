# Enterprise Security Model

Layered over CCOS Core's security boundary (never replacing it):

1. **Identity** — every request carries org + actor + strength (`ccos-enterprise-auth`).
2. **Authorization** — RBAC with fail-closed unknown-role refusal (`ccos-enterprise-rbac`).
3. **Tenancy** — typed isolation scopes; cross-tenant access is a type error (`ccos-enterprise-tenancy`).
4. **Policy** — budgets/quotas/allowlists, every decision loggable (`ccos-enterprise-policy`).
5. **Gateway** — namespace boundary: Research Lab namespaces rejected (`ccos-enterprise-gateway`).
6. **Audit** — administrative acts validated and journaled with justification (`ccos-enterprise-admin`).

Invariant: Enterprise ADDS gates; it never WEAKENS a Core guarantee
(determinism, replay, no-process-execution, no RSI/Forge).
