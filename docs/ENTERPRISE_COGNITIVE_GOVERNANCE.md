# Enterprise Cognitive Governance

Cognitive governance = policies over *cognitive artifacts*, not just requests:

- which Q-Page variants a tenant may activate (`ccos-enterprise-qpages`);
- retention/invalidation obligations per data class (COGNITIVE_RETENTION_POLICY.md);
- contradiction-resolution audit per tenant (who resolved, which policy, when);
- model switching policy per tenant (allowed providers, state-preservation
  verification cadence);
- human approval gates for sensitive cognitive operations
  (HUMAN_APPROVAL_POLICIES.md).
