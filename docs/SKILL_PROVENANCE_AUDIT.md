# Skill Provenance Audit

Operator-facing, read-only audit over the validated skill and
observational-trial ledgers (`ccos-enterprise-skills-audit`).

## Contract

- **Tenant-scoped**: a query names exactly one tenant; a cross-tenant query
  is refused.
- **RBAC-governed**: the caller must hold a role granting
  `audit.provenance`. This is deliberately distinct from `memory.read`, the
  permission the model-visible `memory.skills` projection rides on: the audit
  exposes correlation and evidence identifiers the model projection
  withholds, so the two must never share a grant.
- **Read-only**: the audit never mutates a ledger.
- **Bounded**: per-skill row caps and a report cap; aggregate counters always
  cover the whole ledger, and every truncated row set carries `truncated:
  true`.
- **Deterministic**: trials newest-first by durable ordinal, ties by
  identifier; reports in stable skill order.
- **Fail-closed**: the report is derived only from validated registries
  (`SkillRegistry`, `SkillTrialRegistry`), so corrupt or schema-unknown
  ledger state is a refusal, never a guess.
- **Schema-versioned output**: serialized reports carry
  `ccos.enterprise.skill-audit/v1`.
- **No raw content**: no prompts, assistant text, tool input/output, session
  ids or workspace paths. Only the hashed identifiers already validated in
  the ledgers (trial ids, turn keys, evidence hashes) are exposed.
- **Pending trials** contribute no synthetic evidence id.
- **An empty registry** is reported as the explicit fact it is
  (`empty: true`), never fabricated into a report and never an error.
- **Complete operator trail**: the audit request itself is admitted through
  the governed path, so it is journaled, replay-suppressed and budgeted like
  any other tool — an audit of the audit.

## Surface

The capability is exposed on the authenticated stdio front door as the
`audit.provenance` tool (under the `audit.provenance` permission). The
DeepSeek Harness role (`dsh-memory`) does not grant it, so the capability is
never reachable from model context; operators are provisioned the `auditor`
role separately.
