# Cognitive Retention Policy

Executable policy behind this document lives in `ccos-enterprise-retention`.

## What is implemented

- **Retention classes per tenant**: `ephemeral_context`, `episodic_journal`,
  `sealed_snapshots`, `compliance_archives` — each governed by an explicit
  retention period; a class with no period never expires.
- **Deterministic evaluation**: `RetentionEngine::run_once(tenant, policy,
  items, now, bound)` is a pure function of its inputs. There is no internal
  counter, no randomness and no dependence on the wall clock inside the
  engine — replaying a run after a crash converges to the same end state,
  and the enforcement ledger is append-only so continuation never duplicates
  effects.
- **Deletion = invalidation**: the Core contract keeps sealed history
  auditable, so enforcement never rewrites or destroys history. An expired
  item is *invalidated* (a durable tombstone) when the policy permits and
  the item is not sealed; a sealed item — or a policy that forbids
  invalidation — is *reported* as expired and left in place, auditable.
- **Every enforcement action produces an audit event**: the append-only
  enforcement ledger records tenant, class, item creation time, action and
  the enforcement clock.
- **No global cron assumption as the source of truth**: enforcement is
  invocable deterministically and testably. Any driver (operator, scheduler,
  test) may call `run_once` with an explicit clock.
- **Sensitive retention-policy changes use approval gates**: policy writes
  flow through the runtime approval engine (`docs/HUMAN_APPROVAL_POLICIES.md`).
- **Tenant isolation**: the engine takes a single `TenantId`; every record
  carries it; there is no cross-tenant path.
- **Bounded processing**: one run examines at most `batch_limit` items, in
  stable order (class, then creation time).
- **Schema-versioned durable policy state** (v1): corrupt state is refused
  on load, never silently reset; an unsupported future schema is refused;
  persistence is crash-safe (write/fsync/rename + directory fsync,
  single-writer kernel lock).
