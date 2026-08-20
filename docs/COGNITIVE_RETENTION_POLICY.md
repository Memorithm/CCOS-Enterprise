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
- **Deletion = invalidation**: enforcement never rewrites or destroys sealed
  history. An expired unsealed item is invalidated with a durable tombstone
  only when its class policy permits invalidation. A sealed item, or a class
  whose policy forbids invalidation, produces `ReportOnly` and is left in
  place.
- **Every enforcement action produces an audit event**: the append-only
  enforcement ledger records tenant, stable item identity, class, item
  creation time, action and the enforcement clock.
- **No global cron assumption as the source of truth**: enforcement is
  invocable deterministically and testably. Any driver (operator, scheduler,
  test) may call `run_once` with an explicit clock.
- **Sensitive retention-policy changes require an approval gate**: there is no
  public unchecked policy writer. `RetentionStore::save_policy_with_approval`
  derives the canonical SHA-256 artifact identity and invokes the supplied
  product approval gate before any disk mutation. The Enterprise conformance
  suite wires that callback to `Deployment::approval_gate` and proves that an
  unrecorded approval leaves the policy absent. The action is always
  `retention.policy.set`; see `docs/HUMAN_APPROVAL_POLICIES.md`.
- **Tenant isolation is fail-closed in both evaluation and persistence**: the
  engine validates the policy and every item against the requested `TenantId`.
  The durable enforcement ledger additionally validates every append and load
  against the tenant stored in the validated retention policy; a mismatch is
  rejected rather than relabelled or ignored.
- **Bounded processing**: one invocation accepts at most `MAX_INPUT_ITEMS`
  input artifacts and emits at most the caller-supplied `batch_limit`, itself
  capped by `MAX_BATCH_LIMIT`, in stable order by class, creation time and item
  identity.
- **Schema-versioned durable policy state** (v1): corrupt state is refused on
  load, never silently reset; an unsupported future schema is refused;
  persistence is crash-safe (write/fsync/rename + directory fsync,
  single-writer kernel lock). A torn final JSONL ledger record is truncated
  before continuation while committed malformed records fail closed.
