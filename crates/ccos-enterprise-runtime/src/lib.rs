//! # CCOS Enterprise — the composed admission path
//!
//! `docs/ENTERPRISE_SECURITY_MODEL.md` describes a six-layer product. Until
//! this crate existed, no shipped crate composed any two of those layers: the
//! composition lived only in a `publish = false` test harness, so the
//! behaviour that *only* exists once the pieces are wired together — evaluation
//! order, what a refusal costs, whether a privileged tenant can widen the
//! boundary, whether an authenticated caller can act as somebody else — was
//! shipped by nobody and owned by nobody.
//!
//! This crate is that composition. It adds no product semantics of its own
//! beyond wiring and the invariants named below: every gate is a call into the
//! crate that owns it.
//!
//! ## Evaluation order, and why
//!
//! [`Deployment::admit`] evaluates:
//!
//! 1. **identity** — proof strength first, before anything tenant-specific;
//! 2. **credential binding** — the request must name the actor the credential
//!    proves, and a tenant that actor's org owns. See below; this is the gate
//!    that did not exist;
//! 3. **tenant resolution** — an unknown tenant reaches no gate;
//! 4. **namespace boundary** — *before* every tenant-configurable gate,
//!    because no tenant's roles, allowlists or budgets may ever widen it;
//! 5. **authorization** — deny by default, ungoverned tools included;
//! 6. **justification** — an administrative act needs a reason a human can
//!    read. After authorization on purpose: refusing earlier would tell an
//!    unauthorized prober which tools are sensitive;
//! 7. **model governance**, then **Q-Page activation**;
//! 8. **replay** — a `request_id` already decided returns its prior outcome
//!    rather than being billed twice;
//! 9. **budget** — charged **last**, so a call refused for any other reason
//!    costs the tenant nothing.
//!
//! Both ordering choices are load-bearing and pinned by tests: the boundary is
//! unreachable-around, and no refusal is ever billed.
//!
//! ## The credential binding
//!
//! The predecessor of this crate authenticated one identity and authorized a
//! **different, caller-supplied** one: it read only `AuthenticatedActor`'s
//! *strength*, then keyed RBAC on `request.actor` — a plain client string —
//! and resolved the tenant from `request.tenant`. Nothing bound them, so any
//! token-strength principal could present another actor's name and another
//! tenant's id and act with their permissions against their budget.
//!
//! Here, a request must name the actor its credential proves
//! ([`Refusal::ActorMismatch`]) and a tenant that actor's organization owns
//! ([`Refusal::TenantNotOwnedByOrg`]). That second rule is what [`OrgId`] is
//! for; before this crate it was carried on every credential and read by
//! nothing.
//!
//! ## Layer 6, and where it lives
//!
//! `docs/ENTERPRISE_SECURITY_MODEL.md` calls layer 6 "administrative acts
//! validated and journaled with justification". `ccos_enterprise_admin`
//! implemented the rule — for an `AdminAction` type nothing in the product
//! constructed — while this path forwarded and journaled the deployment's one
//! administrative tool with no "why" at all. The layer was enforced on a
//! surface nobody called and absent from the one everybody called.
//!
//! [`Deployment::require_justification`] marks a governed tool as an
//! administrative act. The predicate is
//! `ccos_enterprise_admin::is_written_justification` **itself**, not a copy:
//! the workspace already carries one duplicated predicate that agrees only by
//! luck, and the rule deciding whether a privileged act is recorded is not the
//! place for a second.
//!
//! ## What this crate bounds, and what it does not
//!
//! The audit journal is an in-memory **buffer** with a hard capacity
//! ([`Deployment::with_audit_capacity`]). When it fills, the oldest records are
//! dropped and counted ([`Deployment::audit_dropped`]), and a metric moves.
//! That is a deliberate, announced loss, and it is **not** an audit story on
//! its own: a compliance-grade deployment must flush this buffer to durable
//! storage. Dropping is the honest failure mode for a bounded buffer; growing
//! without bound is not, and the unbounded predecessor let an unauthenticated
//! caller retain 1.15 GiB across five million refused calls.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use ccos_enterprise_auth::{AuthStrength, AuthenticatedActor, OrgId};
use ccos_enterprise_gateway::{classify, Disposition, GatewayRequest};
use ccos_enterprise_observability::CounterRegistry;
use ccos_enterprise_policy::{ModelAllowlist, PolicyDecision, TokenBudget};
use ccos_enterprise_qpages::{AdvancedQPageVariant, QPageRegistry};
use ccos_enterprise_rbac::{Permission, Role, RoleBook};
use ccos_enterprise_tenancy::{TenantId, TenantScope};

/// Longest identifier the runtime will record verbatim. Tenant and actor
/// names arrive from the wire; the gateway bounds tool names, nothing bounded
/// these, and an unauthenticated caller could make every audit record a
/// megabyte wide.
pub const MAX_IDENTIFIER_BYTES: usize = 128;

/// Default ceiling on the in-memory audit buffer. See the module docs: this
/// bounds memory, it does not substitute for durable storage.
pub const DEFAULT_AUDIT_CAPACITY: usize = 100_000;

/// How many decided `request_id`s are remembered per deployment for replay
/// suppression. Bounded for the same reason as the journal.
pub const DEFAULT_REPLAY_MEMORY: usize = 65_536;

/// Why a call did not reach Core. Every variant is an announced refusal — the
/// product never fails open and never fails silently.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Refusal {
    /// The caller's identity was not proven to the required strength.
    Unauthenticated,
    /// The request names an actor other than the one the credential proves.
    ActorMismatch,
    /// The credential's organization does not own the requested tenant.
    TenantNotOwnedByOrg,
    /// An identifier on the request is empty, oversized or not canonical.
    MalformedRequest(String),
    /// No such tenant in this deployment.
    UnknownTenant,
    /// The gateway placed the tool outside the Enterprise boundary.
    OutsideBoundary(String),
    /// No permission was ever declared for this tool (deny by default).
    ToolNotGoverned,
    /// The actor holds no role granting the tool's permission.
    PermissionDenied,
    /// The model is not on this tenant's allowlist.
    ModelNotAllowed,
    /// The call needs an advanced Q-Page variant this tenant has not activated.
    VariantNotActivated,
    /// The call would exceed the tenant's token budget.
    BudgetExhausted,
    /// The tool is an administrative act and the call carried no legible
    /// reason. See [`Deployment::require_justification`].
    JustificationRequired,
}

/// The outcome of one admission decision, as journaled.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Outcome {
    Forwarded,
    Refused(Refusal),
}

impl Outcome {
    pub fn is_forwarded(&self) -> bool {
        matches!(self, Outcome::Forwarded)
    }

    pub fn refusal(&self) -> Option<&Refusal> {
        match self {
            Outcome::Refused(r) => Some(r),
            Outcome::Forwarded => None,
        }
    }
}

/// One journaled decision.
///
/// Carries what an operator needs to reconcile the meter against the journal:
/// the **sequence** (so a concurrent journal can be replayed in the order the
/// deployment actually decided) and the **cost** actually charged, which is
/// `0` for every refusal. The predecessor had neither, so no amount of
/// auditing could reconcile the ledger and two interleavings produced two
/// journals that could not reproduce one another.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuditRecord {
    /// Monotonic, assigned under the same borrow that decided.
    pub sequence: u64,
    pub request_id: String,
    pub tenant: String,
    pub actor: String,
    pub tool: String,
    /// Tokens actually charged. Always `0` for a refusal.
    pub cost: u64,
    /// The reason the caller gave, for an act that needed one.
    ///
    /// `None` for the overwhelming majority of traffic, which is not
    /// administrative. When the tool *is* administrative this is `Some` on
    /// every forwarded record, because the call could not have been admitted
    /// otherwise — which is the whole point of the field.
    pub justification: Option<String>,
    pub outcome: Outcome,
}

/// Per-tenant governed state. Nothing here is shared between tenants.
///
/// The ledger is **private**: it was `pub` and directly assignable, so
/// `tenant_mut(..).budget.spent = 0` rewound the meter with nothing journaled.
pub struct TenantState {
    budget: TokenBudget,
    models: ModelAllowlist,
    qpages: QPageRegistry,
}

impl TenantState {
    pub fn new(token_limit: u64) -> Self {
        Self {
            budget: TokenBudget::new(token_limit),
            models: ModelAllowlist::default(),
            qpages: QPageRegistry::default(),
        }
    }

    pub fn allow_model(&mut self, model: &str) -> &mut Self {
        self.models.0.insert(model.to_string());
        self
    }

    pub fn activate(&mut self, variant: AdvancedQPageVariant) -> &mut Self {
        self.qpages.activate(variant);
        self
    }

    /// Tokens charged to this tenant so far.
    pub fn spent(&self) -> u64 {
        self.budget.spent
    }

    /// The tenant's ceiling.
    pub fn limit(&self) -> u64 {
        self.budget.limit
    }
}

/// One call presented at the gateway.
pub struct Call<'a> {
    /// The **verified** identity. Its actor and org are what authorization
    /// keys on; the request must agree with both.
    pub actor: &'a AuthenticatedActor,
    pub request: &'a GatewayRequest,
    pub model: &'a str,
    pub cost_tokens: u64,
    /// Set when the call needs an advanced Q-Page variant; `None` uses only
    /// Core's standard primitives, which every tenant has.
    pub variant: Option<AdvancedQPageVariant>,
    /// Why the caller is performing an administrative act.
    ///
    /// Required — and required to be *legible* — for any tool the deployment
    /// has marked with [`Deployment::require_justification`]. Ignored for
    /// every other tool, and journaled either way when present, so a reason
    /// offered voluntarily is still recorded.
    pub justification: Option<&'a str>,
}

/// `TenantScope`'s key form: the tenant is part of every key, so there is no
/// way to name a cell without naming its tenant.
type TenantScopeKey = (TenantId, String);

/// A running Enterprise deployment.
pub struct Deployment {
    tenants: BTreeMap<TenantId, TenantState>,
    /// Which organization owns each tenant. The credential's org must match
    /// before any tenant-specific gate is consulted.
    tenant_owner: BTreeMap<TenantId, OrgId>,
    roles: RoleBook,
    /// tool → the permission it requires. A tool absent from this map is
    /// refused: governance is opt-in, exposure is not.
    governed_tools: BTreeMap<String, Permission>,
    /// Tools that are administrative acts: admitted only with a legible
    /// reason, which is then journaled with the decision.
    justification_required: BTreeSet<String>,
    /// Tenant-scoped storage, standing in for Core's memory roots.
    store: BTreeMap<TenantScopeKey, String>,
    metrics: CounterRegistry,
    audit: VecDeque<AuditRecord>,
    audit_capacity: usize,
    audit_dropped: u64,
    next_sequence: u64,
    /// Decided request ids, newest last, bounded by `replay_memory`.
    decided: BTreeSet<(TenantId, String)>,
    decided_order: VecDeque<(TenantId, String)>,
    replay_memory: usize,
    required_strength: AuthStrength,
}

impl Default for Deployment {
    fn default() -> Self {
        Self::new()
    }
}

impl Deployment {
    /// A deployment that demands at least token-strength identity — the
    /// floor, not the ceiling (see [`Deployment::require_strength`]).
    pub fn new() -> Self {
        Self {
            tenants: BTreeMap::new(),
            tenant_owner: BTreeMap::new(),
            roles: RoleBook::default(),
            governed_tools: BTreeMap::new(),
            justification_required: BTreeSet::new(),
            store: BTreeMap::new(),
            metrics: CounterRegistry::default(),
            audit: VecDeque::new(),
            audit_capacity: DEFAULT_AUDIT_CAPACITY,
            audit_dropped: 0,
            next_sequence: 0,
            decided: BTreeSet::new(),
            decided_order: VecDeque::new(),
            replay_memory: DEFAULT_REPLAY_MEMORY,
            required_strength: AuthStrength::Token,
        }
    }

    /// Bound the in-memory audit buffer. A capacity of zero keeps no journal
    /// at all, which is a legitimate choice only when records are flushed
    /// elsewhere synchronously.
    pub fn with_audit_capacity(mut self, capacity: usize) -> Self {
        self.audit_capacity = capacity;
        self
    }

    /// Demand a stronger proof of identity for every call.
    pub fn require_strength(&mut self, strength: AuthStrength) -> &mut Self {
        self.required_strength = strength;
        self
    }

    /// Provision a tenant owned by `org`.
    ///
    /// Refuses to overwrite a live tenant: the predecessor was a bare
    /// `insert`, so re-provisioning silently zeroed a running tenant's ledger,
    /// allowlist and activations while the journal still showed its forwarded
    /// calls. Returns `false` and changes nothing when the tenant exists.
    pub fn add_tenant(&mut self, org: &str, tenant: &str, state: TenantState) -> bool {
        let id = TenantId(tenant.to_string());
        if self.tenants.contains_key(&id) {
            return false;
        }
        self.tenant_owner.insert(id.clone(), OrgId(org.to_string()));
        self.tenants.insert(id, state);
        true
    }

    pub fn tenant_mut(&mut self, tenant: &str) -> Option<&mut TenantState> {
        self.tenants.get_mut(&TenantId(tenant.to_string()))
    }

    pub fn add_role(&mut self, name: &str, permissions: &[&str]) -> &mut Self {
        let mut role = Role {
            name: name.to_string(),
            ..Default::default()
        };
        for p in permissions {
            role.permissions.insert(Permission(p.to_string()));
        }
        self.roles.add_role(role);
        self
    }

    /// Assign a role. Returns false (and grants nothing) for unknown roles —
    /// the RBAC crate's fail-closed rule, surfaced here.
    pub fn assign(&mut self, actor: &str, role: &str) -> bool {
        self.roles.assign(actor, role)
    }

    /// Declare which permission a tool requires. Undeclared tools are refused.
    /// Mark a governed tool as an **administrative act**: it is admitted only
    /// when the call carries a reason a human could read, and that reason is
    /// journaled with the decision.
    ///
    /// This is layer 6 of `docs/ENTERPRISE_SECURITY_MODEL.md` — "administrative
    /// acts validated and journaled with justification" — reaching the composed
    /// path at last. `ccos_enterprise_admin::validate` implemented the rule for
    /// an `AdminAction` type nothing in the product constructed; meanwhile the
    /// deployment's one administrative tool was forwarded and journaled with no
    /// "why" at all. The layer was enforced on a surface nobody called and
    /// absent from the one everybody called.
    ///
    /// The predicate is `ccos_enterprise_admin::is_written_justification`, not
    /// a copy of it: there is one definition of "legible" in the product.
    pub fn require_justification(&mut self, tool: &str) -> &mut Self {
        self.justification_required.insert(tool.to_string());
        self
    }

    /// Whether a tool is an administrative act in this deployment.
    pub fn requires_justification(&self, tool: &str) -> bool {
        self.justification_required.contains(tool)
    }

    pub fn govern_tool(&mut self, tool: &str, permission: &str) -> &mut Self {
        self.governed_tools
            .insert(tool.to_string(), Permission(permission.to_string()));
        self
    }

    // ── Tenant-scoped storage ────────────────────────────────────────────

    /// Write through a tenant scope. The scope carries the tenant, so a
    /// caller cannot address a cell without saying whose it is.
    pub fn put(&mut self, scope: &TenantScope<String>, value: &str) {
        self.store.insert(
            (scope.tenant.clone(), scope.inner.clone()),
            value.to_string(),
        );
    }

    /// Read through a tenant scope. A scope for tenant B never reaches a cell
    /// written under tenant A, however identical the inner key.
    pub fn get(&self, scope: &TenantScope<String>) -> Option<&str> {
        self.store
            .get(&(scope.tenant.clone(), scope.inner.clone()))
            .map(String::as_str)
    }

    /// Every cell visible to a tenant — the shape a cross-tenant leak would
    /// have to show up in.
    pub fn cells_of(&self, tenant: &str) -> Vec<(&str, &str)> {
        let tenant = TenantId(tenant.to_string());
        self.store
            .range((tenant.clone(), String::new())..)
            .take_while(|((t, _), _)| *t == tenant)
            .map(|((_, k), v)| (k.as_str(), v.as_str()))
            .collect()
    }

    // ── The admission decision ───────────────────────────────────────────

    /// Run one call through every gate, journal the outcome, and return it.
    ///
    /// See the module docs for the order. The two rules worth restating: the
    /// **budget is charged last**, so a call refused by any other gate costs
    /// the tenant nothing; and the **credential is checked against the
    /// request** before any tenant state is touched.
    pub fn admit(&mut self, call: Call<'_>) -> Outcome {
        let (outcome, cost) = self.decide(&call);
        self.metrics.inc("gateway.requests", 1);
        match &outcome {
            Outcome::Forwarded => self.metrics.inc("gateway.forwarded", 1),
            Outcome::Refused(r) => {
                self.metrics.inc("gateway.refused", 1);
                self.metrics.inc(&format!("gateway.refused.{}", tag(r)), 1);
            }
        }
        self.journal(&call, &outcome, cost);
        outcome
    }

    /// Append one record, dropping the oldest if the buffer is full.
    fn journal(&mut self, call: &Call<'_>, outcome: &Outcome, cost: u64) {
        if self.audit_capacity == 0 {
            self.audit_dropped += 1;
            self.metrics.inc("audit.dropped", 1);
            return;
        }
        while self.audit.len() >= self.audit_capacity {
            self.audit.pop_front();
            self.audit_dropped += 1;
            self.metrics.inc("audit.dropped", 1);
        }
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        self.audit.push_back(AuditRecord {
            sequence,
            // Truncated on purpose: these arrive from the wire, and an
            // oversized identifier is already a refusal, so the record only
            // needs enough to identify the attempt.
            request_id: clamp(&call.request.request_id),
            tenant: clamp(&call.request.tenant),
            actor: clamp(&call.request.actor),
            tool: clamp(&call.request.tool),
            cost,
            // Recorded whenever offered, not only when demanded: a reason
            // given voluntarily is still evidence, and dropping it would make
            // the trail depend on configuration rather than on what happened.
            justification: call.justification.map(clamp),
            outcome: outcome.clone(),
        });
    }

    /// Returns the outcome and the tokens actually charged for it.
    fn decide(&mut self, call: &Call<'_>) -> (Outcome, u64) {
        let refuse = |r: Refusal| (Outcome::Refused(r), 0u64);

        // 1. Identity.
        if call.actor.strength < self.required_strength {
            return refuse(Refusal::Unauthenticated);
        }

        // 2. Well-formed identifiers, before they are compared or stored.
        for (what, value) in [
            ("tenant", &call.request.tenant),
            ("actor", &call.request.actor),
            ("request_id", &call.request.request_id),
        ] {
            if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
                return refuse(Refusal::MalformedRequest(what.to_string()));
            }
        }

        // 3. The credential binds the request. Checked before tenant
        //    resolution so a probe cannot enumerate tenants by their refusal.
        if call.request.actor != call.actor.actor.0 {
            return refuse(Refusal::ActorMismatch);
        }
        let tenant_id = TenantId(call.request.tenant.clone());
        match self.tenant_owner.get(&tenant_id) {
            None => return refuse(Refusal::UnknownTenant),
            Some(owner) if *owner != call.actor.org => return refuse(Refusal::TenantNotOwnedByOrg),
            Some(_) => {}
        }
        if !self.tenants.contains_key(&tenant_id) {
            return refuse(Refusal::UnknownTenant);
        }

        // 4. Namespace boundary, BEFORE anything a tenant can configure.
        if let Disposition::Reject(why) = classify(call.request) {
            return refuse(Refusal::OutsideBoundary(why));
        }

        // 5. Authorization: deny by default, ungoverned tools included. Keyed
        //    on the VERIFIED actor, never on the request's copy of it.
        let Some(permission) = self.governed_tools.get(&call.request.tool) else {
            return refuse(Refusal::ToolNotGoverned);
        };
        if !self.roles.allows(&call.actor.actor.0, permission) {
            return refuse(Refusal::PermissionDenied);
        }

        // 5b. Administrative acts need a recorded reason.
        //
        // Placed *after* authorization on purpose: "this act needs a reason" is
        // only a meaningful answer to a caller who is entitled to perform it,
        // and refusing earlier would tell an unauthorized prober which tools
        // are sensitive. Placed *before* the budget, like every other refusal,
        // so a missing reason costs the tenant nothing.
        if self.justification_required.contains(&call.request.tool)
            && !ccos_enterprise_admin::is_written_justification(call.justification)
        {
            return refuse(Refusal::JustificationRequired);
        }

        // 6. Model governance, then Q-Page activation.
        let state = self
            .tenants
            .get_mut(&tenant_id)
            .expect("tenant presence checked above");
        if state.models.evaluate(call.model) != PolicyDecision::Allow {
            return refuse(Refusal::ModelNotAllowed);
        }
        if let Some(variant) = call.variant {
            if !state.qpages.is_active(variant) {
                return refuse(Refusal::VariantNotActivated);
            }
        }

        // 7. Replay suppression. `request_id` is documented as an idempotency
        //    key; nothing read it, so a retried request was billed again.
        let key = (tenant_id.clone(), call.request.request_id.clone());
        if self.decided.contains(&key) {
            self.metrics.inc("gateway.replayed", 1);
            return (Outcome::Forwarded, 0);
        }

        // 8. Budget, last: a refusal above never reaches this line.
        let charged = match state.budget.charge(call.cost_tokens) {
            PolicyDecision::Allow => call.cost_tokens,
            _ => return refuse(Refusal::BudgetExhausted),
        };
        self.remember(key);
        (Outcome::Forwarded, charged)
    }

    /// Record a decided request id, evicting the oldest past the bound.
    fn remember(&mut self, key: (TenantId, String)) {
        if self.replay_memory == 0 {
            return;
        }
        while self.decided_order.len() >= self.replay_memory {
            if let Some(old) = self.decided_order.pop_front() {
                self.decided.remove(&old);
            }
        }
        self.decided.insert(key.clone());
        self.decided_order.push_back(key);
    }

    // ── Observation ──────────────────────────────────────────────────────

    /// Tokens charged to a tenant. `None` for a tenant this deployment does
    /// not have — distinguishable from a tenant that has spent nothing, which
    /// the predecessor's bare `0` was not.
    pub fn spent(&self, tenant: &str) -> Option<u64> {
        self.tenants
            .get(&TenantId(tenant.to_string()))
            .map(TenantState::spent)
    }

    pub fn audit(&self) -> impl Iterator<Item = &AuditRecord> {
        self.audit.iter()
    }

    /// How many records the buffer has dropped. Non-zero means the journal is
    /// incomplete and must be read from durable storage instead.
    pub fn audit_dropped(&self) -> u64 {
        self.audit_dropped
    }

    /// The audit trail for one tenant, in decision order.
    pub fn audit_of(&self, tenant: &str) -> Vec<&AuditRecord> {
        self.audit.iter().filter(|r| r.tenant == tenant).collect()
    }

    /// Deterministic metrics snapshot (see `CounterRegistry::export`).
    pub fn metrics(&self) -> Vec<(String, u64)> {
        self.metrics
            .export()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect()
    }
}

/// Truncate an identifier to what a record needs, on a character boundary.
fn clamp(value: &str) -> String {
    if value.len() <= MAX_IDENTIFIER_BYTES {
        return value.to_string();
    }
    let mut end = MAX_IDENTIFIER_BYTES;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

/// Stable, low-cardinality label for a refusal — metric names must not carry
/// unbounded strings.
fn tag(r: &Refusal) -> &'static str {
    match r {
        Refusal::Unauthenticated => "unauthenticated",
        Refusal::ActorMismatch => "actor_mismatch",
        Refusal::TenantNotOwnedByOrg => "tenant_not_owned",
        Refusal::MalformedRequest(_) => "malformed_request",
        Refusal::UnknownTenant => "unknown_tenant",
        Refusal::OutsideBoundary(_) => "outside_boundary",
        Refusal::ToolNotGoverned => "tool_not_governed",
        Refusal::PermissionDenied => "permission_denied",
        Refusal::ModelNotAllowed => "model_not_allowed",
        Refusal::VariantNotActivated => "variant_not_activated",
        Refusal::BudgetExhausted => "budget_exhausted",
        Refusal::JustificationRequired => "justification_required",
    }
}

// ── Snapshot and restore ─────────────────────────────────────────────────

/// Schema tag written into every snapshot. A snapshot whose tag this build
/// does not recognise is refused, never coerced: a governance ledger read
/// under the wrong shape is worse than no ledger at all.
pub const SNAPSHOT_SCHEMA: &str = "ccos.enterprise.deployment/v1";

/// One tenant's governed state, as plain data.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TenantSnapshot {
    pub owner: String,
    pub budget: TokenBudget,
    pub models: ModelAllowlist,
    pub qpages: QPageRegistry,
}

/// A deployment's governed state, as plain data.
///
/// This is the boundary between the runtime and durable storage: the runtime
/// owns the *shape* of its state and the invariants that make it legal, and
/// `ccos-enterprise-store` owns bytes, atomicity and corruption. Neither
/// crate reaches into the other's job.
///
/// What is **not** here, deliberately: the audit buffer, the replay memory and
/// the decision counter. Those are rebuilt by replaying the journal from
/// [`DeploymentSnapshot::sequence_watermark`], so there is exactly one
/// authority for the ordering of decisions and it is the journal.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeploymentSnapshot {
    pub schema: String,
    /// The sequence the next decision will take *as of this snapshot*. The
    /// journal is replayed from here on restore.
    pub sequence_watermark: u64,
    /// Records evicted from the in-memory buffer before this snapshot. Carried
    /// so a restored deployment cannot understate what it has already lost.
    pub audit_dropped: u64,
    pub required_strength: AuthStrength,
    pub tenants: BTreeMap<String, TenantSnapshot>,
    pub roles: RoleBook,
    pub governed_tools: BTreeMap<String, Permission>,
    /// Tools that are administrative acts. Persisted because a restart that
    /// forgot them would silently stop demanding reasons.
    #[serde(default)]
    pub justification_required: BTreeSet<String>,
    /// Tenant-scoped cells, as `(tenant, key, value)` triples.
    pub cells: Vec<(String, String, String)>,
}

/// Why a snapshot was refused. Every variant is a **fail-closed** outcome: a
/// deployment that cannot be restored exactly must not start approximately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreError {
    /// The snapshot was written by a build with a different state shape.
    SchemaMismatch { found: String, expected: String },
    /// A ledger holding `spent > limit` is a state `charge` cannot produce, so
    /// the file was edited or corrupted. Accepting it would hand the tenant a
    /// budget the product never granted — or a negative one.
    LedgerOverLimit {
        tenant: String,
        spent: u64,
        limit: u64,
    },
    /// A tenant with no owning organization can never pass the credential
    /// binding, so it is unreachable state that will silently refuse every
    /// call — indistinguishable, to an operator, from a permissions bug.
    TenantWithoutOwner { tenant: String },
    /// An identifier that `admit` would refuse as malformed must not be
    /// installable through the back door.
    MalformedIdentifier { what: String, value: String },
    /// A journaled record whose tenant no longer exists cannot be re-applied,
    /// so the ledger it implies cannot be reproduced.
    JournalTenantUnknown { sequence: u64, tenant: String },
    /// The journal does not continue the snapshot: replaying it would either
    /// skip decisions or double-count them.
    JournalDiscontinuity { expected: u64, found: u64 },
}

impl std::fmt::Display for RestoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SchemaMismatch { found, expected } => {
                write!(f, "snapshot schema {found:?}, this build reads {expected:?}")
            }
            Self::LedgerOverLimit {
                tenant,
                spent,
                limit,
            } => write!(
                f,
                "tenant {tenant:?} has spent {spent} of a {limit} limit — \
                 a state `charge` cannot produce"
            ),
            Self::TenantWithoutOwner { tenant } => {
                write!(f, "tenant {tenant:?} has no owning organization")
            }
            Self::MalformedIdentifier { what, value } => {
                write!(f, "{what} {value:?} is empty or over the identifier bound")
            }
            Self::JournalTenantUnknown { sequence, tenant } => write!(
                f,
                "journal record {sequence} names tenant {tenant:?}, which the snapshot does not have"
            ),
            Self::JournalDiscontinuity { expected, found } => write!(
                f,
                "journal resumes at sequence {found}, snapshot expects {expected}"
            ),
        }
    }
}

impl std::error::Error for RestoreError {}

fn check_identifier(what: &str, value: &str) -> Result<(), RestoreError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        return Err(RestoreError::MalformedIdentifier {
            what: what.to_string(),
            value: clamp(value),
        });
    }
    Ok(())
}

impl Deployment {
    /// Capture the governed state. Cheap enough to take on every admin change
    /// and small enough to write atomically; the journal carries the volume.
    pub fn snapshot(&self) -> DeploymentSnapshot {
        DeploymentSnapshot {
            schema: SNAPSHOT_SCHEMA.to_string(),
            sequence_watermark: self.next_sequence,
            audit_dropped: self.audit_dropped,
            required_strength: self.required_strength,
            tenants: self
                .tenants
                .iter()
                .map(|(id, state)| {
                    (
                        id.0.clone(),
                        TenantSnapshot {
                            owner: self
                                .tenant_owner
                                .get(id)
                                .map(|o| o.0.clone())
                                .unwrap_or_default(),
                            budget: state.budget.clone(),
                            models: state.models.clone(),
                            qpages: state.qpages.clone(),
                        },
                    )
                })
                .collect(),
            roles: self.roles.clone(),
            governed_tools: self.governed_tools.clone(),
            justification_required: self.justification_required.clone(),
            cells: self
                .store
                .iter()
                .map(|((t, k), v)| (t.0.clone(), k.clone(), v.clone()))
                .collect(),
        }
    }

    /// Rebuild a deployment from a snapshot, then replay `journal` on top.
    ///
    /// The journal is the authority for ordering and for anything decided
    /// after the snapshot was taken, so a crash between the last snapshot and
    /// the last decision loses nothing: the tail is re-applied here. Only the
    /// **cost** is re-applied — the decision itself is not re-made, because
    /// re-deciding against restored state could produce a different answer
    /// (a role revoked in between, say) and rewrite history.
    ///
    /// Every failure is fail-closed. In particular a ledger holding
    /// `spent > limit` is refused rather than clamped: clamping would silently
    /// hand a tenant capacity nobody granted.
    pub fn restore(
        snapshot: DeploymentSnapshot,
        journal: &[AuditRecord],
    ) -> Result<Self, RestoreError> {
        if snapshot.schema != SNAPSHOT_SCHEMA {
            return Err(RestoreError::SchemaMismatch {
                found: snapshot.schema,
                expected: SNAPSHOT_SCHEMA.to_string(),
            });
        }

        let mut d = Deployment::new();
        d.required_strength = snapshot.required_strength;
        d.roles = snapshot.roles;
        d.governed_tools = snapshot.governed_tools;
        d.justification_required = snapshot.justification_required;
        d.audit_dropped = snapshot.audit_dropped;

        for (name, t) in snapshot.tenants {
            check_identifier("tenant", &name)?;
            if t.owner.is_empty() {
                return Err(RestoreError::TenantWithoutOwner { tenant: name });
            }
            if t.budget.spent > t.budget.limit {
                return Err(RestoreError::LedgerOverLimit {
                    tenant: name,
                    spent: t.budget.spent,
                    limit: t.budget.limit,
                });
            }
            let id = TenantId(name);
            d.tenant_owner.insert(id.clone(), OrgId(t.owner));
            d.tenants.insert(
                id,
                TenantState {
                    budget: t.budget,
                    models: t.models,
                    qpages: t.qpages,
                },
            );
        }

        for (tenant, key, value) in snapshot.cells {
            d.store.insert((TenantId(tenant), key), value);
        }

        // Replay the journal.
        //
        // Two different things happen to a record, and the distinction is the
        // whole correctness argument:
        //
        // * **cost** is applied only at or after `sequence_watermark`, because
        //   the snapshot's ledger already folded in everything before it.
        //   Re-applying those would bill a tenant twice for one call.
        // * **everything else** — the audit buffer, the counters and the
        //   replay memory — is rebuilt from the *whole* journal, because the
        //   snapshot deliberately does not carry them. Skipping the older
        //   records would understate `gateway.requests` and hand back a trail
        //   that starts at the last checkpoint rather than at the beginning.
        //
        // Sequences must be dense and ascending throughout. A gap means
        // decisions were lost; a repeat means one would be counted twice.
        // Both are refusals rather than repairs.
        let mut next = journal.first().map(|r| r.sequence).unwrap_or(0);
        for record in journal {
            if record.sequence != next {
                return Err(RestoreError::JournalDiscontinuity {
                    expected: next,
                    found: record.sequence,
                });
            }
            next = record.sequence + 1;

            let tenant = TenantId(record.tenant.clone());
            if record.cost > 0 && record.sequence >= snapshot.sequence_watermark {
                let Some(state) = d.tenants.get_mut(&tenant) else {
                    return Err(RestoreError::JournalTenantUnknown {
                        sequence: record.sequence,
                        tenant: record.tenant.clone(),
                    });
                };
                if state.budget.charge(record.cost) != PolicyDecision::Allow {
                    return Err(RestoreError::LedgerOverLimit {
                        tenant: record.tenant.clone(),
                        spent: state.budget.spent.saturating_add(record.cost),
                        limit: state.budget.limit,
                    });
                }
            }
            // A forwarded decision holds its request id against replay, and
            // the buffer and counters are rebuilt exactly as `admit` left them.
            if record.outcome.is_forwarded() {
                d.remember((tenant, record.request_id.clone()));
            }
            d.metrics.inc("gateway.requests", 1);
            match &record.outcome {
                Outcome::Forwarded => d.metrics.inc("gateway.forwarded", 1),
                Outcome::Refused(r) => {
                    d.metrics.inc("gateway.refused", 1);
                    d.metrics.inc(&format!("gateway.refused.{}", tag(r)), 1);
                }
            }
            while d.audit.len() >= d.audit_capacity {
                d.audit.pop_front();
                d.audit_dropped += 1;
                d.metrics.inc("audit.dropped", 1);
            }
            if d.audit_capacity > 0 {
                d.audit.push_back(record.clone());
            } else {
                d.audit_dropped += 1;
                d.metrics.inc("audit.dropped", 1);
            }
        }
        d.next_sequence = next;
        Ok(d)
    }
}

// ── Construction helpers ─────────────────────────────────────────────────

/// A `GatewayRequest` with the boring fields filled in.
pub fn request(tenant: &str, actor: &str, tool: &str, request_id: &str) -> GatewayRequest {
    GatewayRequest {
        tenant: tenant.to_string(),
        actor: actor.to_string(),
        tool: tool.to_string(),
        request_id: request_id.to_string(),
    }
}

/// An authenticated actor at the given strength.
pub fn actor(org: &str, name: &str, strength: AuthStrength) -> AuthenticatedActor {
    use ccos_enterprise_auth::ActorId;
    AuthenticatedActor {
        org: OrgId(org.to_string()),
        actor: ActorId(name.to_string()),
        strength,
    }
}

/// A two-tenant deployment resembling a real install: `acme` and `globex`,
/// both owned by the `memorithm` organization, each with its own budget,
/// allowlist and Q-Page activations, plus the roles and governed tools a
/// Hermes session would use.
pub fn two_tenant_deployment() -> Deployment {
    let mut d = Deployment::new();
    d.add_role("reader", &["memory.read"])
        .add_role("writer", &["memory.read", "memory.write"])
        .add_role("operator", &["memory.read", "memory.write", "policy.admin"])
        .govern_tool("memory.recall", "memory.read")
        .govern_tool("memory.ingest", "memory.write")
        .govern_tool("policy.set", "policy.admin")
        .govern_tool("audit.query", "memory.read")
        // `policy.set` is the deployment's one administrative act: it changes
        // what the tenant is allowed to do. It is the tool `stress_admin_fuzz`
        // used to demonstrate that layer 6 was enforced nowhere.
        .require_justification("policy.set");

    let mut acme = TenantState::new(1_000);
    acme.allow_model("claude-opus")
        .activate(AdvancedQPageVariant::Hierarchical);
    d.add_tenant("memorithm", "acme", acme);

    let mut globex = TenantState::new(500);
    globex.allow_model("gpt-5");
    d.add_tenant("memorithm", "globex", globex);

    d.assign("alice", "writer");
    d.assign("bob", "reader");
    d.assign("root", "operator");
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_cannot_name_an_actor_the_credential_does_not_prove() {
        let mut d = two_tenant_deployment();
        // bob authenticates, then claims to be alice — who can write.
        let bob = actor("memorithm", "bob", AuthStrength::Token);
        let req = request("acme", "alice", "memory.ingest", "r-1");
        let outcome = d.admit(Call {
            actor: &bob,
            request: &req,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
            justification: None,
        });
        assert_eq!(outcome.refusal(), Some(&Refusal::ActorMismatch));
        assert_eq!(d.spent("acme"), Some(0), "an impersonation costs nothing");
    }

    #[test]
    fn an_org_cannot_reach_a_tenant_it_does_not_own() {
        let mut d = two_tenant_deployment();
        let mut other = TenantState::new(100);
        other.allow_model("claude-opus");
        assert!(d.add_tenant("initech", "hooli", other));
        d.assign("mallory", "reader");

        // mallory is genuinely authenticated, in the wrong organization.
        let mallory = actor("initech", "mallory", AuthStrength::Token);
        let req = request("acme", "mallory", "memory.recall", "r-1");
        assert_eq!(
            d.admit(Call {
                actor: &mallory,
                request: &req,
                model: "claude-opus",
                cost_tokens: 10,
                variant: None,
                justification: None,
            })
            .refusal(),
            Some(&Refusal::TenantNotOwnedByOrg)
        );
        assert_eq!(d.spent("acme"), Some(0));
    }

    #[test]
    fn re_provisioning_a_live_tenant_is_refused() {
        let mut d = two_tenant_deployment();
        let alice = actor("memorithm", "alice", AuthStrength::Token);
        let req = request("acme", "alice", "memory.ingest", "r-1");
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 400,
            variant: None,
            justification: None,
        });
        assert_eq!(d.spent("acme"), Some(400));

        assert!(
            !d.add_tenant("memorithm", "acme", TenantState::new(9_999)),
            "a live tenant is not silently replaced"
        );
        assert_eq!(d.spent("acme"), Some(400), "the ledger survived");
    }

    #[test]
    fn a_replayed_request_id_is_not_billed_twice() {
        let mut d = two_tenant_deployment();
        let alice = actor("memorithm", "alice", AuthStrength::Token);
        let req = request("acme", "alice", "memory.ingest", "r-same");
        for _ in 0..5 {
            assert_eq!(
                d.admit(Call {
                    actor: &alice,
                    request: &req,
                    model: "claude-opus",
                    cost_tokens: 100,
                    variant: None,
                    justification: None,
                }),
                Outcome::Forwarded
            );
        }
        assert_eq!(
            d.spent("acme"),
            Some(100),
            "billed once, replayed four times"
        );
    }

    #[test]
    fn the_journal_carries_cost_and_a_monotonic_sequence() {
        let mut d = two_tenant_deployment();
        let alice = actor("memorithm", "alice", AuthStrength::Token);
        for (i, (tool, cost)) in [("memory.ingest", 10u64), ("shell.exec", 10)]
            .iter()
            .enumerate()
        {
            let req = request("acme", "alice", tool, &format!("r-{i}"));
            d.admit(Call {
                actor: &alice,
                request: &req,
                model: "claude-opus",
                cost_tokens: *cost,
                variant: None,
                justification: None,
            });
        }
        let trail: Vec<&AuditRecord> = d.audit().collect();
        assert_eq!(trail.len(), 2);
        assert_eq!(trail[0].sequence, 0);
        assert_eq!(trail[1].sequence, 1);
        assert_eq!(trail[0].cost, 10, "the forwarded call carries its cost");
        assert_eq!(trail[1].cost, 0, "a refusal is never billed");
        // The whole journal reconciles the meter.
        let billed: u64 = trail.iter().map(|r| r.cost).sum();
        assert_eq!(Some(billed), d.spent("acme"));
    }

    #[test]
    fn the_audit_buffer_is_bounded_and_says_what_it_dropped() {
        let mut d = Deployment::new().with_audit_capacity(8);
        d.add_role("reader", &["memory.read"])
            .govern_tool("memory.recall", "memory.read");
        let mut t = TenantState::new(10_000);
        t.allow_model("m");
        d.add_tenant("memorithm", "acme", t);
        d.assign("bob", "reader");
        let bob = actor("memorithm", "bob", AuthStrength::Token);

        for i in 0..100 {
            let req = request("acme", "bob", "memory.recall", &format!("r-{i}"));
            d.admit(Call {
                actor: &bob,
                request: &req,
                model: "m",
                cost_tokens: 1,
                variant: None,
                justification: None,
            });
        }
        assert_eq!(d.audit().count(), 8, "the buffer never grows past its cap");
        assert_eq!(d.audit_dropped(), 92, "and it says exactly what it lost");
        // The retained window is the newest, and still ordered.
        let seqs: Vec<u64> = d.audit().map(|r| r.sequence).collect();
        assert_eq!(seqs, (92..100).collect::<Vec<_>>());
    }

    /// Layer 6 reaching the composed path. `policy.set` changes what a tenant
    /// may do; before this it was forwarded and journaled with no "why".
    #[test]
    fn an_administrative_act_needs_a_reason_and_the_reason_is_journaled() {
        let mut d = two_tenant_deployment();
        let root = actor("memorithm", "root", AuthStrength::Strong);
        let req = request("acme", "root", "policy.set", "r-1");

        assert_eq!(
            d.admit(Call {
                actor: &root,
                request: &req,
                model: "claude-opus",
                cost_tokens: 10,
                variant: None,
                justification: None,
            })
            .refusal(),
            Some(&Refusal::JustificationRequired)
        );
        assert_eq!(d.spent("acme"), Some(0), "a missing reason costs nothing");

        // An invisible reason is no reason — the rule is the admin crate's,
        // not a second copy of it.
        for blank in ["", "   ", "\u{200b}", "\u{feff}\t\u{202e}"] {
            let req = request("acme", "root", "policy.set", &format!("r-{blank:?}"));
            assert_eq!(
                d.admit(Call {
                    actor: &root,
                    request: &req,
                    model: "claude-opus",
                    cost_tokens: 10,
                    variant: None,
                    justification: Some(blank),
                })
                .refusal(),
                Some(&Refusal::JustificationRequired),
                "{blank:?} passed as a reason"
            );
        }

        // With a legible reason it is admitted, and the reason is in the trail.
        let req = request("acme", "root", "policy.set", "r-ok");
        assert_eq!(
            d.admit(Call {
                actor: &root,
                request: &req,
                model: "claude-opus",
                cost_tokens: 10,
                variant: None,
                justification: Some("tightening the allowlist after the audit"),
            }),
            Outcome::Forwarded
        );
        let record = d
            .audit()
            .find(|r| r.request_id == "r-ok")
            .expect("journaled");
        assert_eq!(
            record.justification.as_deref(),
            Some("tightening the allowlist after the audit")
        );
        // Every *forwarded* administrative record carries one, necessarily.
        assert!(d
            .audit()
            .filter(|r| r.tool == "policy.set" && r.outcome.is_forwarded())
            .all(|r| r.justification.is_some()));
    }

    /// The gate must not spread. A reason is demanded for the tools marked
    /// administrative and for no others, and it is *recorded* whenever offered
    /// — so the trail reflects what happened, not what was configured.
    #[test]
    fn an_ordinary_tool_neither_demands_a_reason_nor_discards_one() {
        let mut d = two_tenant_deployment();
        let alice = actor("memorithm", "alice", AuthStrength::Token);

        let req = request("acme", "alice", "memory.ingest", "r-plain");
        assert_eq!(
            d.admit(Call {
                actor: &alice,
                request: &req,
                model: "claude-opus",
                cost_tokens: 10,
                variant: None,
                justification: None,
            }),
            Outcome::Forwarded,
            "an ordinary tool must not inherit the requirement"
        );

        let req = request("acme", "alice", "memory.ingest", "r-volunteered");
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
            justification: Some("bulk import, ticket 4471"),
        });
        assert_eq!(
            d.audit()
                .find(|r| r.request_id == "r-volunteered")
                .and_then(|r| r.justification.as_deref()),
            Some("bulk import, ticket 4471"),
            "a reason given voluntarily is still evidence"
        );
        assert!(!d.requires_justification("memory.ingest"));
        assert!(d.requires_justification("policy.set"));
    }

    /// Ordering: the reason is demanded only of a caller entitled to the act.
    /// Asking earlier would tell an unauthorized prober which tools are
    /// sensitive — a free map of the administrative surface.
    #[test]
    fn a_caller_without_the_permission_is_refused_before_being_asked_for_a_reason() {
        let mut d = two_tenant_deployment();
        // bob is a reader; `policy.set` needs `policy.admin`.
        let bob = actor("memorithm", "bob", AuthStrength::Token);
        let req = request("acme", "bob", "policy.set", "r-probe");
        assert_eq!(
            d.admit(Call {
                actor: &bob,
                request: &req,
                model: "claude-opus",
                cost_tokens: 0,
                variant: None,
                justification: None,
            })
            .refusal(),
            Some(&Refusal::PermissionDenied),
            "an unauthorized caller must not learn that this tool is administrative"
        );
    }

    #[test]
    fn an_unknown_tenant_is_distinguishable_from_one_that_spent_nothing() {
        let d = two_tenant_deployment();
        assert_eq!(d.spent("acme"), Some(0));
        assert_eq!(d.spent("nowhere"), None);
    }
}
