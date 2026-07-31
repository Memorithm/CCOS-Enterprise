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
//! 6. **model governance**, then **Q-Page activation**;
//! 7. **replay** — a `request_id` already decided returns its prior outcome
//!    rather than being billed twice;
//! 8. **budget** — charged **last**, so a call refused for any other reason
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

/// The outcome of one admission decision, as journaled.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// Monotonic, assigned under the same borrow that decided.
    pub sequence: u64,
    pub request_id: String,
    pub tenant: String,
    pub actor: String,
    pub tool: String,
    /// Tokens actually charged. Always `0` for a refusal.
    pub cost: u64,
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
        .govern_tool("audit.query", "memory.read");

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
            });
        }
        assert_eq!(d.audit().count(), 8, "the buffer never grows past its cap");
        assert_eq!(d.audit_dropped(), 92, "and it says exactly what it lost");
        // The retained window is the newest, and still ordered.
        let seqs: Vec<u64> = d.audit().map(|r| r.sequence).collect();
        assert_eq!(seqs, (92..100).collect::<Vec<_>>());
    }

    #[test]
    fn an_unknown_tenant_is_distinguishable_from_one_that_spent_nothing() {
        let d = two_tenant_deployment();
        assert_eq!(d.spent("acme"), Some(0));
        assert_eq!(d.spent("nowhere"), None);
    }
}
