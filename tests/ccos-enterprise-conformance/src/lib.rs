//! # The composed Enterprise path
//!
//! Every Enterprise crate ships its own unit tests, and each passes in
//! isolation. But the crates do not depend on one another: nothing in the
//! workspace composes identity, tenancy, authorization, policy and the
//! namespace boundary into the single admission decision the product is
//! *described* as making (`docs/ENTERPRISE_SECURITY_MODEL.md`). The
//! behaviour that only exists once they are wired together — evaluation
//! order, what a refusal costs, whether a privileged tenant can widen the
//! boundary, whether two tenants can ever see each other — was therefore
//! untested, because there was nothing to test it on.
//!
//! This crate is that missing composition, kept deliberately small and
//! honest: it adds **no** product semantics of its own beyond wiring, and
//! every gate below is a call into the crate that owns it. It exists to be
//! exercised (see `tests/`), and doubles as the executable reading of the
//! security model.
//!
//! ## Evaluation order and why
//!
//! `docs/ENTERPRISE_SECURITY_MODEL.md` lists six layers; that list describes
//! what is layered over Core, not the order in which a request meets them.
//! [`Deployment::admit`] evaluates:
//!
//! 1. **identity** — an unauthenticated caller is refused before anything
//!    tenant-specific is consulted;
//! 2. **tenant resolution** — an unknown tenant cannot reach a gate;
//! 3. **namespace boundary** — *before* every tenant-configurable gate,
//!    because no tenant's roles, allowlists or budgets may ever widen it;
//! 4. **authorization** — deny by default, including for tools nobody
//!    declared a permission for;
//! 5. **model governance**, then **Q-Page activation**;
//! 6. **budget** — charged **last**, so a call refused for any other reason
//!    costs the tenant nothing.
//!
//! Both ordering choices are load-bearing and pinned by tests: the boundary
//! is unreachable-around (`tests/adversarial.rs`), and no refusal is ever
//! billed (`tests/governed_path.rs`).

use std::collections::BTreeMap;

use ccos_enterprise_auth::{AuthStrength, AuthenticatedActor};
use ccos_enterprise_gateway::{classify, Disposition, GatewayRequest};
use ccos_enterprise_observability::CounterRegistry;
use ccos_enterprise_policy::{ModelAllowlist, PolicyDecision, TokenBudget};
use ccos_enterprise_qpages::{AdvancedQPageVariant, QPageRegistry};
use ccos_enterprise_rbac::{Permission, Role, RoleBook};
use ccos_enterprise_tenancy::{TenantId, TenantScope};

/// Why a call did not reach Core. Every variant is an announced refusal —
/// the product never fails open and never fails silently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The caller's identity was not proven to the required strength.
    Unauthenticated,
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

/// One journaled decision. Correlated by `request_id`
/// (`docs/HERMES_INTEGRATION.md`: "every tool call is policy-gated and
/// audit-correlated by request id").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub request_id: String,
    pub tenant: String,
    pub actor: String,
    pub tool: String,
    pub outcome: Outcome,
}

/// Per-tenant governed state. Nothing here is shared between tenants — the
/// type says so, and `tests/isolation.rs` proves it.
pub struct TenantState {
    pub budget: TokenBudget,
    pub models: ModelAllowlist,
    pub qpages: QPageRegistry,
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
}

/// One call presented at the gateway.
pub struct Call<'a> {
    pub actor: &'a AuthenticatedActor,
    pub request: &'a GatewayRequest,
    pub model: &'a str,
    pub cost_tokens: u64,
    /// Set when the call needs an advanced Q-Page variant; `None` uses only
    /// Core's standard primitives, which every tenant has.
    pub variant: Option<AdvancedQPageVariant>,
}

/// A running Enterprise deployment: tenants, the role book, the tool
/// governance map, metrics and the audit journal.
pub struct Deployment {
    tenants: BTreeMap<TenantId, TenantState>,
    roles: RoleBook,
    /// tool → the permission it requires. A tool absent from this map is
    /// refused: governance is opt-in, exposure is not.
    governed_tools: BTreeMap<String, Permission>,
    /// Tenant-scoped storage, standing in for Core's memory roots.
    store: BTreeMap<TenantScopeKey, String>,
    metrics: CounterRegistry,
    audit: Vec<AuditRecord>,
    /// The authentication strength this deployment demands.
    required_strength: AuthStrength,
}

/// `TenantScope`'s key form: the tenant is part of every key, so there is no
/// way to name a cell without naming its tenant.
type TenantScopeKey = (TenantId, String);

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
            roles: RoleBook::default(),
            governed_tools: BTreeMap::new(),
            store: BTreeMap::new(),
            metrics: CounterRegistry::default(),
            audit: Vec::new(),
            required_strength: AuthStrength::Token,
        }
    }

    /// Demand a stronger proof of identity for every call.
    pub fn require_strength(&mut self, strength: AuthStrength) -> &mut Self {
        self.required_strength = strength;
        self
    }

    pub fn add_tenant(&mut self, tenant: &str, state: TenantState) -> &mut Self {
        self.tenants.insert(TenantId(tenant.to_string()), state);
        self
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
            .iter()
            .filter(|((t, _), _)| *t == tenant)
            .map(|((_, k), v)| (k.as_str(), v.as_str()))
            .collect()
    }

    // ── The admission decision ───────────────────────────────────────────

    /// Run one call through every gate, journal the outcome, and return it.
    ///
    /// See the module docs for the order and why it is what it is. The one
    /// rule worth restating here: **the budget is charged last**, so a call
    /// refused by any other gate costs the tenant nothing.
    pub fn admit(&mut self, call: Call<'_>) -> Outcome {
        let outcome = self.decide(&call);
        self.metrics.inc("gateway.requests", 1);
        match &outcome {
            Outcome::Forwarded => self.metrics.inc("gateway.forwarded", 1),
            Outcome::Refused(r) => {
                self.metrics.inc("gateway.refused", 1);
                self.metrics.inc(&format!("gateway.refused.{}", tag(r)), 1);
            }
        }
        self.audit.push(AuditRecord {
            request_id: call.request.request_id.clone(),
            tenant: call.request.tenant.clone(),
            actor: call.request.actor.clone(),
            tool: call.request.tool.clone(),
            outcome: outcome.clone(),
        });
        outcome
    }

    fn decide(&mut self, call: &Call<'_>) -> Outcome {
        // 1. Identity.
        if call.actor.strength < self.required_strength {
            return Outcome::Refused(Refusal::Unauthenticated);
        }

        // 2. Tenant resolution. Checked before any gate, and the request's
        //    tenant — not the actor's word — selects the state.
        let tenant_id = TenantId(call.request.tenant.clone());
        if !self.tenants.contains_key(&tenant_id) {
            return Outcome::Refused(Refusal::UnknownTenant);
        }

        // 3. Namespace boundary, BEFORE anything a tenant can configure.
        if let Disposition::Reject(why) = classify(call.request) {
            return Outcome::Refused(Refusal::OutsideBoundary(why));
        }

        // 4. Authorization: deny by default, ungoverned tools included.
        let Some(permission) = self.governed_tools.get(&call.request.tool) else {
            return Outcome::Refused(Refusal::ToolNotGoverned);
        };
        if !self.roles.allows(&call.request.actor, permission) {
            return Outcome::Refused(Refusal::PermissionDenied);
        }

        let state = self
            .tenants
            .get_mut(&tenant_id)
            .expect("tenant presence checked above");

        // 5. Model governance, then Q-Page activation.
        if state.models.evaluate(call.model) != PolicyDecision::Allow {
            return Outcome::Refused(Refusal::ModelNotAllowed);
        }
        if let Some(variant) = call.variant {
            if !state.qpages.is_active(variant) {
                return Outcome::Refused(Refusal::VariantNotActivated);
            }
        }

        // 6. Budget, last: a refusal above never reaches this line.
        match state.budget.charge(call.cost_tokens) {
            PolicyDecision::Allow => Outcome::Forwarded,
            _ => Outcome::Refused(Refusal::BudgetExhausted),
        }
    }

    // ── Observation ──────────────────────────────────────────────────────

    pub fn spent(&self, tenant: &str) -> u64 {
        self.tenants
            .get(&TenantId(tenant.to_string()))
            .map(|t| t.budget.spent)
            .unwrap_or(0)
    }

    pub fn audit(&self) -> &[AuditRecord] {
        &self.audit
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

/// Stable, low-cardinality label for a refusal — metric names must not carry
/// unbounded strings (the registry folds at `MAX_SERIES`, but a label
/// explosion would still bury the useful series).
fn tag(r: &Refusal) -> &'static str {
    match r {
        Refusal::Unauthenticated => "unauthenticated",
        Refusal::UnknownTenant => "unknown_tenant",
        Refusal::OutsideBoundary(_) => "outside_boundary",
        Refusal::ToolNotGoverned => "tool_not_governed",
        Refusal::PermissionDenied => "permission_denied",
        Refusal::ModelNotAllowed => "model_not_allowed",
        Refusal::VariantNotActivated => "variant_not_activated",
        Refusal::BudgetExhausted => "budget_exhausted",
    }
}

// ── Test fixtures ────────────────────────────────────────────────────────

/// A two-tenant deployment resembling a real install: `acme` and `globex`,
/// each with its own budget, allowlist and Q-Page activations, plus the
/// roles and governed tools a Hermes session would use.
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
    d.add_tenant("acme", acme);

    let mut globex = TenantState::new(500);
    globex.allow_model("gpt-5");
    d.add_tenant("globex", globex);

    d.assign("alice", "writer");
    d.assign("bob", "reader");
    d.assign("root", "operator");
    d
}

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
    use ccos_enterprise_auth::{ActorId, OrgId};
    AuthenticatedActor {
        org: OrgId(org.to_string()),
        actor: ActorId(name.to_string()),
        strength,
    }
}
