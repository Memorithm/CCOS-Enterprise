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
//! 8. **replay** — a `request_id` already forwarded yields explicit
//!    [`Outcome::Replayed`], is journaled at zero cost, and no effect may
//!    execute again;
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
//! ## Two journals, one order
//!
//! A decision journal alone cannot explain its own contents. The same call,
//! refused and then forwarded, used to leave exactly two records and nothing
//! between them saying what changed — because the change *was* nothing, as far
//! as the product was concerned: `redefine_role` escalated every holder of a
//! role and journaled nothing, and `tenant_mut(..).allow_model(..)` widened an
//! allowlist and journaled nothing.
//!
//! Every rule change on a serving deployment is now a [`GovernanceRecord`]:
//! what changed, from what to what, and — for role edits — every principal
//! whose rights moved. [`Deployment::journal`] merges the two streams into the
//! one order in which either is readable.
//!
//! Three decisions in that design are worth stating because each rules out an
//! easier one:
//!
//! * **Anchored, not sharing a counter.** A governance record carries the
//!   sequence of the decision it precedes rather than consuming one. Sharing
//!   would make [`AuditRecord::sequence`] non-dense, and that density is what
//!   lets a restore detect a *lost decision*.
//! * **Provisioning is not journaled.** Before the first decision there is no
//!   outcome for a change to explain, and journaling the builder would fill a
//!   bounded buffer with the provisioning script. [`Deployment::is_serving`]
//!   is where the line sits.
//! * **Attribution is recorded, not demanded.** [`Deployment::as_admin`]
//!   carries an operator's name and reason into the record. The bare mutators
//!   journal the same change with both fields empty, because a
//!   `&mut Deployment` is already the whole authority — a method that refused
//!   without a name would only push callers back to a path that is not in the
//!   trail. What the product guarantees here is visibility, not permission.
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

/// Whether an organization or tenant identifier is one this product will
/// provision: non-empty, at most [`MAX_IDENTIFIER_BYTES`], and made only of
/// ASCII `[a-z0-9_-]`.
///
/// Two separate reasons, and the second is why this is a refusal at
/// provisioning time rather than a warning:
///
/// * **Confusables.** Raw `String` ids let `acme`, `Acme`, `ACME`, `"acme "`,
///   `acme\u{200b}`, `\u{430}cme` (Cyrillic а) and the NFC/NFD spellings of an
///   accented name all coexist as distinct tenants that render identically.
///   An operator reading a console cannot tell which one holds the data, and
///   a support request naming "acme" is unanswerable.
/// * **Path safety.** Any tenant-scoped storage keyed by name — Core sessions,
///   backups, exports — turns the id into a path component. `..`, `/`, a NUL
///   or a leading `-` are then a traversal or an argument-injection away from
///   another tenant's data. Constraining the id makes `<root>/<tenant>` safe
///   *by construction*, which is a much better property than remembering to
///   sanitize at every use site.
///
/// Hyphens are allowed because real tenant names use them (`victim-corp`,
/// `t-00`); dots are not, so no id can be `.` or `..`.
pub fn is_canonical_identifier(id: &str) -> bool {
    let mut bytes = id.bytes();
    // The first byte must be alphanumeric. A leading `-` reads as a flag to
    // anything that ever passes the id to a command line, and a leading `_`
    // is the conventional hidden-file prefix; neither is worth the ambiguity
    // when no real tenant name needs one.
    let Some(first) = bytes.next() else {
        return false;
    };
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return false;
    }
    id.len() <= MAX_IDENTIFIER_BYTES
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// Default ceiling on the in-memory audit buffer. See the module docs: this
/// bounds memory, it does not substitute for durable storage.
pub const DEFAULT_AUDIT_CAPACITY: usize = 100_000;

/// How many decided `request_id`s are remembered per deployment for replay
/// suppression. Bounded for the same reason as the journal.
pub const DEFAULT_REPLAY_MEMORY: usize = 65_536;

/// Maximum cells one tenant may hold.
///
/// The store had no cap on cells, on key bytes, on value bytes or on tenants,
/// and no delete — so growth was linear, caller-controlled and irreversible,
/// and a tenant whose token budget was **zero** could still fill it, because
/// the meter is on `admit` and the store was not on that path at all.
pub const MAX_CELLS_PER_TENANT: usize = 65_536;

/// Maximum bytes in a cell key.
pub const MAX_CELL_KEY_BYTES: usize = 1_024;

/// Maximum bytes in a cell value. Generous — a cell holds a memory root, not a
/// token — but finite, which is the property that was missing.
pub const MAX_CELL_VALUE_BYTES: usize = 1_048_576;

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
    /// The tenant has filled its cell allowance ([`MAX_CELLS_PER_TENANT`]).
    ///
    /// Distinct from [`Refusal::BudgetExhausted`] on purpose: that one means
    /// "this tenant has spent its tokens", which a new billing period clears,
    /// and this one means "this tenant is holding as much as it may", which
    /// only a delete clears. An operator alerting on one must not be woken by
    /// the other.
    StorageExhausted,
    /// The tool is gated on a recorded human approval
    /// ([`Deployment::require_approval`], `docs/HUMAN_APPROVAL_POLICIES.md`)
    /// and no live approval exists for this call's artifact. Unrecorded
    /// approval is denial.
    RequiresApproval,
}

/// The outcome of one admission decision, as journaled.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Outcome {
    /// The call passed every gate and its effect may execute exactly once.
    Forwarded,
    /// This tenant/request_id was already forwarded earlier. The replay is
    /// journaled at zero cost but MUST NOT execute the effect again.
    Replayed,
    Refused(Refusal),
}

impl Outcome {
    /// True only for the first admitted execution, never for a replay.
    pub fn is_forwarded(&self) -> bool {
        matches!(self, Outcome::Forwarded)
    }

    pub fn is_replayed(&self) -> bool {
        matches!(self, Outcome::Replayed)
    }

    pub fn refusal(&self) -> Option<&Refusal> {
        match self {
            Outcome::Refused(r) => Some(r),
            Outcome::Forwarded | Outcome::Replayed => None,
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

/// A change to the rules the admission path decides by.
///
/// Each variant records the *effect*, not the call: what a reader needs in
/// order to explain why an outcome changed, without having to hold the code
/// that made the change. Redefinition and removal carry their blast radius —
/// the holders affected — because "the role changed" is not evidence and
/// "these four principals gained `policy.admin`" is.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GovernanceChange {
    /// A role was defined on a serving deployment.
    RoleDefined {
        role: String,
        permissions: Vec<String>,
    },
    /// A live role's permission set was replaced, affecting every holder.
    RoleRedefined {
        role: String,
        from: Vec<String>,
        to: Vec<String>,
        holders: Vec<String>,
    },
    /// A role and every grant of it were removed.
    RoleRemoved {
        role: String,
        holders: Vec<String>,
    },
    RoleAssigned {
        actor: String,
        role: String,
    },
    RoleUnassigned {
        actor: String,
        role: String,
    },
    /// A principal was de-provisioned.
    ActorRemoved {
        actor: String,
        roles: Vec<String>,
    },
    /// A tenant was provisioned on a serving deployment.
    TenantAdded {
        tenant: String,
        org: String,
    },
    /// A tenant's own rules changed, as measured across a mutable borrow.
    /// Only non-empty differences are journaled, so an inspection that changed
    /// nothing leaves no row.
    TenantRulesChanged {
        tenant: String,
        models_allowed: Vec<String>,
        models_revoked: Vec<String>,
        variants_activated: Vec<String>,
        variants_deactivated: Vec<String>,
    },
    /// A tool became governed, or the permission it requires changed.
    ToolGoverned {
        tool: String,
        permission: String,
        previous: Option<String>,
    },
    /// A tool became an administrative act.
    ToolMadeAdministrative {
        tool: String,
    },
    /// A tool became gated on a recorded human approval.
    ToolMadeApprovalGated {
        tool: String,
    },
    /// A human approval was recorded in the deployment's ledger.
    ApprovalRecorded {
        approval_id: String,
    },
    /// The identity floor moved.
    StrengthRequired {
        from: AuthStrength,
        to: AuthStrength,
    },
}

/// One journaled governance change.
///
/// The question the journal previously could not answer is "the same call was
/// refused and then forwarded — what changed in between?", and answering it
/// requires the change and the decisions to be *orderable against one
/// another*, not merely both recorded somewhere. So a governance record is
/// anchored to the decision stream rather than given a sequence of its own:
/// it sits immediately before the decision that will take
/// [`GovernanceRecord::at_sequence`].
///
/// Anchoring rather than sharing one counter is deliberate. A shared counter
/// would make [`AuditRecord::sequence`] non-dense, and the density of the
/// decision journal is what lets a restore detect that a decision was lost —
/// a guarantee worth more than the tidiness of one counter.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GovernanceRecord {
    /// The sequence the *next* decision will take. This record sits between
    /// decision `at_sequence - 1` and decision `at_sequence`.
    pub at_sequence: u64,
    /// Monotonic among governance records, so several changes made between the
    /// same pair of decisions keep the order they were made in.
    pub ordinal: u64,
    /// Who made the change, when the caller said so.
    ///
    /// `None` is not an omission the journal hides: it is the recorded fact
    /// that the change was made through an unattributed handle. Nothing in
    /// this product *demands* an identity to mutate a live deployment — that
    /// is a real remaining defect — and a journal that silently attributed
    /// such a change to "system" would be lying about it.
    pub actor: Option<String>,
    /// The reason the caller gave, if any. Legibility is
    /// `ccos_enterprise_admin::is_written_justification`, the one definition in
    /// the product; a reason that renders blank is recorded as `None`.
    pub justification: Option<String>,
    pub change: GovernanceChange,
}

/// One row of the deployment's journal: a decision, or a change to the rules
/// decisions are made by.
///
/// [`Deployment::journal`] merges the two streams by sequence, which is the
/// only form in which either is fully readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalEntry<'a> {
    Decision(&'a AuditRecord),
    Governance(&'a GovernanceRecord),
}

impl JournalEntry<'_> {
    /// The decision sequence this row sits at. A governance row shares the
    /// number of the decision it precedes.
    pub fn sequence(&self) -> u64 {
        match self {
            JournalEntry::Decision(r) => r.sequence,
            JournalEntry::Governance(r) => r.at_sequence,
        }
    }

    /// The total order over the merged journal: rows sort by sequence, and
    /// within one sequence every governance change precedes the decision it
    /// was made before, in the order the changes were made.
    fn order(&self) -> (u64, u8, u64) {
        match self {
            JournalEntry::Governance(r) => (r.at_sequence, 0, r.ordinal),
            JournalEntry::Decision(r) => (r.sequence, 1, 0),
        }
    }
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
    ///
    /// Nested rather than keyed by `(TenantId, String)`. The flat map copied
    /// the tenant name into every single key — a 64 KiB name written to 256
    /// cells retained 256 copies of it — and could only be probed by building
    /// an owned key, so a 4 MiB `get` that missed still allocated 4 MiB. Here
    /// the name is held once per tenant and both lookups take a `&str`.
    store: BTreeMap<TenantId, BTreeMap<String, String>>,
    metrics: CounterRegistry,
    audit: VecDeque<AuditRecord>,
    audit_capacity: usize,
    audit_dropped: u64,
    /// Changes to the rules, in the same sequence space as the decisions.
    governance: VecDeque<GovernanceRecord>,
    governance_dropped: u64,
    next_governance_ordinal: u64,
    /// Whether this deployment has decided anything yet.
    ///
    /// Before the first decision there is no outcome for a rule change to
    /// explain, so provisioning journals nothing; after it, every change does.
    /// This is the whole line between "building a deployment" and "mutating a
    /// live one", and it is drawn where an auditor would draw it rather than
    /// by which method was called.
    serving: bool,
    next_sequence: u64,
    /// Decided request ids, newest last, bounded by `replay_memory`.
    decided: BTreeSet<(TenantId, String)>,
    decided_order: VecDeque<(TenantId, String)>,
    replay_memory: usize,
    required_strength: AuthStrength,
    /// Tools that are gated on a recorded human approval
    /// (docs/HUMAN_APPROVAL_POLICIES.md). An admitted call for one of these is
    /// refused with [`Refusal::RequiresApproval`] unless the deployment's
    /// approval ledger holds a live approval for the call's artifact.
    approval_required: BTreeSet<String>,
    /// The durable human approval ledger: unrecorded approval is denial.
    approvals: ApprovalLedger,
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
            governance: VecDeque::new(),
            governance_dropped: 0,
            next_governance_ordinal: 0,
            serving: false,
            next_sequence: 0,
            decided: BTreeSet::new(),
            decided_order: VecDeque::new(),
            replay_memory: DEFAULT_REPLAY_MEMORY,
            required_strength: AuthStrength::Token,
            approval_required: BTreeSet::new(),
            approvals: ApprovalLedger::default(),
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
        let from = self.required_strength;
        self.required_strength = strength;
        if from != strength {
            self.record(
                GovernanceChange::StrengthRequired { from, to: strength },
                None,
                None,
            );
        }
        self
    }

    // ── Governance journalling ───────────────────────────────────────────

    /// Journal one rule change, if this deployment has decided anything yet.
    ///
    /// Before the first decision the deployment is being *built*, and a change
    /// with no outcome behind it has nothing to explain — journalling it would
    /// fill the trail with the provisioning script and push every real record
    /// out of a bounded buffer. From the first decision on, every change is
    /// recorded, whether or not the caller offered a name or a reason.
    fn record(
        &mut self,
        change: GovernanceChange,
        actor: Option<&str>,
        justification: Option<&str>,
    ) {
        if !self.serving {
            return;
        }
        // The ordinal advances whether or not the record is kept, so two
        // changes never share one and a reader can tell a dropped record from
        // a reordered one.
        let ordinal = self.next_governance_ordinal;
        self.next_governance_ordinal += 1;
        if self.audit_capacity == 0 {
            self.governance_dropped += 1;
            self.metrics.inc("governance.dropped", 1);
            return;
        }
        while self.governance.len() >= self.audit_capacity {
            self.governance.pop_front();
            self.governance_dropped += 1;
            self.metrics.inc("governance.dropped", 1);
        }
        self.governance.push_back(GovernanceRecord {
            at_sequence: self.next_sequence,
            ordinal,
            actor: actor.map(clamp),
            // A reason that renders blank is no reason: recording `Some("​")`
            // would let an invisible string pass for evidence, which is the
            // hole `is_written_justification` exists to close.
            justification: justification
                .filter(|j| ccos_enterprise_admin::is_written_justification(Some(j)))
                .map(clamp),
            change,
        });
    }

    /// Make rule changes under a recorded identity and reason.
    ///
    /// The bare mutators journal too — an unattributed change is still a
    /// change, and hiding it would be worse than recording it as anonymous —
    /// but nothing in them can *demand* a name, because a `&mut Deployment` is
    /// already the whole authority. This handle is how a caller that has an
    /// operator's identity puts it in the trail.
    ///
    /// It does not gate: a blank reason is recorded as no reason rather than
    /// refused, because refusing here would tempt callers back to the bare
    /// methods and out of the trail entirely. Gating administrative *calls* is
    /// layer 6's job, on the admission path, where a caller cannot route
    /// around it.
    pub fn as_admin<'a>(&'a mut self, actor: &str, why: &str) -> Admin<'a> {
        Admin {
            deployment: self,
            actor: actor.to_string(),
            justification: why.to_string(),
        }
    }

    /// Provision a tenant owned by `org`.
    ///
    /// Refuses to overwrite a live tenant: the predecessor was a bare
    /// `insert`, so re-provisioning silently zeroed a running tenant's ledger,
    /// allowlist and activations while the journal still showed its forwarded
    /// calls. Returns `false` and changes nothing when the tenant exists.
    pub fn add_tenant(&mut self, org: &str, tenant: &str, state: TenantState) -> bool {
        self.add_tenant_as(org, tenant, state, None, None)
    }

    fn add_tenant_as(
        &mut self,
        org: &str,
        tenant: &str,
        state: TenantState,
        by: Option<&str>,
        why: Option<&str>,
    ) -> bool {
        // Refused before anything is inserted: an id that cannot be rendered
        // unambiguously, or safely turned into a path component, is not a
        // tenant this product will carry. See [`is_canonical_identifier`].
        if !is_canonical_identifier(org) || !is_canonical_identifier(tenant) {
            return false;
        }
        let id = TenantId(tenant.to_string());
        if self.tenants.contains_key(&id) {
            return false;
        }
        self.tenant_owner.insert(id.clone(), OrgId(org.to_string()));
        self.tenants.insert(id, state);
        self.record(
            GovernanceChange::TenantAdded {
                tenant: tenant.to_string(),
                org: org.to_string(),
            },
            by,
            why,
        );
        true
    }

    /// Borrow a tenant's rules for change.
    ///
    /// The returned guard journals **what actually differed** across the
    /// borrow, on drop: models allowed or revoked, variants activated or
    /// deactivated. An inspection that changes nothing leaves no row.
    ///
    /// This shape is forced by the signature it replaces. `tenant_mut` handed
    /// out a `&mut TenantState`, so the deployment could not see what was done
    /// with it — and `tenant_mut(..).allow_model(..)` was the exact call that
    /// widened an allowlist between two identical requests, flipping a refusal
    /// into a forward with a journal of two rows and nothing between them. A
    /// borrow cannot report intent, but it can be made to report its own
    /// effect, and that is what an auditor needs.
    pub fn tenant_mut(&mut self, tenant: &str) -> Option<TenantRules<'_>> {
        self.tenant_mut_as(tenant, None, None)
    }

    fn tenant_mut_as<'a>(
        &'a mut self,
        tenant: &str,
        by: Option<&str>,
        why: Option<&str>,
    ) -> Option<TenantRules<'a>> {
        let id = TenantId(tenant.to_string());
        let state = self.tenants.get(&id)?;
        let before_models = state.models.0.clone();
        let before_variants: BTreeSet<AdvancedQPageVariant> =
            state.qpages.active().into_iter().collect();
        Some(TenantRules {
            actor: by.map(str::to_string),
            justification: why.map(str::to_string),
            deployment: self,
            tenant: id,
            before_models,
            before_variants,
        })
    }

    /// Define a role. **Provisioning only**: a name already taken is left
    /// exactly as it was.
    ///
    /// The no-op on a duplicate is deliberate and worth defending. This is a
    /// builder used at construction time, where a repeated name is a
    /// programmer error; the previous behaviour made that error a *silent mass
    /// privilege change* affecting every holder. First-definition-wins turns
    /// the same mistake into a safe one. Changing a live role is
    /// [`redefine_role`](Self::redefine_role), which says so and reports what
    /// it hit.
    pub fn add_role(&mut self, name: &str, permissions: &[&str]) -> &mut Self {
        self.add_role_as(name, permissions, None, None);
        self
    }

    fn add_role_as(
        &mut self,
        name: &str,
        permissions: &[&str],
        by: Option<&str>,
        why: Option<&str>,
    ) -> bool {
        let mut role = Role {
            name: name.to_string(),
            ..Default::default()
        };
        for p in permissions {
            role.permissions.insert(Permission(p.to_string()));
        }
        if !self.roles.add_role(role) {
            return false;
        }
        self.record(
            GovernanceChange::RoleDefined {
                role: name.to_string(),
                permissions: owned(permissions),
            },
            by,
            why,
        );
        true
    }

    /// Replace a live role's permission set, affecting every holder at once.
    /// Returns whether a role of that name existed.
    ///
    /// Separate from [`add_role`](Self::add_role) so that a mass privilege
    /// change cannot be reached by a typo, and journaled with its **blast
    /// radius**: the permissions before and after, and every principal whose
    /// rights just moved. That last part is the reason the record is worth
    /// having — "the `reader` role was redefined" is a note, and "these 400
    /// principals gained `policy.admin` at sequence 91 812" is evidence.
    pub fn redefine_role(&mut self, name: &str, permissions: &[&str]) -> bool {
        self.redefine_role_as(name, permissions, None, None)
    }

    fn redefine_role_as(
        &mut self,
        name: &str,
        permissions: &[&str],
        by: Option<&str>,
        why: Option<&str>,
    ) -> bool {
        let from = owned(&self.roles.permissions_of(name));
        let holders = owned(&self.roles.holders_of(name));
        let mut role = Role {
            name: name.to_string(),
            ..Default::default()
        };
        for p in permissions {
            role.permissions.insert(Permission(p.to_string()));
        }
        if !self.roles.redefine_role(role) {
            return false;
        }
        self.record(
            GovernanceChange::RoleRedefined {
                role: name.to_string(),
                from,
                to: owned(&self.roles.permissions_of(name)),
                holders,
            },
            by,
            why,
        );
        true
    }

    /// Remove a role and every grant of it. Returns whether it existed.
    pub fn remove_role(&mut self, name: &str) -> bool {
        self.remove_role_as(name, None, None)
    }

    fn remove_role_as(&mut self, name: &str, by: Option<&str>, why: Option<&str>) -> bool {
        let holders = owned(&self.roles.holders_of(name));
        if !self.roles.remove_role(name) {
            return false;
        }
        self.record(
            GovernanceChange::RoleRemoved {
                role: name.to_string(),
                holders,
            },
            by,
            why,
        );
        true
    }

    /// Withdraw one role from one actor. Returns whether the grant existed.
    pub fn unassign(&mut self, actor: &str, role: &str) -> bool {
        self.unassign_as(actor, role, None, None)
    }

    fn unassign_as(
        &mut self,
        actor: &str,
        role: &str,
        by: Option<&str>,
        why: Option<&str>,
    ) -> bool {
        if !self.roles.unassign(actor, role) {
            return false;
        }
        self.record(
            GovernanceChange::RoleUnassigned {
                actor: actor.to_string(),
                role: role.to_string(),
            },
            by,
            why,
        );
        true
    }

    /// De-provision a principal entirely. Returns whether it held anything.
    pub fn remove_actor(&mut self, actor: &str) -> bool {
        self.remove_actor_as(actor, None, None)
    }

    fn remove_actor_as(&mut self, actor: &str, by: Option<&str>, why: Option<&str>) -> bool {
        let roles = owned(&self.roles.roles_of(actor));
        if !self.roles.remove_actor(actor) {
            return false;
        }
        self.record(
            GovernanceChange::ActorRemoved {
                actor: actor.to_string(),
                roles,
            },
            by,
            why,
        );
        true
    }

    /// The roles an actor holds, in name order.
    pub fn roles_of(&self, actor: &str) -> Vec<&str> {
        self.roles.roles_of(actor)
    }

    /// The tenant ids of this deployment, in name order. `None` is never
    /// conflated with an empty tenant: an empty deployment reports nothing.
    pub fn tenant_ids(&self) -> impl Iterator<Item = &TenantId> {
        self.tenants.keys()
    }

    /// The deployment's role book — the authority for permission checks.
    pub fn roles(&self) -> &RoleBook {
        &self.roles
    }

    /// Grant a role. Returns false (and grants nothing) for unknown roles —
    /// the RBAC crate's fail-closed rule, surfaced here.
    pub fn assign(&mut self, actor: &str, role: &str) -> bool {
        self.assign_as(actor, role, None, None)
    }

    fn assign_as(&mut self, actor: &str, role: &str, by: Option<&str>, why: Option<&str>) -> bool {
        if !self.roles.assign(actor, role) {
            return false;
        }
        self.record(
            GovernanceChange::RoleAssigned {
                actor: actor.to_string(),
                role: role.to_string(),
            },
            by,
            why,
        );
        true
    }

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
        if self.justification_required.insert(tool.to_string()) {
            self.record(
                GovernanceChange::ToolMadeAdministrative {
                    tool: tool.to_string(),
                },
                None,
                None,
            );
        }
        self
    }

    /// Whether a tool is an administrative act in this deployment.
    pub fn requires_justification(&self, tool: &str) -> bool {
        self.justification_required.contains(tool)
    }

    // ── Human approval gates (docs/HUMAN_APPROVAL_POLICIES.md) ──────────

    /// Mark a governed tool as requiring a recorded human approval for every
    /// call: the tool is admitted by every other gate, then refused with
    /// [`Refusal::RequiresApproval`] unless the approval ledger holds a live
    /// (unrevoked, unexpired) approval for the call's artifact hash.
    ///
    /// Unrecorded approval is denial; the requirement itself is durable state
    /// (carried in the snapshot) so a restart never silently drops it.
    pub fn require_approval(&mut self, tool: &str) -> &mut Self {
        if self.approval_required.insert(tool.to_string()) {
            self.record(
                GovernanceChange::ToolMadeApprovalGated {
                    tool: tool.to_string(),
                },
                None,
                None,
            );
        }
        self
    }

    /// Whether a tool is gated on a recorded human approval.
    pub fn requires_approval(&self, tool: &str) -> bool {
        self.approval_required.contains(tool)
    }

    /// Evaluate the approval gate for one admitted call.
    ///
    /// Returns `Ok(())` when the call is not approval-gated, or when a live
    /// approval exists for exactly this artifact; returns
    /// [`Refusal::RequiresApproval`] otherwise. This is the executable form
    /// of "unrecorded approval == denial".
    ///
    /// `artifact_hash` is the SHA-256 (lowercase hex) of the artifact the
    /// call would affect. It must be canonical, or the gate fails closed.
    pub fn approval_gate(&self, call: &Call<'_>, artifact_hash: &str) -> Result<(), Refusal> {
        if !self.approval_required.contains(&call.request.tool) {
            return Ok(());
        }
        let tenant = TenantId(call.request.tenant.clone());
        let query = ccos_enterprise_approval::ApprovalQuery {
            tenant: &tenant,
            action: &call.request.tool,
            artifact_hash,
            now: now_unix(),
        };
        match self.approvals.evaluate(&query) {
            ccos_enterprise_approval::GateOutcome::Approved => Ok(()),
            _ => Err(Refusal::RequiresApproval),
        }
    }

    /// Record one human approval in the deployment's ledger.
    ///
    /// Returns the approval id. Refuses duplicates, malformed requests and
    /// non-canonical identifiers; the record is journaled as a governance
    /// change so the ledger has a complete trail.
    pub fn record_approval(
        &mut self,
        request: ccos_enterprise_approval::ApprovalRequest,
    ) -> Result<String, ccos_enterprise_approval::ApprovalError> {
        let id = self.approvals.record(request)?;
        self.record(
            GovernanceChange::ApprovalRecorded {
                approval_id: id.clone(),
            },
            None,
            None,
        );
        Ok(id)
    }

    /// The current approval ledger (validated state only).
    pub fn approvals(&self) -> &ApprovalLedger {
        &self.approvals
    }

    /// The approval-required tool set, in name order.
    pub fn approval_required(&self) -> impl Iterator<Item = &str> {
        self.approval_required.iter().map(String::as_str)
    }

    /// Declare which permission a tool requires. Undeclared tools are refused.
    pub fn govern_tool(&mut self, tool: &str, permission: &str) -> &mut Self {
        let previous = self
            .governed_tools
            .insert(tool.to_string(), Permission(permission.to_string()));
        if previous.as_ref().map(|p| p.0.as_str()) != Some(permission) {
            self.record(
                GovernanceChange::ToolGoverned {
                    tool: tool.to_string(),
                    permission: permission.to_string(),
                    previous: previous.map(|p| p.0),
                },
                None,
                None,
            );
        }
        self
    }

    // ── Tenant-scoped storage ────────────────────────────────────────────
    //
    // Two ways in, and the difference between them is the point.
    //
    // `put_cell`/`get_cell`/`remove_cell` run a cell access through the same
    // nine gates as any other call, journal it, meter it and bill it. That is
    // the shape tenant memory traffic has to have: `docs/COGNITIVE_AUDIT.md`
    // promises a journal of it, and a store reachable without an identity
    // cannot keep that promise however careful its keys are.
    //
    // `put`/`get`/`cells_of` are the storage layer underneath, with no gate in
    // front. They are public because the stress suite measures this map's own
    // growth, aliasing and cost characteristics, and running those through the
    // gates would measure the gates instead — and bill a hundred thousand
    // tokens to do it. What they are NOT is a way around the governed path
    // for anything in the product: nothing outside these tests calls them, and
    // the bounds and the unknown-tenant refusal below apply to both paths, so
    // the storage layer is never in a state the governed path could not have
    // produced.

    /// Write a cell directly, with **no gate in front**. Returns whether it
    /// landed.
    ///
    /// Refuses a tenant this deployment does not have. That used to be
    /// accepted and readable, which made `Refusal::UnknownTenant` a property of
    /// `admit` rather than of the product: a cell could exist under a tenant
    /// no credential could ever name.
    pub fn put(&mut self, scope: &TenantScope<String>, value: &str) -> bool {
        self.write_cell(&scope.tenant, &scope.inner, value).is_ok()
    }

    /// Read a cell directly. A scope for tenant B never reaches a cell written
    /// under tenant A, however identical the inner key.
    ///
    /// Allocates nothing, including on a miss: the tenant map is probed by
    /// `&str` through [`TenantId`]'s `Borrow` impl, so a caller-sized key costs
    /// a comparison rather than a copy.
    pub fn get(&self, scope: &TenantScope<String>) -> Option<&str> {
        self.store
            .get(scope.tenant.0.as_str())?
            .get(scope.inner.as_str())
            .map(String::as_str)
    }

    /// Every cell visible to a tenant — the shape a cross-tenant leak would
    /// have to show up in.
    pub fn cells_of(&self, tenant: &str) -> Vec<(&str, &str)> {
        self.store
            .get(tenant)
            .into_iter()
            .flatten()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }

    /// How many cells a tenant holds, of [`MAX_CELLS_PER_TENANT`].
    pub fn cell_count(&self, tenant: &str) -> usize {
        self.store.get(tenant).map_or(0, BTreeMap::len)
    }

    /// The shared rule both paths obey. `Err` carries the refusal the governed
    /// path reports; the direct path reports it as `false`.
    fn write_cell(&mut self, tenant: &TenantId, key: &str, value: &str) -> Result<(), Refusal> {
        if !self.tenants.contains_key(tenant) {
            return Err(Refusal::UnknownTenant);
        }
        // Sized like every other caller-controlled string on this path. Before
        // this, a 4 MiB key and a 4 MiB value were both accepted and retained
        // for the lifetime of the process.
        if key.is_empty() || key.len() > MAX_CELL_KEY_BYTES {
            return Err(Refusal::MalformedRequest("cell_key".to_string()));
        }
        if value.len() > MAX_CELL_VALUE_BYTES {
            return Err(Refusal::MalformedRequest("cell_value".to_string()));
        }
        let cells = self.store.entry(tenant.clone()).or_default();
        // The cap is on *new* keys: overwriting one a tenant already holds
        // cannot grow the map, and refusing it would make a full tenant unable
        // to correct its own data.
        if cells.len() >= MAX_CELLS_PER_TENANT && !cells.contains_key(key) {
            return Err(Refusal::StorageExhausted);
        }
        cells.insert(key.to_string(), value.to_string());
        Ok(())
    }

    /// Delete a cell directly. Returns whether it existed.
    ///
    /// Its absence was the whole of finding 3: every byte ever written was
    /// retained for the lifetime of the process, because no `remove`, `evict`
    /// or `clear` existed anywhere in the API. Overwriting a value with `""`
    /// returned 7% of the bytes and there was no way to get the rest.
    pub fn remove(&mut self, scope: &TenantScope<String>) -> bool {
        let Some(cells) = self.store.get_mut(scope.tenant.0.as_str()) else {
            return false;
        };
        let existed = cells.remove(scope.inner.as_str()).is_some();
        if cells.is_empty() {
            // Drop the tenant's map with it, so an emptied tenant costs
            // nothing — the map, its keys and the tenant name held once.
            self.store.remove(scope.tenant.0.as_str());
        }
        existed
    }

    /// Delete every cell a tenant holds. Returns how many were removed.
    pub fn clear_cells(&mut self, tenant: &str) -> usize {
        self.store.remove(tenant).map_or(0, |cells| cells.len())
    }

    // ── The governed cell path ───────────────────────────────────────────

    /// Write a cell **through every gate**, journaled, metered and billed.
    ///
    /// The tool named on the request is what the deployment governs, so a
    /// deployment that has not called `govern_tool("memory.put", ..)` refuses
    /// with [`Refusal::ToolNotGoverned`] like any other ungoverned tool. The
    /// cell is written only if the call is forwarded, and the tenant it lands
    /// under is the **verified** one from the request — not a `TenantScope` the
    /// caller assembled, which is what made `rescope` a silent crossing.
    pub fn put_cell(&mut self, call: Call<'_>, key: &str, value: &str) -> Outcome {
        self.cell_call(call, |d, tenant| {
            d.write_cell(&tenant, key, value).map(|()| None)
        })
    }

    /// Read a cell through every gate. Returns the decision and, when
    /// forwarded, the value.
    ///
    /// Owned rather than borrowed because the read is journaled: the record is
    /// written under the same `&mut` borrow that answers, so there is no way to
    /// hand back a reference into a deployment the caller must then be able to
    /// read the journal of.
    pub fn get_cell(&mut self, call: Call<'_>, key: &str) -> (Outcome, Option<String>) {
        let mut found = None;
        let outcome = self.cell_call(call, |d, tenant| {
            if !d.tenants.contains_key(&tenant) {
                return Err(Refusal::UnknownTenant);
            }
            found = d
                .store
                .get(tenant.0.as_str())
                .and_then(|cells| cells.get(key))
                .cloned();
            Ok(found.clone())
        });
        // A refusal returns nothing, ever — including the "no such cell" a
        // caller could otherwise difference against a permission failure to
        // probe another tenant's key space.
        //
        // Today that already holds by construction, because `cell_call` runs
        // the effect only on `Forwarded` and `found` is therefore untouched on
        // every refusal — deleting this line changes no test. It is written
        // out anyway: the property is a security guarantee, and the next
        // effect that sets state *before* deciding it must refuse would
        // otherwise leak it silently.
        if outcome.is_forwarded() {
            (outcome, found)
        } else {
            (outcome, None)
        }
    }

    /// Delete a cell through every gate.
    pub fn remove_cell(&mut self, call: Call<'_>, key: &str) -> Outcome {
        let scope = TenantScope::new(TenantId(call.request.tenant.clone()), key.to_string());
        self.cell_call(call, move |d, _| {
            d.remove(&scope);
            Ok(None)
        })
    }

    /// Run one cell access through `admit`, then perform the effect.
    ///
    /// The effect runs **only** on `Forwarded`, and its own refusal (an unknown
    /// tenant, an oversized key, a full store) replaces the outcome and rolls
    /// the billing back — a call that did not happen must not be charged for.
    fn cell_call<F>(&mut self, call: Call<'_>, effect: F) -> Outcome
    where
        F: FnOnce(&mut Self, TenantId) -> Result<Option<String>, Refusal>,
    {
        let tenant = TenantId(call.request.tenant.clone());
        let cost = call.cost_tokens;
        let outcome = self.admit(call);
        if !outcome.is_forwarded() {
            return outcome;
        }
        match effect(self, tenant.clone()) {
            Ok(_) => outcome,
            Err(refusal) => {
                // Refund and re-journal: the admission said yes and the store
                // said no, so the trail must show the refusal rather than a
                // forward that never took effect.
                if let Some(state) = self.tenants.get_mut(&tenant) {
                    state.budget.refund(cost);
                }
                self.metrics.inc("gateway.cell_rejected", 1);
                if let Some(record) = self.audit.back_mut() {
                    record.cost = 0;
                    record.outcome = Outcome::Refused(refusal.clone());
                }
                Outcome::Refused(refusal)
            }
        }
    }

    // ── The admission decision ───────────────────────────────────────────

    /// Run one call through every gate, journal the outcome, and return it.
    ///
    /// See the module docs for the order. The two rules worth restating: the
    /// **budget is charged last**, so a call refused by any other gate costs
    /// the tenant nothing; and the **credential is checked against the
    /// request** before any tenant state is touched.
    pub fn admit(&mut self, call: Call<'_>) -> Outcome {
        // From here on the deployment has decided something, so every later
        // rule change has an outcome to explain and is journaled. See
        // [`Deployment::record`].
        self.serving = true;
        let (outcome, cost) = self.decide(&call);
        self.metrics.inc("gateway.requests", 1);
        match &outcome {
            Outcome::Forwarded => self.metrics.inc("gateway.forwarded", 1),
            Outcome::Replayed => self.metrics.inc("gateway.replayed", 1),
            Outcome::Refused(r) => {
                self.metrics.inc("gateway.refused", 1);
                self.metrics.inc(&format!("gateway.refused.{}", tag(r)), 1);
            }
        }
        self.journal_decision(&call, &outcome, cost);
        outcome
    }

    /// Append one record, dropping the oldest if the buffer is full.
    fn journal_decision(&mut self, call: &Call<'_>, outcome: &Outcome, cost: u64) {
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
        if call.actor.strength() < self.required_strength {
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
        if call.request.actor != call.actor.actor().0 {
            return refuse(Refusal::ActorMismatch);
        }
        let tenant_id = TenantId(call.request.tenant.clone());
        match self.tenant_owner.get(&tenant_id) {
            None => return refuse(Refusal::UnknownTenant),
            Some(owner) if *owner != *call.actor.org() => {
                return refuse(Refusal::TenantNotOwnedByOrg)
            }
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
        if !self.roles.allows(&call.actor.actor().0, permission) {
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
            return (Outcome::Replayed, 0);
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

    /// The rule changes this deployment has made since it started serving, in
    /// the order it made them.
    pub fn governance(&self) -> impl Iterator<Item = &GovernanceRecord> {
        self.governance.iter()
    }

    /// How many governance records the buffer has dropped.
    pub fn governance_dropped(&self) -> u64 {
        self.governance_dropped
    }

    /// Decisions and rule changes, merged into the single ordered stream they
    /// share a sequence space for.
    ///
    /// This is the form the journal has to be read in to answer "why did the
    /// answer change?": the two buffers are each in order, and the merge is
    /// the only place their *relative* order is recoverable.
    ///
    /// Both buffers are bounded independently, so a burst of one can age the
    /// other out of view; [`Deployment::audit_dropped`] and
    /// [`Deployment::governance_dropped`] are how a reader learns that the
    /// stream they are holding is not the whole one.
    pub fn journal(&self) -> Vec<JournalEntry<'_>> {
        let mut rows: Vec<JournalEntry<'_>> = self
            .audit
            .iter()
            .map(JournalEntry::Decision)
            .chain(self.governance.iter().map(JournalEntry::Governance))
            .collect();
        rows.sort_by_key(JournalEntry::order);
        rows
    }

    /// Whether this deployment has decided anything yet — and therefore
    /// whether a rule change made now is journaled rather than treated as
    /// provisioning.
    pub fn is_serving(&self) -> bool {
        self.serving
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

/// An attributed handle on a deployment's rules.
///
/// Every change made through it carries the operator's name and reason into
/// the governance journal. The bare methods on [`Deployment`] do the same work
/// and journal the same change with both fields empty — the difference is
/// attribution, not enforcement, and that is deliberate: a `&mut Deployment`
/// is already the whole authority, so a method that *refused* without a name
/// would only push callers back to the bare path and out of the trail.
pub struct Admin<'a> {
    deployment: &'a mut Deployment,
    actor: String,
    justification: String,
}

impl Admin<'_> {
    fn by(&self) -> (Option<&str>, Option<&str>) {
        (Some(self.actor.as_str()), Some(self.justification.as_str()))
    }

    /// See [`Deployment::add_tenant`].
    pub fn add_tenant(&mut self, org: &str, tenant: &str, state: TenantState) -> bool {
        let (by, why) = (self.actor.clone(), self.justification.clone());
        self.deployment
            .add_tenant_as(org, tenant, state, Some(&by), Some(&why))
    }

    /// See [`Deployment::add_role`].
    pub fn add_role(&mut self, name: &str, permissions: &[&str]) -> bool {
        let (by, why) = self.by();
        let (by, why) = (by.map(str::to_string), why.map(str::to_string));
        self.deployment
            .add_role_as(name, permissions, by.as_deref(), why.as_deref())
    }

    /// See [`Deployment::redefine_role`].
    pub fn redefine_role(&mut self, name: &str, permissions: &[&str]) -> bool {
        let (by, why) = (self.actor.clone(), self.justification.clone());
        self.deployment
            .redefine_role_as(name, permissions, Some(&by), Some(&why))
    }

    /// See [`Deployment::remove_role`].
    pub fn remove_role(&mut self, name: &str) -> bool {
        let (by, why) = (self.actor.clone(), self.justification.clone());
        self.deployment.remove_role_as(name, Some(&by), Some(&why))
    }

    /// See [`Deployment::assign`].
    pub fn assign(&mut self, actor: &str, role: &str) -> bool {
        let (by, why) = (self.actor.clone(), self.justification.clone());
        self.deployment
            .assign_as(actor, role, Some(&by), Some(&why))
    }

    /// See [`Deployment::unassign`].
    pub fn unassign(&mut self, actor: &str, role: &str) -> bool {
        let (by, why) = (self.actor.clone(), self.justification.clone());
        self.deployment
            .unassign_as(actor, role, Some(&by), Some(&why))
    }

    /// See [`Deployment::remove_actor`].
    pub fn remove_actor(&mut self, actor: &str) -> bool {
        let (by, why) = (self.actor.clone(), self.justification.clone());
        self.deployment
            .remove_actor_as(actor, Some(&by), Some(&why))
    }

    /// See [`Deployment::tenant_mut`].
    pub fn tenant_mut(&mut self, tenant: &str) -> Option<TenantRules<'_>> {
        let (by, why) = (self.actor.clone(), self.justification.clone());
        self.deployment.tenant_mut_as(tenant, Some(&by), Some(&why))
    }
}

/// A tenant's rules, borrowed for change, journalling what actually differed.
///
/// Dereferences to [`TenantState`], so it is used exactly as the `&mut
/// TenantState` it replaces. The record is written on drop, from a comparison
/// of the allowlist and activation set before and after — which is the most a
/// borrow can honestly report. It says what changed, not what the caller meant
/// to change, and nothing at all when nothing changed.
pub struct TenantRules<'a> {
    deployment: &'a mut Deployment,
    tenant: TenantId,
    before_models: BTreeSet<String>,
    before_variants: BTreeSet<AdvancedQPageVariant>,
    actor: Option<String>,
    justification: Option<String>,
}

impl std::ops::Deref for TenantRules<'_> {
    type Target = TenantState;

    fn deref(&self) -> &TenantState {
        self.deployment.tenants.get(&self.tenant).expect(
            "the tenant was present when the guard was made, and the \
                     guard holds the only mutable borrow of the deployment",
        )
    }
}

impl std::ops::DerefMut for TenantRules<'_> {
    fn deref_mut(&mut self) -> &mut TenantState {
        self.deployment.tenants.get_mut(&self.tenant).expect(
            "the tenant was present when the guard was made, and the \
                     guard holds the only mutable borrow of the deployment",
        )
    }
}

impl Drop for TenantRules<'_> {
    fn drop(&mut self) {
        let (after_models, after_variants) = {
            let state = &self.deployment.tenants[&self.tenant];
            (
                state.models.0.clone(),
                state.qpages.active().into_iter().collect::<BTreeSet<_>>(),
            )
        };
        let models_allowed = owned_diff(&after_models, &self.before_models);
        let models_revoked = owned_diff(&self.before_models, &after_models);
        let variants_activated = variant_diff(&after_variants, &self.before_variants);
        let variants_deactivated = variant_diff(&self.before_variants, &after_variants);
        if models_allowed.is_empty()
            && models_revoked.is_empty()
            && variants_activated.is_empty()
            && variants_deactivated.is_empty()
        {
            return;
        }
        let change = GovernanceChange::TenantRulesChanged {
            tenant: self.tenant.0.clone(),
            models_allowed,
            models_revoked,
            variants_activated,
            variants_deactivated,
        };
        let (by, why) = (self.actor.clone(), self.justification.clone());
        self.deployment
            .record(change, by.as_deref(), why.as_deref());
    }
}

/// Names present in `a` and absent from `b`, in order.
fn owned_diff(a: &BTreeSet<String>, b: &BTreeSet<String>) -> Vec<String> {
    a.difference(b).cloned().collect()
}

fn variant_diff(
    a: &BTreeSet<AdvancedQPageVariant>,
    b: &BTreeSet<AdvancedQPageVariant>,
) -> Vec<String> {
    a.difference(b).map(|v| format!("{v:?}")).collect()
}

/// Borrowed names, owned for a record.
fn owned(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| (*s).to_string()).collect()
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
        Refusal::StorageExhausted => "storage_exhausted",
        Refusal::RequiresApproval => "requires_approval",
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

/// The deployment's durable human approval ledger.
///
/// Thin wrapper over the validated approval registry so the snapshot can
/// carry it. Construction refuses corrupt or schema-unknown state; an empty
/// ledger is fine (a genuinely fresh deployment).
#[derive(Debug, Default)]
pub struct ApprovalLedger {
    registry: ccos_enterprise_approval::ApprovalRegistry,
}

impl ApprovalLedger {
    pub fn evaluate(
        &self,
        query: &ccos_enterprise_approval::ApprovalQuery<'_>,
    ) -> ccos_enterprise_approval::GateOutcome {
        self.registry.evaluate(query)
    }

    pub fn record(
        &mut self,
        request: ccos_enterprise_approval::ApprovalRequest,
    ) -> Result<String, ccos_enterprise_approval::ApprovalError> {
        self.registry.record(request)
    }

    pub fn snapshot(&self) -> &ccos_enterprise_approval::ApprovalSnapshot {
        self.registry.snapshot()
    }

    pub fn from_snapshot(
        snapshot: ccos_enterprise_approval::ApprovalSnapshot,
    ) -> Result<Self, ccos_enterprise_approval::ApprovalError> {
        Ok(Self {
            registry: ccos_enterprise_approval::ApprovalRegistry::from_snapshot(snapshot)?,
        })
    }

    pub fn registry(&self) -> &ccos_enterprise_approval::ApprovalRegistry {
        &self.registry
    }
}

/// Unix seconds, saturating to `0` if the system clock is before the epoch
/// (which a governance product must not trust as a negative timestamp).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
    /// Governance records evicted from the in-memory buffer before this
    /// snapshot, for the same reason `audit_dropped` is carried.
    #[serde(default)]
    pub governance_dropped: u64,
    /// Tools gated on a recorded human approval. Persisted because a restart
    /// that forgot them would silently stop demanding approvals.
    #[serde(default)]
    pub approval_required: BTreeSet<String>,
    /// The human approval ledger. Empty by default so older snapshots load.
    #[serde(default)]
    pub approvals: ccos_enterprise_approval::ApprovalSnapshot,
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
    /// The approval ledger carried in the snapshot is corrupt or
    /// schema-unknown. Refused rather than silently dropping approvals:
    /// unrecorded approval must stay a denial, never an accident.
    ApprovalLedgerCorrupt { detail: String },
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
            Self::ApprovalLedgerCorrupt { detail } => {
                write!(f, "approval ledger is corrupt: {detail}")
            }
            Self::JournalDiscontinuity { expected, found } => write!(
                f,
                "journal resumes at sequence {found}, snapshot expects {expected}"
            ),
        }
    }
}

impl std::error::Error for RestoreError {}

fn check_identifier(what: &str, value: &str) -> Result<(), RestoreError> {
    // The same rule `add_tenant` enforces. A snapshot is a file an operator or
    // a bad merge can edit, so the restore path must not be the back door
    // through which a confusable or path-unsafe id enters a live deployment.
    if !is_canonical_identifier(value) {
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
            governance_dropped: self.governance_dropped,
            approval_required: self.approval_required.clone(),
            approvals: self.approvals.snapshot().clone(),
            cells: self
                .store
                .iter()
                .flat_map(|(t, cells)| {
                    cells
                        .iter()
                        .map(move |(k, v)| (t.0.clone(), k.clone(), v.clone()))
                })
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
        governance: &[GovernanceRecord],
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
        d.governance_dropped = snapshot.governance_dropped;
        d.approval_required = snapshot.approval_required;
        d.approvals = ApprovalLedger::from_snapshot(snapshot.approvals).map_err(|error| {
            RestoreError::ApprovalLedgerCorrupt {
                detail: error.to_string(),
            }
        })?;

        for (name, t) in snapshot.tenants {
            check_identifier("tenant", &name)?;
            check_identifier("org", &t.owner)?;
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
            // Through the same rule the live paths obey, so a snapshot
            // cannot install a cell state neither path could have produced —
            // an unknown tenant, an oversized key, or a tenant over its cell
            // allowance. A snapshot is a file an operator or a bad merge can
            // edit; it is not a back door.
            let tenant = TenantId(tenant);
            if d.write_cell(&tenant, &key, &value).is_err() {
                return Err(RestoreError::MalformedIdentifier {
                    what: "cell".to_string(),
                    value: clamp(&key),
                });
            }
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
        //
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
                Outcome::Replayed => d.metrics.inc("gateway.replayed", 1),
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

        // Governance records are replayed into the buffer but never re-applied
        // to the state: the snapshot already holds the roles, allowlists and
        // activations they produced. They are evidence, not instructions.
        for record in governance {
            while d.governance.len() >= d.audit_capacity {
                d.governance.pop_front();
                d.governance_dropped += 1;
                d.metrics.inc("governance.dropped", 1);
            }
            if d.audit_capacity > 0 {
                d.governance.push_back(record.clone());
            } else {
                d.governance_dropped += 1;
                d.metrics.inc("governance.dropped", 1);
            }
        }

        d.next_sequence = next;
        d.next_governance_ordinal = governance.last().map_or(0, |r| r.ordinal + 1);
        // A restored deployment has a history: it has decided or changed
        // something, so every change from here on is journaled rather than
        // treated as provisioning.
        d.serving = next > 0 || !governance.is_empty();
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

/// An authenticated actor at the given strength — **asserted, not proved**.
///
/// Behind `test-fixtures`, which is off by default. This function used to be
/// unconditional public API, and it took three strings and returned a verified
/// identity: the whole forgery that `AuthenticatedActor`'s private fields
/// exist to prevent, relocated one crate over and re-exported. Any caller who
/// could reach the runtime could mint an administrator.
///
/// It goes through `asserted` and inherits its gate rather than routing around
/// it. A scaffold able to build an identity the product cannot would be
/// exercising a different type than the one that ships.
// `test` as well as the feature: this crate's own unit tests need the
// constructor, and a crate cannot enable its own feature from dev-dependencies.
// `cfg(test)` is true only when compiling this crate's test harness — never
// when it is built as somebody's dependency — so the shipped artifact is
// unaffected either way.
#[cfg(any(test, feature = "test-fixtures"))]
pub fn actor(org: &str, name: &str, strength: AuthStrength) -> AuthenticatedActor {
    AuthenticatedActor::asserted(org, name, strength)
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
    fn a_replayed_request_id_is_explicit_and_not_billed_twice() {
        let mut d = two_tenant_deployment();
        let alice = actor("memorithm", "alice", AuthStrength::Token);
        let req = request("acme", "alice", "memory.ingest", "r-same");
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
        for _ in 0..4 {
            assert_eq!(
                d.admit(Call {
                    actor: &alice,
                    request: &req,
                    model: "claude-opus",
                    cost_tokens: 100,
                    variant: None,
                    justification: None,
                }),
                Outcome::Replayed
            );
        }
        assert_eq!(
            d.spent("acme"),
            Some(100),
            "billed once, replayed four times"
        );
        let trail: Vec<_> = d.audit_of("acme");
        assert_eq!(trail.len(), 5);
        assert_eq!(trail[0].outcome, Outcome::Forwarded);
        assert!(trail[1..].iter().all(|r| r.outcome.is_replayed()));
        assert!(trail[1..].iter().all(|r| r.cost == 0));
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

    /// The predicate itself, stated as a table. Two properties are being
    /// bought — unambiguous rendering and path safety — and every rejected
    /// shape below buys one of them.
    #[test]
    fn the_identifier_rule_admits_real_names_and_refuses_confusable_or_unsafe_ones() {
        for good in ["acme", "t-00", "victim-corp", "a", "9lives", "a_b-c9"] {
            assert!(is_canonical_identifier(good), "{good:?} is a real name");
        }
        for bad in [
            "",                                    // nothing to name
            "Acme",                                // case confusable
            "acme ",                               // trailing space
            " acme",                               // leading space
            "acme\u{200b}",                        // zero-width
            "\u{430}cme",                          // Cyrillic homoglyph
            "e\u{301}quipe",                       // NFD
            "..",                                  // traversal
            ".",                                   // self
            "a/b",                                 // separator
            "a\\b",                                // Windows separator
            "a\u{0}b",                             // NUL
            "-rf",                                 // reads as a flag
            "_hidden",                             // conventional hidden prefix
            "a.b",                                 // dots are not allowed at all
            &"a".repeat(MAX_IDENTIFIER_BYTES + 1), // over the bound
        ] {
            assert!(!is_canonical_identifier(bad), "{bad:?} must be refused");
        }
        // Exactly at the bound is fine; one past it is not.
        assert!(is_canonical_identifier(&"a".repeat(MAX_IDENTIFIER_BYTES)));
    }

    #[test]
    fn an_unknown_tenant_is_distinguishable_from_one_that_spent_nothing() {
        let d = two_tenant_deployment();
        assert_eq!(d.spent("acme"), Some(0));
        assert_eq!(d.spent("nowhere"), None);
    }

    #[test]
    fn approval_gate_denies_without_a_recorded_approval() {
        let mut d = two_tenant_deployment();
        d.require_approval("policy.set");
        let alice = actor("memorithm", "alice", AuthStrength::Token);
        let req = request("acme", "alice", "policy.set", "r-approval");
        let call = Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
            justification: Some("an operator reason"),
        };
        // The call is otherwise admissible; the approval gate is the only
        // thing standing in its way.
        assert_eq!(
            d.approval_gate(&call, &"a".repeat(64)),
            Err(Refusal::RequiresApproval),
            "unrecorded approval must be denial"
        );
        // A non-gated tool is untouched by the gate.
        let recall = request("acme", "alice", "memory.recall", "r-plain");
        let call = Call {
            actor: &alice,
            request: &recall,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
            justification: None,
        };
        assert_eq!(d.approval_gate(&call, &"b".repeat(64)), Ok(()));
    }

    #[test]
    fn recorded_approval_authorizes_exactly_one_artifact_and_tenant() {
        let mut d = two_tenant_deployment();
        d.require_approval("policy.set");
        let artifact = "c".repeat(64);
        let recorded = d
            .record_approval(
                ccos_enterprise_approval::ApprovalRequest::new(
                    ccos_enterprise_tenancy::TenantId("acme".into()),
                    "policy.set",
                    &artifact,
                    "ZEKRITI Tarek",
                    ccos_enterprise_approval::ApprovalDecision::Approved,
                    1_000,
                    None,
                    "approve the allowlist change",
                )
                .unwrap(),
            )
            .unwrap();
        assert!(recorded.starts_with("approval-v1-"));
        let alice = actor("memorithm", "alice", AuthStrength::Token);
        let req = request("acme", "alice", "policy.set", "r-approved");
        let call = Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
            justification: Some("operator reason"),
        };
        assert_eq!(d.approval_gate(&call, &artifact), Ok(()));
        // Same action, different artifact: denial.
        assert_eq!(
            d.approval_gate(&call, &"d".repeat(64)),
            Err(Refusal::RequiresApproval)
        );
        // Same artifact, other tenant: denial.
        let globex_req = request("globex", "alice", "policy.set", "r-other-tenant");
        let call = Call {
            actor: &alice,
            request: &globex_req,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
            justification: Some("operator reason"),
        };
        assert_eq!(
            d.approval_gate(&call, &artifact),
            Err(Refusal::RequiresApproval)
        );
    }

    #[test]
    fn approval_ledger_survives_snapshot_and_restore() {
        let mut d = two_tenant_deployment();
        d.require_approval("policy.set");
        let artifact = "e".repeat(64);
        d.record_approval(
            ccos_enterprise_approval::ApprovalRequest::new(
                ccos_enterprise_tenancy::TenantId("acme".into()),
                "policy.set",
                &artifact,
                "ZEKRITI Tarek",
                ccos_enterprise_approval::ApprovalDecision::Approved,
                1_000,
                None,
                "durable approval",
            )
            .unwrap(),
        )
        .unwrap();
        let snapshot = d.snapshot();
        assert!(snapshot.approval_required.contains("policy.set"));
        assert_eq!(snapshot.approvals.approvals.len(), 1);

        let restored = Deployment::restore(snapshot, &[], &[]).expect("restored deployment");
        assert!(restored.requires_approval("policy.set"));
        let alice = actor("memorithm", "alice", AuthStrength::Token);
        let req = request("acme", "alice", "policy.set", "r-restored");
        let call = Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
            justification: Some("operator reason"),
        };
        assert_eq!(
            restored.approval_gate(&call, &artifact),
            Ok(()),
            "the approval survives a restart"
        );
    }

    #[test]
    fn corrupt_approval_ledger_is_refused_on_restore() {
        let d = two_tenant_deployment();
        let mut snapshot = d.snapshot();
        let mut approvals = ccos_enterprise_approval::ApprovalSnapshot::default();
        approvals.approvals.insert(
            "approval-v1-broken".into(),
            ccos_enterprise_approval::ApprovalRecord {
                id: "approval-v1-broken".into(),
                tenant: "acme".into(),
                approver: "ZEKRITI Tarek".into(),
                action: "policy.set".into(),
                artifact_hash: "f".repeat(64),
                decision: ccos_enterprise_approval::ApprovalDecision::Approved,
                recorded_at: 1_000,
                expires_at: None,
                justification: Some("x".into()),
                schema_version: 1,
            },
        );
        snapshot.approvals = approvals;
        let err = match Deployment::restore(snapshot, &[], &[]) {
            Ok(_) => panic!("a corrupt approval ledger must refuse restore"),
            Err(error) => error,
        };
        assert!(
            matches!(err, RestoreError::ApprovalLedgerCorrupt { .. }),
            "{err}"
        );
    }
}
