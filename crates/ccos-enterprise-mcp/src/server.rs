//! The governed front door.
//!
//! [`GovernedMcp`] is the only way a client is meant to reach Core or an
//! explicitly enabled Enterprise-local capability in an Enterprise deployment.
//! It does three things and refuses to do a fourth:
//!
//! 1. advertises **Enterprise** capability names, never Core's bare ones, so a
//!    client cannot learn a name that bypasses the table;
//! 2. runs every call through [`Deployment::admit`] — identity, credential
//!    binding, tenant ownership, boundary, authorization, model governance,
//!    Q-Page activation, replay and budget, in that order;
//! 3. dispatches only on [`Outcome::Forwarded`], under the verified tenant and,
//!    for Enterprise-local capabilities, with the verified actor.
//!
//! The fourth thing — deciding policy itself — is what it must not do. Every
//! refusal here is the runtime's, so there is exactly one admission policy in
//! the product and this crate cannot drift from it.
//!
//! ## Why the backends are traits
//!
//! A governed deployment needs one Core session **per tenant**: two tenants
//! sharing a session share a memory graph, and tenant isolation is the
//! outermost promise the product makes. That session lifecycle — creation,
//! eviction, on-disk location, crash recovery — is a substantial design in its
//! own right and is not settled here. [`Backend`] is the seam where it lands:
//! it receives the verified tenant id on every dispatch precisely so the
//! implementation cannot forget to scope by it.
//!
//! Enterprise-local Decision Intelligence is separate from Core's catalogue.
//! [`DecisionBackend`] receives both the verified tenant and the verified
//! [`ccos_enterprise_auth::AuthenticatedActor`], so authority fields cannot be
//! reconstructed from caller JSON.

use ccos_enterprise_decision_service::DECISION_TOOLS;
use ccos_enterprise_runtime::{Call, Deployment, Outcome, Refusal};

use crate::decision::{
    govern_decision_catalogue, is_decision_tool, DecisionBackend, NoDecisionBackend,
};
use crate::{governed_names, to_core, Disposition, CATALOGUE};

/// Where an admitted Core call actually runs.
///
/// Implementations **must** scope every effect by `tenant`. The front door
/// verifies which tenant a caller may name; it cannot verify what a backend
/// then does with it.
pub trait Backend {
    /// Run `core_tool` — a bare Core name, already translated — for `tenant`.
    fn dispatch(
        &mut self,
        tenant: &str,
        core_tool: &str,
        arguments: &serde_json::Value,
    ) -> Result<serde_json::Value, String>;
}

/// One entry of the advertised catalogue.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AdvertisedTool {
    pub name: &'static str,
    pub permission: &'static str,
}

/// What the front door answered.
#[derive(Debug, Clone, PartialEq)]
pub enum McpOutcome {
    /// Admitted and executed. Carries the selected backend's result.
    Ok(serde_json::Value),
    /// Admitted, executed, and the selected backend failed. The distinction
    /// matters: a governance refusal and a backend fault are different
    /// incidents, and collapsing them hides one behind the other.
    BackendError(String),
    /// The request_id was already forwarded earlier. No backend is called
    /// again; callers can correlate this acknowledgement to the original
    /// request without duplicating its effect.
    Replayed,
    /// Refused by the admission path. Never reached a backend.
    Refused(Refusal),
    /// The call was admitted but no enabled local/Core executor owns the tool.
    /// This remains separate from `Refused`: the latter is a governance
    /// decision, this is a front-door catalogue mismatch.
    UnknownTool,
}

impl McpOutcome {
    pub fn reached_the_backend(&self) -> bool {
        matches!(self, Self::Ok(_) | Self::BackendError(_))
    }
}

/// The governed MCP front door.
///
/// `D = NoDecisionBackend` preserves the historical Core-only surface.
/// Decision capabilities become governed and advertised only through
/// [`GovernedMcp::with_decisions`].
pub struct GovernedMcp<B: Backend, D: DecisionBackend = NoDecisionBackend> {
    deployment: Deployment,
    backend: B,
    decision_backend: D,
}

impl<B: Backend> GovernedMcp<B, NoDecisionBackend> {
    /// Existing Core-only front door. Decision tools remain absent.
    pub fn new(deployment: Deployment, backend: B) -> Self {
        Self {
            deployment,
            backend,
            decision_backend: NoDecisionBackend,
        }
    }

    /// Build a front door with the exact Enterprise-local Decision Intelligence
    /// catalogue enabled and governed by its declared permissions.
    pub fn with_decisions<D: DecisionBackend>(
        mut deployment: Deployment,
        backend: B,
        decision_backend: D,
    ) -> GovernedMcp<B, D> {
        govern_decision_catalogue(&mut deployment);
        GovernedMcp {
            deployment,
            backend,
            decision_backend,
        }
    }
}

impl<B: Backend, D: DecisionBackend> GovernedMcp<B, D> {
    /// The deployment underneath, for provisioning and for reading the trail.
    pub fn deployment(&self) -> &Deployment {
        &self.deployment
    }

    pub fn deployment_mut(&mut self) -> &mut Deployment {
        &mut self.deployment
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// The Core backend, mutably — for lifecycle calls a deployment owns, such
    /// as checkpointing sessions on a clean shutdown. Not a governance
    /// surface: nothing reached through `call` goes past `admit`.
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    pub fn decision_backend(&self) -> &D {
        &self.decision_backend
    }

    pub fn decision_backend_mut(&mut self) -> &mut D {
        &mut self.decision_backend
    }

    /// The `tools/list` answer: Enterprise names only.
    ///
    /// Core names remain translated by [`crate::CATALOGUE`]. The local
    /// Decision Intelligence catalogue is appended only when a decision
    /// backend is enabled; there is no open `decision.*` wildcard.
    pub fn list_tools(&self) -> Vec<AdvertisedTool> {
        let mut tools: Vec<AdvertisedTool> = CATALOGUE
            .iter()
            .filter_map(|t| match t.disposition {
                Disposition::Governed {
                    enterprise,
                    permission,
                } => Some(AdvertisedTool {
                    name: enterprise,
                    permission,
                }),
                Disposition::OutsideBoundary { .. } => None,
            })
            .collect();
        if self.decision_backend.enabled() {
            tools.extend(DECISION_TOOLS.iter().map(|tool| AdvertisedTool {
                name: tool.name,
                permission: tool.permission,
            }));
        }
        tools.sort_by_key(|t| t.name);
        tools
    }

    /// Run one `tools/call`.
    ///
    /// The runtime decides admission exactly once. Only the first forwarded
    /// call may dispatch; [`Outcome::Replayed`] suppresses both Core and local
    /// Decision Intelligence effects.
    pub fn call(&mut self, call: Call<'_>, arguments: &serde_json::Value) -> McpOutcome {
        let tool = call.request.tool.clone();
        let tenant = call.request.tenant.clone();
        // `AuthenticatedActor` is produced by a verifier and is intentionally
        // cloned before `admit` consumes the Call wrapper. The decision backend
        // never receives an actor string parsed from client arguments.
        let actor = call.actor.clone();

        match self.deployment.admit(call) {
            Outcome::Refused(r) => return McpOutcome::Refused(r),
            Outcome::Replayed => return McpOutcome::Replayed,
            Outcome::Forwarded => {}
        }

        if let Some(core_tool) = to_core(&tool) {
            return match self.backend.dispatch(&tenant, core_tool, arguments) {
                Ok(value) => McpOutcome::Ok(value),
                Err(error) => McpOutcome::BackendError(error),
            };
        }

        if self.decision_backend.enabled() && is_decision_tool(&tool) {
            return match self
                .decision_backend
                .dispatch_decision(&tenant, &actor, &tool, arguments)
            {
                Ok(value) => McpOutcome::Ok(value),
                Err(error) => McpOutcome::BackendError(error),
            };
        }

        McpOutcome::UnknownTool
    }
}

/// Provision a deployment so it governs exactly Core's translated catalogue.
///
/// Enterprise-local decision tools are deliberately absent here; they are
/// added only by [`GovernedMcp::with_decisions`].
pub fn govern_catalogue(deployment: &mut Deployment) {
    for (tool, permission) in crate::governance_map() {
        deployment.govern_tool(tool, permission);
    }
    debug_assert_eq!(governed_names().len(), crate::governance_map().len());
}

#[cfg(test)]
mod tests {
    use super::*;
    use ccos_enterprise_auth::AuthStrength;
    use ccos_enterprise_auth::AuthenticatedActor;
    use ccos_enterprise_gateway::GatewayRequest;
    use ccos_enterprise_runtime::{actor, request, TenantState};
    use serde_json::json;

    /// Records every dispatch, so "did this reach Core" is a fact and not an
    /// inference from a return value.
    #[derive(Default)]
    struct Recorder {
        calls: Vec<(String, String)>,
        fail_with: Option<String>,
    }

    impl Backend for Recorder {
        fn dispatch(
            &mut self,
            tenant: &str,
            core_tool: &str,
            _arguments: &serde_json::Value,
        ) -> Result<serde_json::Value, String> {
            self.calls.push((tenant.to_string(), core_tool.to_string()));
            match &self.fail_with {
                Some(e) => Err(e.clone()),
                None => Ok(json!({"ok": true, "tool": core_tool})),
            }
        }
    }

    fn deployment() -> Deployment {
        let mut d = Deployment::new();
        d.add_role("reader", &["memory.read"])
            .add_role("writer", &["memory.read", "memory.write"]);
        govern_catalogue(&mut d);
        let mut acme = TenantState::new(10_000);
        acme.allow_model("claude-opus");
        d.add_tenant("memorithm", "acme", acme);
        let mut globex = TenantState::new(10_000);
        globex.allow_model("claude-opus");
        d.add_tenant("memorithm", "globex", globex);
        d.assign("alice", "writer");
        d.assign("bob", "reader");
        d
    }

    fn front_door() -> GovernedMcp<Recorder> {
        GovernedMcp::new(deployment(), Recorder::default())
    }

    #[test]
    fn the_catalogue_advertises_enterprise_names_and_never_cores() {
        let mcp = front_door();
        let names: Vec<&str> = mcp.list_tools().iter().map(|t| t.name).collect();
        assert_eq!(names, governed_names());
        for name in &names {
            assert!(
                name.contains('.'),
                "{name} is a bare name — the front door leaked Core's namespace"
            );
        }
        // The bare Core names a client might try are simply not offered.
        for bare in ["recall", "ingest", "octa_feedback", "page_fault"] {
            assert!(!names.contains(&bare), "{bare} is advertised");
        }
    }

    #[test]
    fn an_admitted_call_reaches_the_backend_under_the_core_name() {
        let mut mcp = front_door();
        let a = actor("memorithm", "alice", AuthStrength::Token);
        let req = request("acme", "alice", "memory.recall", "r-1");
        let out = mcp.call(
            Call {
                actor: &a,
                request: &req,
                model: "claude-opus",
                cost_tokens: 10,
                variant: None,
                justification: None,
            },
            &json!({}),
        );
        assert!(matches!(out, McpOutcome::Ok(_)), "{out:?}");
        assert_eq!(
            mcp.backend().calls,
            vec![("acme".to_string(), "recall".to_string())],
            "the backend must see the *Core* name and the verified tenant"
        );
        assert_eq!(mcp.deployment().spent("acme"), Some(10));
    }

    #[test]
    fn a_replayed_call_never_dispatches_the_backend_twice() {
        let mut mcp = front_door();
        let a = actor("memorithm", "alice", AuthStrength::Token);
        let req = request("acme", "alice", "memory.ingest", "r-idempotent");

        let first = mcp.call(
            Call {
                actor: &a,
                request: &req,
                model: "claude-opus",
                cost_tokens: 10,
                variant: None,
                justification: None,
            },
            &json!({}),
        );
        assert!(matches!(first, McpOutcome::Ok(_)), "{first:?}");

        let replay = mcp.call(
            Call {
                actor: &a,
                request: &req,
                model: "claude-opus",
                cost_tokens: 10,
                variant: None,
                justification: None,
            },
            &json!({}),
        );
        assert_eq!(replay, McpOutcome::Replayed);
        assert_eq!(
            mcp.backend().calls,
            vec![("acme".to_string(), "ingest".to_string())],
            "a replay must not duplicate the backend effect"
        );
        assert_eq!(mcp.deployment().spent("acme"), Some(10));
    }

    /// The property the whole crate exists for: nothing reaches Core unless
    /// the admission path said yes. Every gate is exercised, and after all of
    /// them the recorder is still empty.
    #[test]
    fn no_refused_call_ever_reaches_the_backend() {
        let mut mcp = front_door();
        let alice = actor("memorithm", "alice", AuthStrength::Token);
        let bob = actor("memorithm", "bob", AuthStrength::Token);
        let anon = actor("memorithm", "alice", AuthStrength::Anonymous);
        let foreign = actor("initech", "mallory", AuthStrength::Token);

        let cases: Vec<(&AuthenticatedActor, GatewayRequest, &str, Refusal)> = vec![
            (
                &anon,
                request("acme", "alice", "memory.recall", "r-anon"),
                "claude-opus",
                Refusal::Unauthenticated,
            ),
            (
                &bob,
                request("acme", "alice", "memory.recall", "r-forged"),
                "claude-opus",
                Refusal::ActorMismatch,
            ),
            (
                &foreign,
                request("acme", "mallory", "memory.recall", "r-foreign"),
                "claude-opus",
                Refusal::TenantNotOwnedByOrg,
            ),
            (
                &alice,
                request("", "alice", "memory.recall", "r-empty"),
                "claude-opus",
                Refusal::MalformedRequest("tenant".into()),
            ),
            (
                &alice,
                request("nowhere", "alice", "memory.recall", "r-nowhere"),
                "claude-opus",
                Refusal::UnknownTenant,
            ),
            (
                &alice,
                request("acme", "alice", "shell.exec", "r-shell"),
                "claude-opus",
                Refusal::OutsideBoundary(String::new()),
            ),
            (
                &alice,
                request("acme", "alice", "memory.ungoverned", "r-ungov"),
                "claude-opus",
                Refusal::ToolNotGoverned,
            ),
            (
                &bob,
                request("acme", "bob", "memory.ingest", "r-perm"),
                "claude-opus",
                Refusal::PermissionDenied,
            ),
            (
                &alice,
                request("acme", "alice", "memory.recall", "r-model"),
                "gpt-5",
                Refusal::ModelNotAllowed,
            ),
        ];

        for (a, req, model, expected) in &cases {
            let out = mcp.call(
                Call {
                    actor: a,
                    request: req,
                    model,
                    cost_tokens: 10,
                    variant: None,
                    justification: None,
                },
                &json!({}),
            );
            let McpOutcome::Refused(actual) = &out else {
                panic!("{:?} was not refused: {out:?}", req.request_id);
            };
            // `OutsideBoundary` carries a message; compare the shape.
            match (expected, actual) {
                (Refusal::OutsideBoundary(_), Refusal::OutsideBoundary(_)) => {}
                (e, a) => assert_eq!(e, a, "{:?}", req.request_id),
            }
            assert!(!out.reached_the_backend());
        }

        assert!(
            mcp.backend().calls.is_empty(),
            "a refused call reached Core: {:?}",
            mcp.backend().calls
        );
        assert_eq!(
            mcp.deployment().spent("acme"),
            Some(0),
            "and not one of them was billed"
        );
        // Every refusal is still journaled — a probe is exactly the traffic an
        // audit trail is for.
        assert_eq!(mcp.deployment().audit().count(), cases.len());
    }

    #[test]
    fn a_client_cannot_reach_core_by_naming_a_core_tool_directly() {
        let mut mcp = front_door();
        let a = actor("memorithm", "alice", AuthStrength::Token);
        // The bare Core names, tried directly. `recall` and friends have no
        // dot, so the gateway's canonical grammar refuses them outright.
        for bare in ["recall", "ingest", "page_fault", "octa_feedback"] {
            let req = request("acme", "alice", bare, &format!("r-{bare}"));
            let out = mcp.call(
                Call {
                    actor: &a,
                    request: &req,
                    model: "claude-opus",
                    cost_tokens: 1,
                    variant: None,
                    justification: None,
                },
                &json!({}),
            );
            assert!(
                matches!(out, McpOutcome::Refused(_)),
                "{bare} was not refused: {out:?}"
            );
        }
        assert!(mcp.backend().calls.is_empty());
    }

    #[test]
    fn a_backend_fault_is_not_reported_as_a_governance_refusal() {
        let mut mcp = GovernedMcp::new(
            deployment(),
            Recorder {
                calls: Vec::new(),
                fail_with: Some("core said no".into()),
            },
        );
        let a = actor("memorithm", "alice", AuthStrength::Token);
        let req = request("acme", "alice", "memory.recall", "r-fault");
        let out = mcp.call(
            Call {
                actor: &a,
                request: &req,
                model: "claude-opus",
                cost_tokens: 10,
                variant: None,
                justification: None,
            },
            &json!({}),
        );
        assert_eq!(out, McpOutcome::BackendError("core said no".into()));
        assert!(
            out.reached_the_backend(),
            "it did reach Core, and failed there"
        );
        // It was admitted, so it was billed: the tenant used its quota, and
        // conflating this with a refusal would silently refund every fault.
        assert_eq!(mcp.deployment().spent("acme"), Some(10));
    }

    #[test]
    fn each_tenant_is_dispatched_under_its_own_name() {
        let mut mcp = front_door();
        let a = actor("memorithm", "alice", AuthStrength::Token);
        for (index, tenant) in ["acme", "globex", "acme"].into_iter().enumerate() {
            let req = request(
                tenant,
                "alice",
                "memory.recall",
                &format!("r-{tenant}-{index}"),
            );
            let out = mcp.call(
                Call {
                    actor: &a,
                    request: &req,
                    model: "claude-opus",
                    cost_tokens: 1,
                    variant: None,
                    justification: None,
                },
                &json!({}),
            );
            assert!(matches!(out, McpOutcome::Ok(_)), "{tenant}: {out:?}");
        }
        let tenants: Vec<&str> = mcp
            .backend()
            .calls
            .iter()
            .map(|(t, _)| t.as_str())
            .collect();
        assert_eq!(tenants, vec!["acme", "globex", "acme"]);
    }

    #[test]
    fn every_advertised_capability_is_actually_callable() {
        // The failure this prevents: a tool advertised, admitted by the
        // boundary, and then refused as ungoverned — which reads to a client
        // as a product bug rather than a policy decision.
        let mut mcp = front_door();
        let a = actor("memorithm", "alice", AuthStrength::Token);
        for (i, tool) in mcp.list_tools().iter().map(|t| t.name).enumerate() {
            let req = request("acme", "alice", tool, &format!("r-{i}"));
            let out = mcp.call(
                Call {
                    actor: &a,
                    request: &req,
                    model: "claude-opus",
                    cost_tokens: 1,
                    variant: None,
                    justification: None,
                },
                &json!({}),
            );
            assert!(
                matches!(out, McpOutcome::Ok(_)),
                "advertised {tool} was not callable: {out:?}"
            );
        }
        assert_eq!(mcp.backend().calls.len(), governed_names().len());
    }
}
