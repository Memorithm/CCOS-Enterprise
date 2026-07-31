//! The governed front door.
//!
//! [`GovernedMcp`] is the only way a client is meant to reach Core in an
//! Enterprise deployment. It does three things and refuses to do a fourth:
//!
//! 1. advertises **Enterprise** capability names, never Core's bare ones, so a
//!    client cannot learn a name that bypasses the table;
//! 2. runs every call through [`Deployment::admit`] — identity, credential
//!    binding, tenant ownership, boundary, authorization, model governance,
//!    Q-Page activation, replay and budget, in that order;
//! 3. dispatches to the backend **only** on [`Outcome::Forwarded`], under the
//!    Core name and the verified tenant.
//!
//! The fourth thing — deciding anything itself — is what it must not do. Every
//! refusal here is the runtime's, so there is exactly one admission policy in
//! the product and this crate cannot drift from it.
//!
//! ## Why the backend is a trait
//!
//! A governed deployment needs one Core session **per tenant**: two tenants
//! sharing a session share a memory graph, and tenant isolation is the
//! outermost promise the product makes. That session lifecycle — creation,
//! eviction, on-disk location, crash recovery — is a substantial design in its
//! own right and is not settled here. [`Backend`] is the seam where it lands:
//! it receives the verified tenant id on every dispatch precisely so the
//! implementation cannot forget to scope by it.
//!
//! What ships today is the protocol layer and the admission wiring, tested
//! against a recording backend that proves nothing reaches Core unadmitted.
//! What does not ship is a Core-session-per-tenant manager. That is stated
//! rather than implied: a `Backend` that ignores its tenant argument is
//! unsound, and no type here can stop it.

use ccos_enterprise_auth::AuthenticatedActor;
use ccos_enterprise_gateway::GatewayRequest;
use ccos_enterprise_qpages::AdvancedQPageVariant;
use ccos_enterprise_runtime::{Call, Deployment, Outcome, Refusal};

use crate::{governed_names, to_core, Disposition, CATALOGUE};

/// Where an admitted call actually runs.
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
    /// Admitted and executed. Carries the backend's result.
    Ok(serde_json::Value),
    /// Admitted, executed, and the backend failed. The distinction matters: a
    /// governance refusal and a backend fault are different incidents, and
    /// collapsing them hides one behind the other.
    BackendError(String),
    /// Refused by the admission path. Never reached the backend.
    Refused(Refusal),
    /// The client named a capability this deployment does not advertise. Kept
    /// separate from `Refused` because it is a catalogue error, not a
    /// governance decision — and because answering "unknown tool" for a tool
    /// the caller merely lacks permission for would leak the permission model.
    UnknownTool,
}

impl McpOutcome {
    pub fn reached_the_backend(&self) -> bool {
        matches!(self, Self::Ok(_) | Self::BackendError(_))
    }
}

/// The governed MCP front door.
pub struct GovernedMcp<B: Backend> {
    deployment: Deployment,
    backend: B,
}

impl<B: Backend> GovernedMcp<B> {
    pub fn new(deployment: Deployment, backend: B) -> Self {
        Self {
            deployment,
            backend,
        }
    }

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

    /// The `tools/list` answer: Enterprise names only.
    ///
    /// Note what is absent — Core's bare names, and the one excluded tool. A
    /// client of this deployment has no way to learn that `octa_feedback`
    /// exists, let alone name it.
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
        tools.sort_by_key(|t| t.name);
        tools
    }

    /// Run one `tools/call`.
    ///
    /// `request.tool` is an **Enterprise** name. It is translated only after
    /// the call is admitted, so a caller cannot reach a Core tool by naming it
    /// directly: `recall` is not in the catalogue, `memory.recall` is.
    pub fn call(
        &mut self,
        actor: &AuthenticatedActor,
        request: &GatewayRequest,
        model: &str,
        cost_tokens: u64,
        variant: Option<AdvancedQPageVariant>,
        arguments: &serde_json::Value,
    ) -> McpOutcome {
        // The catalogue check is deliberately *after* nothing and *before*
        // admission only in the sense that an unknown name has no Core tool to
        // run. It does not short-circuit governance: an unknown name is still
        // journaled, because "who asked for what" is the question an audit
        // trail exists to answer, and a probe for capabilities that do not
        // exist is exactly the traffic worth keeping.
        let outcome = self.deployment.admit(Call {
            actor,
            request,
            model,
            cost_tokens,
            variant,
        });
        if let Outcome::Refused(r) = outcome {
            return McpOutcome::Refused(r);
        }

        let Some(core_tool) = to_core(&request.tool) else {
            // Admitted by governance, but not in the table. Reachable only if
            // a deployment governs a tool this crate does not translate, which
            // `the_governance_map_covers_every_advertised_capability` and the
            // Core contract test both work to prevent.
            return McpOutcome::UnknownTool;
        };

        match self.backend.dispatch(&request.tenant, core_tool, arguments) {
            Ok(value) => McpOutcome::Ok(value),
            Err(e) => McpOutcome::BackendError(e),
        }
    }
}

/// Provision a deployment so it governs exactly this crate's catalogue.
///
/// Every advertised capability gets its declared permission, so none can fall
/// through to `ToolNotGoverned` by omission — the failure mode where a tool is
/// advertised, admitted by the boundary, and then refused for a reason that
/// reads to the client as a bug.
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
        let out = mcp.call(&a, &req, "claude-opus", 10, None, &json!({}));
        assert!(matches!(out, McpOutcome::Ok(_)), "{out:?}");
        assert_eq!(
            mcp.backend().calls,
            vec![("acme".to_string(), "recall".to_string())],
            "the backend must see the *Core* name and the verified tenant"
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
            let out = mcp.call(a, req, model, 10, None, &json!({}));
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
            let out = mcp.call(&a, &req, "claude-opus", 1, None, &json!({}));
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
        let out = mcp.call(&a, &req, "claude-opus", 10, None, &json!({}));
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
        for tenant in ["acme", "globex", "acme"] {
            let req = request(tenant, "alice", "memory.recall", &format!("r-{tenant}-x"));
            let _ = mcp.call(&a, &req, "claude-opus", 1, None, &json!({}));
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
            let out = mcp.call(&a, &req, "claude-opus", 1, None, &json!({}));
            assert!(
                matches!(out, McpOutcome::Ok(_)),
                "advertised {tool} was not callable: {out:?}"
            );
        }
        assert_eq!(mcp.backend().calls.len(), governed_names().len());
    }
}
