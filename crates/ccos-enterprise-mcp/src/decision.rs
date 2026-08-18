//! Enterprise-local Decision Intelligence catalogue and execution seam.
//!
//! These tools are not Core translations, so they must never be inserted into
//! `crate::CATALOGUE`, whose total/injective contract is specifically about Core.
//! [`GovernedDecisionMcp`] wraps the existing Core-only [`crate::GovernedMcp`]
//! rather than modifying it: Core calls keep their historical path unchanged,
//! while exact decision tools reuse the same [`ccos_enterprise_runtime::Deployment::admit`]
//! gate and #34 replay suppression before any local effect runs.

use ccos_enterprise_auth::AuthenticatedActor;
use ccos_enterprise_decision_service::{DecisionService, DECISION_TOOLS};
use ccos_enterprise_runtime::{Call, Deployment, Outcome};
use serde_json::Value;

use crate::{AdvertisedTool, Backend, GovernedMcp, McpOutcome};

/// A backend for Enterprise-local decision capabilities.
///
/// Implementations receive the verified tenant and the unforgeable authenticated
/// actor rather than copies parsed from arguments.
pub trait DecisionBackend {
    fn dispatch_decision(
        &mut self,
        tenant: &str,
        actor: &AuthenticatedActor,
        enterprise_tool: &str,
        arguments: &Value,
    ) -> Result<Value, String>;
}

/// Explicit null implementation kept for callers that want to carry a decision
/// backend type without enabling any local execution path. [`GovernedDecisionMcp`]
/// is still opt-in; constructing the historical [`GovernedMcp`] alone advertises
/// no decision tools.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoDecisionBackend;

impl DecisionBackend for NoDecisionBackend {
    fn dispatch_decision(
        &mut self,
        _tenant: &str,
        _actor: &AuthenticatedActor,
        enterprise_tool: &str,
        _arguments: &Value,
    ) -> Result<Value, String> {
        Err(format!(
            "decision backend is disabled; cannot execute {enterprise_tool:?}"
        ))
    }
}

impl DecisionBackend for DecisionService {
    fn dispatch_decision(
        &mut self,
        tenant: &str,
        actor: &AuthenticatedActor,
        enterprise_tool: &str,
        arguments: &Value,
    ) -> Result<Value, String> {
        self.dispatch(tenant, actor, enterprise_tool, arguments)
            .map_err(|error| error.to_string())
    }
}

pub fn decision_governed_names() -> Vec<&'static str> {
    DECISION_TOOLS.iter().map(|tool| tool.name).collect()
}

pub fn decision_governance_map() -> Vec<(&'static str, &'static str)> {
    DECISION_TOOLS
        .iter()
        .map(|tool| (tool.name, tool.permission))
        .collect()
}

pub fn is_decision_tool(name: &str) -> bool {
    DECISION_TOOLS.iter().any(|tool| tool.name == name)
}

/// Add exactly the local decision catalogue to a deployment. No prefix rule is
/// used here or at the gateway.
pub fn govern_decision_catalogue(deployment: &mut Deployment) {
    for (tool, permission) in decision_governance_map() {
        deployment.govern_tool(tool, permission);
    }
}

/// Opt-in front door for Enterprise-local Decision Intelligence.
///
/// The inner [`GovernedMcp`] remains unchanged and continues to own all Core
/// translation/dispatch. The wrapper only intercepts exact decision tool names.
/// For those names it calls the same runtime admission path itself, so replay,
/// tenant ownership, RBAC, policy, budget and audit remain authoritative before
/// the local backend is allowed to mutate durable decision state.
pub struct GovernedDecisionMcp<B: Backend, D: DecisionBackend> {
    core: GovernedMcp<B>,
    decisions: D,
}

impl<B: Backend, D: DecisionBackend> GovernedDecisionMcp<B, D> {
    pub fn new(mut core: GovernedMcp<B>, decisions: D) -> Self {
        govern_decision_catalogue(core.deployment_mut());
        Self { core, decisions }
    }

    pub fn deployment(&self) -> &Deployment {
        self.core.deployment()
    }

    pub fn deployment_mut(&mut self) -> &mut Deployment {
        self.core.deployment_mut()
    }

    pub fn backend(&self) -> &B {
        self.core.backend()
    }

    pub fn backend_mut(&mut self) -> &mut B {
        self.core.backend_mut()
    }

    pub fn decision_backend(&self) -> &D {
        &self.decisions
    }

    pub fn decision_backend_mut(&mut self) -> &mut D {
        &mut self.decisions
    }

    /// Advertise the stable Core catalogue plus the exact local decision tools.
    pub fn list_tools(&self) -> Vec<AdvertisedTool> {
        let mut tools = self.core.list_tools();
        tools.extend(DECISION_TOOLS.iter().map(|tool| AdvertisedTool {
            name: tool.name,
            permission: tool.permission,
        }));
        tools.sort_by_key(|tool| tool.name);
        tools
    }

    pub fn call(&mut self, call: Call<'_>, arguments: &Value) -> McpOutcome {
        if !is_decision_tool(&call.request.tool) {
            return self.core.call(call, arguments);
        }

        let tool = call.request.tool.clone();
        let tenant = call.request.tenant.clone();
        let actor = call.actor.clone();
        match self.core.deployment_mut().admit(call) {
            Outcome::Refused(refusal) => McpOutcome::Refused(refusal),
            Outcome::Replayed => McpOutcome::Replayed,
            Outcome::Forwarded => match self
                .decisions
                .dispatch_decision(&tenant, &actor, &tool, arguments)
            {
                Ok(value) => McpOutcome::Ok(value),
                Err(error) => McpOutcome::BackendError(error),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ccos_enterprise_gateway::{classify, GatewayRequest, DECISION_TOOLS as GATEWAY_TOOLS};
    use std::collections::BTreeSet;

    #[test]
    fn local_catalogue_matches_gateway_exactly() {
        let service: BTreeSet<&str> = decision_governed_names().into_iter().collect();
        let gateway: BTreeSet<&str> = GATEWAY_TOOLS.iter().copied().collect();
        assert_eq!(service, gateway, "gateway and local executor drifted");
        for tool in service {
            let request = GatewayRequest {
                tenant: "acme".into(),
                actor: "alice".into(),
                tool: tool.into(),
                request_id: "r-1".into(),
            };
            assert!(matches!(
                classify(&request),
                ccos_enterprise_gateway::Disposition::Forward
            ));
        }
    }

    #[test]
    fn permission_vocabulary_is_closed() {
        let permissions: BTreeSet<&str> = decision_governance_map()
            .into_iter()
            .map(|(_, permission)| permission)
            .collect();
        assert_eq!(
            permissions,
            BTreeSet::from(["decision.read", "decision.write"])
        );
    }
}
