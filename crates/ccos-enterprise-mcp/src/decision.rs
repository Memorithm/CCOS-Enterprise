//! Enterprise-local Decision Intelligence catalogue and execution seam.
//!
//! These tools are not Core translations, so they must never be inserted into
//! `crate::CATALOGUE`, whose total/injective contract is specifically about Core.

use ccos_enterprise_auth::AuthenticatedActor;
use ccos_enterprise_decision_service::{DecisionService, DECISION_TOOLS};
use ccos_enterprise_runtime::Deployment;
use serde_json::Value;

/// A backend for Enterprise-local decision capabilities.
///
/// The MCP front door has already run the full composed admission path before
/// calling this trait. Implementations receive the verified tenant and the
/// unforgeable authenticated actor rather than copies parsed from arguments.
pub trait DecisionBackend {
    fn enabled(&self) -> bool {
        true
    }

    fn dispatch_decision(
        &mut self,
        tenant: &str,
        actor: &AuthenticatedActor,
        enterprise_tool: &str,
        arguments: &Value,
    ) -> Result<Value, String>;
}

/// Default for the existing Core-only front door. It advertises and governs no
/// decision tools, preserving the previous catalogue exactly.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoDecisionBackend;

impl DecisionBackend for NoDecisionBackend {
    fn enabled(&self) -> bool {
        false
    }

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
            assert!(matches!(classify(&request), ccos_enterprise_gateway::Disposition::Forward));
        }
    }

    #[test]
    fn permission_vocabulary_is_closed() {
        let permissions: BTreeSet<&str> = decision_governance_map()
            .into_iter()
            .map(|(_, permission)| permission)
            .collect();
        assert_eq!(permissions, BTreeSet::from(["decision.read", "decision.write"]));
    }
}
