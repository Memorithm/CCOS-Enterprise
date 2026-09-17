//! Real stdio execution seam for the Enterprise-local `memory.context` tool.
//!
//! This child module intentionally reuses the parent server's authenticated
//! identity, `Deployment::admit`, execution journal, effect marker and durable
//! governance settlement. It owns no independent authorization state.

use super::*;
use ccos_enterprise_mcp::GOVERNED_CONTEXT_TOOL;
use ccos_enterprise_memory::{
    assemble_governed_bootstrap_context, attest_governed_context, BudgetedMemoryRecall,
    GovernedRecallTrustPolicy, MemoryContextBudget, MemoryRecallBudget, MemorySpace,
    MemoryValidationState,
};
use ccos_enterprise_tenancy::{TenantId, TenantScope};

struct GovernedContextArguments {
    embedding: Vec<f32>,
    recall_budget: MemoryRecallBudget,
    context_budget: MemoryContextBudget,
}

impl Server {
    pub(super) fn call_governed_context(
        &mut self,
        identity: &ccos_enterprise_auth::AuthenticatedActor,
        request: &GatewayRequest,
        meta: &Meta,
        arguments: &Value,
    ) -> Result<Value, (i64, String)> {
        let parsed = parse_arguments(arguments).map_err(|error| (-32602, error))?;
        let checkpoint = DeploymentCheckpoint::capture(self.front_door.deployment());
        let execution = DispatchExecution::new(
            meta.turn_id.clone(),
            meta.step_id.clone(),
            meta.execution_attempt_id.clone(),
        );
        let mut forwarded = false;

        let response = match self.front_door.deployment_mut().admit(Call {
            actor: identity,
            request,
            model: &meta.model,
            cost_tokens: self.config.call_cost_tokens,
            variant: None,
            justification: None,
        }) {
            Outcome::Forwarded => {
                forwarded = true;
                let input_sha256 = successful_output_sha256(arguments).map_err(|error| {
                    let reason = format!("cannot hash governed-context input: {error}");
                    self.poisoned = Some(reason);
                    (
                        -32000,
                        "Enterprise governed-context input is not durable".to_string(),
                    )
                })?;
                self.append_skill_execution_event(
                    &request.tenant,
                    execution::ExecutionEvent::ToolRequested {
                        turn_id: execution.turn_id.clone(),
                        step_id: execution.step_id.clone(),
                        call_id: execution.call_id.clone(),
                        tool: GOVERNED_CONTEXT_TOOL.to_string(),
                        input_sha256,
                    },
                )?;
                self.append_skill_execution_event(
                    &request.tenant,
                    execution::ExecutionEvent::ToolStarted {
                        call_id: execution.call_id.clone(),
                    },
                )?;

                // This is a read-only provider operation, but the durable effect
                // witness closes the same crash window as `memory.skills`: once
                // a response is physically produced, startup can settle the
                // admitted request without repeating an ambiguous operation.
                let mut effect = EffectRecord::from_request(
                    request,
                    meta,
                    self.config.call_cost_tokens,
                    arguments,
                );
                if let Err(error) = write_effect(&effect_path(&self.config.state_dir), &effect) {
                    self.poisoned = Some(error.clone());
                    return Err((
                        -32000,
                        "Enterprise governed-context settlement state is not durable".to_string(),
                    ));
                }

                let result = self.read_governed_context(request, &parsed);
                let (success, output_sha256) = match &result {
                    Ok(value) => (
                        true,
                        successful_output_sha256(value).map_err(|error| {
                            let reason = format!("cannot hash governed-context output: {error}");
                            self.poisoned = Some(reason);
                            (
                                -32000,
                                "Enterprise governed-context output is not durable".to_string(),
                            )
                        })?,
                    ),
                    Err(error) => (false, failed_output_sha256(error)),
                };
                effect.state = if success {
                    EffectState::Succeeded
                } else {
                    EffectState::Failed
                };
                effect.output_sha256 = Some(output_sha256.clone());
                if let Err(error) = write_effect(&effect_path(&self.config.state_dir), &effect) {
                    self.poisoned = Some(error.clone());
                    return Err((
                        -32000,
                        "Enterprise governed-context outcome is not durable".to_string(),
                    ));
                }
                self.append_skill_execution_event(
                    &request.tenant,
                    execution::ExecutionEvent::ToolFinished {
                        call_id: execution.call_id.clone(),
                        success,
                        output_sha256,
                    },
                )?;

                match result {
                    Ok(value) => value,
                    Err(error) => {
                        let restored = checkpoint.restore().map_err(|restore_error| {
                            self.poisoned = Some(restore_error.clone());
                            (-32000, "Enterprise admission rollback failed".to_string())
                        })?;
                        *self.front_door.deployment_mut() = restored;
                        if let Err(settle_error) = self
                            .front_door
                            .backend_mut()
                            .inner_mut()
                            .settle_marker(&request.request_id)
                        {
                            self.poisoned = Some(settle_error.clone());
                            return Err((
                                -32000,
                                "Enterprise failed governed-context outcome could not be settled"
                                    .to_string(),
                            ));
                        }
                        eprintln!(
                            "ccos-enterprise-mcp: admitted governed context failed without external side effect: {error}"
                        );
                        return Ok(tool_error("CCOS Enterprise governed context failed"));
                    }
                }
            }
            Outcome::Replayed => json!({
                "content": [{ "type": "text", "text": "CCOS Enterprise replay suppressed" }],
                "structuredContent": { "replayed": true }
            }),
            Outcome::Refused(refusal) => {
                eprintln!("ccos-enterprise-mcp: governed context refused: {refusal:?}");
                tool_error("CCOS Enterprise request refused")
            }
        };

        if let Err(error) = persist_deployment(&mut self.store, self.front_door.deployment()) {
            self.poisoned = Some(error.clone());
            eprintln!(
                "ccos-enterprise-mcp: durable governed-context governance commit failed: {error}"
            );
            return Err((
                -32000,
                "Enterprise governance state is not durable".to_string(),
            ));
        }
        if forwarded {
            if let Err(error) = self
                .front_door
                .backend_mut()
                .inner_mut()
                .settle_marker(&request.request_id)
            {
                self.poisoned = Some(error.clone());
                eprintln!(
                    "ccos-enterprise-mcp: governed-context settlement marker failed: {error}"
                );
                return Err((
                    -32000,
                    "Enterprise governed-context settlement is not durable".to_string(),
                ));
            }
        }
        Ok(response)
    }

    fn read_governed_context(
        &self,
        request: &GatewayRequest,
        parsed: &GovernedContextArguments,
    ) -> Result<Value, String> {
        let store = self
            .governed_memory
            .as_ref()
            .ok_or_else(|| "governed provider generation is unavailable".to_string())?;
        if store.tenant().as_str() != request.tenant {
            return Err("governed provider tenant differs from admitted request".into());
        }
        if parsed.embedding.len() != store.config().dimension {
            return Err(format!(
                "embedding dimension mismatch: expected {}, found {}",
                store.config().dimension,
                parsed.embedding.len()
            ));
        }

        let authority = store.governance();
        let loadout = authority
            .loadout
            .bootstrap_loadout()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "governed memory has no bootstrap-enabled loadout".to_string())?;
        let tenant = TenantId::validated(&request.tenant)
            .ok_or_else(|| "admitted tenant is not canonical".to_string())?;
        let observations = store
            .recovered()
            .recall(
                authority,
                TenantScope::new(
                    tenant,
                    BudgetedMemoryRecall {
                        embedding: &parsed.embedding,
                        loadout: &loadout,
                        budget: parsed.recall_budget,
                    },
                ),
                GovernedRecallTrustPolicy::VerifiedOnly,
            )
            .map_err(|error| error.to_string())?;
        let assembly =
            assemble_governed_bootstrap_context(authority, observations, parsed.context_budget)
                .map_err(|error| error.to_string())?;
        let attestations = attest_governed_context(&assembly);
        if assembly.len() != attestations.len() {
            return Err("governed context attestation cardinality mismatch".into());
        }
        let items: Vec<Value> = assembly
            .chunks()
            .iter()
            .zip(attestations.iter())
            .map(|(chunk, attestation)| {
                json!({
                    "asset_id": chunk.asset_id.as_str(),
                    "space": memory_space_label(&chunk.space),
                    "similarity": chunk.similarity,
                    "payload_bytes": &chunk.payload,
                    "payload_sha256": attestation.payload_sha256,
                    "tenant": attestation.tenant.as_str(),
                    "projection_version": attestation.projection_version,
                    "projection_sha256": attestation.projection_sha256,
                    "asset_state": "active",
                    "trust_state": validation_state_label(attestation.trust_state),
                    "parents": attestation.parents.iter().map(|id| id.as_str()).collect::<Vec<_>>(),
                    "evidence": attestation.evidence.iter().map(|evidence| evidence.as_str()).collect::<Vec<_>>()
                })
            })
            .collect();
        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "CCOS Enterprise supplied {} verified governed context item(s)",
                    items.len()
                )
            }],
            "structuredContent": {
                "tool": GOVERNED_CONTEXT_TOOL,
                "generation": store.generation(),
                "trust_policy": "verified_only",
                "payload_bytes": assembly.payload_bytes(),
                "tenant": assembly.tenant().as_str(),
                "projection_version": assembly.projection_version(),
                "projection_sha256": assembly.projection_sha256_hex(),
                "items": items
            }
        }))
    }
}

fn parse_arguments(arguments: &Value) -> Result<GovernedContextArguments, String> {
    let object = arguments
        .as_object()
        .ok_or_else(|| "memory.context arguments must be an object".to_string())?;
    const ALLOWED: &[&str] = &[
        "embedding",
        "recall_max_items",
        "recall_max_shortlist",
        "recall_max_payload_bytes",
        "context_max_items",
        "context_max_payload_bytes",
    ];
    if object.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
        return Err("memory.context contains an unknown argument".into());
    }
    let values = object
        .get("embedding")
        .and_then(Value::as_array)
        .ok_or_else(|| "memory.context embedding must be an array".to_string())?;
    if values.is_empty() || values.len() > 8192 {
        return Err("memory.context embedding length is outside 1..=8192".into());
    }
    let mut embedding = Vec::with_capacity(values.len());
    for value in values {
        let numeric = value
            .as_f64()
            .ok_or_else(|| "memory.context embedding contains a non-number".to_string())?;
        let narrowed = numeric as f32;
        if !numeric.is_finite() || !narrowed.is_finite() {
            return Err("memory.context embedding contains a non-finite f32".into());
        }
        embedding.push(narrowed);
    }
    let get = |name: &str, default: usize| -> Result<usize, String> {
        match object.get(name) {
            None => Ok(default),
            Some(value) => value
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .ok_or_else(|| format!("memory.context {name} must be a non-negative integer")),
        }
    };
    let recall_items = get("recall_max_items", 32)?;
    let recall_shortlist = get("recall_max_shortlist", recall_items.max(128))?;
    let recall_payload = get("recall_max_payload_bytes", 1024 * 1024)?;
    let context_items = get("context_max_items", 16)?;
    let context_payload = get("context_max_payload_bytes", 512 * 1024)?;
    Ok(GovernedContextArguments {
        embedding,
        recall_budget: MemoryRecallBudget::new(recall_items, recall_shortlist, recall_payload)
            .map_err(|error| error.to_string())?,
        context_budget: MemoryContextBudget::new(context_items, context_payload)
            .map_err(|error| error.to_string())?,
    })
}

fn memory_space_label(space: &MemorySpace) -> String {
    match space {
        MemorySpace::Tenant => "tenant".into(),
        MemorySpace::Project(id) => format!("project:{id}"),
        MemorySpace::Team(id) => format!("team:{id}"),
        MemorySpace::Agent(id) => format!("agent:{id}"),
    }
}

fn validation_state_label(state: MemoryValidationState) -> &'static str {
    match state {
        MemoryValidationState::Unverified => "unverified",
        MemoryValidationState::Corroborated => "corroborated",
        MemoryValidationState::Verified => "verified",
        MemoryValidationState::Disputed => "disputed",
        MemoryValidationState::Quarantined => "quarantined",
    }
}
