//! Durable stdio execution seam for `memory.evidence.write`.
//!
//! The module reuses the server's authenticated identity, Deployment admission,
//! execution journal, effect marker and quota settlement. Provider generation
//! publication is the physical side effect; failures after publication begins
//! are therefore treated as uncertain and poison the process instead of being
//! converted to a retryable tool failure.

use super::*;
use ccos_enterprise_mcp::GOVERNED_EVIDENCE_WRITE_TOOL;
use ccos_enterprise_memory::{MemoryAssetId, MemoryEvidenceRef};
use ccos_enterprise_provider_adapter::accepted_write::{
    AcceptedEvidenceWrite, EvidenceGenerationReceipt,
};
use ccos_enterprise_tenancy::TenantId;

struct GovernedEvidenceArguments {
    write: AcceptedEvidenceWrite,
}

impl Server {
    pub(super) fn call_governed_evidence_write(
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
                    let reason = format!("cannot hash governed-evidence input: {error}");
                    self.poisoned = Some(reason);
                    (
                        -32000,
                        "Enterprise governed-evidence input is not durable".to_string(),
                    )
                })?;
                self.append_skill_execution_event(
                    &request.tenant,
                    execution::ExecutionEvent::ToolRequested {
                        turn_id: execution.turn_id.clone(),
                        step_id: execution.step_id.clone(),
                        call_id: execution.call_id.clone(),
                        tool: GOVERNED_EVIDENCE_WRITE_TOOL.to_string(),
                        input_sha256,
                    },
                )?;
                self.append_skill_execution_event(
                    &request.tenant,
                    execution::ExecutionEvent::ToolStarted {
                        call_id: execution.call_id.clone(),
                    },
                )?;

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
                        "Enterprise governed-evidence start state is not durable".to_string(),
                    ));
                }

                let store = self.governed_memory.take().ok_or_else(|| {
                    self.poisoned = Some("governed provider generation disappeared".into());
                    (
                        -32000,
                        "Enterprise governed memory is unavailable".to_string(),
                    )
                })?;
                if store.tenant().as_str() != request.tenant {
                    self.governed_memory = Some(store);
                    return self.fail_governed_evidence_without_side_effect(
                        checkpoint,
                        request,
                        &execution,
                        effect,
                        "governed provider tenant differs from admitted request".into(),
                    );
                }
                if parsed.write.embedding.len() != store.config().dimension {
                    let found = parsed.write.embedding.len();
                    let expected = store.config().dimension;
                    self.governed_memory = Some(store);
                    return self.fail_governed_evidence_without_side_effect(
                        checkpoint,
                        request,
                        &execution,
                        effect,
                        format!("embedding dimension mismatch: expected {expected}, found {found}"),
                    );
                }

                let prepared = match store.prepare_unverified_evidence(parsed.write) {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        self.governed_memory = Some(store);
                        return self.fail_governed_evidence_without_side_effect(
                            checkpoint,
                            request,
                            &execution,
                            effect,
                            error.to_string(),
                        );
                    }
                };

                // From here publication can become externally visible. Any error
                // is an unknown outcome: do not rewrite the Started marker and do
                // not restore the admission checkpoint. Startup will fail closed.
                let (store, receipt) = match store.commit_prepared_evidence(prepared) {
                    Ok(committed) => committed,
                    Err(error) => {
                        let reason = format!(
                            "governed evidence generation publication is uncertain: {error}"
                        );
                        self.poisoned = Some(reason.clone());
                        return Err((-32000, reason));
                    }
                };
                self.governed_memory = Some(store);

                let value = evidence_write_result(&receipt);
                let output_sha256 = successful_output_sha256(&value).map_err(|error| {
                    let reason = format!("cannot hash governed-evidence output: {error}");
                    self.poisoned = Some(reason);
                    (
                        -32000,
                        "Enterprise governed-evidence output is not durable".to_string(),
                    )
                })?;
                effect.state = EffectState::Succeeded;
                effect.output_sha256 = Some(output_sha256.clone());
                effect.governed_generation = Some(receipt.generation);
                effect.governed_asset_id = Some(receipt.asset_id.as_str().to_string());
                effect.governed_image_sha256 = Some(hex_digest(receipt.image_digest));
                if let Err(error) = write_effect(&effect_path(&self.config.state_dir), &effect) {
                    self.poisoned = Some(error.clone());
                    return Err((
                        -32000,
                        "Enterprise governed-evidence outcome is not durable".to_string(),
                    ));
                }
                self.append_skill_execution_event(
                    &request.tenant,
                    execution::ExecutionEvent::ToolFinished {
                        call_id: execution.call_id.clone(),
                        success: true,
                        output_sha256,
                    },
                )?;
                value
            }
            Outcome::Replayed => json!({
                "content": [{ "type": "text", "text": "CCOS Enterprise replay suppressed" }],
                "structuredContent": { "replayed": true }
            }),
            Outcome::Refused(refusal) => {
                eprintln!("ccos-enterprise-mcp: governed evidence write refused: {refusal:?}");
                tool_error("CCOS Enterprise request refused")
            }
        };

        if let Err(error) = persist_deployment(&mut self.store, self.front_door.deployment()) {
            self.poisoned = Some(error.clone());
            eprintln!(
                "ccos-enterprise-mcp: durable governed-evidence governance commit failed: {error}"
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
                    "ccos-enterprise-mcp: governed-evidence settlement marker failed: {error}"
                );
                return Err((
                    -32000,
                    "Enterprise governed-evidence settlement is not durable".to_string(),
                ));
            }
        }
        Ok(response)
    }

    fn fail_governed_evidence_without_side_effect(
        &mut self,
        checkpoint: DeploymentCheckpoint,
        request: &GatewayRequest,
        execution: &DispatchExecution,
        mut effect: EffectRecord,
        error: String,
    ) -> Result<Value, (i64, String)> {
        let output_sha256 = failed_output_sha256(&error);
        effect.state = EffectState::Failed;
        effect.output_sha256 = Some(output_sha256.clone());
        if let Err(persist_error) = write_effect(&effect_path(&self.config.state_dir), &effect) {
            self.poisoned = Some(persist_error.clone());
            return Err((
                -32000,
                "Enterprise failed governed-evidence outcome is not durable".to_string(),
            ));
        }
        self.append_skill_execution_event(
            &request.tenant,
            execution::ExecutionEvent::ToolFinished {
                call_id: execution.call_id.clone(),
                success: false,
                output_sha256,
            },
        )?;
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
                "Enterprise failed governed-evidence outcome could not be settled".to_string(),
            ));
        }
        eprintln!(
            "ccos-enterprise-mcp: admitted governed evidence failed before provider publication: {error}"
        );
        Ok(tool_error("CCOS Enterprise governed evidence write failed"))
    }
}

pub(super) fn validate_recovered_evidence_effect(
    config: &Config,
    effect: &EffectRecord,
) -> Result<(), String> {
    if effect.tool != GOVERNED_EVIDENCE_WRITE_TOOL || effect.state != EffectState::Succeeded {
        return Ok(());
    }
    let generation = effect
        .governed_generation
        .ok_or_else(|| "governed evidence effect is missing generation receipt".to_string())?;
    let asset = MemoryAssetId::new(
        effect
            .governed_asset_id
            .clone()
            .ok_or_else(|| "governed evidence effect is missing asset receipt".to_string())?,
    )
    .map_err(|error| format!("invalid governed evidence effect asset: {error}"))?;
    let digest = parse_digest(
        effect
            .governed_image_sha256
            .as_deref()
            .ok_or_else(|| "governed evidence effect is missing provider digest".to_string())?,
    )?;
    let root = config
        .governed_memory_root
        .as_ref()
        .ok_or_else(|| "governed evidence effect requires configured provider root".to_string())?;
    let tenant = TenantId::validated(&config.tenant)
        .ok_or_else(|| "configured tenant cannot validate governed evidence receipt".to_string())?;
    let store =
        ccos_enterprise_provider_adapter::generation::ProviderGenerationStore::open(root, tenant)
            .map_err(|error| format!("cannot reopen governed evidence generation: {error}"))?;
    let receipt = EvidenceGenerationReceipt {
        generation,
        asset_id: asset,
        image_digest: digest,
    };
    if !store.matches_evidence_receipt(&receipt) {
        return Err("governed evidence effect receipt does not match selected generation".into());
    }
    Ok(())
}

fn parse_arguments(arguments: &Value) -> Result<GovernedEvidenceArguments, String> {
    let object = arguments
        .as_object()
        .ok_or_else(|| "memory.evidence.write arguments must be an object".to_string())?;
    const ALLOWED: &[&str] = &["asset_id", "evidence_ref", "embedding", "payload_bytes"];
    if object.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
        return Err("memory.evidence.write contains an unknown argument".into());
    }
    let asset = object
        .get("asset_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "memory.evidence.write asset_id must be a string".to_string())?;
    let evidence = object
        .get("evidence_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| "memory.evidence.write evidence_ref must be a string".to_string())?;
    let values = object
        .get("embedding")
        .and_then(Value::as_array)
        .ok_or_else(|| "memory.evidence.write embedding must be an array".to_string())?;
    if values.is_empty() || values.len() > 8192 {
        return Err("memory.evidence.write embedding length is outside 1..=8192".into());
    }
    let mut embedding = Vec::with_capacity(values.len());
    for value in values {
        let numeric = value
            .as_f64()
            .ok_or_else(|| "memory.evidence.write embedding contains a non-number".to_string())?;
        let narrowed = numeric as f32;
        if !numeric.is_finite() || !narrowed.is_finite() {
            return Err("memory.evidence.write embedding contains a non-finite f32".into());
        }
        embedding.push(narrowed);
    }
    let payload_values = object
        .get("payload_bytes")
        .and_then(Value::as_array)
        .ok_or_else(|| "memory.evidence.write payload_bytes must be an array".to_string())?;
    if payload_values.is_empty() || payload_values.len() > 1024 * 1024 {
        return Err("memory.evidence.write payload length is outside 1..=1048576".into());
    }
    let mut payload = Vec::with_capacity(payload_values.len());
    for value in payload_values {
        let byte = value
            .as_u64()
            .and_then(|value| u8::try_from(value).ok())
            .ok_or_else(|| "memory.evidence.write payload contains a non-byte".to_string())?;
        payload.push(byte);
    }
    Ok(GovernedEvidenceArguments {
        write: AcceptedEvidenceWrite {
            asset_id: MemoryAssetId::new(asset.to_string())
                .map_err(|error| format!("invalid governed evidence asset id: {error}"))?,
            evidence: MemoryEvidenceRef::new(evidence.to_string())
                .map_err(|error| format!("invalid governed evidence reference: {error}"))?,
            embedding,
            payload,
        },
    })
}

fn evidence_write_result(receipt: &EvidenceGenerationReceipt) -> Value {
    json!({
        "content": [{
            "type": "text",
            "text": "CCOS Enterprise stored direct evidence as unverified governed memory"
        }],
        "structuredContent": {
            "tool": GOVERNED_EVIDENCE_WRITE_TOOL,
            "generation": receipt.generation,
            "asset_id": receipt.asset_id.as_str(),
            "space": "tenant",
            "stratum": "evidence",
            "trust_state": "unverified",
            "provider_image_sha256": hex_digest(receipt.image_digest)
        }
    })
}

fn hex_digest(digest: [u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn parse_digest(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("governed evidence provider digest is not 64 hex characters".into());
    }
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid governed evidence provider digest".to_string())?;
    }
    Ok(digest)
}
