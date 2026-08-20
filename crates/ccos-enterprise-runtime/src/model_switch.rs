//! Governed model-switch transaction (`docs/MODEL_SWITCHING_POLICY.md`).
//!
//! A switch is not an allowlist edit. The tenant has one explicit active
//! model, the allowlist remains the set of models it may select, and a caller
//! supplied transition callback must perform the provider transition plus the
//! deterministic replay/equivalence preparation before this module can commit.
//! Unlisted target models require an exact live approval bound to the canonical
//! allowlist-change artifact. Divergence or transition failure restores both
//! active-model and allowlist state and is journaled with a digest linking the
//! governance event to the full transaction record.

use std::collections::BTreeSet;

use ccos_enterprise_approval::{ApprovalDecision, APPROVAL_SCHEMA};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Deployment, TenantId};

pub const MODEL_SWITCH_SCHEMA: &str = "ccos.enterprise.model-switch/v2";
pub const MODEL_ALLOWLIST_ACTION: &str = "model.allowlist.change";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwitchOutcome {
    Committed,
    DivergedReverted,
    TransitionFailedReverted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelSwitchRecord {
    pub schema: String,
    pub tenant: String,
    pub authorizing_actor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    pub old_model: String,
    pub new_model: String,
    pub snapshot_hash_before: String,
    pub snapshot_hash_after: String,
    pub equivalent: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub divergence_digest: Option<String>,
    pub outcome: SwitchOutcome,
    pub at_unix: u64,
}

impl ModelSwitchRecord {
    /// Stable digest used by the governance journal to point at the complete
    /// transaction without copying its fields into the bounded journal.
    pub fn digest(&self) -> String {
        let bytes =
            serde_json::to_vec(self).expect("serializing a model-switch record cannot fail");
        digest_framed(b"ccos-enterprise-model-switch-record-v2", &[&bytes])
    }
}

/// Provider-independent tenant state that must survive a provider transition.
/// The active model itself is intentionally absent: changing it is the intended
/// transaction. A newly-added target model can also be excluded from the
/// allowlist comparison because that addition is separately approval-gated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantState {
    pub tenant: String,
    pub spent: u64,
    pub limit: u64,
    pub models: BTreeSet<String>,
    pub variants: Vec<String>,
    pub cells: Vec<(String, String, String)>,
}

impl InvariantState {
    pub fn capture_excluding(
        deployment: &Deployment,
        tenant: &TenantId,
        excluded_models: &[&str],
    ) -> Option<Self> {
        let mut models = deployment.tenant_models(&tenant.0)?;
        for excluded in excluded_models {
            models.remove(*excluded);
        }
        let variants = deployment.tenant_variants(&tenant.0)?;
        let mut cells = deployment
            .cells_of(&tenant.0)
            .into_iter()
            .map(|(key, value)| (tenant.0.clone(), key.to_string(), value.to_string()))
            .collect::<Vec<_>>();
        cells.sort();
        Some(Self {
            tenant: tenant.0.clone(),
            spent: deployment.spent(&tenant.0)?,
            limit: deployment.tenant_limit(&tenant.0)?,
            models,
            variants,
            cells,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Equivalence {
    Equal,
    Divergent { digest: String },
}

pub fn compare_invariant_states(before: &InvariantState, after: &InvariantState) -> Equivalence {
    if before == after {
        return Equivalence::Equal;
    }
    let before_bytes = serde_json::to_vec(before).expect("serializable invariant state");
    let after_bytes = serde_json::to_vec(after).expect("serializable invariant state");
    Equivalence::Divergent {
        digest: digest_framed(
            b"ccos-enterprise-model-switch-divergence-v2",
            &[&before_bytes, &after_bytes],
        ),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchResult {
    pub record: ModelSwitchRecord,
}

/// Canonical approval artifact for adding `new_model` to `tenant`'s allowlist.
pub fn allowlist_artifact_hash(tenant: &TenantId, new_model: &str) -> Result<String, String> {
    validate_model_name(new_model)?;
    Ok(digest_framed(
        b"ccos-enterprise-model-allowlist-change-v1",
        &[tenant.0.as_bytes(), new_model.as_bytes()],
    ))
}

/// A transition callback must perform the provider switch and deterministic
/// replay/preparation needed to make the post-transition Enterprise/Core state
/// meaningful. It may mutate provider-independent tenant state; that mutation
/// is exactly what the subsequent invariant comparison is designed to catch.
pub trait ModelTransition {
    fn transition_and_replay(
        &mut self,
        deployment: &mut Deployment,
        tenant: &TenantId,
        old_model: &str,
        new_model: &str,
    ) -> Result<(), String>;
}

impl<F> ModelTransition for F
where
    F: FnMut(&mut Deployment, &TenantId, &str, &str) -> Result<(), String>,
{
    fn transition_and_replay(
        &mut self,
        deployment: &mut Deployment,
        tenant: &TenantId,
        old_model: &str,
        new_model: &str,
    ) -> Result<(), String> {
        self(deployment, tenant, old_model, new_model)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn switch_tenant_model(
    deployment: &mut Deployment,
    tenant: &TenantId,
    new_model: &str,
    authorizing_actor: &str,
    approval_id: Option<&str>,
    at_unix: u64,
    transition: &mut dyn ModelTransition,
) -> Result<SwitchResult, String> {
    validate_model_name(new_model)?;
    if authorizing_actor.is_empty() || authorizing_actor.len() > 256 {
        return Err("authorizing actor is empty or oversized".into());
    }
    if !deployment.tenant_exists(tenant) {
        return Err(format!("unknown tenant {:?}", tenant.0));
    }
    let old_model = deployment
        .tenant_active_model(tenant)
        .ok_or_else(|| format!("tenant {:?} has no active model", tenant.0))?;
    if old_model == new_model {
        return Err("switching to the same active model is refused".into());
    }

    let models_before = deployment
        .tenant_models(&tenant.0)
        .ok_or_else(|| format!("unknown tenant {:?}", tenant.0))?;
    let target_was_allowlisted = models_before.contains(new_model);
    let validated_approval = if target_was_allowlisted {
        None
    } else {
        Some(validate_allowlist_approval(
            deployment,
            tenant,
            new_model,
            approval_id,
            at_unix,
        )?)
    };

    // Only an approved allowlist addition is excluded from invariant
    // comparison. Existing allowlisted models remain part of the state and may
    // not silently disappear during transition/replay.
    let excluded = if target_was_allowlisted {
        Vec::new()
    } else {
        vec![new_model]
    };
    let before = InvariantState::capture_excluding(deployment, tenant, &excluded)
        .ok_or_else(|| "cannot capture pre-switch invariant state".to_string())?;
    let snapshot_hash_before = snapshot_digest(&before);

    let checkpoint = deployment
        .checkpoint_model_switch(tenant)
        .ok_or_else(|| "cannot capture model-switch rollback checkpoint".to_string())?;
    deployment
        .begin_model_switch(tenant, new_model)
        .map_err(|error| format!("cannot begin model switch: {error}"))?;

    let transition_error = transition
        .transition_and_replay(deployment, tenant, &old_model, new_model)
        .err();
    let after = InvariantState::capture_excluding(deployment, tenant, &excluded)
        .ok_or_else(|| "cannot capture post-switch invariant state".to_string())?;
    let snapshot_hash_after = snapshot_digest(&after);

    let (equivalent, divergence_digest, outcome) = if let Some(error) = transition_error {
        let digest = digest_framed(
            b"ccos-enterprise-model-switch-transition-error-v1",
            &[error.as_bytes()],
        );
        deployment.restore_model_switch_checkpoint(tenant, checkpoint);
        (false, Some(digest), SwitchOutcome::TransitionFailedReverted)
    } else {
        match compare_invariant_states(&before, &after) {
            Equivalence::Equal => (true, None, SwitchOutcome::Committed),
            Equivalence::Divergent { digest } => {
                deployment.restore_model_switch_checkpoint(tenant, checkpoint);
                (false, Some(digest), SwitchOutcome::DivergedReverted)
            }
        }
    };

    let record = ModelSwitchRecord {
        schema: MODEL_SWITCH_SCHEMA.to_string(),
        tenant: tenant.0.clone(),
        authorizing_actor: authorizing_actor.to_string(),
        approval_id: validated_approval,
        old_model,
        new_model: new_model.to_string(),
        snapshot_hash_before,
        snapshot_hash_after,
        equivalent,
        divergence_digest,
        outcome,
        at_unix,
    };
    deployment.journal_model_switch(&record);
    Ok(SwitchResult { record })
}

fn validate_allowlist_approval(
    deployment: &Deployment,
    tenant: &TenantId,
    new_model: &str,
    approval_id: Option<&str>,
    at_unix: u64,
) -> Result<String, String> {
    let approval_id = approval_id.ok_or_else(|| {
        "adding a model to the allowlist requires a recorded human approval".to_string()
    })?;
    let artifact_hash = allowlist_artifact_hash(tenant, new_model)?;
    let registry = deployment.approvals().registry();
    let record = registry
        .snapshot()
        .approvals
        .get(approval_id)
        .ok_or_else(|| "supplied model-switch approval id is not recorded".to_string())?;
    if !record.id.starts_with("approval-v2-")
        || record.schema_version != APPROVAL_SCHEMA
        || record.tenant != tenant.0
        || record.action != MODEL_ALLOWLIST_ACTION
        || record.artifact_hash != artifact_hash
        || record.decision != ApprovalDecision::Approved
    {
        return Err(
            "supplied approval is not a live v2 approval bound to this model change".into(),
        );
    }
    if registry.is_revoked(approval_id) {
        return Err("supplied model-switch approval is revoked".into());
    }
    if record.expires_at.is_some_and(|expiry| expiry <= at_unix) {
        return Err("supplied model-switch approval is expired".into());
    }
    Ok(approval_id.to_string())
}

fn validate_model_name(model: &str) -> Result<(), String> {
    if model.is_empty()
        || model.len() > 256
        || model.chars().any(|c| c.is_control())
        || model.trim() != model
    {
        return Err(
            "model name is empty, oversized, padded, or contains control characters".into(),
        );
    }
    Ok(())
}

fn snapshot_digest(state: &InvariantState) -> String {
    let bytes = serde_json::to_vec(state).expect("serializable invariant state");
    digest_framed(b"ccos-enterprise-model-switch-snapshot-v2", &[&bytes])
}

fn digest_framed(domain: &[u8], fields: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    let mut out = String::with_capacity(64);
    use std::fmt::Write as _;
    for byte in hasher.finalize() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ccos_enterprise_approval::{ApprovalDecision, ApprovalRequest};
    use ccos_enterprise_auth::AuthStrength;
    use ccos_enterprise_tenancy::TenantScope;

    use crate::{actor, request, two_tenant_deployment, Call, GovernanceChange, Outcome, Refusal};

    fn noop_transition(
        _deployment: &mut Deployment,
        _tenant: &TenantId,
        _old_model: &str,
        _new_model: &str,
    ) -> Result<(), String> {
        Ok(())
    }

    #[test]
    fn framing_distinguishes_variable_length_fields() {
        assert_ne!(
            digest_framed(b"d", &[b"a", b"bc"]),
            digest_framed(b"d", &[b"ab", b"c"])
        );
    }

    #[test]
    fn allowlist_artifact_is_tenant_and_model_bound() {
        let acme = TenantId("acme".into());
        let globex = TenantId("globex".into());
        let a = allowlist_artifact_hash(&acme, "gpt-5").unwrap();
        assert_ne!(a, allowlist_artifact_hash(&acme, "gpt-6").unwrap());
        assert_ne!(a, allowlist_artifact_hash(&globex, "gpt-5").unwrap());
    }

    #[test]
    fn invariant_digest_is_unambiguous() {
        let a = InvariantState {
            tenant: "acme".into(),
            spent: 1,
            limit: 10,
            models: BTreeSet::from(["a".into(), "bc".into()]),
            variants: vec![],
            cells: vec![],
        };
        let mut b = a.clone();
        b.models = BTreeSet::from(["ab".into(), "c".into()]);
        assert!(matches!(
            compare_invariant_states(&a, &b),
            Equivalence::Divergent { .. }
        ));
        assert_ne!(snapshot_digest(&a), snapshot_digest(&b));
    }

    #[test]
    fn active_model_is_distinct_from_allowlist_and_enforced_by_admission() {
        let mut d = two_tenant_deployment();
        let tenant = TenantId("acme".into());
        d.tenant_mut("acme").unwrap().allow_model("gpt-5");
        assert_eq!(
            d.tenant_active_model(&tenant).as_deref(),
            Some("claude-opus")
        );

        let alice = actor("memorithm", "alice", AuthStrength::Token);
        let before = request("acme", "alice", "memory.recall", "before-switch");
        assert_eq!(
            d.admit(Call {
                actor: &alice,
                request: &before,
                model: "gpt-5",
                cost_tokens: 1,
                variant: None,
                justification: None,
            })
            .refusal(),
            Some(&Refusal::ModelNotAllowed)
        );

        let mut transition = noop_transition;
        let result = switch_tenant_model(
            &mut d,
            &tenant,
            "gpt-5",
            "root",
            None,
            1_000,
            &mut transition,
        )
        .unwrap();
        assert_eq!(result.record.outcome, SwitchOutcome::Committed);
        assert_eq!(d.tenant_active_model(&tenant).as_deref(), Some("gpt-5"));

        let old = request("acme", "alice", "memory.recall", "after-old");
        assert_eq!(
            d.admit(Call {
                actor: &alice,
                request: &old,
                model: "claude-opus",
                cost_tokens: 1,
                variant: None,
                justification: None,
            })
            .refusal(),
            Some(&Refusal::ModelNotAllowed)
        );
        let selected = request("acme", "alice", "memory.recall", "after-new");
        assert_eq!(
            d.admit(Call {
                actor: &alice,
                request: &selected,
                model: "gpt-5",
                cost_tokens: 1,
                variant: None,
                justification: None,
            }),
            Outcome::Forwarded
        );
    }

    #[test]
    fn failed_transition_restores_full_target_tenant_checkpoint() {
        let mut d = two_tenant_deployment();
        let tenant = TenantId("acme".into());
        d.tenant_mut("acme").unwrap().allow_model("gpt-5");
        let scope = TenantScope::new(tenant.clone(), "checkpoint-cell".to_string());
        assert!(d.put(&scope, "before"));
        let spent_before = d.spent("acme");
        let models_before = d.tenant_models("acme").unwrap();
        let active_before = d.tenant_active_model(&tenant);
        let variants_before = d.tenant_variants("acme").unwrap();

        let mut transition = |deployment: &mut Deployment,
                              tenant: &TenantId,
                              _old: &str,
                              _new: &str|
         -> Result<(), String> {
            let state = deployment.tenants.get_mut(tenant).unwrap();
            state.budget.spent = state.budget.spent.saturating_add(37);
            state
                .qpages
                .activate(ccos_enterprise_qpages::AdvancedQPageVariant::ExperimentalBridge);
            let scope = TenantScope::new(tenant.clone(), "checkpoint-cell".to_string());
            assert!(deployment.put(&scope, "mutated"));
            Err("provider transition failed after partial replay".into())
        };
        let result = switch_tenant_model(
            &mut d,
            &tenant,
            "gpt-5",
            "root",
            None,
            1_000,
            &mut transition,
        )
        .unwrap();
        assert_eq!(
            result.record.outcome,
            SwitchOutcome::TransitionFailedReverted
        );
        assert_eq!(d.spent("acme"), spent_before);
        assert_eq!(d.tenant_models("acme").unwrap(), models_before);
        assert_eq!(d.tenant_active_model(&tenant), active_before);
        assert_eq!(d.tenant_variants("acme").unwrap(), variants_before);
        assert_eq!(d.get(&scope), Some("before"));
    }

    #[test]
    fn supplied_approval_id_must_itself_be_live() {
        let mut d = two_tenant_deployment();
        let tenant = TenantId("acme".into());
        let artifact = allowlist_artifact_hash(&tenant, "gpt-5").unwrap();

        let expired_id = d
            .record_approval(
                ApprovalRequest::new(
                    tenant.clone(),
                    MODEL_ALLOWLIST_ACTION,
                    &artifact,
                    "operator-one",
                    ApprovalDecision::Approved,
                    100,
                    Some(200),
                    "temporary model approval",
                )
                .unwrap(),
            )
            .unwrap();
        let _live_id = d
            .record_approval(
                ApprovalRequest::new(
                    tenant.clone(),
                    MODEL_ALLOWLIST_ACTION,
                    &artifact,
                    "operator-two",
                    ApprovalDecision::Approved,
                    150,
                    None,
                    "replacement model approval",
                )
                .unwrap(),
            )
            .unwrap();

        let mut transition = noop_transition;
        let error = switch_tenant_model(
            &mut d,
            &tenant,
            "gpt-5",
            "root",
            Some(&expired_id),
            300,
            &mut transition,
        )
        .expect_err("an expired supplied id cannot borrow validity from another record");
        assert!(error.contains("expired"), "{error}");
        assert_eq!(
            d.tenant_active_model(&tenant).as_deref(),
            Some("claude-opus")
        );
    }

    #[test]
    fn model_switch_is_journaled_before_first_request_and_links_record_digest() {
        let mut d = two_tenant_deployment();
        let tenant = TenantId("acme".into());
        d.tenant_mut("acme").unwrap().allow_model("gpt-5");
        assert!(!d.is_serving());

        let mut transition = noop_transition;
        let result = switch_tenant_model(
            &mut d,
            &tenant,
            "gpt-5",
            "root",
            None,
            1_000,
            &mut transition,
        )
        .unwrap();
        let expected = result.record.digest();
        let change = d
            .governance()
            .find_map(|record| match &record.change {
                GovernanceChange::ModelSwitch { record_digest, .. } => Some(record_digest.clone()),
                _ => None,
            })
            .expect("model switch must be journaled even before request #1");
        assert_eq!(change, expected);
    }

    #[test]
    fn snapshot_roundtrip_preserves_active_model_and_ambiguous_legacy_state_fails_closed() {
        let mut d = two_tenant_deployment();
        let tenant = TenantId("acme".into());
        d.tenant_mut("acme").unwrap().allow_model("gpt-5");
        let mut transition = noop_transition;
        switch_tenant_model(
            &mut d,
            &tenant,
            "gpt-5",
            "root",
            None,
            1_000,
            &mut transition,
        )
        .unwrap();

        let snapshot = d.snapshot();
        let restored = Deployment::restore(snapshot.clone(), &[], &[]).unwrap();
        assert_eq!(
            restored.tenant_active_model(&tenant).as_deref(),
            Some("gpt-5")
        );

        let mut legacy = snapshot;
        legacy.tenants.get_mut("acme").unwrap().active_model = None;
        let error = match Deployment::restore(legacy, &[], &[]) {
            Ok(_) => panic!("multi-model snapshot without active selection must fail closed"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            crate::RestoreError::ActiveModelInvalid { .. }
        ));
    }
}
