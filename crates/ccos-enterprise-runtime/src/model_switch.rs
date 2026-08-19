//! Governed model switch transaction (docs/MODEL_SWITCHING_POLICY.md).
//!
//! A model change is a transaction:
//!
//! 1. authenticate/admin authorize (the caller gates this before invoking);
//! 2. evaluate the model allowlist — the new model must be admissible;
//! 3. `RequireApproval` for allowlist/policy changes when required (the
//!    deployment's approval engine gates this before invoking);
//! 4. snapshot tenant state before the switch;
//! 5. record old model and requested new model;
//! 6. switch the tenant model policy;
//! 7. execute deterministic replay/state-equivalence verification;
//! 8. compare invariant state;
//! 9. if equivalent, commit;
//! 10. if divergent, report explicitly and revert/fail closed.
//!
//! Divergence is never silently absorbed. The equivalence contract is defined
//! around provider-independent Enterprise/Core state — the deployment
//! snapshot's ledger, roles, allowlists, activations and cells — never
//! provider-specific transient text.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::{Deployment, TenantId};

/// The schema tag of a journaled switch transaction record.
pub const MODEL_SWITCH_SCHEMA: &str = "ccos.enterprise.model-switch/v1";

/// The outcome of a model switch transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwitchOutcome {
    /// The switch applied, verified equivalent and committed.
    Committed,
    /// The switch was refused before any state changed.
    Refused,
    /// The switch applied but verification diverged: the switch was reverted
    /// and the deployment failed closed with the old model.
    DivergedReverted,
}

/// One complete, journaled model switch transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelSwitchRecord {
    pub schema: String,
    pub tenant: String,
    /// The actor identity that authorized the switch (the caller's proven
    /// identity; the journal never guesses one).
    pub authorizing_actor: String,
    /// The approval id that gated the switch, when one was required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    pub old_model: String,
    pub new_model: String,
    /// Snapshot hash of the tenant's governed state before the switch.
    pub snapshot_hash_before: String,
    /// Snapshot hash of the tenant's governed state after the switch.
    pub snapshot_hash_after: String,
    /// Whether the before/after comparison was invariant-equivalent.
    pub equivalent: bool,
    /// Digest of the divergence, when the comparison found one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub divergence_digest: Option<String>,
    pub outcome: SwitchOutcome,
    /// Unix seconds of the transaction.
    pub at_unix: u64,
}

/// The provider-independent invariant state of one tenant that a model switch
/// must preserve. Everything here is Enterprise/Core governed state — no
/// provider text, no transient model output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantState {
    pub tenant: String,
    /// Tokens charged to the tenant (the ledger must not move).
    pub spent: u64,
    pub limit: u64,
    /// The model allowlist, excluding the model being switched.
    pub models: BTreeSet<String>,
    /// Active Q-Page variants.
    pub variants: Vec<String>,
    /// Tenant-scoped cells, sorted.
    pub cells: Vec<(String, String, String)>,
}

impl InvariantState {
    /// Capture the invariant state of one tenant from a deployment.
    ///
    /// `excluded_model` is the model the switch itself is moving; the
    /// allowlist difference between the old and new active model is the
    /// *intended* change, not divergence, so it is excluded from the
    /// comparison. Everything else — the ledger, the remaining allowlist,
    /// activations and cells — must be identical before and after.
    pub fn capture(deployment: &Deployment, tenant: &TenantId) -> Option<Self> {
        let spent = deployment.spent(&tenant.0)?;
        let limit = deployment.tenant_limit(&tenant.0)?;
        let models: BTreeSet<String> = deployment
            .tenant_models(&tenant.0)?
            .iter()
            .filter(|model| model.as_str() != "SWITCH-TARGET-PLACEHOLDER")
            .cloned()
            .collect();
        let variants = deployment.tenant_variants(&tenant.0)?;
        let mut cells = deployment
            .cells_of(&tenant.0)
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect::<Vec<_>>();
        cells.sort();
        let cells = cells
            .into_iter()
            .map(|(key, value)| (tenant.0.clone(), key, value))
            .collect();
        Some(Self {
            tenant: tenant.0.clone(),
            spent,
            limit,
            models,
            variants,
            cells,
        })
    }

    /// Capture invariant state excluding the models the switch transaction is
    /// moving — the whole intended allowlist delta (old removed, new added)
    /// is not divergence; everything else must be identical.
    pub fn capture_excluding(
        deployment: &Deployment,
        tenant: &TenantId,
        excluded: &[&str],
    ) -> Option<Self> {
        let mut state = Self::capture(deployment, tenant)?;
        for model in excluded {
            state.models.remove(*model);
        }
        Some(state)
    }
}

/// The result of the state-equivalence comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Equivalence {
    Equal,
    Divergent { digest: String },
}

/// Compare two invariant states deterministically.
///
/// The digest is sha256 (lowercase hex) over the canonical serialization of
/// the two states' *difference*. Equal states are `Equal`; anything else is
/// `Divergent` with a stable digest an operator can compare offline.
pub fn compare_invariant_states(before: &InvariantState, after: &InvariantState) -> Equivalence {
    if before == after {
        return Equivalence::Equal;
    }
    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    hasher.update(b"ccos-enterprise-model-switch-diff-v1");
    if before.spent != after.spent {
        hasher.update(b"spent");
        hasher.update(before.spent.to_be_bytes());
        hasher.update(after.spent.to_be_bytes());
    }
    if before.limit != after.limit {
        hasher.update(b"limit");
        hasher.update(before.limit.to_be_bytes());
        hasher.update(after.limit.to_be_bytes());
    }
    let before_models: BTreeSet<&String> = before.models.iter().collect();
    let after_models: BTreeSet<&String> = after.models.iter().collect();
    for added in after_models.difference(&before_models) {
        hasher.update(b"model+");
        hasher.update(added.as_bytes());
    }
    for removed in before_models.difference(&after_models) {
        hasher.update(b"model-");
        hasher.update(removed.as_bytes());
    }
    if before.variants != after.variants {
        hasher.update(b"variants");
        hasher.update(before.variants.join(",").as_bytes());
        hasher.update(after.variants.join(",").as_bytes());
    }
    if before.cells != after.cells {
        hasher.update(b"cells");
        for (tenant, key, value) in &before.cells {
            hasher.update(tenant.as_bytes());
            hasher.update(key.as_bytes());
            hasher.update(value.as_bytes());
        }
        for (tenant, key, value) in &after.cells {
            hasher.update(tenant.as_bytes());
            hasher.update(key.as_bytes());
            hasher.update(value.as_bytes());
        }
    }
    let mut out = String::with_capacity(64);
    use std::fmt::Write as _;
    for byte in hasher.finalize() {
        let _ = write!(out, "{byte:02x}");
    }
    Equivalence::Divergent { digest: out }
}

/// The result of a completed model switch transaction, with its durable
/// journal record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchResult {
    pub record: ModelSwitchRecord,
}

/// Execute one governed model switch transaction.
///
/// The caller is responsible for the authorization gates *before* calling:
/// authentication, RBAC, and the approval gate for allowlist changes
/// (docs/HUMAN_APPROVAL_POLICIES.md). This function is the transaction
/// itself:
///
/// - captures the invariant state before;
/// - refuses a model that is not on the tenant's allowlist, or a switch to
///   the same model, without changing anything;
/// - switches the tenant's model policy;
/// - captures the invariant state after;
/// - compares; on equivalence the switch is committed (the record says so);
///   on divergence the switch is reverted — the tenant's allowlist is
///   restored exactly, the deployment fails closed with the old model, and
///   the record reports `DivergedReverted` with the divergence digest.
///
/// The switch is journaled as a governance change and returned as a durable
/// record in both outcomes, so a divergent switch is never silent.
pub fn switch_tenant_model(
    deployment: &mut Deployment,
    tenant: &TenantId,
    new_model: &str,
    authorizing_actor: &str,
    approval_id: Option<&str>,
    at_unix: u64,
) -> Result<SwitchResult, String> {
    if new_model.is_empty() || new_model.len() > 256 {
        return Err("new model is empty or oversized".into());
    }
    if !deployment.tenant_exists(tenant) {
        return Err(format!("unknown tenant {:?}", tenant.0));
    }
    let old_model = deployment
        .tenant_active_model(tenant)
        .ok_or_else(|| format!("tenant {:?} has no active model", tenant.0))?;
    if old_model == new_model {
        return Err("switching to the same model is a no-op and is refused".into());
    }

    // Step 2/3 of the policy: the new model must be on the allowlist, and
    // allowlist changes need approval — the caller's approval gate has
    // already run; here we refuse an absent approval id when the model is not
    // already allowlisted (the strictest reading of "RequireApproval for
    // allowlist changes").
    let allowlisted = deployment
        .tenant_models(&tenant.0)
        .map(|models| models.contains(new_model))
        .unwrap_or(false);
    if !allowlisted && approval_id.is_none() {
        return Err("adding a model to the allowlist requires a recorded human approval".into());
    }

    // Step 4-6: snapshot before and after with the SAME exclusion set — the
    // whole intended allowlist delta (old removed, new added) is not
    // divergence; everything else must be identical.
    let excluded: [&str; 2] = [&old_model, new_model];
    let before = InvariantState::capture_excluding(deployment, tenant, &excluded)
        .ok_or_else(|| format!("cannot capture invariant state for {:?}", tenant.0))?;
    let snapshot_hash_before = snapshot_digest(&before);
    deployment.switch_model(tenant, new_model);

    // Step 7-8: verify equivalence against invariant state.
    let after = InvariantState::capture_excluding(deployment, tenant, &excluded)
        .ok_or_else(|| format!("cannot capture invariant state for {:?}", tenant.0))?;
    let snapshot_hash_after = snapshot_digest(&after);
    let equivalence = compare_invariant_states(&before, &after);

    // Step 9-10: commit or revert.
    let equivalent = matches!(equivalence, Equivalence::Equal);
    let (outcome, divergence_digest) = match equivalence {
        Equivalence::Equal => (SwitchOutcome::Committed, None),
        Equivalence::Divergent { digest } => {
            // Revert: restore the previous allowlist exactly and fail closed
            // with the old model. The deployment's tenant rules are restored
            // by removing the new model and re-adding the old.
            deployment.revert_model_switch(tenant, &old_model, new_model);
            (SwitchOutcome::DivergedReverted, Some(digest))
        }
    };

    let record = ModelSwitchRecord {
        schema: MODEL_SWITCH_SCHEMA.to_string(),
        tenant: tenant.0.clone(),
        authorizing_actor: authorizing_actor.to_string(),
        approval_id: approval_id.map(str::to_string),
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

/// Deterministic digest of one invariant state (sha256 of its canonical
/// serialization).
fn snapshot_digest(state: &InvariantState) -> String {
    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    hasher.update(b"ccos-enterprise-model-switch-snapshot-v1");
    hasher.update(state.tenant.as_bytes());
    hasher.update(state.spent.to_be_bytes());
    hasher.update(state.limit.to_be_bytes());
    for model in &state.models {
        hasher.update(model.as_bytes());
    }
    for variant in &state.variants {
        hasher.update(variant.as_bytes());
    }
    for (tenant, key, value) in &state.cells {
        hasher.update(tenant.as_bytes());
        hasher.update(key.as_bytes());
        hasher.update(value.as_bytes());
    }
    let mut out = String::with_capacity(64);
    use std::fmt::Write as _;
    for byte in hasher.finalize() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}
