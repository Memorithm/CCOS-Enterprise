from pathlib import Path

LIB = Path("crates/ccos-enterprise-runtime/src/lib.rs")
MS = Path("crates/ccos-enterprise-runtime/src/model_switch.rs")

lib = LIB.read_text()
ms = MS.read_text()

def one(text, old, new, label):
    n = text.count(old)
    if n != 1:
        raise SystemExit(f"{label}: expected 1 anchor, found {n}")
    return text.replace(old, new, 1)

lib = one(lib,
'''    ModelSwitch {
        tenant: String,
        old_model: String,
        new_model: String,
        outcome: String,
    },
''',
'''    ModelSwitch {
        tenant: String,
        old_model: String,
        new_model: String,
        outcome: String,
        record_digest: String,
    },
''', "model switch governance digest")

lib = one(lib,
'''pub struct TenantState {
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
''',
'''#[derive(Clone)]
pub struct TenantState {
    budget: TokenBudget,
    models: ModelAllowlist,
    qpages: QPageRegistry,
    active_model: Option<String>,
}

#[derive(Clone)]
pub(crate) struct ModelSwitchCheckpoint {
    state: TenantState,
    cells: Option<BTreeMap<String, String>>,
}

impl TenantState {
    pub fn new(token_limit: u64) -> Self {
        Self {
            budget: TokenBudget::new(token_limit),
            models: ModelAllowlist::default(),
            qpages: QPageRegistry::default(),
            active_model: None,
        }
    }

    pub fn allow_model(&mut self, model: &str) -> &mut Self {
        self.models.0.insert(model.to_string());
        if self.active_model.is_none() {
            self.active_model = Some(model.to_string());
        }
        self
    }
''', "tenant active model")

start = lib.index("    fn record(\n")
end = lib.index("    /// Make rule changes under a recorded identity", start)
new = '''    fn record(
        &mut self,
        change: GovernanceChange,
        actor: Option<&str>,
        justification: Option<&str>,
    ) {
        if !self.serving {
            return;
        }
        self.record_governance(change, actor, justification);
    }

    /// Record a security transaction regardless of provisioning/serving
    /// state. Model switches are externally consequential and must never
    /// disappear merely because they happen before the first normal request.
    fn record_governance(
        &mut self,
        change: GovernanceChange,
        actor: Option<&str>,
        justification: Option<&str>,
    ) {
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
            justification: justification
                .filter(|j| ccos_enterprise_admin::is_written_justification(Some(j)))
                .map(clamp),
            change,
        });
    }

'''
lib = lib[:start] + new + lib[end:]

lib = one(lib,
'''        if state.models.evaluate(call.model) != PolicyDecision::Allow {
            return refuse(Refusal::ModelNotAllowed);
        }
''',
'''        if state.active_model.as_deref() != Some(call.model)
            || state.models.evaluate(call.model) != PolicyDecision::Allow
        {
            return refuse(Refusal::ModelNotAllowed);
        }
''', "admission active model")

obs_start = lib.index("    /// The tenant's active model: the single model")
obs_end = lib.index("    /// Tokens charged to a tenant.", obs_start)
replacement = '''    /// The tenant's active model: the single model the deployment governs
    /// calls against. `None` when no model has been selected.
    pub fn tenant_active_model(&self, tenant: &TenantId) -> Option<String> {
        self.tenants.get(tenant)?.active_model.clone()
    }

    /// Capture every mutable tenant-owned runtime field that a transition may
    /// touch. Rollback restores this checkpoint at the logical state level,
    /// including cells and budget, not only model policy.
    pub(crate) fn checkpoint_model_switch(
        &self,
        tenant: &TenantId,
    ) -> Option<ModelSwitchCheckpoint> {
        Some(ModelSwitchCheckpoint {
            state: self.tenants.get(tenant)?.clone(),
            cells: self.store.get(tenant).cloned(),
        })
    }

    /// Select the target model. Existing allowlist membership is preserved; an
    /// approved unlisted target is added rather than replacing another entry.
    pub(crate) fn begin_model_switch(
        &mut self,
        tenant: &TenantId,
        new_model: &str,
    ) -> Result<(), String> {
        let state = self
            .tenants
            .get_mut(tenant)
            .ok_or_else(|| format!("unknown tenant {:?}", tenant.0))?;
        state.models.0.insert(new_model.to_string());
        state.active_model = Some(new_model.to_string());
        Ok(())
    }

    /// Restore the complete target-tenant checkpoint after transition failure
    /// or invariant divergence.
    pub(crate) fn restore_model_switch_checkpoint(
        &mut self,
        tenant: &TenantId,
        checkpoint: ModelSwitchCheckpoint,
    ) {
        self.tenants.insert(tenant.clone(), checkpoint.state);
        match checkpoint.cells {
            Some(cells) => {
                self.store.insert(tenant.clone(), cells);
            }
            None => {
                self.store.remove(tenant);
            }
        }
    }

    /// Journal one completed model switch transaction as a governance change.
    /// This path is intentionally not suppressed during provisioning: a model
    /// transition is security-relevant even before request #1.
    pub(crate) fn journal_model_switch(&mut self, record: &crate::model_switch::ModelSwitchRecord) {
        self.record_governance(
            GovernanceChange::ModelSwitch {
                tenant: record.tenant.clone(),
                old_model: record.old_model.clone(),
                new_model: record.new_model.clone(),
                outcome: format!("{:?}", record.outcome),
                record_digest: record.digest(),
            },
            Some(&record.authorizing_actor),
            None,
        );
    }

'''
lib = lib[:obs_start] + replacement + lib[obs_end:]

lib = one(lib,
'''pub struct TenantSnapshot {
    pub owner: String,
    pub budget: TokenBudget,
    pub models: ModelAllowlist,
    pub qpages: QPageRegistry,
}
''',
'''pub struct TenantSnapshot {
    pub owner: String,
    pub budget: TokenBudget,
    pub models: ModelAllowlist,
    pub qpages: QPageRegistry,
    #[serde(default)]
    pub active_model: Option<String>,
}
''', "tenant snapshot active model")

lib = one(lib,
'''    ApprovalLedgerCorrupt { detail: String },
    /// The journal does not continue the snapshot: replaying it would either
''',
'''    ApprovalLedgerCorrupt { detail: String },
    /// The selected model is missing, ambiguous, or not in the tenant's
    /// allowlist. Restore refuses rather than guessing a provider.
    ActiveModelInvalid {
        tenant: String,
        active_model: Option<String>,
    },
    /// The journal does not continue the snapshot: replaying it would either
''', "restore active model error")

lib = one(lib,
'''            Self::ApprovalLedgerCorrupt { detail } => {
                write!(f, "approval ledger is corrupt: {detail}")
            }
            Self::JournalDiscontinuity { expected, found } => write!(
''',
'''            Self::ApprovalLedgerCorrupt { detail } => {
                write!(f, "approval ledger is corrupt: {detail}")
            }
            Self::ActiveModelInvalid {
                tenant,
                active_model,
            } => write!(
                f,
                "tenant {tenant:?} has invalid or ambiguous active model {active_model:?}"
            ),
            Self::JournalDiscontinuity { expected, found } => write!(
''', "restore active model display")

lib = one(lib,
'''                            budget: state.budget.clone(),
                            models: state.models.clone(),
                            qpages: state.qpages.clone(),
''',
'''                            budget: state.budget.clone(),
                            models: state.models.clone(),
                            qpages: state.qpages.clone(),
                            active_model: state.active_model.clone(),
''', "snapshot active model field")

old_restore = '''            let id = TenantId(name);
            d.tenant_owner.insert(id.clone(), OrgId(t.owner));
            d.tenants.insert(
                id,
                TenantState {
                    budget: t.budget,
                    models: t.models,
                    qpages: t.qpages,
                },
            );
'''
new_restore = '''            let active_model = match t.active_model {
                Some(model) if t.models.0.contains(&model) => Some(model),
                Some(model) => {
                    return Err(RestoreError::ActiveModelInvalid {
                        tenant: name,
                        active_model: Some(model),
                    })
                }
                None if t.models.0.is_empty() => None,
                None if t.models.0.len() == 1 => t.models.0.iter().next().cloned(),
                None => {
                    return Err(RestoreError::ActiveModelInvalid {
                        tenant: name,
                        active_model: None,
                    })
                }
            };
            let id = TenantId(name);
            d.tenant_owner.insert(id.clone(), OrgId(t.owner));
            d.tenants.insert(
                id,
                TenantState {
                    budget: t.budget,
                    models: t.models,
                    qpages: t.qpages,
                    active_model,
                },
            );
'''
lib = one(lib, old_restore, new_restore, "restore active model")

marker = "\n    #[test]\n    fn model_switch_commits_when_invariant_state_is_equivalent()"
idx = lib.index(marker)
lib = lib[:idx] + "\n}\n"

ms = one(ms,
'''use ccos_enterprise_approval::{ApprovalDecision, ApprovalQuery, GateOutcome};
''',
'''use ccos_enterprise_approval::{ApprovalDecision, APPROVAL_SCHEMA};
''', "approval imports")

ms = one(ms,
'''        let bytes = serde_json::to_vec(self).expect("serializing a model-switch record cannot fail");
''',
'''        let bytes =
            serde_json::to_vec(self).expect("serializing a model-switch record cannot fail");
''', "record digest fmt")

ms = one(ms,
'''    deployment
        .begin_model_switch(tenant, new_model)
        .map_err(|error| format!("cannot begin model switch: {error}"))?;

    let transition_error = transition
''',
'''    let checkpoint = deployment
        .checkpoint_model_switch(tenant)
        .ok_or_else(|| "cannot capture model-switch rollback checkpoint".to_string())?;
    deployment
        .begin_model_switch(tenant, new_model)
        .map_err(|error| format!("cannot begin model switch: {error}"))?;

    let transition_error = transition
''', "checkpoint before transition")

old_outcome = '''    let (equivalent, divergence_digest, outcome) = if let Some(error) = transition_error {
        let digest = digest_framed(
            b"ccos-enterprise-model-switch-transition-error-v1",
            &[error.as_bytes()],
        );
        deployment.revert_model_switch(tenant, &old_model, new_model, target_was_allowlisted);
        (false, Some(digest), SwitchOutcome::TransitionFailedReverted)
    } else {
        match compare_invariant_states(&before, &after) {
            Equivalence::Equal => (true, None, SwitchOutcome::Committed),
            Equivalence::Divergent { digest } => {
                deployment.revert_model_switch(
                    tenant,
                    &old_model,
                    new_model,
                    target_was_allowlisted,
                );
                (false, Some(digest), SwitchOutcome::DivergedReverted)
            }
        }
    };
'''
new_outcome = '''    let (equivalent, divergence_digest, outcome) = if let Some(error) = transition_error {
        let digest = digest_framed(
            b"ccos-enterprise-model-switch-transition-error-v1",
            &[error.as_bytes()],
        );
        deployment.restore_model_switch_checkpoint(tenant, checkpoint);
        (
            false,
            Some(digest),
            SwitchOutcome::TransitionFailedReverted,
        )
    } else {
        match compare_invariant_states(&before, &after) {
            Equivalence::Equal => (true, None, SwitchOutcome::Committed),
            Equivalence::Divergent { digest } => {
                deployment.restore_model_switch_checkpoint(tenant, checkpoint);
                (false, Some(digest), SwitchOutcome::DivergedReverted)
            }
        }
    };
'''
ms = one(ms, old_outcome, new_outcome, "full checkpoint rollback")

start = ms.index("fn validate_allowlist_approval(")
end = ms.index("\nfn validate_model_name(", start)
new_validate = '''fn validate_allowlist_approval(
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
        return Err("supplied approval is not a live v2 approval bound to this model change".into());
    }
    if registry.is_revoked(approval_id) {
        return Err("supplied model-switch approval is revoked".into());
    }
    if record.expires_at.is_some_and(|expiry| expiry <= at_unix) {
        return Err("supplied model-switch approval is expired".into());
    }
    Ok(approval_id.to_string())
}
'''
ms = ms[:start] + new_validate + ms[end:]

test_start = ms.index("#[cfg(test)]\nmod tests {")
ms_prefix = ms[:test_start]
tests = r'''#[cfg(test)]
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
        assert_eq!(d.tenant_active_model(&tenant).as_deref(), Some("claude-opus"));

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
                GovernanceChange::ModelSwitch { record_digest, .. } => {
                    Some(record_digest.clone())
                }
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
'''
ms = ms_prefix + tests

LIB.write_text(lib)
MS.write_text(ms)
