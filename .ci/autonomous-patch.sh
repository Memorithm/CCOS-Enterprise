#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
from pathlib import Path

p = Path('crates/ccos-enterprise-runtime/src/lib.rs')
s = p.read_text()

def one(old, new, label):
    global s
    n = s.count(old)
    if n != 1:
        raise SystemExit(f'{label}: expected one anchor, found {n}')
    s = s.replace(old, new, 1)

one(
'''    ModelSwitch {\n        tenant: String,\n        old_model: String,\n        new_model: String,\n        outcome: String,\n    },\n''',
'''    ModelSwitch {\n        tenant: String,\n        old_model: String,\n        new_model: String,\n        outcome: String,\n        /// Digest of the complete schema-versioned ModelSwitchRecord.\n        record_digest: String,\n    },\n''',
'governance record digest')

one(
'''pub struct TenantState {\n    budget: TokenBudget,\n    models: ModelAllowlist,\n    qpages: QPageRegistry,\n}\n''',
'''#[derive(Clone)]\npub struct TenantState {\n    budget: TokenBudget,\n    models: ModelAllowlist,\n    /// The one model currently selected for calls. The allowlist may contain\n    /// additional approved alternatives, but admission accepts only this one.\n    active_model: Option<String>,\n    qpages: QPageRegistry,\n}\n''',
'tenant active model')

one(
'''            models: ModelAllowlist::default(),\n            qpages: QPageRegistry::default(),\n''',
'''            models: ModelAllowlist::default(),\n            active_model: None,\n            qpages: QPageRegistry::default(),\n''',
'new active model')

one(
'''    pub fn allow_model(&mut self, model: &str) -> &mut Self {\n        self.models.0.insert(model.to_string());\n        self\n    }\n''',
'''    pub fn allow_model(&mut self, model: &str) -> &mut Self {\n        self.models.0.insert(model.to_string());\n        if self.active_model.is_none() {\n            self.active_model = Some(model.to_string());\n        }\n        self\n    }\n\n    /// Explicitly select one already-allowlisted model. This is primarily a\n    /// provisioning/test helper; live provider changes use model_switch.\n    pub fn select_model(&mut self, model: &str) -> Result<&mut Self, String> {\n        if !self.models.0.contains(model) {\n            return Err(format!("model {model:?} is not allowlisted"));\n        }\n        self.active_model = Some(model.to_string());\n        Ok(self)\n    }\n''',
'allow/select model')

one(
'''        if state.models.evaluate(call.model) != PolicyDecision::Allow {\n            return refuse(Refusal::ModelNotAllowed);\n        }\n''',
'''        if state.models.evaluate(call.model) != PolicyDecision::Allow\n            || state.active_model.as_deref() != Some(call.model)\n        {\n            return refuse(Refusal::ModelNotAllowed);\n        }\n''',
'admission active model')

# Replace the old lexicographic switch helpers wholesale.
start = s.index('    /// The tenant\'s active model: the single model the deployment governs')
end = s.index('    /// Tokens charged to a tenant.', start)
helpers = r'''    /// The tenant's explicitly selected active model.
    pub fn tenant_active_model(&self, tenant: &TenantId) -> Option<String> {
        self.tenants.get(tenant)?.active_model.clone()
    }

    /// Full tenant rollback state captured before a provider transition. It is
    /// crate-private because only the model-switch transaction may restore it.
    pub(crate) fn checkpoint_model_switch(
        &self,
        tenant: &TenantId,
    ) -> Option<(TenantState, BTreeMap<String, String>)> {
        Some((
            self.tenants.get(tenant)?.clone(),
            self.store.get(tenant).cloned().unwrap_or_default(),
        ))
    }

    /// Begin the intended policy delta. Returns whether the target was already
    /// allowlisted; callers need that fact only for audit/equivalence rules.
    pub(crate) fn begin_model_switch(
        &mut self,
        tenant: &TenantId,
        new_model: &str,
    ) -> Result<bool, String> {
        let state = self
            .tenants
            .get_mut(tenant)
            .ok_or_else(|| format!("unknown tenant {:?}", tenant.0))?;
        let was_allowlisted = state.models.0.contains(new_model);
        state.models.0.insert(new_model.to_string());
        state.active_model = Some(new_model.to_string());
        Ok(was_allowlisted)
    }

    pub(crate) fn rollback_model_switch(
        &mut self,
        tenant: &TenantId,
        checkpoint: (TenantState, BTreeMap<String, String>),
    ) {
        let (state, cells) = checkpoint;
        self.tenants.insert(tenant.clone(), state);
        if cells.is_empty() {
            self.store.remove(tenant);
        } else {
            self.store.insert(tenant.clone(), cells);
        }
    }

    /// Journal one completed model switch transaction with a digest that
    /// cryptographically links the bounded governance event to the complete
    /// transaction record returned/persisted by the caller.
    pub(crate) fn journal_model_switch(&mut self, record: &crate::model_switch::ModelSwitchRecord) {
        self.record(
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
s = s[:start] + helpers + s[end:]

one(
'''pub struct TenantSnapshot {\n    pub owner: String,\n    pub budget: TokenBudget,\n    pub models: ModelAllowlist,\n    pub qpages: QPageRegistry,\n}\n''',
'''pub struct TenantSnapshot {\n    pub owner: String,\n    pub budget: TokenBudget,\n    pub models: ModelAllowlist,\n    /// Added with the model-switch transaction. Old snapshots omit it and are\n    /// migrated deterministically from their allowlist during restore.\n    #[serde(default)]\n    pub active_model: Option<String>,\n    pub qpages: QPageRegistry,\n}\n''',
'tenant snapshot active model')

one(
'''                            models: state.models.clone(),\n                            qpages: state.qpages.clone(),\n''',
'''                            models: state.models.clone(),\n                            active_model: state.active_model.clone(),\n                            qpages: state.qpages.clone(),\n''',
snapshot active model')

one(
'''    ApprovalLedgerCorrupt { detail: String },\n    /// The journal does not continue the snapshot: replaying it would either\n''',
'''    ApprovalLedgerCorrupt { detail: String },\n    /// The selected active model is absent from the tenant allowlist.\n    ActiveModelInvalid { tenant: String, model: String },\n    /// The journal does not continue the snapshot: replaying it would either\n''',
'restore active model error')

one(
'''            Self::ApprovalLedgerCorrupt { detail } => {\n                write!(f, "approval ledger is corrupt: {detail}")\n            }\n            Self::JournalDiscontinuity { expected, found } => write!(\n''',
'''            Self::ApprovalLedgerCorrupt { detail } => {\n                write!(f, "approval ledger is corrupt: {detail}")\n            }\n            Self::ActiveModelInvalid { tenant, model } => write!(\n                f,\n                "tenant {tenant:?} selects model {model:?}, which is not allowlisted"\n            ),\n            Self::JournalDiscontinuity { expected, found } => write!(\n''',
'restore active model display')

old = '''            let id = TenantId(name);\n            d.tenant_owner.insert(id.clone(), OrgId(t.owner));\n            d.tenants.insert(\n                id,\n                TenantState {\n                    budget: t.budget,\n                    models: t.models,\n                    qpages: t.qpages,\n                },\n            );\n'''
new = '''            let id = TenantId(name);\n            let active_model = match t.active_model {\n                Some(model) => {\n                    if !t.models.0.contains(&model) {\n                        return Err(RestoreError::ActiveModelInvalid {\n                            tenant: id.0.clone(),\n                            model,\n                        });\n                    }\n                    Some(model)\n                }\n                // Migration of pre-active-model snapshots. The old runtime had\n                // no selection state; choose the deterministic first allowlisted\n                // model once and persist it on the next snapshot.\n                None => t.models.0.iter().next().cloned(),\n            };\n            d.tenant_owner.insert(id.clone(), OrgId(t.owner));\n            d.tenants.insert(\n                id,\n                TenantState {\n                    budget: t.budget,\n                    models: t.models,\n                    active_model,\n                    qpages: t.qpages,\n                },\n            );\n'''
one(old, new, 'restore active model')

# Replace model-switch tests added by the original PR with tests for the new API.
marker = '    #[test]\n    fn model_switch_commits_when_invariant_state_is_equivalent()'
idx = s.find(marker)
if idx < 0:
    raise SystemExit('old model-switch tests not found')
# These tests were the final block in the module; preserve exactly one module close.
close = s.rfind('\n}')
if close <= idx:
    raise SystemExit('runtime test module close not found')
new_tests = r'''    #[test]
    fn active_model_is_explicit_and_admission_enforces_it() {
        let mut d = two_tenant_deployment();
        d.tenant_mut("acme").unwrap().allow_model("gpt-5");
        let tenant = TenantId("acme".into());
        assert_eq!(d.tenant_active_model(&tenant).as_deref(), Some("claude-opus"));
        let alice = actor("memorithm", "alice", AuthStrength::Token);
        let req = request("acme", "alice", "memory.recall", "active-model-gate");
        assert!(matches!(
            d.admit(Call {
                actor: &alice,
                request: &req,
                model: "gpt-5",
                cost_tokens: 1,
                variant: None,
                justification: None,
            }),
            Outcome::Refused(Refusal::ModelNotAllowed)
        ));
    }

    #[test]
    fn model_switch_requires_real_replay_before_commit() {
        let mut d = two_tenant_deployment();
        d.tenant_mut("acme").unwrap().allow_model("gpt-5");
        let tenant = TenantId("acme".into());
        let mut replayed = false;
        let mut transition = |_: &mut Deployment, _: &TenantId, old: &str, new: &str| {
            assert_eq!(old, "claude-opus");
            assert_eq!(new, "gpt-5");
            replayed = true;
            Ok(())
        };
        let result = model_switch::switch_tenant_model(
            &mut d,
            &tenant,
            "gpt-5",
            "root",
            None,
            1_000,
            &mut transition,
        )
        .unwrap();
        assert!(replayed);
        assert_eq!(result.record.outcome, model_switch::SwitchOutcome::Committed);
        assert_eq!(d.tenant_active_model(&tenant).as_deref(), Some("gpt-5"));
        let digest = result.record.digest();
        assert!(d.governance().any(|row| matches!(
            &row.change,
            GovernanceChange::ModelSwitch { record_digest, .. } if record_digest == &digest
        )));
    }

    #[test]
    fn fabricated_or_wrong_artifact_approval_cannot_add_model() {
        let mut d = two_tenant_deployment();
        let tenant = TenantId("acme".into());
        let mut noop = |_: &mut Deployment, _: &TenantId, _: &str, _: &str| Ok(());
        assert!(model_switch::switch_tenant_model(
            &mut d,
            &tenant,
            "gpt-5",
            "root",
            Some("fabricated"),
            1_000,
            &mut noop,
        )
        .is_err());

        let wrong = ccos_enterprise_approval::ApprovalRequest::new(
            tenant.clone(),
            model_switch::MODEL_ALLOWLIST_ACTION,
            &"11".repeat(32),
            "root",
            ccos_enterprise_approval::ApprovalDecision::Approved,
            900,
            None,
            "wrong artifact",
        )
        .unwrap();
        let wrong_id = d.record_approval(wrong).unwrap();
        assert!(model_switch::switch_tenant_model(
            &mut d,
            &tenant,
            "gpt-5",
            "root",
            Some(&wrong_id),
            1_000,
            &mut noop,
        )
        .is_err());
    }

    #[test]
    fn exact_live_approval_can_add_model() {
        let mut d = two_tenant_deployment();
        let tenant = TenantId("acme".into());
        let artifact = model_switch::allowlist_artifact_hash(&tenant, "gpt-5").unwrap();
        let approval = ccos_enterprise_approval::ApprovalRequest::new(
            tenant.clone(),
            model_switch::MODEL_ALLOWLIST_ACTION,
            &artifact,
            "root",
            ccos_enterprise_approval::ApprovalDecision::Approved,
            900,
            Some(2_000),
            "approve exact model allowlist addition",
        )
        .unwrap();
        let id = d.record_approval(approval).unwrap();
        let mut noop = |_: &mut Deployment, _: &TenantId, _: &str, _: &str| Ok(());
        let result = model_switch::switch_tenant_model(
            &mut d,
            &tenant,
            "gpt-5",
            "root",
            Some(&id),
            1_000,
            &mut noop,
        )
        .unwrap();
        assert_eq!(result.record.approval_id.as_deref(), Some(id.as_str()));
        assert_eq!(d.tenant_active_model(&tenant).as_deref(), Some("gpt-5"));
        assert!(d.tenant_models("acme").unwrap().contains("claude-opus"));
    }

    #[test]
    fn divergence_restores_complete_tenant_checkpoint() {
        let mut d = two_tenant_deployment();
        d.tenant_mut("acme").unwrap().allow_model("gpt-5");
        let tenant = TenantId("acme".into());
        let before = d.snapshot();
        let mut corrupt = |deployment: &mut Deployment, tenant: &TenantId, _: &str, _: &str| {
            deployment
                .write_cell(tenant, "provider-corruption", "unexpected")
                .map_err(|e| format!("{e:?}"))?;
            Ok(())
        };
        let result = model_switch::switch_tenant_model(
            &mut d,
            &tenant,
            "gpt-5",
            "root",
            None,
            1_000,
            &mut corrupt,
        )
        .unwrap();
        assert_eq!(
            result.record.outcome,
            model_switch::SwitchOutcome::DivergedReverted
        );
        assert_eq!(d.tenant_active_model(&tenant).as_deref(), Some("claude-opus"));
        assert_eq!(d.read_cell(&tenant, "provider-corruption"), None);
        assert_eq!(d.snapshot().cells, before.cells);
    }

    #[test]
    fn transition_failure_restores_checkpoint_and_is_journaled() {
        let mut d = two_tenant_deployment();
        d.tenant_mut("acme").unwrap().allow_model("gpt-5");
        let tenant = TenantId("acme".into());
        let mut fail = |_: &mut Deployment, _: &TenantId, _: &str, _: &str| {
            Err("provider replay failed".to_string())
        };
        let result = model_switch::switch_tenant_model(
            &mut d,
            &tenant,
            "gpt-5",
            "root",
            None,
            1_000,
            &mut fail,
        )
        .unwrap();
        assert_eq!(
            result.record.outcome,
            model_switch::SwitchOutcome::TransitionFailedReverted
        );
        assert_eq!(d.tenant_active_model(&tenant).as_deref(), Some("claude-opus"));
        assert!(result.record.divergence_digest.is_some());
    }
'''
s = s[:idx] + new_tests + s[close:]
p.write_text(s)
PY

cargo fmt --all
cargo check -p ccos-enterprise-runtime
cargo clippy -p ccos-enterprise-runtime --all-targets -- -D warnings
cargo test -p ccos-enterprise-runtime

rm -f .ci/autonomous-patch.sh
rmdir .ci 2>/dev/null || true

git config user.name 'MEMOPERF'
git config user.email 'contact@checkupauto.fr'
git add -A
git commit -m 'fix(runtime): close model-switch authorization and replay gaps'
git push origin HEAD:feat/model-switch-transaction
