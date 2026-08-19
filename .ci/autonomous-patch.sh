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

# sha2 is already a dependency on this branch.
one(
'''use ccos_enterprise_tenancy::{TenantId, TenantScope};\n''',
'''use ccos_enterprise_tenancy::{TenantId, TenantScope};\nuse sha2::{Digest, Sha256};\n''',
'sha2 import')

one(
'''    TenantRulesChanged {\n        tenant: String,\n        models_allowed: Vec<String>,\n        models_revoked: Vec<String>,\n        variants_activated: Vec<String>,\n        variants_deactivated: Vec<String>,\n    },\n''',
'''    TenantRulesChanged {\n        tenant: String,\n        models_allowed: Vec<String>,\n        models_revoked: Vec<String>,\n        variants_activated: Vec<String>,\n        variants_deactivated: Vec<String>,\n    },\n    /// The tenant's Q-Page policy changed. The full deterministic after-state\n    /// is recorded so an auditor can explain a later activation decision.\n    QPagePolicyChanged {\n        tenant: String,\n        permitted: Vec<String>,\n        experimental_bridge_opted_in: bool,\n    },\n''',
'qpage governance variant')

one(
'''    variant_policy: ccos_enterprise_qpages::policy::VariantPolicy,\n}\n''',
'''    variant_policy: ccos_enterprise_qpages::policy::VariantPolicy,\n    /// Approval id that authorized an activation requiring approval. Variants\n    /// allowed without approval have no entry. This is durable so restart can\n    /// revalidate expiry/revocation instead of trusting a bare active bit.\n    variant_approvals: BTreeMap<AdvancedQPageVariant, String>,\n}\n''',
'tenant variant approvals')
one(
'''            variant_policy: ccos_enterprise_qpages::policy::VariantPolicy::default(),\n        }\n''',
'''            variant_policy: ccos_enterprise_qpages::policy::VariantPolicy::default(),\n            variant_approvals: BTreeMap::new(),\n        }\n''',
'new variant approvals')

# Raw activation/policy mutation is no longer public through TenantRules'
# DerefMut surface. Live callers use the explicit guard/deployment APIs below.
one(
'''    pub fn activate(&mut self, variant: AdvancedQPageVariant) -> &mut Self {\n        self.qpages.activate(variant);\n        self\n    }\n\n    /// Activate a variant **through the variant policy**.\n''',
'''    pub(crate) fn activate_raw(&mut self, variant: AdvancedQPageVariant) {\n        self.qpages.activate(variant);\n    }\n\n    pub(crate) fn deactivate_raw(&mut self, variant: AdvancedQPageVariant) {\n        self.qpages.deactivate(variant);\n        self.variant_approvals.remove(&variant);\n    }\n\n    /// Activate a variant **through the variant policy**.\n''',
'raw activation private')
# Remove the unsafe TenantState activation method entirely.
start = s.index('    /// Activate a variant **through the variant policy**.')
end = s.index('    /// The tenant\'s variant policy (validated state only).', start)
s = s[:start] + s[end:]

one(
'''    pub fn permit_variant(&mut self, variant: AdvancedQPageVariant) -> bool {\n        self.variant_policy.permit(variant)\n    }\n\n    /// Opt the experimental bridge into the tenant's policy.\n    pub fn opt_in_experimental_bridge(&mut self) {\n        self.variant_policy.opt_in_experimental_bridge();\n    }\n''',
'''    pub(crate) fn permit_variant_raw(&mut self, variant: AdvancedQPageVariant) -> bool {\n        self.variant_policy.permit(variant)\n    }\n\n    pub(crate) fn revoke_variant_raw(&mut self, variant: AdvancedQPageVariant) -> bool {\n        let changed = self.variant_policy.revoke(variant);\n        if changed {\n            self.deactivate_raw(variant);\n        }\n        changed\n    }\n\n    pub(crate) fn opt_in_experimental_bridge_raw(&mut self) {\n        self.variant_policy.opt_in_experimental_bridge();\n    }\n''',
'policy mutation private')

# TenantRules captures policy state as well as model/activation state.
one(
'''    before_variants: BTreeSet<AdvancedQPageVariant>,\n    actor: Option<String>,\n''',
'''    before_variants: BTreeSet<AdvancedQPageVariant>,\n    before_variant_policy: ccos_enterprise_qpages::policy::VariantPolicy,\n    actor: Option<String>,\n''',
'tenant rules policy snapshot')
one(
'''        let before_variants: BTreeSet<AdvancedQPageVariant> =\n            state.qpages.active().into_iter().collect();\n        Some(TenantRules {\n''',
'''        let before_variants: BTreeSet<AdvancedQPageVariant> =\n            state.qpages.active().into_iter().collect();\n        let before_variant_policy = state.variant_policy.clone();\n        Some(TenantRules {\n''',
'tenant rules before policy')
one(
'''            before_models,\n            before_variants,\n        })\n''',
'''            before_models,\n            before_variants,\n            before_variant_policy,\n        })\n''',
'tenant rules construct policy')

# Explicit policy APIs on the guard are the only public mutation route.
insert_anchor = '''impl std::ops::DerefMut for TenantRules<'_> {\n'''
methods = r'''impl TenantRules<'_> {
    pub fn permit_variant(&mut self, variant: AdvancedQPageVariant) -> bool {
        self.deployment
            .tenants
            .get_mut(&self.tenant)
            .expect("tenant guard remains valid")
            .permit_variant_raw(variant)
    }

    pub fn revoke_variant(&mut self, variant: AdvancedQPageVariant) -> bool {
        self.deployment
            .tenants
            .get_mut(&self.tenant)
            .expect("tenant guard remains valid")
            .revoke_variant_raw(variant)
    }

    pub fn opt_in_experimental_bridge(&mut self) {
        self.deployment
            .tenants
            .get_mut(&self.tenant)
            .expect("tenant guard remains valid")
            .opt_in_experimental_bridge_raw();
    }
}

'''
if insert_anchor not in s:
    raise SystemExit('TenantRules methods anchor missing')
s = s.replace(insert_anchor, methods + insert_anchor, 1)

# Drop now journals policy changes independently of activation/model diffs.
one(
'''        let (after_models, after_variants) = {\n            let state = &self.deployment.tenants[&self.tenant];\n            (\n                state.models.0.clone(),\n                state.qpages.active().into_iter().collect::<BTreeSet<_>>(),\n            )\n        };\n''',
'''        let (after_models, after_variants, after_variant_policy) = {\n            let state = &self.deployment.tenants[&self.tenant];\n            (\n                state.models.0.clone(),\n                state.qpages.active().into_iter().collect::<BTreeSet<_>>(),\n                state.variant_policy.clone(),\n            )\n        };\n''',
drop after policy')
# Replace final Drop body from emptiness check through record with two records.
old = '''        if models_allowed.is_empty()\n            && models_revoked.is_empty()\n            && variants_activated.is_empty()\n            && variants_deactivated.is_empty()\n        {\n            return;\n        }\n        let change = GovernanceChange::TenantRulesChanged {\n            tenant: self.tenant.0.clone(),\n            models_allowed,\n            models_revoked,\n            variants_activated,\n            variants_deactivated,\n        };\n        let (by, why) = (self.actor.clone(), self.justification.clone());\n        self.deployment\n            .record(change, by.as_deref(), why.as_deref());\n'''
new = '''        let (by, why) = (self.actor.clone(), self.justification.clone());\n        if !models_allowed.is_empty()\n            || !models_revoked.is_empty()\n            || !variants_activated.is_empty()\n            || !variants_deactivated.is_empty()\n        {\n            self.deployment.record(\n                GovernanceChange::TenantRulesChanged {\n                    tenant: self.tenant.0.clone(),\n                    models_allowed,\n                    models_revoked,\n                    variants_activated,\n                    variants_deactivated,\n                },\n                by.as_deref(),\n                why.as_deref(),\n            );\n        }\n        if after_variant_policy != self.before_variant_policy {\n            self.deployment.record(\n                GovernanceChange::QPagePolicyChanged {\n                    tenant: self.tenant.0.clone(),\n                    permitted: after_variant_policy\n                        .permitted\n                        .iter()\n                        .map(|variant| format!("{variant:?}"))\n                        .collect(),\n                    experimental_bridge_opted_in: after_variant_policy\n                        .experimental_bridge_opted_in,\n                },\n                by.as_deref(),\n                why.as_deref(),\n            );\n        }\n'''
one(old, new, 'drop governance')

# Add public deployment activation/deactivation and artifact helper before human
# approval-gate section.
anchor = '''    // ── Human approval gates (docs/HUMAN_APPROVAL_POLICIES.md) ──────────\n'''
api = r'''    /// Canonical approval artifact for one tenant/variant activation.
    pub fn qpage_activation_artifact_hash(
        tenant: &TenantId,
        variant: AdvancedQPageVariant,
    ) -> String {
        let mut hasher = Sha256::new();
        for field in [
            b"ccos-enterprise-qpage-activation-v1".as_slice(),
            tenant.0.as_bytes(),
            format!("{variant:?}").as_bytes(),
        ] {
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

    /// Live activation path. Policy is evaluated first; approval-required
    /// variants require the exact live approval record, not a caller string.
    pub fn activate_variant_governed(
        &mut self,
        tenant: &TenantId,
        variant: AdvancedQPageVariant,
        approval_id: Option<&str>,
        now: u64,
    ) -> Result<(), String> {
        let decision = self
            .tenants
            .get(tenant)
            .ok_or_else(|| format!("unknown tenant {:?}", tenant.0))?
            .variant_policy
            .evaluate(variant);
        let validated_approval = match decision {
            ccos_enterprise_qpages::policy::ActivationDecision::Allowed => None,
            ccos_enterprise_qpages::policy::ActivationDecision::Denied => {
                return Err(format!(
                    "{variant:?} is not permitted by the tenant variant policy"
                ))
            }
            ccos_enterprise_qpages::policy::ActivationDecision::RequiresApproval => {
                let id = approval_id.ok_or_else(|| {
                    format!("{variant:?} requires a recorded human approval")
                })?;
                let artifact = Self::qpage_activation_artifact_hash(tenant, variant);
                let record = self
                    .approvals
                    .registry()
                    .snapshot()
                    .approvals
                    .get(id)
                    .ok_or_else(|| "supplied Q-Page approval id is not recorded".to_string())?;
                if record.tenant != tenant.0
                    || record.action != "qpage.activate"
                    || record.artifact_hash != artifact
                    || record.decision != ccos_enterprise_approval::ApprovalDecision::Approved
                {
                    return Err("supplied approval is not bound to this Q-Page activation".into());
                }
                let query = ccos_enterprise_approval::ApprovalQuery {
                    tenant,
                    action: "qpage.activate",
                    artifact_hash: &artifact,
                    now,
                };
                if self.approvals.evaluate(&query)
                    != ccos_enterprise_approval::GateOutcome::Approved
                {
                    return Err("Q-Page approval is expired, revoked, legacy, or invalid".into());
                }
                Some(id.to_string())
            }
        };
        let mut rules = self
            .tenant_mut(&tenant.0)
            .ok_or_else(|| format!("unknown tenant {:?}", tenant.0))?;
        let state = rules
            .deployment
            .tenants
            .get_mut(&rules.tenant)
            .expect("tenant guard remains valid");
        state.activate_raw(variant);
        match validated_approval {
            Some(id) => {
                state.variant_approvals.insert(variant, id);
            }
            None => {
                state.variant_approvals.remove(&variant);
            }
        }
        Ok(())
    }

    pub fn deactivate_variant_governed(
        &mut self,
        tenant: &TenantId,
        variant: AdvancedQPageVariant,
    ) -> Result<(), String> {
        let mut rules = self
            .tenant_mut(&tenant.0)
            .ok_or_else(|| format!("unknown tenant {:?}", tenant.0))?;
        rules
            .deployment
            .tenants
            .get_mut(&rules.tenant)
            .expect("tenant guard remains valid")
            .deactivate_raw(variant);
        Ok(())
    }

'''
if anchor not in s:
    raise SystemExit('activation API anchor missing')
s = s.replace(anchor, api + anchor, 1)

# Admission must enforce both active registry and current policy/approval state.
one(
'''        if let Some(v) = call.variant {\n            if !state.qpages.is_active(v) {\n                return refuse(Refusal::VariantNotActivated);\n            }\n        }\n''',
'''        if let Some(v) = call.variant {\n            if !state.qpages.is_active(v) {\n                return refuse(Refusal::VariantNotActivated);\n            }\n            match state.variant_policy.evaluate(v) {\n                ccos_enterprise_qpages::policy::ActivationDecision::Denied => {\n                    return refuse(Refusal::VariantNotActivated);\n                }\n                ccos_enterprise_qpages::policy::ActivationDecision::Allowed => {}\n                ccos_enterprise_qpages::policy::ActivationDecision::RequiresApproval => {\n                    let Some(id) = state.variant_approvals.get(&v) else {\n                        return refuse(Refusal::RequiresApproval);\n                    };\n                    let artifact = Self::qpage_activation_artifact_hash(&tenant_id, v);\n                    let Some(record) = self.approvals.registry().snapshot().approvals.get(id) else {\n                        return refuse(Refusal::RequiresApproval);\n                    };\n                    if record.tenant != tenant_id.0\n                        || record.action != "qpage.activate"\n                        || record.artifact_hash != artifact\n                        || record.decision\n                            != ccos_enterprise_approval::ApprovalDecision::Approved\n                        || self.approvals.evaluate(&ccos_enterprise_approval::ApprovalQuery {\n                            tenant: &tenant_id,\n                            action: "qpage.activate",\n                            artifact_hash: &artifact,\n                            now: now_unix(),\n                        }) != ccos_enterprise_approval::GateOutcome::Approved\n                    {\n                        return refuse(Refusal::RequiresApproval);\n                    }\n                }\n            }\n        }\n''',
admission qpage policy')

# Snapshot carries activation approval ids.
one(
'''    #[serde(default)]\n    pub variant_policy: ccos_enterprise_qpages::policy::VariantPolicy,\n}\n''',
'''    #[serde(default)]\n    pub variant_policy: ccos_enterprise_qpages::policy::VariantPolicy,\n    /// Approval evidence for approval-required active variants.\n    #[serde(default)]\n    pub variant_approvals: BTreeMap<AdvancedQPageVariant, String>,\n}\n''',
snapshot activation approvals')
one(
'''                            qpages: state.qpages.clone(),\n                            variant_policy: state.variant_policy.clone(),\n''',
'''                            qpages: state.qpages.clone(),\n                            variant_policy: state.variant_policy.clone(),\n                            variant_approvals: state.variant_approvals.clone(),\n''',
snapshot write approvals')

# Restore validates every active variant against policy. Approval-required
# variants must at least carry a recorded, structurally matching approval id;
# admission rechecks expiry/revocation against the current clock on each call.
old = '''            d.tenants.insert(\n                id,\n                TenantState {\n                    budget: t.budget,\n                    models: t.models,\n                    qpages: t.qpages,\n                    variant_policy: t.variant_policy,\n                },\n            );\n'''
new = '''            for variant in t.qpages.active() {\n                match t.variant_policy.evaluate(variant) {\n                    ccos_enterprise_qpages::policy::ActivationDecision::Denied => {\n                        return Err(RestoreError::VariantPolicyCorrupt {\n                            tenant: id.0.clone(),\n                            detail: format!("active variant {variant:?} is denied by restored policy"),\n                        });\n                    }\n                    ccos_enterprise_qpages::policy::ActivationDecision::Allowed => {}\n                    ccos_enterprise_qpages::policy::ActivationDecision::RequiresApproval => {\n                        let Some(approval_id) = t.variant_approvals.get(&variant) else {\n                            return Err(RestoreError::VariantPolicyCorrupt {\n                                tenant: id.0.clone(),\n                                detail: format!(\n                                    "active variant {variant:?} has no persisted approval identity"\n                                ),\n                            });\n                        };\n                        let Some(record) = d.approvals.registry().snapshot().approvals.get(approval_id) else {\n                            return Err(RestoreError::VariantPolicyCorrupt {\n                                tenant: id.0.clone(),\n                                detail: format!("unknown activation approval {approval_id:?}"),\n                            });\n                        };\n                        let artifact = Self::qpage_activation_artifact_hash(&id, variant);\n                        if record.tenant != id.0\n                            || record.action != "qpage.activate"\n                            || record.artifact_hash != artifact\n                            || record.decision\n                                != ccos_enterprise_approval::ApprovalDecision::Approved\n                        {\n                            return Err(RestoreError::VariantPolicyCorrupt {\n                                tenant: id.0.clone(),\n                                detail: format!(\n                                    "activation approval {approval_id:?} is not bound to {variant:?}"\n                                ),\n                            });\n                        }\n                    }\n                }\n            }\n            d.tenants.insert(\n                id,\n                TenantState {\n                    budget: t.budget,\n                    models: t.models,\n                    qpages: t.qpages,\n                    variant_policy: t.variant_policy,\n                    variant_approvals: t.variant_approvals,\n                },\n            );\n'''
one(old, new, 'restore active policy binding')

# Replace original PR's Q-Page tests with hardened API tests.
marker = '    #[test]\n    fn variant_policy_is_durable_and_governs_activation()'
idx = s.find(marker)
if idx < 0:
    raise SystemExit('old qpage tests not found')
close = s.rfind('\n}')
new_tests = r'''    #[test]
    fn live_raw_activation_is_not_public_and_governed_activation_obeys_policy() {
        let mut d = two_tenant_deployment();
        let tenant = TenantId("acme".into());
        assert!(d
            .activate_variant_governed(
                &tenant,
                AdvancedQPageVariant::Hierarchical,
                None,
                100
            )
            .is_err());
        d.tenant_mut("acme")
            .unwrap()
            .permit_variant(AdvancedQPageVariant::Hierarchical);
        d.activate_variant_governed(
            &tenant,
            AdvancedQPageVariant::Hierarchical,
            None,
            100,
        )
        .unwrap();
        assert!(d
            .tenants
            .get(&tenant)
            .unwrap()
            .qpages
            .is_active(AdvancedQPageVariant::Hierarchical));
    }

    #[test]
    fn experimental_bridge_rejects_fabricated_and_wrong_artifact_approval() {
        let mut d = two_tenant_deployment();
        let tenant = TenantId("acme".into());
        d.tenant_mut("acme")
            .unwrap()
            .opt_in_experimental_bridge();
        assert!(d
            .activate_variant_governed(
                &tenant,
                AdvancedQPageVariant::ExperimentalBridge,
                Some("fabricated"),
                100,
            )
            .is_err());
        let wrong = ccos_enterprise_approval::ApprovalRequest::new(
            tenant.clone(),
            "qpage.activate",
            &"11".repeat(32),
            "operator",
            ccos_enterprise_approval::ApprovalDecision::Approved,
            10,
            None,
            "wrong artifact",
        )
        .unwrap();
        let wrong_id = d.record_approval(wrong).unwrap();
        assert!(d
            .activate_variant_governed(
                &tenant,
                AdvancedQPageVariant::ExperimentalBridge,
                Some(&wrong_id),
                100,
            )
            .is_err());
    }

    #[test]
    fn exact_bridge_approval_is_persisted_and_revalidated_on_admission() {
        let mut d = two_tenant_deployment();
        let tenant = TenantId("acme".into());
        d.tenant_mut("acme")
            .unwrap()
            .opt_in_experimental_bridge();
        let artifact = Deployment::qpage_activation_artifact_hash(
            &tenant,
            AdvancedQPageVariant::ExperimentalBridge,
        );
        let approval = ccos_enterprise_approval::ApprovalRequest::new(
            tenant.clone(),
            "qpage.activate",
            &artifact,
            "operator",
            ccos_enterprise_approval::ApprovalDecision::Approved,
            10,
            None,
            "approve exact experimental bridge activation",
        )
        .unwrap();
        let id = d.record_approval(approval).unwrap();
        d.activate_variant_governed(
            &tenant,
            AdvancedQPageVariant::ExperimentalBridge,
            Some(&id),
            100,
        )
        .unwrap();
        let snap = d.snapshot();
        assert_eq!(
            snap.tenants["acme"]
                .variant_approvals
                .get(&AdvancedQPageVariant::ExperimentalBridge),
            Some(&id)
        );
        let restored = Deployment::restore(snap, &[], d.governance().cloned().collect::<Vec<_>>().as_slice()).unwrap();
        assert_eq!(
            restored.tenants[&tenant]
                .variant_approvals
                .get(&AdvancedQPageVariant::ExperimentalBridge),
            Some(&id)
        );
    }

    #[test]
    fn restored_active_variant_denied_by_default_policy_is_refused() {
        let mut d = two_tenant_deployment();
        let tenant = TenantId("acme".into());
        d.tenants
            .get_mut(&tenant)
            .unwrap()
            .activate_raw(AdvancedQPageVariant::Hierarchical);
        let mut snap = d.snapshot();
        snap.tenants.get_mut("acme").unwrap().variant_policy =
            ccos_enterprise_qpages::policy::VariantPolicy::default();
        assert!(matches!(
            Deployment::restore(snap, &[], &[]),
            Err(RestoreError::VariantPolicyCorrupt { .. })
        ));
    }

    #[test]
    fn qpage_policy_changes_are_governance_visible_after_serving() {
        let mut d = two_tenant_deployment();
        // Create one decision so subsequent rule changes are journaled.
        let alice = actor("memorithm", "alice", AuthStrength::Token);
        let req = request("acme", "alice", "memory.recall", "qpage-policy-anchor");
        let _ = d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
            justification: None,
        });
        d.tenant_mut("acme")
            .unwrap()
            .permit_variant(AdvancedQPageVariant::Hierarchical);
        assert!(d.governance().any(|row| matches!(
            row.change,
            GovernanceChange::QPagePolicyChanged { .. }
        )));
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
git commit -m 'fix(qpages): enforce policy and approval on every live activation'
git push origin HEAD:feat/durable-qpage-activation
