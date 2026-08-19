#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
from pathlib import Path

p = Path('crates/ccos-enterprise-runtime/src/lib.rs')
s = p.read_text()

def one(old, new, label):
    global s
    count = s.count(old)
    if count != 1:
        raise SystemExit(f'{label}: expected one anchor, found {count}')
    s = s.replace(old, new, 1)

one(
'''pub const DEFAULT_REPLAY_MEMORY: usize = 65_536;\n''',
'''pub const DEFAULT_REPLAY_MEMORY: usize = 65_536;\n\n/// Administrative actions that are approval-gated on every deployment.\n/// Callers may add stricter gates, but these documented sensitive actions\n/// never depend on provisioning code remembering to opt in.\npub const DEFAULT_APPROVAL_REQUIRED_ACTIONS: &[&str] = &[\n    "tenant.delete",\n    "tenant.suspend",\n    "quota.override",\n    "policy.disable",\n    "license.revoke",\n    "model.allowlist.change",\n    "schema.migrate",\n];\n\nfn default_approval_required_actions() -> BTreeSet<String> {\n    DEFAULT_APPROVAL_REQUIRED_ACTIONS\n        .iter()\n        .map(|action| (*action).to_string())\n        .collect()\n}\n''',
'default approval actions')

one(
'''            approval_required: BTreeSet::new(),\n            approvals: ApprovalLedger::default(),\n''',
'''            approval_required: default_approval_required_actions(),\n            approvals: ApprovalLedger::default(),\n''',
'deployment default approval gates')

one(
'''    #[serde(default)]\n    pub approval_required: BTreeSet<String>,\n''',
'''    #[serde(default = "default_approval_required_actions")]\n    pub approval_required: BTreeSet<String>,\n''',
'snapshot default approval gates')

one(
'''        d.approval_required = snapshot.approval_required;\n        d.approvals = ApprovalLedger::from_snapshot(snapshot.approvals).map_err(|error| {\n''',
'''        d.approval_required = snapshot.approval_required;\n        d.approval_required\n            .extend(default_approval_required_actions());\n        d.approvals = ApprovalLedger::from_snapshot(snapshot.approvals).map_err(|error| {\n''',
'restore mandatory approval gates')

one(
'''#[derive(Debug, Default)]\npub struct ApprovalLedger {\n''',
'''#[derive(Debug, Clone, Default)]\npub struct ApprovalLedger {\n''',
'clone approval ledger')

one(
'''    pub fn record_approval(\n        &mut self,\n        request: ccos_enterprise_approval::ApprovalRequest,\n    ) -> Result<String, ccos_enterprise_approval::ApprovalError> {\n        let id = self.approvals.record(request)?;\n        self.record(\n            GovernanceChange::ApprovalRecorded {\n                approval_id: id.clone(),\n            },\n            None,\n            None,\n        );\n        Ok(id)\n    }\n''',
'''    pub fn record_approval(\n        &mut self,\n        request: ccos_enterprise_approval::ApprovalRequest,\n    ) -> Result<String, ccos_enterprise_approval::ApprovalError> {\n        // A usable authorization without governance evidence would violate the\n        // approval contract. Zero-capacity audit therefore refuses the record\n        // rather than creating an authorization that cannot be explained.\n        if self.audit_capacity == 0 {\n            return Err(ccos_enterprise_approval::ApprovalError::AuditUnavailable);\n        }\n        let actor = request.approver.clone();\n        let justification = request.justification.clone();\n        let before = self.approvals.clone();\n        let id = self.approvals.record(request)?;\n        let change = GovernanceChange::ApprovalRecorded {\n            approval_id: id.clone(),\n        };\n        if self.serving {\n            self.record(change, Some(&actor), Some(&justification));\n        } else {\n            // Ordinary provisioning changes are intentionally omitted before\n            // serving, but an authorization record is itself security evidence\n            // and must be journaled before it can authorize an effect.\n            while self.governance.len() >= self.audit_capacity {\n                self.governance.pop_front();\n                self.governance_dropped = self.governance_dropped.saturating_add(1);\n                self.metrics.inc("governance.dropped", 1);\n            }\n            let ordinal = self.next_governance_ordinal;\n            self.next_governance_ordinal = self.next_governance_ordinal.saturating_add(1);\n            self.governance.push_back(GovernanceRecord {\n                at_sequence: self.next_sequence,\n                ordinal,\n                actor: Some(clamp(&actor)),\n                justification: ccos_enterprise_admin::is_written_justification(Some(&justification))\n                    .then(|| clamp(&justification)),\n                change,\n            });\n        }\n        if !self.governance.iter().any(|record| {\n            matches!(\n                &record.change,\n                GovernanceChange::ApprovalRecorded { approval_id } if approval_id == &id\n            )\n        }) {\n            self.approvals = before;\n            return Err(ccos_enterprise_approval::ApprovalError::AuditUnavailable);\n        }\n        Ok(id)\n    }\n''',
'mandatory approval audit')

# Runtime regressions: append inside the existing test module.
pos = s.rfind('\n}\n')
if pos < 0:
    raise SystemExit('runtime test module terminator not found')
tests = r'''

    #[test]
    fn documented_sensitive_actions_are_gated_by_default_and_after_restore() {
        let deployment = Deployment::new();
        for action in DEFAULT_APPROVAL_REQUIRED_ACTIONS {
            assert!(
                deployment.requires_approval(action),
                "{action} was not approval-gated by default"
            );
        }
        let restored = Deployment::restore(deployment.snapshot(), &[], &[]).unwrap();
        for action in DEFAULT_APPROVAL_REQUIRED_ACTIONS {
            assert!(
                restored.requires_approval(action),
                "{action} lost its mandatory gate after restore"
            );
        }
    }

    #[test]
    fn approval_recorded_before_serving_still_has_governance_evidence() {
        let mut deployment = Deployment::new();
        let request = ccos_enterprise_approval::ApprovalRequest::new(
            TenantId("acme".into()),
            "policy.disable",
            &"ab".repeat(32),
            "operator",
            ccos_enterprise_approval::ApprovalDecision::Approved,
            100,
            None,
            "approved for the exact policy artifact",
        )
        .unwrap();
        let id = deployment.record_approval(request).unwrap();
        assert!(deployment.governance().any(|record| {
            matches!(
                &record.change,
                GovernanceChange::ApprovalRecorded { approval_id } if approval_id == &id
            )
        }));
    }

    #[test]
    fn zero_capacity_refuses_unaudited_authorization() {
        let mut deployment = Deployment::new().with_audit_capacity(0);
        let request = ccos_enterprise_approval::ApprovalRequest::new(
            TenantId("acme".into()),
            "policy.disable",
            &"cd".repeat(32),
            "operator",
            ccos_enterprise_approval::ApprovalDecision::Approved,
            100,
            None,
            "must not become usable without audit",
        )
        .unwrap();
        assert!(matches!(
            deployment.record_approval(request),
            Err(ccos_enterprise_approval::ApprovalError::AuditUnavailable)
        ));
        assert!(deployment.approvals().registry().snapshot().approvals.is_empty());
    }
'''
s = s[:pos] + tests + s[pos:]
p.write_text(s)
PY

cargo fmt --all
cargo check -p ccos-enterprise-approval -p ccos-enterprise-runtime
cargo clippy -p ccos-enterprise-approval -p ccos-enterprise-runtime --all-targets -- -D warnings
cargo test -p ccos-enterprise-approval
cargo test -p ccos-enterprise-runtime
cargo test -p ccos-enterprise-conformance --test human_approval

# Remove every temporary patch artifact and restore the official Fast workflow.
rm -f .ci/autonomous-patch.sh
rmdir .ci 2>/dev/null || true
rm -f .github/approval-hardening-trigger .github/workflows/zz-approval-hardening.yml
git checkout origin/main -- .github/workflows/ci-fast.yml

git config user.name 'MEMOPERF'
git config user.email 'contact@checkupauto.fr'
git add -A
git commit -m 'fix(approval): close post-merge authorization gaps'
git push origin HEAD:fix/approval-postmerge-hardening
