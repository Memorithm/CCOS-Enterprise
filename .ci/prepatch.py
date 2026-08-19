from pathlib import Path

p = Path("crates/ccos-enterprise-approval/src/lib.rs")
s = p.read_text()
old = '''    pub fn evaluate(&self, query: &ApprovalQuery<'_>) -> GateOutcome {
        if !canonical_action(query.action) || !is_sha256_hex(query.artifact_hash) {
            return GateOutcome::Denied;
        }
        let mut saw_other_artifact = None;
        for record in self.snapshot.approvals.values().rev() {
            if record.tenant != query.tenant.0 || record.action != query.action {
                continue;
            }
            if record.artifact_hash != query.artifact_hash {
                saw_other_artifact = Some(record.artifact_hash.clone());
                continue;
            }
            // Legacy ids are audit-only after upgrade: their identity did not
            // bind all authorization fields, so trusting them would preserve
            // the exact vulnerability this version repairs.
            if !record.id.starts_with("approval-v2-")
                || record.decision != ApprovalDecision::Approved
            {
                continue;
            }
            if self.is_revoked(&record.id) {
                return GateOutcome::Revoked;
            }
            if record.expires_at.is_some_and(|expiry| expiry <= query.now) {
                return GateOutcome::Expired;
            }
            return GateOutcome::Approved;
        }
        saw_other_artifact
            .map(|found| GateOutcome::ArtifactMismatch { found })
            .unwrap_or(GateOutcome::Denied)
    }
'''
new = '''    pub fn evaluate(&self, query: &ApprovalQuery<'_>) -> GateOutcome {
        if !canonical_action(query.action) || !is_sha256_hex(query.artifact_hash) {
            return GateOutcome::Denied;
        }

        // Approval ids are cryptographic identities, not chronology. Never let
        // BTreeMap's hash-key order decide which renewal controls an artifact.
        // The newest exact v2 decision wins, with id as a deterministic tie
        // breaker for two records created at the same second.
        let newest_exact = self
            .snapshot
            .approvals
            .values()
            .filter(|record| {
                record.id.starts_with("approval-v2-")
                    && record.tenant == query.tenant.0
                    && record.action == query.action
                    && record.artifact_hash == query.artifact_hash
            })
            .max_by(|left, right| {
                left.recorded_at
                    .cmp(&right.recorded_at)
                    .then_with(|| left.id.cmp(&right.id))
            });

        if let Some(record) = newest_exact {
            if record.decision != ApprovalDecision::Approved {
                return GateOutcome::Denied;
            }
            if self.is_revoked(&record.id) {
                return GateOutcome::Revoked;
            }
            if record.expires_at.is_some_and(|expiry| expiry <= query.now) {
                return GateOutcome::Expired;
            }
            return GateOutcome::Approved;
        }

        // A different artifact under the same tenant/action is useful
        // diagnostic evidence, but it never authorizes this query. Keep that
        // result deterministic as well.
        self.snapshot
            .approvals
            .values()
            .filter(|record| {
                record.tenant == query.tenant.0
                    && record.action == query.action
                    && record.artifact_hash != query.artifact_hash
            })
            .max_by(|left, right| {
                left.recorded_at
                    .cmp(&right.recorded_at)
                    .then_with(|| left.id.cmp(&right.id))
            })
            .map(|record| GateOutcome::ArtifactMismatch {
                found: record.artifact_hash.clone(),
            })
            .unwrap_or(GateOutcome::Denied)
    }
'''
if s.count(old) != 1:
    raise SystemExit(f"evaluate anchor count={s.count(old)}")
s = s.replace(old, new, 1)
anchor = '''    #[test]
    fn gate_is_exact_tenant_artifact_expiry_and_revocation() {
'''
test = '''    #[test]
    fn newest_exact_renewal_controls_instead_of_hash_order() {
        let mut registry = ApprovalRegistry::new();
        registry.record(request(100, Some(150))).unwrap();
        let renewal = registry.record(request(151, Some(300))).unwrap();
        let tenant = TenantId("acme".into());
        assert_eq!(
            registry.evaluate(&ApprovalQuery {
                tenant: &tenant,
                action: "tenant.delete",
                artifact_hash: &artifact(1),
                now: 200,
            }),
            GateOutcome::Approved,
            "an older expired record must not mask the newer live renewal"
        );
        registry
            .revoke(&renewal, "operator", 210, "renewal withdrawn")
            .unwrap();
        assert_eq!(
            registry.evaluate(&ApprovalQuery {
                tenant: &tenant,
                action: "tenant.delete",
                artifact_hash: &artifact(1),
                now: 220,
            }),
            GateOutcome::Revoked,
            "the newest exact decision controls after revocation"
        );
    }

'''
if s.count(anchor) != 1:
    raise SystemExit(f"test anchor count={s.count(anchor)}")
s = s.replace(anchor, test + anchor, 1)
p.write_text(s)
Path(".ci/prepatch.py").unlink()
