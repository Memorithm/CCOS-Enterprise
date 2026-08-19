#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
from pathlib import Path
import re

# ---------- skills-audit domain contract ----------
p = Path('crates/ccos-enterprise-skills-audit/src/lib.rs')
s = p.read_text()

def one(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'{label}: expected one anchor, found {count}')
    return text.replace(old, new, 1)

s = one(s,
'''    /// The named tenant does not exist in this deployment.\n    UnknownTenant,\n''',
'''    /// The named tenant does not exist in this deployment.\n    UnknownTenant,\n    /// The validated source bundle belongs to a different tenant than the\n    /// requested scope. Source identity is checked before any ledger row is read.\n    SourceTenantMismatch { requested: String, source: String },\n''', 'audit error variant')
s = one(s,
'''            Self::UnknownTenant => write!(f, "unknown tenant"),\n            Self::InvalidLimits => write!(f, "audit limits must all be non-zero"),\n''',
'''            Self::UnknownTenant => write!(f, "unknown tenant"),\n            Self::SourceTenantMismatch { requested, source } => write!(\n                f,\n                "audit source tenant {source:?} does not match requested tenant {requested:?}"\n            ),\n            Self::InvalidLimits => write!(f, "audit limits must all be non-zero"),\n''', 'audit error display')
s = one(s,
'''pub struct ProvenanceReport {\n    pub schema: String,\n    pub tenant: String,\n    pub skills: Vec<SkillProvenanceReport>,\n    /// The tenant holds no skills at all.\n    pub empty: bool,\n}\n''',
'''pub struct ProvenanceReport {\n    pub schema: String,\n    pub tenant: String,\n    /// Total skills in the validated source before the report-level cap.\n    pub total_skills: usize,\n    pub skills: Vec<SkillProvenanceReport>,\n    /// Whether `max_skills` omitted one or more skill rows. Per-skill\n    /// `truncated` remains about trial/evidence row caps only.\n    pub truncated: bool,\n    /// The tenant holds no skills at all.\n    pub empty: bool,\n}\n''', 'report truncation fields')
s = one(s,
'''pub struct AuditSources<'a> {\n    pub skills: &'a SkillRegistry,\n    pub trials: &'a SkillTrialRegistry,\n}\n''',
'''pub struct AuditSources<'a> {\n    /// Tenant identity of the store from which both validated registries were\n    /// loaded. The audit query refuses a mismatch with its requested scope.\n    pub tenant: TenantId,\n    pub skills: &'a SkillRegistry,\n    pub trials: &'a SkillTrialRegistry,\n}\n''', 'source tenant identity')
s = one(s,
'''    if !known_tenants.contains_key(&query.scope.tenant) {\n        return Err(AuditError::UnknownTenant);\n    }\n\n    let provenance = index_skill_trial_provenance(query.sources.trials);\n''',
'''    if !known_tenants.contains_key(&query.scope.tenant) {\n        return Err(AuditError::UnknownTenant);\n    }\n    if query.sources.tenant != query.scope.tenant {\n        return Err(AuditError::SourceTenantMismatch {\n            requested: query.scope.tenant.0.clone(),\n            source: query.sources.tenant.0.clone(),\n        });\n    }\n\n    let provenance = index_skill_trial_provenance(query.sources.trials);\n''', 'source tenant gate')
s = one(s,
'''    let provenance = index_skill_trial_provenance(query.sources.trials);\n    let summaries = summarize_observational_trials(query.sources.trials);\n    let mut skills = Vec::new();\n\n    for record in query.sources.skills.snapshot().skills.values() {\n''',
'''    let provenance = index_skill_trial_provenance(query.sources.trials);\n    let summaries = summarize_observational_trials(query.sources.trials);\n    let total_skills = query.sources.skills.snapshot().skills.len();\n    let mut skills = Vec::new();\n\n    for record in query.sources.skills.snapshot().skills.values() {\n''', 'total skills')
s = one(s,
'''    Ok(ProvenanceReport {\n        schema: SKILL_AUDIT_SCHEMA.to_string(),\n        tenant: query.scope.tenant.0.clone(),\n        skills,\n        empty: query.sources.skills.snapshot().skills.is_empty(),\n    })\n''',
'''    Ok(ProvenanceReport {\n        schema: SKILL_AUDIT_SCHEMA.to_string(),\n        tenant: query.scope.tenant.0.clone(),\n        total_skills,\n        truncated: skills.len() < total_skills,\n        skills,\n        empty: total_skills == 0,\n    })\n''', 'report build')

# All crate-local fixtures use a `scope` variable whose tenant is the source.
s = re.sub(
    r'sources: AuditSources \{\n(?P<indent>\s*)skills:',
    r'sources: AuditSources {\n\g<indent>tenant: scope.tenant.clone(),\n\g<indent>skills:',
    s,
)
p.write_text(s)

# ---------- MCP audit projection ----------
p = Path('crates/ccos-enterprise-mcp/src/skill_audit.rs')
s = p.read_text()
s = one(s,
'''    let scope = TenantScope::new(TenantId(tenant.to_string()), ());\n''',
'''    let tenant_id = TenantId(tenant.to_string());\n    let scope = TenantScope::new(tenant_id.clone(), ());\n''', 'mcp tenant id')
s = one(s,
'''            sources: AuditSources { skills, trials },\n''',
'''            sources: AuditSources {\n                tenant: tenant_id,\n                skills,\n                trials,\n            },\n''', 'mcp source tenant')
p.write_text(s)

# ---------- conformance source binding + report-level truncation ----------
p = Path('tests/ccos-enterprise-conformance/tests/provenance_audit.rs')
s = p.read_text()
# Add tenant field to every source bundle based on the query scope variable.
# The common cases use `scope`; the cross-tenant test intentionally binds Acme
# sources to a Globex request and should now fail SourceTenantMismatch when
# Globex itself is known.
s = re.sub(
    r'sources: AuditSources \{\n(?P<indent>\s*)skills:',
    r'sources: AuditSources {\n\g<indent>tenant: TenantId("acme".into()),\n\g<indent>skills:',
    s,
)
# Make Globex authoritative in the mismatch test so the source mismatch, not
# the earlier unknown-tenant check, is the reason for refusal.
s = s.replace(
'''    let known: BTreeMap<TenantId, ()> = BTreeMap::from([(TenantId("acme".into()), ())]);\n    let foreign = TenantScope::new(TenantId("globex".into()), ());\n''',
'''    let known: BTreeMap<TenantId, ()> = BTreeMap::from([\n        (TenantId("acme".into()), ()),\n        (TenantId("globex".into()), ()),\n    ]);\n    let foreign = TenantScope::new(TenantId("globex".into()), ());\n''', 1)
s = s.replace(
'''        ccos_enterprise_skills_audit::AuditError::UnknownTenant\n''',
'''        ccos_enterprise_skills_audit::AuditError::SourceTenantMismatch { .. }\n''', 1)
# Pin report-level truncation independently from per-skill trial truncation.
insert = r'''

#[test]
fn report_level_skill_cap_is_explicit() {
    let (_d, skills, trials, roles, scope) = composed_fixture();
    // Clone the validated registry and add a second distinct active sequence.
    let mut skills = skills;
    for (turn, evidence) in [(20, 'd'), (21, 'e'), (22, 'f')] {
        let mut ep = episode("second-sequence", turn, evidence);
        ep.tools[0].name = "memory.timeline".into();
        skills.observe(&ep).unwrap();
    }
    let known = BTreeMap::from([(TenantId("acme".into()), ())]);
    let report = audit_provenance(
        AuditQuery {
            caller: "operator",
            scope: &scope,
            limits: AuditLimits {
                max_trials_per_skill: 8,
                max_evidence_per_skill: 8,
                max_skills: 1,
            },
            sources: AuditSources {
                tenant: TenantId("acme".into()),
                skills: &skills,
                trials: &trials,
            },
            roles: &roles,
        },
        &known,
    )
    .unwrap();
    assert!(report.total_skills >= 2);
    assert_eq!(report.skills.len(), 1);
    assert!(report.truncated);
}
'''
pos = s.rfind('\n}')
# this file is integration tests, no outer module; append at EOF instead.
s += insert
p.write_text(s)

# ---------- server: separate operator RPC from model-visible tools ----------
p = Path('crates/ccos-enterprise-mcp/src/bin/ccos-enterprise-mcp-server.rs')
s = p.read_text()
s = s.replace('    govern_skill_catalogue, permission_for, skill_audit_result, skill_audit_tool_spec,\n',
              '    govern_skill_catalogue, permission_for, skill_audit_result,\n')
s = one(s,
'''const HOST_KIND: &str = "deepseek-harness";\n''',
'''const HOST_KIND: &str = "deepseek-harness";\nconst OPERATOR_HOST_KIND: &str = "ccos-operator";\nconst OPERATOR_AUDIT_METHOD: &str = "ccos/operator/audit/provenance";\n''', 'operator constants')
s = one(s,
'''            "tools/call" => self.call_tool(message.get("params").unwrap_or(&Value::Null)),\n            "ccos/execution/event" => execution_backend::handle_lifecycle_event(\n''',
'''            "tools/call" => self.call_tool(message.get("params").unwrap_or(&Value::Null)),\n            OPERATOR_AUDIT_METHOD => {\n                self.call_operator_audit(message.get("params").unwrap_or(&Value::Null))\n            }\n            "ccos/execution/event" => execution_backend::handle_lifecycle_event(\n''', 'operator rpc dispatch')
# Remove model tools/call ability even if the actor also has auditor role.
s = one(s,
'''        if request.tool == SKILL_READ_TOOL {\n            return self.call_skill_tool(&identity, &request, &meta, &arguments);\n        }\n        if request.tool == SKILL_AUDIT_TOOL {\n            return self.call_skill_audit(&identity, &request, &meta, &arguments);\n        }\n''',
'''        if request.tool == SKILL_READ_TOOL {\n            return self.call_skill_tool(&identity, &request, &meta, &arguments);\n        }\n        if request.tool == SKILL_AUDIT_TOOL {\n            // Operator audit is intentionally absent from tools/list and from\n            // model-originated tools/call even when the same human identity\n            // also holds an auditor role. Context, not RBAC alone, separates it.\n            return Ok(tool_error("unknown CCOS Enterprise tool"));\n        }\n''', 'remove model audit call')
# Keep collision guard, remove published spec.
s = one(s,
'''    governed.push(skill_tool_spec());\n    governed.push(skill_audit_tool_spec());\n''',
'''    governed.push(skill_tool_spec());\n''', 'remove audit tool spec')

# Add separate operator RPC before call_tool. It uses the same identity/meta,
# host-correlation and call_skill_audit governance path, but requires a distinct
# host claim that DSH cannot legitimately send under its adapter contract.
anchor = '''    fn call_tool(&mut self, params: &Value) -> Result<Value, (i64, String)> {\n'''
operator_method = r'''    fn call_operator_audit(&mut self, params: &Value) -> Result<Value, (i64, String)> {
        if let Some(reason) = &self.poisoned {
            eprintln!("ccos-enterprise-mcp: refusing operator audit after durability failure: {reason}");
            return Err((-32000, "Enterprise durable state unavailable".to_string()));
        }
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let meta = parse_meta(params).map_err(|_| (-32602, "invalid params".to_string()))?;
        let identity = self
            .authenticator
            .authenticate(
                &self.config.identity_token,
                now().map_err(|_| (-32000, "server time unavailable".to_string()))?,
            )
            .map_err(|error| {
                eprintln!("ccos-enterprise-mcp: operator identity refused: {error}");
                (-32001, error.client_message().to_string())
            })?;
        if identity.org().0.as_str() != self.org.as_str()
            || identity.actor().0.as_str() != self.actor.as_str()
            || meta.tenant != self.config.tenant
            || meta.actor != self.actor
            || meta.host != OPERATOR_HOST_KIND
            || meta.model != self.config.model
        {
            eprintln!("ccos-enterprise-mcp: operator claims did not match configured identity/context");
            return Err((-32001, "not authenticated".to_string()));
        }
        self.append_host_correlation(SKILL_AUDIT_TOOL, &meta)
            .map_err(|error| {
                self.poisoned = Some(error.clone());
                (-32000, "Enterprise host correlation is not durable".to_string())
            })?;
        let request = GatewayRequest {
            tenant: meta.tenant.clone(),
            actor: meta.actor.clone(),
            tool: SKILL_AUDIT_TOOL.to_string(),
            request_id: meta.request_id.clone(),
        };
        self.call_skill_audit(&identity, &request, &meta, &arguments)
    }

'''
if anchor not in s:
    raise SystemExit('operator method insertion anchor missing')
s = s.replace(anchor, operator_method + anchor, 1)

# Catalogue test: audit must be absent.
s = one(s,
'''        assert!(tools.iter().any(|tool| tool["name"] == SKILL_READ_TOOL));\n        assert!(tools.iter().any(|tool| tool["name"] == SKILL_AUDIT_TOOL));\n''',
'''        assert!(tools.iter().any(|tool| tool["name"] == SKILL_READ_TOOL));\n        assert!(\n            !tools.iter().any(|tool| tool["name"] == SKILL_AUDIT_TOOL),\n            "operator audit must never be model-visible"\n        );\n''', 'catalogue audit absence')

# Add test helper for the separate operator RPC.
helper_anchor = '''    fn lifecycle(id: u64, actor: &str, event: Value) -> Value {\n'''
helper = r'''    fn operator_audit(id: u64, actor: &str, request_id: &str, arguments: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": OPERATOR_AUDIT_METHOD,
            "params": {
                "arguments": arguments,
                "_meta": { "ccos": {
                    "tenant_id": "acme",
                    "actor_id": actor,
                    "agent_id": "ccos-operator-agent",
                    "host": OPERATOR_HOST_KIND,
                    "dsh_profile": "operator",
                    "dsh_session_id": "operator-session",
                    "request_id": request_id,
                    "trace_id": "0123456789abcdef0123456789abcdef",
                    "model": "deepseek-harness",
                    "turn_id": format!("operator-turn-{id}"),
                    "step_id": "operator-step-1",
                    "execution_attempt_id": format!("operator-attempt-{id}")
                }}
            }
        })
    }

'''
if helper_anchor not in s:
    raise SystemExit('test helper anchor missing')
s = s.replace(helper_anchor, helper + helper_anchor, 1)

# Existing tests first attempt through model tools/call remains a refusal. Once
# role is granted, replace admitted operator calls with the operator RPC.
s = s.replace(
'''            .handle(&call(\n                2,\n                "alice",\n                "audit-request-2",\n                SKILL_AUDIT_TOOL,\n                json!({"limit": 4}),\n            ))\n''',
'''            .handle(&operator_audit(\n                2,\n                "alice",\n                "audit-request-2",\n                json!({"limit": 4}),\n            ))\n''', 1)
s = s.replace(
'''                .handle(&call(\n                    1,\n                    "alice",\n                    "audit-replay-request",\n                    SKILL_AUDIT_TOOL,\n                    json!({"limit": 4}),\n                ))\n''',
'''                .handle(&operator_audit(\n                    1,\n                    "alice",\n                    "audit-replay-request",\n                    json!({"limit": 4}),\n                ))\n''', 1)
s = s.replace(
'''                .handle(&call(\n                    2,\n                    "alice",\n                    "audit-replay-request",\n                    SKILL_AUDIT_TOOL,\n                    json!({"limit": 99}),\n                ))\n''',
'''                .handle(&operator_audit(\n                    2,\n                    "alice",\n                    "audit-replay-request",\n                    json!({"limit": 99}),\n                ))\n''', 1)

# Strengthen first audit test: even after granting auditor role, guessed model
# tools/call remains inaccessible before the operator RPC succeeds.
needle = '''        let admitted = server\n            .handle(&operator_audit(\n'''
if needle not in s:
    raise SystemExit('audit admitted call anchor missing')
probe = r'''        let guessed_from_model = server
            .handle(&call(
                20,
                "alice",
                "audit-model-guess",
                SKILL_AUDIT_TOOL,
                json!({"limit": 4}),
            ))
            .unwrap();
        assert_eq!(guessed_from_model["result"]["isError"], true);
        assert_eq!(server.front_door.deployment().spent("acme"), Some(0));

'''
s = s.replace(needle, probe + needle, 1)
p.write_text(s)
PY

cargo fmt --all
cargo check -p ccos-enterprise-skills-audit -p ccos-enterprise-mcp
cargo clippy -p ccos-enterprise-skills-audit -p ccos-enterprise-mcp --all-targets -- -D warnings
cargo test -p ccos-enterprise-skills-audit
cargo test -p ccos-enterprise-mcp
cargo test -p ccos-enterprise-conformance --test provenance_audit

rm -f .ci/autonomous-patch.sh
rmdir .ci 2>/dev/null || true

git config user.name 'MEMOPERF'
git config user.email 'contact@checkupauto.fr'
git add -A
git commit -m 'fix(audit): enforce operator-only tenant-bound provenance'
git push origin HEAD:fix/audit-postmerge-hardening
