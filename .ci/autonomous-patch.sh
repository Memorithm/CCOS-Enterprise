#!/usr/bin/env bash
set -euo pipefail

PRODUCT_BASE=805cee52d652c7ed479be3df95906f5a999a1f85
PRODUCT_BRANCH=fix/audit-postmerge-hardening-clean

python3 - <<'PY'
from pathlib import Path
import re

def one(s, old, new, label):
    n=s.count(old)
    if n != 1:
        raise SystemExit(f"{label}: expected 1 anchor, found {n}")
    return s.replace(old,new,1)

# ------------------------------------------------------------------
# 1. Stores expose their canonical root so audit can bind registries
#    to the store that actually validated them, not a caller label.
# ------------------------------------------------------------------
for filename, marker in [
    ('crates/ccos-enterprise-skills/src/store.rs', '    pub fn load(&self) -> Result<Option<SkillSnapshot>, SkillError> {\n'),
    ('crates/ccos-enterprise-skills/src/trial_store.rs', '    pub fn load(&self) -> Result<Option<SkillTrialSnapshot>, SkillError> {\n'),
]:
    p=Path(filename); s=p.read_text()
    method='''    /// Canonical root backing this validated store. Audit code uses this\n    /// identity to bind loaded registries to their actual tenant-scoped store.\n    pub fn canonical_root(&self) -> Result<PathBuf, SkillError> {\n        std::fs::canonicalize(&self.root).map_err(io(&self.root))\n    }\n\n'''
    s=one(s, marker, method+marker, f'canonical root {filename}')
    p.write_text(s)

# ------------------------------------------------------------------
# 2. AuditSources is no longer freely constructible. Construction
#    requires the two stores, proves they share one canonical root,
#    derives the source tenant from that root, and proves the supplied
#    validated registries exactly match what those stores load.
# ------------------------------------------------------------------
p=Path('crates/ccos-enterprise-skills-audit/src/lib.rs'); s=p.read_text()
s=one(s,
'''use ccos_enterprise_skills::{\n    index_skill_trial_provenance, summarize_observational_trials, SkillRegistry, SkillStatus,\n    SkillTrialRegistry, SkillTrialStatus,\n};\n''',
'''use ccos_enterprise_skills::{\n    index_skill_trial_provenance, summarize_observational_trials, SkillConfig, SkillRegistry,\n    SkillStatus, SkillStore, SkillTrialConfig, SkillTrialRegistry, SkillTrialStatus,\n    SkillTrialStore,\n};\n''','audit imports')
old='''pub struct AuditSources<'a> {\n    /// Tenant identity of the store from which both validated registries were\n    /// loaded. The audit query refuses a mismatch with its requested scope.\n    pub tenant: TenantId,\n    pub skills: &'a SkillRegistry,\n    pub trials: &'a SkillTrialRegistry,\n}\n'''
new='''pub struct AuditSources<'a> {\n    tenant: TenantId,\n    skills: &'a SkillRegistry,\n    trials: &'a SkillTrialRegistry,\n}\n\nimpl<'a> AuditSources<'a> {\n    /// Bind validated registries to the stores that actually loaded them.\n    /// The tenant is derived from the shared canonical store root; callers\n    /// cannot supply or relabel it independently. The snapshots are reloaded\n    /// under the stores' single-writer locks and must exactly match.\n    pub fn from_stores(\n        skill_store: &SkillStore,\n        trial_store: &SkillTrialStore,\n        skills: &'a SkillRegistry,\n        trials: &'a SkillTrialRegistry,\n    ) -> Result<Self, AuditError> {\n        let skill_root = skill_store.canonical_root().map_err(|error| AuditError::CorruptLedger {\n            detail: format!("cannot identify skill source store: {error}"),\n        })?;\n        let trial_root = trial_store.canonical_root().map_err(|error| AuditError::CorruptLedger {\n            detail: format!("cannot identify trial source store: {error}"),\n        })?;\n        if skill_root != trial_root {\n            return Err(AuditError::CorruptLedger {\n                detail: "skill and trial registries came from different stores".into(),\n            });\n        }\n        let source = skill_root\n            .file_name()\n            .and_then(|name| name.to_str())\n            .filter(|name| !name.is_empty())\n            .ok_or_else(|| AuditError::CorruptLedger {\n                detail: "audit source store has no canonical tenant component".into(),\n            })?\n            .to_string();\n\n        let loaded_skills = skill_store\n            .load_registry(SkillConfig::default())\n            .map_err(|error| AuditError::CorruptLedger {\n                detail: format!("cannot reload skill source store: {error}"),\n            })?;\n        let loaded_trials = trial_store\n            .load_registry(SkillTrialConfig::default())\n            .map_err(|error| AuditError::CorruptLedger {\n                detail: format!("cannot reload trial source store: {error}"),\n            })?;\n        let expected_skills = serde_json::to_vec(loaded_skills.snapshot()).map_err(|error| AuditError::CorruptLedger {\n            detail: format!("cannot canonicalize reloaded skill registry: {error}"),\n        })?;\n        let supplied_skills = serde_json::to_vec(skills.snapshot()).map_err(|error| AuditError::CorruptLedger {\n            detail: format!("cannot canonicalize supplied skill registry: {error}"),\n        })?;\n        let expected_trials = serde_json::to_vec(loaded_trials.snapshot()).map_err(|error| AuditError::CorruptLedger {\n            detail: format!("cannot canonicalize reloaded trial registry: {error}"),\n        })?;\n        let supplied_trials = serde_json::to_vec(trials.snapshot()).map_err(|error| AuditError::CorruptLedger {\n            detail: format!("cannot canonicalize supplied trial registry: {error}"),\n        })?;\n        if expected_skills != supplied_skills || expected_trials != supplied_trials {\n            return Err(AuditError::CorruptLedger {\n                detail: "audit registries do not match their validated source stores".into(),\n            });\n        }\n\n        Ok(Self {\n            tenant: TenantId(source),\n            skills,\n            trials,\n        })\n    }\n}\n'''
s=one(s,old,new,'audit sources constructor')
# Test helper inside crate: persist snapshots under canonical tenant root, then bind.
anchor='''    fn tenants(scope: &TenantScope<()>) -> BTreeMap<TenantId, ()> {\n        BTreeMap::from([(scope.tenant.clone(), ())])\n    }\n'''
helper='''    fn bound_sources<'a>(\n        tenant: &str,\n        skills: &'a SkillRegistry,\n        trials: &'a SkillTrialRegistry,\n    ) -> AuditSources<'a> {\n        let nonce = std::time::SystemTime::now()\n            .duration_since(std::time::UNIX_EPOCH)\n            .unwrap()\n            .as_nanos();\n        let root = std::env::temp_dir()\n            .join(format!("ccos-audit-source-{}-{nonce}", std::process::id()))\n            .join(tenant);\n        let skill_store = SkillStore::open(&root).unwrap();\n        skill_store.save(skills.snapshot()).unwrap();\n        let trial_store = SkillTrialStore::open(&root).unwrap();\n        trial_store.save(trials.snapshot()).unwrap();\n        let sources = AuditSources::from_stores(&skill_store, &trial_store, skills, trials).unwrap();\n        drop(trial_store);\n        drop(skill_store);\n        let _ = std::fs::remove_dir_all(root.parent().unwrap());\n        sources\n    }\n\n'''
s=one(s,anchor,anchor+'\n'+helper,'audit test helper')
# Replace every crate-local literal source bundle with bound helper.
s=re.sub(r'''sources: AuditSources \{\n\s*tenant: scope\.tenant\.clone\(\),\n\s*skills: &skills,\n\s*trials: &trials,\n\s*\},''', 'sources: bound_sources(&scope.tenant.0, &skills, &trials),', s)
s=re.sub(r'''sources: AuditSources \{\n\s*tenant: TenantId\("acme"\.into\(\)\),\n\s*skills: &skills,\n\s*trials: &trials,\n\s*\},''', 'sources: bound_sources("acme", &skills, &trials),', s)
p.write_text(s)

# ------------------------------------------------------------------
# 3. MCP projection loads from actual stores and never manufactures
#    a tenant field from the requested tenant string.
# ------------------------------------------------------------------
p=Path('crates/ccos-enterprise-mcp/src/skill_audit.rs'); s=p.read_text()
s=one(s,
'use ccos_enterprise_skills::{SkillRegistry, SkillTrialRegistry};\n',
'use ccos_enterprise_skills::{SkillConfig, SkillStore, SkillTrialConfig, SkillTrialStore};\n','mcp audit imports')
s=one(s,
'''    skills: &SkillRegistry,\n    trials: &SkillTrialRegistry,\n    arguments: &Value,\n''',
'''    skill_store: &SkillStore,\n    trial_store: &SkillTrialStore,\n    arguments: &Value,\n''','mcp audit signature')
s=one(s,
'''    let tenant_id = TenantId(tenant.to_string());\n    let scope = TenantScope::new(tenant_id.clone(), ());\n''',
'''    let tenant_id = TenantId(tenant.to_string());\n    let scope = TenantScope::new(tenant_id, ());\n    let skills = skill_store\n        .load_registry(SkillConfig::default())\n        .map_err(|error| format!("cannot load Enterprise skill registry: {error}"))?;\n    let trials = trial_store\n        .load_registry(SkillTrialConfig::default())\n        .map_err(|error| format!("cannot load Enterprise skill trial registry: {error}"))?;\n    let sources = AuditSources::from_stores(skill_store, trial_store, &skills, &trials)\n        .map_err(|error| format!("skill provenance source binding refused: {error}"))?;\n''','mcp audit store load')
s=one(s,
'''            sources: AuditSources {\n                tenant: tenant_id,\n                skills,\n                trials,\n            },\n''',
'''            sources,\n''','mcp bound sources')
# Rewrite unit test setup to use tenant-rooted stores.
s=one(s,
'''        let skills = SkillRegistry::new(ccos_enterprise_skills::SkillConfig::default()).unwrap();\n        let trials =\n            SkillTrialRegistry::new(ccos_enterprise_skills::SkillTrialConfig::default()).unwrap();\n''',
'''        let root = std::env::temp_dir()\n            .join(format!("ccos-skill-audit-unit-{}", std::process::id()))\n            .join("acme");\n        let _ = std::fs::remove_dir_all(root.parent().unwrap());\n        let skill_store = SkillStore::open(&root).unwrap();\n        let trial_store = SkillTrialStore::open(&root).unwrap();\n''','mcp unit stores')
s=s.replace('skill_audit_result(&d, "operator", "acme", &skills, &trials, &json!({}))', 'skill_audit_result(&d, "operator", "acme", &skill_store, &trial_store, &json!({}))')
p.write_text(s)

# ------------------------------------------------------------------
# 4. Server operator RPC requires a request-supplied independently
#    signed principal. The DSH principal is explicitly forbidden even
#    if it also holds audit.provenance. Audit uses request.actor.
# ------------------------------------------------------------------
p=Path('crates/ccos-enterprise-mcp/src/bin/ccos-enterprise-mcp-server.rs'); s=p.read_text()
old='''        let arguments = params\n            .get("arguments")\n            .cloned()\n            .unwrap_or_else(|| json!({}));\n        let meta = parse_meta(params).map_err(|_| (-32602, "invalid params".to_string()))?;\n        let identity = self\n            .authenticator\n            .authenticate(\n                &self.config.identity_token,\n                now().map_err(|_| (-32000, "server time unavailable".to_string()))?,\n            )\n'''
new='''        let arguments = params\n            .get("arguments")\n            .cloned()\n            .unwrap_or_else(|| json!({}));\n        let operator_token = params\n            .get("operator_identity_token")\n            .and_then(Value::as_str)\n            .map(str::trim)\n            .filter(|token| !token.is_empty() && token.len() <= 8192)\n            .ok_or_else(|| (-32001, "operator credential required".to_string()))?;\n        let meta = parse_meta(params).map_err(|_| (-32602, "invalid params".to_string()))?;\n        let identity = self\n            .authenticator\n            .authenticate(\n                operator_token,\n                now().map_err(|_| (-32000, "server time unavailable".to_string()))?,\n            )\n'''
# Only replace the operator method occurrence by locating after fn.
pos=s.index('    fn call_operator_audit')
pre=s[:pos]; tail=s[pos:]
tail=one(tail,old,new,'operator token authentication')
s=pre+tail
s=one(s,
'''        if identity.org().0.as_str() != self.org.as_str()\n            || identity.actor().0.as_str() != self.actor.as_str()\n            || meta.tenant != self.config.tenant\n            || meta.actor != self.actor\n            || meta.host != OPERATOR_HOST_KIND\n            || meta.model != self.config.model\n''',
'''        if identity.org().0.as_str() != self.org.as_str()\n            || identity.actor().0.as_str() == self.actor.as_str()\n            || meta.tenant != self.config.tenant\n            || meta.actor != identity.actor().0.as_str()\n            || meta.host != OPERATOR_HOST_KIND\n            || meta.model != self.config.model\n''','operator principal separation')
# Audit projection must authorize/project the independently authenticated request actor.
s=one(s,
'''                            self.front_door.deployment(),\n                            &self.actor,\n                            &self.config.tenant,\n                            &registry,\n                            &trial_registry,\n                            arguments,\n''',
'''                            self.front_door.deployment(),\n                            &request.actor,\n                            &self.config.tenant,\n                            &self.skill_store,\n                            &trials,\n                            arguments,\n''','server audit source call')
# Remove now-unused registry loads in server audit closure.
oldblock='''                let result = self\n                    .skill_store\n                    .load_registry(SkillConfig::default())\n                    .map_err(|error| format!("cannot load Enterprise skill registry: {error}"))\n                    .and_then(|registry| {\n                        let trials = SkillTrialStore::open(&skills_root).map_err(|error| {\n                            format!("cannot open Enterprise skill trial store: {error}")\n                        })?;\n                        let trial_registry = trials\n                            .load_registry(SkillTrialConfig::default())\n                            .map_err(|error| {\n                                format!("cannot load Enterprise skill trial registry: {error}")\n                            })?;\n                        skill_audit_result(\n                            self.front_door.deployment(),\n                            &request.actor,\n                            &self.config.tenant,\n                            &self.skill_store,\n                            &trials,\n                            arguments,\n                        )\n                    });\n'''
newblock='''                let result = SkillTrialStore::open(&skills_root)\n                    .map_err(|error| format!("cannot open Enterprise skill trial store: {error}"))\n                    .and_then(|trials| {\n                        skill_audit_result(\n                            self.front_door.deployment(),\n                            &request.actor,\n                            &self.config.tenant,\n                            &self.skill_store,\n                            &trials,\n                            arguments,\n                        )\n                    });\n'''
s=one(s,oldblock,newblock,'server audit store closure')
# Test operator RPC carries an independently signed operator credential.
s=one(s,
'''    fn operator_audit(id: u64, actor: &str, request_id: &str, arguments: Value) -> Value {\n        json!({\n''',
'''    fn operator_token(actor: &str) -> String {\n        let seed = [7u8; 32];\n        let now = now().unwrap();\n        let claims = IdentityClaims {\n            version: IDENTITY_TOKEN_VERSION,\n            jti: format!("operator-{actor}"),\n            org: "memorithm".into(),\n            actor: actor.into(),\n            audience: "ccos-test".into(),\n            issued_at: now,\n            expires_at: now + 600,\n            not_before: None,\n        };\n        issue_identity_token(&seed, "test-key", &claims).unwrap()\n    }\n\n    fn operator_audit(id: u64, actor: &str, request_id: &str, arguments: Value) -> Value {\n        json!({\n''','operator token test helper')
s=one(s,
'''            "params": {\n                "arguments": arguments,\n                "_meta": { "ccos": {\n''',
'''            "params": {\n                "operator_identity_token": operator_token(actor),\n                "arguments": arguments,\n                "_meta": { "ccos": {\n''','operator request credential')
# In first audit test, keep alice auditor to prove that DSH principal is still rejected, and add distinct operator.
s=one(s,
'''            admin.add_role("auditor", &["audit.provenance"]);\n            admin.assign("alice", "auditor");\n        }\n''',
'''            admin.add_role("auditor", &["audit.provenance"]);\n            admin.assign("alice", "auditor");\n            admin.assign("operator", "auditor");\n        }\n''','first audit role assignment')
needle='''        assert_eq!(guessed_from_model["result"]["isError"], true);\n        assert_eq!(server.front_door.deployment().spent("acme"), Some(0));\n\n        let admitted = server\n'''
probe='''        assert_eq!(guessed_from_model["result"]["isError"], true);\n        assert_eq!(server.front_door.deployment().spent("acme"), Some(0));\n        let dsh_credential_on_operator_rpc = server\n            .handle(&operator_audit(21, "alice", "audit-dsh-credential", json!({"limit": 4})))\n            .unwrap();\n        assert_eq!(dsh_credential_on_operator_rpc["error"]["code"], -32001);\n        assert_eq!(server.front_door.deployment().spent("acme"), Some(0));\n\n        let admitted = server\n'''
s=one(s,needle,probe,'dsh operator credential refusal test')
# Change admitted and replay operator actor to distinct operator principal.
s=s.replace('''                "alice",\n                "audit-request-2",''','''                "operator",\n                "audit-request-2",''',1)
# Replay test: grant operator, not DSH actor, and use it for both calls.
idx=s.index('fn provenance_audit_is_replay_idempotent_across_restart')
pre=s[:idx]; tail=s[idx:]
tail=tail.replace('admin.assign("alice", "auditor");','admin.assign("operator", "auditor");',1)
tail=tail.replace('''                    "alice",\n                    "audit-replay-request",''','''                    "operator",\n                    "audit-replay-request",''',2)
s=pre+tail
p.write_text(s)

# ------------------------------------------------------------------
# 5. Conformance tests construct sources through real tenant-rooted stores.
# ------------------------------------------------------------------
p=Path('tests/ccos-enterprise-conformance/tests/provenance_audit.rs'); s=p.read_text()
s=one(s,
'''    EpisodeObservation, SkillConfig, SkillRegistry, SkillTrialConfig, SkillTrialRegistry,\n    ToolObservation, ToolOutcome,\n''',
'''    EpisodeObservation, SkillConfig, SkillRegistry, SkillStore, SkillTrialConfig,\n    SkillTrialRegistry, SkillTrialStore, ToolObservation, ToolOutcome,\n''','conformance imports')
helper='''\nfn bound_sources<'a>(tenant: &str, skills: &'a SkillRegistry, trials: &'a SkillTrialRegistry) -> AuditSources<'a> {\n    let nonce = std::time::SystemTime::now()\n        .duration_since(std::time::UNIX_EPOCH)\n        .unwrap()\n        .as_nanos();\n    let root = std::env::temp_dir()\n        .join(format!("ccos-conformance-audit-source-{}-{nonce}", std::process::id()))\n        .join(tenant);\n    let skill_store = SkillStore::open(&root).unwrap();\n    skill_store.save(skills.snapshot()).unwrap();\n    let trial_store = SkillTrialStore::open(&root).unwrap();\n    trial_store.save(trials.snapshot()).unwrap();\n    let sources = AuditSources::from_stores(&skill_store, &trial_store, skills, trials).unwrap();\n    drop(trial_store);\n    drop(skill_store);\n    let _ = std::fs::remove_dir_all(root.parent().unwrap());\n    sources\n}\n'''
s=one(s,'fn episode(session: &str, turn: u64, evidence: char) -> EpisodeObservation {\n', helper+'\nfn episode(session: &str, turn: u64, evidence: char) -> EpisodeObservation {\n','conformance source helper')
# All acme source literals become bound sources.
s=re.sub(r'''sources: AuditSources \{\n\s*tenant: TenantId\("acme"\.into\(\)\),\n\s*skills: &skills,\n\s*trials: &trials,\n\s*\},''','sources: bound_sources("acme", &skills, &trials),',s)
p.write_text(s)
PY

cargo fmt --all
cargo check -p ccos-enterprise-skills -p ccos-enterprise-skills-audit -p ccos-enterprise-mcp
cargo clippy -p ccos-enterprise-skills -p ccos-enterprise-skills-audit -p ccos-enterprise-mcp --all-targets -- -D warnings
cargo test -p ccos-enterprise-skills-audit
cargo test -p ccos-enterprise-mcp
cargo test -p ccos-enterprise-conformance --test provenance_audit

# Produce one clean product commit directly on top of the exact tested #83 head.
rm -f .ci/autonomous-patch.sh
rmdir .ci 2>/dev/null || true

git config user.name 'MEMOPERF'
git config user.email 'contact@checkupauto.fr'
git reset --soft "$PRODUCT_BASE"
git add -A
git commit -m 'fix(audit): bind operator identity and source stores'
git push --force-with-lease origin HEAD:"$PRODUCT_BRANCH"
