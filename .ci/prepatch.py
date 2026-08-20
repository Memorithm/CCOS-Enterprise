from pathlib import Path

p = Path('.ci/autonomous-patch.sh')
s = p.read_text()
old = "tail=one(tail,old,new,'operator token authentication')"
new = "\nif old not in tail:\n    raise SystemExit('operator token authentication anchor missing')\ntail=tail.replace(old,new,1)"
if s.count(old) != 1:
    raise SystemExit(f'expected one patch-script anchor, found {s.count(old)}')
p.write_text(s.replace(old, new, 1))

# The P1 patch promotes serde_json from test-only use to production code in
# ccos-enterprise-skills-audit when it canonicalizes loaded/supplied snapshots.
# Promote the dependency as part of the product patch so cargo check can resolve it.
cargo = Path('crates/ccos-enterprise-skills-audit/Cargo.toml')
c = cargo.read_text()
old_dep = '''serde.workspace = true

[dev-dependencies]
ccos-enterprise-runtime = { path = "../ccos-enterprise-runtime", features = ["test-fixtures"] }
serde_json = "1"
'''
new_dep = '''serde.workspace = true
serde_json = "1"

[dev-dependencies]
ccos-enterprise-runtime = { path = "../ccos-enterprise-runtime", features = ["test-fixtures"] }
'''
if c.count(old_dep) != 1:
    raise SystemExit(f'expected one skills-audit dependency anchor, found {c.count(old_dep)}')
cargo.write_text(c.replace(old_dep, new_dep, 1))

# The validator runs clippy over all targets with warnings denied. Keep the
# existing tamper test semantically identical while initializing the lone
# non-default field in the struct initializer instead of reassigning it.
trials = Path('crates/ccos-enterprise-skills/src/trials.rs')
t = trials.read_text()
old_trial = '''        let mut snapshot = SkillTrialSnapshot::default();
        snapshot.next_ordinal = 1;
        snapshot.trials.insert(
'''
new_trial = '''        let mut snapshot = SkillTrialSnapshot {
            next_ordinal: 1,
            ..Default::default()
        };
        snapshot.trials.insert(
'''
if t.count(old_trial) != 1:
    raise SystemExit(f'expected one trial snapshot initializer anchor, found {t.count(old_trial)}')
trials.write_text(t.replace(old_trial, new_trial, 1))

# Operator audit effects are written under the independently authenticated
# operator actor after the P1 patch. A terminal Settled marker needs no startup
# recovery authority, so it may safely survive restart with that actor. Any
# non-terminal marker must still match the configured DSH principal because
# startup has no operator credential with which to recover/settle it.
server = Path('crates/ccos-enterprise-mcp/src/bin/ccos-enterprise-mcp-server.rs')
r = server.read_text()
old_marker = '''            if effect.tenant != config.tenant
                || effect.actor != actor
                || effect.model != config.model
                || effect.cost_tokens != config.call_cost_tokens
            {
'''
new_marker = '''            let settled_operator_audit = effect.tool == SKILL_AUDIT_TOOL
                && effect.state == EffectState::Settled;
            if effect.tenant != config.tenant
                || (effect.actor != actor && !settled_operator_audit)
                || effect.model != config.model
                || effect.cost_tokens != config.call_cost_tokens
            {
'''
if r.count(old_marker) != 1:
    raise SystemExit(f'expected one durable marker principal anchor, found {r.count(old_marker)}')
server.write_text(r.replace(old_marker, new_marker, 1))
