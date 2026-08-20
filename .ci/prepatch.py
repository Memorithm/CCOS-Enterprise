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
