from pathlib import Path

p = Path("tests/ccos-enterprise-conformance/tests/isolation.rs")
s = p.read_text()
old = '''fn exhausting_one_tenants_budget_leaves_the_other_untouched() {\n    let mut d = two_tenant_deployment();\n    d.tenant_mut("globex").unwrap().allow_model("claude-opus");\n    let alice = actor("memorithm", "alice", AuthStrength::Token);\n'''
new = '''fn exhausting_one_tenants_budget_leaves_the_other_untouched() {\n    let mut d = two_tenant_deployment();\n    let alice = actor("memorithm", "alice", AuthStrength::Token);\n'''
if s.count(old) != 1:
    raise SystemExit(f"isolation setup anchor count: {s.count(old)}")
s = s.replace(old, new, 1)
old = '''    // globex is unaffected.\n    let req = request("globex", "alice", "memory.recall", "r-other");\n    assert_eq!(\n        d.admit(Call {\n            actor: &alice,\n            request: &req,\n            model: "claude-opus",\n'''
new = '''    // globex is unaffected. Use its explicitly selected model so this test\n    // isolates budget state rather than relying on allowlist insertion to\n    // change model selection.\n    let req = request("globex", "alice", "memory.recall", "r-other");\n    assert_eq!(\n        d.admit(Call {\n            actor: &alice,\n            request: &req,\n            model: "gpt-5",\n'''
if s.count(old) != 1:
    raise SystemExit(f"isolation model anchor count: {s.count(old)}")
p.write_text(s.replace(old, new, 1))
