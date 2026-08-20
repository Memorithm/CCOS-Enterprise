from pathlib import Path

p = Path("tests/ccos-enterprise-conformance/tests/governed_path.rs")
s = p.read_text()
old = '''    // globex did not — the same call, same actor, same variant, refused.\n    // Both tenants belong to alice's organization, so nothing but the\n    // activation differs between the two calls.\n    d.assign("alice", "writer");\n    d.tenant_mut("globex").unwrap().allow_model("claude-opus");\n    let req = request("globex", "alice", "memory.recall", "r-2");\n    let outcome = d.admit(Call {\n        actor: &alice,\n        request: &req,\n        model: "claude-opus",\n'''
new = '''    // globex did not. Use globex's explicitly selected model so the model\n    // gate passes and this assertion continues to isolate Q-Page activation.\n    // Both tenants belong to alice's organization and each call uses that\n    // tenant's active model; the refusal below must therefore be the variant.\n    d.assign("alice", "writer");\n    let req = request("globex", "alice", "memory.recall", "r-2");\n    let outcome = d.admit(Call {\n        actor: &alice,\n        request: &req,\n        model: "gpt-5",\n'''
if s.count(old) != 1:
    raise SystemExit(f"governed_path anchor count: {s.count(old)}")
p.write_text(s.replace(old, new, 1))
