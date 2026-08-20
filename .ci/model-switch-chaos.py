from pathlib import Path

p = Path("tests/ccos-enterprise-conformance/tests/stress_concurrency_chaos.rs")
s = p.read_text()


def replace_once(old: str, new: str) -> None:
    global s
    count = s.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one occurrence, found {count}: {old[:120]!r}")
    s = s.replace(old, new, 1)


# The staged governance race is about direct tenant-rule mutation. Adding a
# model to the allowlist must remain visible in the governance journal, but it
# must no longer silently select that model for execution.
replace_once(
    "/// **REPAIRED (audit completeness).** A governance change races with the\n"
    "/// admissions it governs, and the journal now records it, in order, between\n"
    "/// the two outcomes it flipped.\n",
    "/// **REPAIRED (audit completeness + explicit selection).** A direct\n"
    "/// allowlist change races with admissions and is journaled in order, while\n"
    "/// remaining deliberately insufficient to select the newly allowed model.\n",
)
replace_once(
    "/// The two admissions below are identical apart from their request id; the\n"
    "/// first is refused, the second forwarded. The merged journal holds three\n"
    "/// rows, and the middle one says the allowlist widened. `tenant_mut` hands out\n"
    "/// a guard that compares the tenant's rules before and after the borrow and\n"
    "/// journals the difference on drop — the most a `&mut` borrow can honestly\n"
    "/// report, and enough to answer the question.\n",
    "/// The two admissions below are identical apart from their request id and\n"
    "/// both are refused: widening the allowlist is not an activation primitive.\n"
    "/// The merged journal still holds three rows, and the middle one says the\n"
    "/// allowlist widened. `tenant_mut` compares the tenant's rules before and\n"
    "/// after the borrow and journals the difference on drop, so the mutation is\n"
    "/// visible without becoming an implicit model switch.\n",
)
replace_once(
    "fn a_concurrent_governance_change_is_journaled_between_the_outcomes_it_flips() {",
    "fn a_concurrent_allowlist_change_is_journaled_without_selecting_the_model() {",
)
replace_once(
    "        assert_eq!(before.refusal(), Some(&Refusal::ModelNotAllowed));\n"
    "        assert_eq!(after, Outcome::Forwarded);",
    "        assert_eq!(before.refusal(), Some(&Refusal::ModelNotAllowed));\n"
    "        assert_eq!(after.refusal(), Some(&Refusal::ModelNotAllowed));",
)
replace_once(
    "    // The two decisions are ordered and priced, so the *flip* is legible — the\n"
    "    // refusal cost 0 and the forward cost 10.\n",
    "    // The two decisions are ordered and priced. Both remain refusals at zero\n"
    "    // cost: direct allowlist widening cannot bypass explicit active selection.\n",
)
replace_once(
    "    assert_eq!((rows[0].forwarded, rows[0].cost), (false, 0));\n"
    "    assert_eq!((rows[1].forwarded, rows[1].cost), (true, 10));",
    "    assert_eq!((rows[0].forwarded, rows[0].cost), (false, 0));\n"
    "    assert_eq!((rows[1].forwarded, rows[1].cost), (false, 0));",
)
replace_once(
    "    // …and the merged journal now says WHY, in the one position that answers\n"
    "    // it: after the refusal, before the forward.\n",
    "    // The merged journal still places the allowlist mutation exactly between\n"
    "    // the two decisions, without pretending that mutation selected a model.\n",
)
replace_once(
    "    assert!(matches!(merged[0], JournalEntry::Decision(r) if !r.outcome.is_forwarded()));\n"
    "    assert!(matches!(merged[2], JournalEntry::Decision(r) if r.outcome.is_forwarded()));",
    "    assert!(matches!(merged[0], JournalEntry::Decision(r) if !r.outcome.is_forwarded()));\n"
    "    assert!(matches!(merged[2], JournalEntry::Decision(r) if !r.outcome.is_forwarded()));",
)

# Random chaos admissions used to rely on concurrent allow_model operations to
# make chaos-model-* executable. That encoded the old security bug. Preserve
# the original 5/6 potentially-valid versus 1/6 never-allowed mix, but drive
# the potentially-valid path through the tenant's explicit active model. The
# concurrent AllowModel operations remain in the storm and widen raw policy;
# they simply cannot silently change active selection anymore.
replace_once(
    "            model: match rng.below(6) {\n"
    "                0 => NEVER_ALLOWED_MODEL.to_string(),\n"
    "                n => format!(\"chaos-model-{}\", n - 1),\n"
    "            },",
    "            model: match rng.below(6) {\n"
    "                0 => NEVER_ALLOWED_MODEL.to_string(),\n"
    "                _ => BASE_MODEL.to_string(),\n"
    "            },",
)

p.write_text(s)

# The RBAC scope test is specifically about a deployment-global role grant.
# Globex's fixture already has gpt-5 as its explicit active model. The old test
# widened Globex's allowlist with claude-opus and then used claude-opus as if
# allowlisting selected it, masking the RBAC invariant behind ModelNotAllowed.
rbac_path = Path("tests/ccos-enterprise-conformance/tests/stress_rbac_scale.rs")
rbac = rbac_path.read_text()
old = '''    let mut d = two_tenant_deployment();
    d.tenant_mut("globex")
        .expect("globex exists")
        .allow_model("claude-opus");

    // alice was assigned `writer` with no tenant in sight; the grant applies
'''
new = '''    let mut d = two_tenant_deployment();

    // alice was assigned `writer` with no tenant in sight; the grant applies
'''
if rbac.count(old) != 1:
    raise SystemExit("expected one stale globex allowlist setup in RBAC scope test")
rbac = rbac.replace(old, new, 1)
old = '''            model: "claude-opus",
            cost_tokens: 10,
            variant: None,
            justification: None,
        }),
        Outcome::Forwarded,
        "an acme grant is honoured inside globex: RBAC is not tenant-scoped"
'''
new = '''            model: "gpt-5",
            cost_tokens: 10,
            variant: None,
            justification: None,
        }),
        Outcome::Forwarded,
        "an acme grant is honoured inside globex: RBAC is not tenant-scoped"
'''
if rbac.count(old) != 1:
    raise SystemExit("expected one stale globex model call in RBAC scope test")
rbac = rbac.replace(old, new, 1)
rbac_path.write_text(rbac)
