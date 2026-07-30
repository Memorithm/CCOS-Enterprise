//! The tool-catalogue contract.
//!
//! `docs/HERMES_INTEGRATION.md` promises: "Contract tests (CI) pin the tool
//! catalogue so a Core upgrade cannot widen the surface silently." This file
//! is that pin. It reads the forbidden list straight out of the document:
//!
//! > Core tools exposed: `memory.*`, `context.*`, `policy.*`, `audit.*`,
//! > `system.health` class. Forbidden: `rsi.*`, `forge.*`, `patch.*`,
//! > `shell.*`, `code.execute`, `repository.modify`, `self.*`.
//!
//! Before this suite existed, five of those seven forbidden entries were
//! forwarded by the gateway — including `shell.exec` and `code.execute`,
//! which charter §4.2 forbids the Enterprise profile from carrying at all.

use ccos_enterprise_auth::AuthStrength;
use ccos_enterprise_conformance::{actor, request, two_tenant_deployment, Call, Refusal};
use ccos_enterprise_gateway::{classify, Disposition, GatewayRequest};

fn req(tool: &str) -> GatewayRequest {
    request("acme", "hermes", tool, "r-contract")
}

/// Every namespace and tool the Hermes profile declares forbidden, refused
/// at the gateway. One entry per documented item — a regression names itself.
#[test]
fn the_forbidden_catalogue_never_traverses() {
    let forbidden = [
        // Research Lab namespaces (README "Product boundary").
        ("rsi.status", "forbidden: recursive self-improvement"),
        ("rsi.propose", "forbidden: recursive self-improvement"),
        ("forge.run", "Forge"),
        ("forge.generate", "Forge"),
        ("slha.explain", "Research Lab"),
        ("octa.recall", "Research Lab"),
        // Capabilities charter §4.2 forbids the Enterprise profile.
        ("patch.apply", "forbidden: autonomous patch promotion"),
        ("patch.promote", "forbidden: autonomous patch promotion"),
        ("shell.exec", "process execution"),
        ("shell.spawn", "process execution"),
        ("code.execute", "forbidden: generated-code execution"),
        (
            "repository.modify",
            "forbidden: repository self-modification",
        ),
        ("self.rewrite", "forbidden: self-modification"),
        ("self.improve", "forbidden: self-modification"),
    ];

    for (tool, why) in forbidden {
        assert!(
            matches!(classify(&req(tool)), Disposition::Reject(_)),
            "'{tool}' must be refused at the boundary ({why})"
        );
    }
}

/// Case is not a loophole: a router that normalises case downstream must not
/// be able to smuggle a forbidden tool past a case-sensitive check.
#[test]
fn the_catalogue_holds_under_case_folding() {
    for tool in [
        "SHELL.exec",
        "Shell.Exec",
        "CODE.EXECUTE",
        "Repository.Modify",
        "SELF.rewrite",
        "PATCH.apply",
        "RSI.status",
    ] {
        assert!(
            matches!(classify(&req(tool)), Disposition::Reject(_)),
            "'{tool}' must be refused whatever its case"
        );
    }
}

/// The documented exposed classes stay available — a boundary that refuses
/// everything is not a boundary, it is an outage.
#[test]
fn the_exposed_catalogue_still_traverses() {
    for tool in [
        "memory.recall",
        "memory.ingest",
        "context.window",
        "policy.get",
        "audit.query",
        "system.health",
        // The `ccos.` alias this crate shipped with stays accepted.
        "ccos.recall",
    ] {
        assert_eq!(
            classify(&req(tool)),
            Disposition::Forward,
            "'{tool}' is in the exposed catalogue"
        );
    }
}

/// The exposed catalogue is a published constant too, so widening the
/// surface is a visible edit rather than a side effect.
#[test]
fn the_published_catalogue_matches_the_documented_classes() {
    use ccos_enterprise_gateway::{ALLOWED_PREFIXES, ALLOWED_TOOLS};

    for class in ["memory.", "context.", "policy.", "audit."] {
        assert!(
            ALLOWED_PREFIXES.contains(&class),
            "'{class}' is documented as exposed but is not in ALLOWED_PREFIXES"
        );
    }
    assert!(ALLOWED_TOOLS.contains(&"system.health"));
    // `system.` is one exposed tool, not an open namespace.
    assert!(!ALLOWED_PREFIXES.contains(&"system."));
    // No entry may appear on both sides of the boundary.
    use ccos_enterprise_gateway::{FORBIDDEN_PREFIXES, FORBIDDEN_TOOLS};
    for allowed in ALLOWED_PREFIXES {
        assert!(
            !FORBIDDEN_PREFIXES.contains(allowed),
            "{allowed} is on both lists"
        );
    }
    for allowed in ALLOWED_TOOLS {
        assert!(
            !FORBIDDEN_TOOLS.contains(allowed),
            "{allowed} is on both lists"
        );
    }
}

/// Deny by default: an unlisted tool does not traverse. But an omission is
/// not a violation, and the audit trail must let an operator tell them
/// apart — "nobody exposed this yet" is a catalogue question, "this is
/// `shell.exec`" is a boundary question.
#[test]
fn unlisted_tools_are_refused_as_omissions_not_violations() {
    // Neighbours of an exactly-named forbidden entry: the docs name
    // `code.execute` and `repository.modify` precisely, not whole namespaces,
    // so these are not boundary violations — they are simply unlisted.
    for tool in [
        "code.read",
        "code.lint",
        "repository.read",
        "repository.list",
        // Words that merely start like a forbidden namespace, likewise.
        "selfcare.report",
        "shellfish.count",
        "patchwork.list",
        "forget.nothing",
    ] {
        let Disposition::Reject(why) = classify(&req(tool)) else {
            panic!("'{tool}' is not in the catalogue and must not traverse");
        };
        assert!(
            why.contains("not in the Enterprise catalogue"),
            "'{tool}' is an omission, not a boundary violation: {why}"
        );
    }
}

/// The boundary is not a permission. No role, no strength, no allowlist and
/// no budget lets a caller through it — this is the property that makes it a
/// *product* boundary rather than an access-control default.
#[test]
fn no_privilege_reaches_past_the_boundary() {
    let mut d = two_tenant_deployment();
    // A maximally-privileged caller: strong identity, every permission, the
    // forbidden tools explicitly governed and the model allowlisted.
    d.add_role(
        "superuser",
        &["memory.read", "memory.write", "policy.admin", "root"],
    );
    d.assign("root", "superuser");
    for tool in [
        "rsi.status",
        "forge.run",
        "shell.exec",
        "code.execute",
        "self.rewrite",
    ] {
        d.govern_tool(tool, "root");
    }
    let root = actor("memorithm", "root", AuthStrength::Strong);

    for tool in [
        "rsi.status",
        "forge.run",
        "shell.exec",
        "code.execute",
        "self.rewrite",
    ] {
        let request = request("acme", "root", tool, "r-root");
        let outcome = d.admit(Call {
            actor: &root,
            request: &request,
            model: "claude-opus",
            cost_tokens: 1,
            variant: None,
        });
        assert!(
            matches!(outcome.refusal(), Some(Refusal::OutsideBoundary(_))),
            "'{tool}' must stay outside the boundary for a superuser too, got {outcome:?}"
        );
    }
    assert_eq!(d.spent("acme"), 0, "and none of it was billed");
}

/// The forbidden list is a published constant, so a future edit to the
/// gateway shows up here rather than silently widening the surface.
#[test]
fn the_published_constants_cover_the_documented_list() {
    use ccos_enterprise_gateway::{FORBIDDEN_PREFIXES, FORBIDDEN_TOOLS};

    for prefix in [
        "rsi.", "forge.", "slha.", "octa.", "patch.", "shell.", "self.",
    ] {
        assert!(
            FORBIDDEN_PREFIXES.contains(&prefix),
            "'{prefix}' is documented as forbidden but is not in FORBIDDEN_PREFIXES"
        );
    }
    for tool in ["code.execute", "repository.modify"] {
        assert!(
            FORBIDDEN_TOOLS.contains(&tool),
            "'{tool}' is documented as forbidden but is not in FORBIDDEN_TOOLS"
        );
    }
}
