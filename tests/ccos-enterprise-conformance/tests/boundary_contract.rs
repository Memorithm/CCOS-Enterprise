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
//! ## What was repaired
//!
//! - **The catalogue leaked.** Before this suite existed, five of those seven
//!   forbidden entries were forwarded by the gateway — including `shell.exec`
//!   and `code.execute`, which charter §4.2 forbids the Enterprise profile
//!   from carrying at all. Each documented entry is pinned below, one
//!   assertion apiece, so a regression names itself.
//! - **The composed path was not shipped.** "No privilege reaches past the
//!   boundary" is a property of the *composition*, and the composition lived
//!   in this `publish = false` harness, so the property held for the harness
//!   and for nothing a customer runs. It now lives in
//!   `ccos-enterprise-runtime` and the harness only re-exports it: the last
//!   two tests here compile against shipped code.
//! - **The composed path authorized a caller-supplied identity.** It proved
//!   one actor and authorized whichever actor the *request* named. A request
//!   must now name the actor its credential proves, and a tenant that actor's
//!   organization owns — and that gate runs *before* the boundary check, so a
//!   privileged-caller test only proves anything if its credential is
//!   genuinely consistent. See [`no_privilege_reaches_past_the_boundary`].
//! - **`spent` could not tell an unbilled tenant from a nonexistent one.** It
//!   answered a bare `0` either way, so "none of it was billed" also passed
//!   for a tenant nobody had provisioned. It returns `Option<u64>` now.
//!
//! Still open: the audit journal these decisions land in is an in-memory
//! bounded buffer, not durable storage — a boundary violation is only
//! forensically available until the buffer wraps.

use ccos_enterprise_auth::AuthStrength;
use ccos_enterprise_conformance::{actor, request, two_tenant_deployment, Call, Outcome, Refusal};
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
///
/// Two repairs are guarded here too. The composed path used to authorize
/// whatever actor the *request* named rather than the one its credential
/// proved, so "a maximally-privileged caller" was a claim any request could
/// simply assert; the credential now binds the request, and that gate is
/// evaluated *before* the boundary. That makes a consistent credential
/// load-bearing for this test rather than incidental: root really is
/// authenticated as root, in org `memorithm`, against `acme`, which
/// `memorithm` owns. Weaken any one of those and every call below would be
/// refused at an earlier gate and this test would quietly stop exercising the
/// boundary at all — which is what the control call at the end proves it
/// still does. And `spent` used to answer a bare `0` for a tenant that did
/// not exist, so "none of it was billed" also passed for a misspelt tenant;
/// `Some(0)` says the tenant is real *and* was charged nothing.
#[test]
fn no_privilege_reaches_past_the_boundary() {
    let mut d = two_tenant_deployment();
    // A maximally-privileged caller: strong identity, every permission, the
    // forbidden tools explicitly governed and the model allowlisted.
    d.add_role(
        "superuser",
        &["memory.read", "memory.write", "policy.admin", "root"],
    );
    assert!(d.assign("root", "superuser"), "the grant really was made");
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

    for (i, tool) in [
        "rsi.status",
        "forge.run",
        "shell.exec",
        "code.execute",
        "self.rewrite",
    ]
    .into_iter()
    .enumerate()
    {
        // Distinct ids: a decided `request_id` is now suppressed as a replay,
        // and this test bills nothing it wants suppressed.
        let request = request("acme", "root", tool, &format!("r-root-{i}"));
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
    assert_eq!(d.spent("acme"), Some(0), "and none of it was billed");

    // The control. Same credential, same tenant, an exposed tool: it is
    // forwarded and charged, so the refusals above were the boundary's doing
    // and not an identity the deployment had already thrown out.
    let exposed = request("acme", "root", "memory.recall", "r-root-control");
    assert_eq!(
        d.admit(Call {
            actor: &root,
            request: &exposed,
            model: "claude-opus",
            cost_tokens: 7,
            variant: None,
        }),
        Outcome::Forwarded,
        "this credential is genuinely admitted; only the boundary refused it"
    );
    assert_eq!(d.spent("acme"), Some(7), "only the exposed call was billed");
}

/// Replay suppression is a short-circuit the composed path did not have: a
/// `(tenant, request_id)` already decided is forwarded without being charged
/// again, which repaired retries being billed twice. It must not also become
/// a way *around* the boundary. A forbidden tool presented under a
/// `request_id` whose earlier, exposed call was forwarded is still refused at
/// the boundary — the boundary is evaluated before the replay check, and
/// only a charged decision is ever remembered — and it still costs nothing.
#[test]
fn a_decided_request_id_does_not_carry_a_forbidden_tool_past_the_boundary() {
    let mut d = two_tenant_deployment();
    let alice = actor("memorithm", "alice", AuthStrength::Token);

    let exposed = request("acme", "alice", "memory.ingest", "r-replay");
    assert_eq!(
        d.admit(Call {
            actor: &alice,
            request: &exposed,
            model: "claude-opus",
            cost_tokens: 25,
            variant: None,
        }),
        Outcome::Forwarded
    );
    assert_eq!(d.spent("acme"), Some(25));

    for tool in ["shell.exec", "code.execute", "rsi.status"] {
        let replayed = request("acme", "alice", tool, "r-replay");
        let outcome = d.admit(Call {
            actor: &alice,
            request: &replayed,
            model: "claude-opus",
            cost_tokens: 25,
            variant: None,
        });
        assert!(
            matches!(outcome.refusal(), Some(Refusal::OutsideBoundary(_))),
            "'{tool}' must not ride a decided request_id past the boundary, got {outcome:?}"
        );
    }
    assert_eq!(d.spent("acme"), Some(25), "and nothing further was billed");
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
