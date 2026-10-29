//! External path: `memory.document_recall` through `Deployment::admit` into
//! `GovernedDocumentMemory`, then `admit_governed_recall`.

use std::collections::BTreeMap;

use ccos_enterprise_auth::AuthStrength;
use ccos_enterprise_docmemory::GovernedDocumentWrite;
use ccos_enterprise_ingest::doc_index::{lexical_only_memory, LexicalDocumentMemory};
use ccos_enterprise_mcp::{
    govern_governed_document_recall, recall_governed_documents, serve_document_recall,
    DocumentRecallError, GOVERNED_DOCUMENT_RECALL_PERMISSION, GOVERNED_DOCUMENT_RECALL_TOOL,
};
use ccos_enterprise_memory::{
    GovernedMemoryProjection, GovernedRecallGateError, GovernedRecallTrustPolicy,
    MemoryAssetDescriptor, MemoryAssetId, MemoryContextBudget, MemoryEvidenceRef, MemoryLineage,
    MemoryLineageGraph, MemoryLoadoutBinding, MemoryLoadoutPlan, MemorySpace, MemoryStratum,
    MemoryTrustMetadata, MemoryUsageMode, MemoryValidationState,
};
use ccos_enterprise_runtime::{actor, request, Call, Deployment, TenantState};
use ccos_enterprise_tenancy::{TenantId, TenantScope};
use serde_json::{json, Value};

fn tid(t: &str) -> TenantId {
    TenantId::validated(t).unwrap()
}
fn aid(a: &str) -> MemoryAssetId {
    MemoryAssetId::new(a).unwrap()
}
fn proj(p: &str) -> MemorySpace {
    MemorySpace::project(p).unwrap()
}
fn verified() -> MemoryTrustMetadata {
    MemoryTrustMetadata::new(MemoryValidationState::Verified, 1, 1, 0, ["proof:1".into()]).unwrap()
}

/// Projection registering `assets` (id, space) with `trust`, loadout over `spaces`.
fn projection(
    tenant: &str,
    assets: &[(&str, MemorySpace)],
    trust: Option<MemoryTrustMetadata>,
    spaces: &[MemorySpace],
) -> GovernedMemoryProjection {
    let mut graph = MemoryLineageGraph::new();
    let mut trusts = BTreeMap::new();
    for (id, space) in assets {
        graph
            .register(
                MemoryAssetDescriptor::new(
                    aid(id),
                    space.clone(),
                    MemoryStratum::Evidence,
                    MemoryLineage::root([MemoryEvidenceRef::new(format!("audit:{id}")).unwrap()])
                        .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        if let Some(t) = &trust {
            trusts.insert(aid(id), t.clone());
        }
    }
    let bindings: Vec<_> = spaces
        .iter()
        .map(|s| MemoryLoadoutBinding::new(s.clone(), 100, MemoryUsageMode::Bootstrap).unwrap())
        .collect();
    GovernedMemoryProjection::new(
        tid(tenant),
        graph,
        trusts,
        MemoryLoadoutPlan::new(bindings).unwrap(),
    )
    .unwrap()
}

fn index(m: &mut LexicalDocumentMemory, tenant: &str, id: &str, space: MemorySpace, text: &str) {
    m.insert_document(TenantScope::new(
        tid(tenant),
        GovernedDocumentWrite {
            asset_id: &aid(id),
            space: &space,
            text,
        },
    ))
    .unwrap();
}

/// acme: `acme:alpha` (project alpha), `acme:beta` (project beta). globex: `globex:alpha`.
/// All share the word "turbine" so a leak would rank.
fn corpus() -> LexicalDocumentMemory {
    let mut m = lexical_only_memory();
    index(
        &mut m,
        "acme",
        "acme:alpha",
        proj("alpha"),
        "acme turbine maintenance schedule",
    );
    index(
        &mut m,
        "acme",
        "acme:beta",
        proj("beta"),
        "acme turbine secret beta design",
    );
    index(
        &mut m,
        "globex",
        "globex:alpha",
        proj("alpha"),
        "globex turbine confidential pricing",
    );
    m
}

fn acme_alpha_projection() -> GovernedMemoryProjection {
    projection(
        "acme",
        &[("acme:alpha", proj("alpha")), ("acme:beta", proj("beta"))],
        Some(verified()),
        &[proj("alpha")],
    )
}

fn deployment() -> Deployment {
    let mut d = Deployment::new();
    d.add_role("reader", &[GOVERNED_DOCUMENT_RECALL_PERMISSION]);
    govern_governed_document_recall(&mut d);
    for (org, t) in [("memorithm", "acme"), ("globex-org", "globex")] {
        let mut s = TenantState::new(1000);
        s.allow_model("model");
        d.add_tenant(org, t, s);
    }
    d.assign("memorithm", "alice", "reader");
    d.assign("globex-org", "mallory", "reader");
    d
}

#[allow(clippy::too_many_arguments)]
fn call(
    d: &mut Deployment,
    m: &mut LexicalDocumentMemory,
    p: &GovernedMemoryProjection,
    org: &str,
    who: &str,
    tenant: &str,
    rid: &str,
    args: Value,
) -> Result<Value, DocumentRecallError> {
    let identity = actor(org, who, AuthStrength::Token);
    let req = request(tenant, who, GOVERNED_DOCUMENT_RECALL_TOOL, rid);
    serve_document_recall(
        d,
        Call {
            actor: &identity,
            request: &req,
            model: "model",
            cost_tokens: 1,
            variant: None,
            justification: None,
        },
        m,
        p,
        &args,
    )
}

fn ids(v: &Value) -> Vec<String> {
    v["structuredContent"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["asset_id"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn served_text_recall_is_scoped_to_tenant_and_loadout() {
    let (mut d, mut m, p) = (deployment(), corpus(), acme_alpha_projection());
    let out = call(
        &mut d,
        &mut m,
        &p,
        "memorithm",
        "alice",
        "acme",
        "r1",
        json!({"query":"turbine","k":10}),
    )
    .unwrap();
    // beta is in the tenant but outside the loadout; globex is another tenant.
    assert_eq!(ids(&out), vec!["acme:alpha".to_string()]);
    let sc = &out["structuredContent"];
    assert_eq!(sc["tenant"], "acme");
    assert_eq!(sc["trust_policy"], "verified_only");
    assert_eq!(sc["items"][0]["space"], "project:alpha");
    assert_eq!(sc["items"][0]["text"], "acme turbine maintenance schedule");
    assert_eq!(sc["projection_sha256"], sc["items"][0]["projection_sha256"]);
}

#[test]
fn widening_the_loadout_reaches_the_second_space_only_in_tenant() {
    let p = projection(
        "acme",
        &[("acme:alpha", proj("alpha")), ("acme:beta", proj("beta"))],
        Some(verified()),
        &[proj("alpha"), proj("beta")],
    );
    let (mut d, mut m) = (deployment(), corpus());
    let mut got = ids(&call(
        &mut d,
        &mut m,
        &p,
        "memorithm",
        "alice",
        "acme",
        "r1",
        json!({"query":"turbine"}),
    )
    .unwrap());
    got.sort();
    assert_eq!(got, vec!["acme:alpha".to_string(), "acme:beta".to_string()]);
}

#[test]
fn cross_tenant_actor_is_refused_before_any_read() {
    let (mut d, mut m, p) = (deployment(), corpus(), acme_alpha_projection());
    // globex actor targeting acme: refused at the front door.
    let r = call(
        &mut d,
        &mut m,
        &p,
        "globex-org",
        "mallory",
        "acme",
        "r1",
        json!({"query":"turbine"}),
    );
    assert!(matches!(r, Err(DocumentRecallError::Refused(_))), "{r:?}");
}

#[test]
fn admitted_tenant_with_foreign_projection_fails_closed() {
    let (mut d, mut m, p) = (deployment(), corpus(), acme_alpha_projection());
    // mallory is legitimately admitted for globex, but the server-side projection is acme's.
    let r = call(
        &mut d,
        &mut m,
        &p,
        "globex-org",
        "mallory",
        "globex",
        "r1",
        json!({"query":"turbine"}),
    );
    assert!(
        matches!(
            r,
            Err(DocumentRecallError::RecallAdmission(
                GovernedRecallGateError::TenantMismatch { .. }
            ))
        ),
        "{r:?}"
    );
}

#[test]
fn globex_recall_never_sees_acme_documents() {
    let p = projection(
        "globex",
        &[("globex:alpha", proj("alpha"))],
        Some(verified()),
        &[proj("alpha")],
    );
    let (mut d, mut m) = (deployment(), corpus());
    let out = call(
        &mut d,
        &mut m,
        &p,
        "globex-org",
        "mallory",
        "globex",
        "r1",
        json!({"query":"acme turbine maintenance"}),
    )
    .unwrap();
    assert_eq!(ids(&out), vec!["globex:alpha".to_string()]);
}

#[test]
fn results_must_pass_governed_recall_admission() {
    let mut m = corpus();
    // Indexed but unknown to governance: gate refuses, nothing partial returned.
    let unknown = projection("acme", &[], Some(verified()), &[proj("alpha")]);
    let r = recall_governed_documents(
        &mut m,
        &tid("acme"),
        &unknown,
        GovernedRecallTrustPolicy::VerifiedOnly,
        "turbine",
        4,
        MemoryContextBudget::new(4, 4096).unwrap(),
    );
    assert!(
        matches!(
            r,
            Err(DocumentRecallError::RecallAdmission(
                GovernedRecallGateError::ProviderReturnedUnknownAsset(_)
            ))
        ),
        "{r:?}"
    );
    // Known but unverified: filtered out by the served (verified-only) policy.
    let unverified = projection(
        "acme",
        &[("acme:alpha", proj("alpha"))],
        Some(MemoryTrustMetadata::unverified(1)),
        &[proj("alpha")],
    );
    let (mut d, mut m) = (deployment(), corpus());
    let out = call(
        &mut d,
        &mut m,
        &unverified,
        "memorithm",
        "alice",
        "acme",
        "r1",
        json!({"query":"turbine"}),
    )
    .unwrap();
    assert!(ids(&out).is_empty());
}

#[test]
fn replay_and_client_space_override_are_refused() {
    let (mut d, mut m, p) = (deployment(), corpus(), acme_alpha_projection());
    call(
        &mut d,
        &mut m,
        &p,
        "memorithm",
        "alice",
        "acme",
        "r1",
        json!({"query":"turbine"}),
    )
    .unwrap();
    let r = call(
        &mut d,
        &mut m,
        &p,
        "memorithm",
        "alice",
        "acme",
        "r1",
        json!({"query":"turbine"}),
    );
    assert!(matches!(r, Err(DocumentRecallError::Replayed)), "{r:?}");
    let r = call(
        &mut d,
        &mut m,
        &p,
        "memorithm",
        "alice",
        "acme",
        "r2",
        json!({"query":"turbine","space":"project:beta"}),
    );
    assert!(
        matches!(r, Err(DocumentRecallError::InvalidArguments(_))),
        "{r:?}"
    );
}

#[test]
fn context_budget_bounds_the_answer() {
    let p = projection(
        "acme",
        &[("acme:alpha", proj("alpha")), ("acme:beta", proj("beta"))],
        Some(verified()),
        &[proj("alpha"), proj("beta")],
    );
    let (mut d, mut m) = (deployment(), corpus());
    let out = call(
        &mut d,
        &mut m,
        &p,
        "memorithm",
        "alice",
        "acme",
        "r1",
        json!({"query":"turbine","context_max_items":1}),
    )
    .unwrap();
    assert_eq!(ids(&out).len(), 1);
}
