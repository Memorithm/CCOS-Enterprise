//! The composed cognitive-retention contract: tenant-scoped policy,
//! deterministic enforcement with an explicit clock, invalidation rather than
//! destructive rewriting, stable artifact identity, bounded processing, audit
//! completeness, and crash-safe continuation.

use std::collections::BTreeMap;

use ccos_enterprise_retention::{
    EnforcementAction, EnforcementRecord, RetainedItem, RetentionClass, RetentionEngine,
    RetentionError, RetentionPolicy, RetentionStore, MAX_INPUT_ITEMS, RETENTION_SCHEMA,
};
use ccos_enterprise_tenancy::TenantId;

fn policy_for(
    tenant: &str,
    class: RetentionClass,
    seconds: Option<u64>,
    invalidate: bool,
) -> RetentionPolicy {
    RetentionPolicy {
        schema_version: RETENTION_SCHEMA,
        tenant: tenant.into(),
        classes: BTreeMap::from([(
            class,
            ccos_enterprise_retention::ClassPolicy {
                retention_seconds: seconds,
                invalidate,
            },
        )]),
    }
}

fn item(id: impl Into<String>, class: RetentionClass, created_at: u64) -> RetainedItem {
    RetainedItem {
        tenant: "acme".into(),
        item_id: id.into(),
        class,
        created_at,
        sealed: false,
    }
}

#[test]
fn enforcement_is_deterministic_replayable_and_audited() {
    let tenant = TenantId("acme".into());
    let policy = policy_for("acme", RetentionClass::EpisodicJournal, Some(30), true);
    let items = vec![
        item("episode-0", RetentionClass::EpisodicJournal, 0),
        item("episode-10", RetentionClass::EpisodicJournal, 10),
        item("episode-80", RetentionClass::EpisodicJournal, 80),
    ];
    let (outcome_a, records_a) =
        RetentionEngine::run_once(&tenant, &policy, &items, 100, 100).unwrap();
    let (outcome_b, records_b) =
        RetentionEngine::run_once(&tenant, &policy, &items, 100, 100).unwrap();
    assert_eq!(outcome_a, outcome_b, "replay converges");
    assert_eq!(records_a, records_b, "replay produces the same audit facts");
    assert_eq!(outcome_a.examined, 3);
    assert_eq!(outcome_a.invalidated, 2);
    assert_eq!(outcome_a.retained, 1);
    assert_eq!(records_a.len(), 2, "every enforcement action is audited");
    assert!(records_a.iter().all(|record| record.tenant == "acme"));
    assert_eq!(records_a[0].item_id, "episode-0");
    assert_eq!(records_a[1].item_id, "episode-10");
}

#[test]
fn sealed_history_is_invalidated_without_rewriting_content() {
    let tenant = TenantId("acme".into());
    let policy = policy_for("acme", RetentionClass::SealedSnapshots, Some(30), true);
    let mut sealed = item("snapshot-1", RetentionClass::SealedSnapshots, 0);
    sealed.sealed = true;
    let (outcome, records) =
        RetentionEngine::run_once(&tenant, &policy, &[sealed], 100, 100).unwrap();
    assert_eq!(outcome.invalidated, 1);
    assert_eq!(outcome.reported, 0);
    assert_eq!(records[0].action, EnforcementAction::Invalidate);
    assert_eq!(records[0].item_id, "snapshot-1");
}

#[test]
fn never_expiring_class_is_never_enforced() {
    let tenant = TenantId("acme".into());
    let policy = policy_for("acme", RetentionClass::ComplianceArchives, None, true);
    let (outcome, records) = RetentionEngine::run_once(
        &tenant,
        &policy,
        &[item("archive-1", RetentionClass::ComplianceArchives, 0)],
        u64::MAX,
        100,
    )
    .unwrap();
    assert_eq!(outcome.retained, 1);
    assert!(records.is_empty());
}

#[test]
fn policy_and_items_are_both_bound_to_the_tenant() {
    let acme = TenantId("acme".into());
    let globex_policy = policy_for("globex", RetentionClass::EphemeralContext, Some(10), true);
    assert!(matches!(
        RetentionEngine::run_once(
            &acme,
            &globex_policy,
            &[item("ctx-1", RetentionClass::EphemeralContext, 0)],
            100,
            100,
        ),
        Err(RetentionError::UnknownTenant { tenant }) if tenant == "globex"
    ));

    let acme_policy = policy_for("acme", RetentionClass::EphemeralContext, Some(10), true);
    let mut foreign = item("ctx-2", RetentionClass::EphemeralContext, 0);
    foreign.tenant = "globex".into();
    assert!(matches!(
        RetentionEngine::run_once(&acme, &acme_policy, &[foreign], 100, 100),
        Err(RetentionError::UnknownTenant { tenant }) if tenant == "globex"
    ));
}

#[test]
fn stable_item_identity_prevents_same_timestamp_collapse() {
    let tenant = TenantId("acme".into());
    let policy = policy_for("acme", RetentionClass::EphemeralContext, Some(10), true);
    let items = [
        item("ctx-a", RetentionClass::EphemeralContext, 0),
        item("ctx-b", RetentionClass::EphemeralContext, 0),
    ];
    let (_, records) = RetentionEngine::run_once(&tenant, &policy, &items, 100, 10).unwrap();
    assert_eq!(records.len(), 2);
    assert_ne!(records[0].item_id, records[1].item_id);
}

#[test]
fn bounded_processing_enforces_action_and_input_caps() {
    let tenant = TenantId("acme".into());
    let policy = policy_for("acme", RetentionClass::EphemeralContext, Some(10), true);
    let items: Vec<RetainedItem> = (0..50)
        .map(|i| item(format!("ctx-{i}"), RetentionClass::EphemeralContext, i))
        .collect();
    let (outcome, records) = RetentionEngine::run_once(&tenant, &policy, &items, 100, 10).unwrap();
    assert_eq!(outcome.invalidated, 10);
    assert_eq!(records.len(), 10);
    assert!(outcome.deferred > 0);

    let too_many: Vec<RetainedItem> = (0..=MAX_INPUT_ITEMS)
        .map(|i| item(format!("bulk-{i}"), RetentionClass::EphemeralContext, 0))
        .collect();
    assert!(matches!(
        RetentionEngine::run_once(&tenant, &policy, &too_many, 100, 1),
        Err(RetentionError::LimitOutOfRange { .. })
    ));
}

#[test]
fn store_round_trip_preserves_tenant_policy_and_audit_identity() {
    let dir =
        std::env::temp_dir().join(format!("ccos-retention-conformance-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    {
        let store = RetentionStore::open(&dir).unwrap();
        store
            .save_policy(&policy_for(
                "acme",
                RetentionClass::EpisodicJournal,
                Some(30),
                true,
            ))
            .unwrap();
        store
            .append_records(&[EnforcementRecord {
                tenant: "acme".into(),
                item_id: "episode-0".into(),
                class: RetentionClass::EpisodicJournal,
                item_created_at: 0,
                action: EnforcementAction::Invalidate,
                at_unix: 100,
            }])
            .unwrap();
    }
    {
        let store = RetentionStore::open(&dir).unwrap();
        let loaded = store.load_policy().unwrap().unwrap();
        assert_eq!(loaded.tenant, "acme");
        assert!(loaded.expired(RetentionClass::EpisodicJournal, 0, 30));
        assert!(!loaded.expired(RetentionClass::EpisodicJournal, 0, 29));
        let ledger = store.load_ledger().unwrap();
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger[0].action, EnforcementAction::Invalidate);
        assert_eq!(ledger[0].item_id, "episode-0");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn crash_continuation_replays_without_duplicate_audit_facts() {
    let tenant = TenantId("acme".into());
    let policy = policy_for("acme", RetentionClass::EphemeralContext, Some(10), true);
    let items: Vec<RetainedItem> = (0..4)
        .map(|i| item(format!("ctx-{i}"), RetentionClass::EphemeralContext, i))
        .collect();
    let (_, first_records) = RetentionEngine::run_once(&tenant, &policy, &items, 100, 2).unwrap();
    let (_, replay_records) = RetentionEngine::run_once(&tenant, &policy, &items, 100, 4).unwrap();
    assert!(replay_records.starts_with(&first_records));

    let dir = std::env::temp_dir().join(format!(
        "ccos-retention-conformance-replay-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let store = RetentionStore::open(&dir).unwrap();
    store.append_records(&first_records).unwrap();
    store.append_records(&replay_records).unwrap();
    let committed = store.load_ledger().unwrap();
    assert_eq!(committed.len(), 4, "replayed prefix was not duplicated");
    let ids: std::collections::BTreeSet<_> =
        committed.iter().map(|record| record.item_id.as_str()).collect();
    assert_eq!(ids.len(), 4);
    let _ = std::fs::remove_dir_all(&dir);
}
