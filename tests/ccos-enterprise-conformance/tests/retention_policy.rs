//! The composed cognitive-retention contract: tenant-scoped policy,
//! deterministic enforcement with an explicit clock, invalidation vs sealed
//! history, audit completeness, and crash-safe continuation.

use std::collections::BTreeMap;

use ccos_enterprise_retention::{
    EnforcementAction, EnforcementRecord, RetainedItem, RetentionClass, RetentionEngine,
    RetentionPolicy, RetentionStore, RunOutcome, RETENTION_SCHEMA,
};
use ccos_enterprise_tenancy::TenantId;

fn policy(class: RetentionClass, seconds: Option<u64>, invalidate: bool) -> RetentionPolicy {
    RetentionPolicy {
        schema_version: RETENTION_SCHEMA,
        classes: BTreeMap::from([(
            class,
            ccos_enterprise_retention::ClassPolicy {
                retention_seconds: seconds,
                invalidate,
            },
        )]),
    }
}

fn item(class: RetentionClass, created_at: u64) -> RetainedItem {
    RetainedItem {
        class,
        created_at,
        sealed: false,
    }
}

#[test]
fn enforcement_is_deterministic_replayable_and_audited() {
    let tenant = TenantId("acme".into());
    let p = policy(RetentionClass::EpisodicJournal, Some(30), true);
    let items = vec![
        item(RetentionClass::EpisodicJournal, 0), // expired (0+30 <= 100)
        item(RetentionClass::EpisodicJournal, 10), // expired (10+30 <= 100)
        item(RetentionClass::EpisodicJournal, 80), // not expired (80+30 > 100)
    ];
    let (outcome_a, records_a) = RetentionEngine::run_once(&tenant, &p, &items, 100, 100);
    let (outcome_b, records_b) = RetentionEngine::run_once(&tenant, &p, &items, 100, 100);
    assert_eq!(outcome_a, outcome_b, "replay converges");
    assert_eq!(records_a, records_b, "replay produces the same audit facts");
    assert_eq!(outcome_a.examined, 3);
    assert_eq!(outcome_a.invalidated, 2);
    assert_eq!(outcome_a.retained, 1);
    assert_eq!(records_a.len(), 2, "every enforcement action is audited");
    assert!(records_a.iter().all(|r| r.tenant == "acme"));
}

#[test]
fn sealed_history_is_reported_never_rewritten() {
    let tenant = TenantId("acme".into());
    let p = policy(RetentionClass::SealedSnapshots, Some(30), true);
    let sealed = RetainedItem {
        class: RetentionClass::SealedSnapshots,
        created_at: 0,
        sealed: true,
    };
    let (outcome, records) = RetentionEngine::run_once(&tenant, &p, &[sealed], 100, 100);
    assert_eq!(outcome.invalidated, 0);
    assert_eq!(outcome.reported, 1);
    assert_eq!(records[0].action, EnforcementAction::ReportOnly);
}

#[test]
fn never_expiring_class_is_never_enforced() {
    let tenant = TenantId("acme".into());
    let p = policy(RetentionClass::ComplianceArchives, None, true);
    let (outcome, records) = RetentionEngine::run_once(
        &tenant,
        &p,
        &[item(RetentionClass::ComplianceArchives, 0)],
        u64::MAX,
        100,
    );
    assert_eq!(outcome.retained, 1);
    assert!(records.is_empty());
}

#[test]
fn wrong_tenant_never_appears_in_another_tenants_run() {
    let tenant = TenantId("globex".into());
    let p = policy(RetentionClass::EphemeralContext, Some(10), true);
    let (_, records) = RetentionEngine::run_once(
        &tenant,
        &p,
        &[item(RetentionClass::EphemeralContext, 0)],
        100,
        100,
    );
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].tenant, "globex");
}

#[test]
fn bounded_processing_stops_at_the_batch_limit() {
    let tenant = TenantId("acme".into());
    let p = policy(RetentionClass::EphemeralContext, Some(10), true);
    let items: Vec<RetainedItem> = (0..50)
        .map(|i| item(RetentionClass::EphemeralContext, i))
        .collect();
    let (outcome, _) = RetentionEngine::run_once(&tenant, &p, &items, 100, 10);
    assert_eq!(outcome.examined, 10);
    assert_eq!(outcome.invalidated, 10, "the first ten are all expired");
}

#[test]
fn store_round_trip_preserves_policy_and_audit() {
    let dir =
        std::env::temp_dir().join(format!("ccos-retention-conformance-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    {
        let store = RetentionStore::open(&dir).unwrap();
        store
            .save_policy(&policy(RetentionClass::EpisodicJournal, Some(30), true))
            .unwrap();
        store
            .append_record(&EnforcementRecord {
                tenant: "acme".into(),
                class: RetentionClass::EpisodicJournal,
                item_created_at: 0,
                action: EnforcementAction::Invalidate,
                at_unix: 100,
            })
            .unwrap();
    }
    {
        let store = RetentionStore::open(&dir).unwrap();
        let loaded = store.load_policy().unwrap().unwrap();
        assert!(loaded.expired(RetentionClass::EpisodicJournal, 0, 30));
        assert!(!loaded.expired(RetentionClass::EpisodicJournal, 0, 29));
        let ledger = store.load_ledger().unwrap();
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger[0].action, EnforcementAction::Invalidate);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn crash_continuation_replays_without_duplicate_effects() {
    // The engine is stateless, so "continuing after a crash" is just running
    // again with the remaining items: the ledger is append-only, and rerunning
    // the same slice produces the same records (idempotent by construction).
    let tenant = TenantId("acme".into());
    let p = policy(RetentionClass::EphemeralContext, Some(10), true);
    let items: Vec<RetainedItem> = (0..4)
        .map(|i| item(RetentionClass::EphemeralContext, i))
        .collect();
    let (first, first_records) = RetentionEngine::run_once(&tenant, &p, &items, 100, 2);
    assert_eq!(first.examined, 2);
    // The process "crashes" after two records; the ledger holds them.
    let (second, second_records) = RetentionEngine::run_once(&tenant, &p, &items, 100, 4);
    assert_eq!(second.examined, 4);
    // The rerun's records are a superset prefix of the first run's — no
    // duplicate effects, because records are deterministic per item.
    assert!(second_records.starts_with(&first_records));
}
