//! Regression for issue #127: replacing a stored value with a shorter value
//! must succeed, preserve the replacement contents, and release the byte budget.
//!
//! This test intentionally exercises the direct storage fixture rather than
//! the governed request path so a failure isolates byte-accounting semantics.

use ccos_enterprise_conformance::two_tenant_deployment;
use ccos_enterprise_tenancy::{TenantId, TenantScope};

fn scope(tenant: &str, key: &str) -> TenantScope<String> {
    TenantScope::new(TenantId(tenant.to_string()), key.to_string())
}

#[test]
fn shorter_overwrite_succeeds_and_releases_storage_budget() {
    let mut deployment = two_tenant_deployment();
    let cell = scope("acme", "shrink-regression");

    let long_value = "x".repeat(4096);
    assert!(
        deployment.put(&cell, &long_value),
        "initial long value must be admitted"
    );
    assert_eq!(deployment.get(&cell), Some(long_value.as_str()));
    assert_eq!(deployment.cell_count("acme"), 1);

    assert!(
        deployment.put(&cell, "short"),
        "a non-growing overwrite must never be refused as storage exhausted"
    );
    assert_eq!(deployment.get(&cell), Some("short"));
    assert_eq!(
        deployment.cell_count("acme"),
        1,
        "overwriting an existing key must not change the cell count"
    );

    // A wrapping/saturating accounting bug can let the shrink itself appear to
    // succeed while poisoning the tenant's byte counter. Prove the released
    // budget remains usable by admitting an independent tiny cell afterwards.
    let probe = scope("acme", "post-shrink-probe");
    assert!(
        deployment.put(&probe, "ok"),
        "shrinking a value must release, not exhaust, the tenant byte budget"
    );
    assert_eq!(deployment.get(&probe), Some("ok"));
    assert_eq!(deployment.cell_count("acme"), 2);
}
