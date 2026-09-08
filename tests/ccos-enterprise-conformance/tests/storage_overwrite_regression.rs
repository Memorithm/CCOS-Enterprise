use ccos_enterprise_runtime::{Deployment, TenantState};
use ccos_enterprise_tenancy::{TenantId, TenantScope};

#[test]
fn shrinking_an_existing_cell_is_accepted_and_replaces_the_value() {
    let mut deployment = Deployment::new();
    let mut tenant = TenantState::new(0);
    tenant.allow_model("model");
    assert!(deployment.add_tenant("test-org", "t-a", tenant));

    let scope = TenantScope::new(TenantId("t-a".into()), "cell-0".to_string());
    let long = "t-a#31#12345678901234567890";
    let short = "t-a#1#1";

    assert!(deployment.put(&scope, long), "initial write must land");
    assert!(
        deployment.put(&scope, short),
        "shrinking overwrite must not be treated as storage growth"
    );
    assert_eq!(deployment.get(&scope), Some(short));
    assert_eq!(deployment.cell_count("t-a"), 1);
}
