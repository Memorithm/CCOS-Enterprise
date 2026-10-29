//! Default build (no `sml-backend`): behaviour of #241 is unchanged, backend is unavailable.
#![cfg(not(feature = "sml-backend"))]

use ccos_enterprise_memory::MemoryLoadout;
use ccos_enterprise_sml_retrieval::*;
use ccos_enterprise_tenancy::TenantId;

#[test]
fn feature_off_backend_is_unavailable() {
    let lo = MemoryLoadout::tenant_only();
    let r = UnavailableSmlRetrieval.retrieve(
        &TenantId::new("acme").unwrap(),
        SmlRetrievalRequest {
            text: "invoice",
            k: 3,
            loadout: &lo,
        },
    );
    assert!(matches!(r, Err(SmlRetrievalError::BackendUnavailable(_))));
}
