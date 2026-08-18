use std::collections::BTreeSet;

use ccos_enterprise_mcp::{clears_the_boundary, permission_for, to_core};
use serde::Deserialize;

const MANIFEST: &str = include_str!(
    "../../../adapters/deepseek-harness/governed-read-tools.json"
);

#[derive(Debug, Deserialize)]
struct Mapping {
    enterprise: String,
    dsh: String,
}

fn valid_dsh_name(name: &str) -> bool {
    name.starts_with("ccos_")
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[test]
fn deepseek_native_manifest_is_exactly_governed_read_only_surface() {
    let rows: Vec<Mapping> = serde_json::from_str(MANIFEST).expect("DSH read manifest is valid JSON");
    assert_eq!(
        rows.len(),
        11,
        "changing the model-visible DSH surface requires an explicit contract review"
    );

    let mut enterprise = BTreeSet::new();
    let mut dsh = BTreeSet::new();
    for row in &rows {
        assert!(
            enterprise.insert(row.enterprise.as_str()),
            "duplicate Enterprise capability in DSH manifest: {}",
            row.enterprise
        );
        assert!(
            dsh.insert(row.dsh.as_str()),
            "duplicate DSH tool name in manifest: {}",
            row.dsh
        );
        assert!(valid_dsh_name(&row.dsh), "invalid DSH tool name: {}", row.dsh);
        assert!(
            clears_the_boundary(&row.enterprise),
            "DSH manifest exposed a capability the Enterprise gateway refuses: {}",
            row.enterprise
        );
        let core = to_core(&row.enterprise)
            .unwrap_or_else(|| panic!("DSH manifest names unknown Enterprise tool: {}", row.enterprise));
        assert_eq!(
            permission_for(core),
            Some("memory.read"),
            "DSH model-visible tool {} drifted away from memory.read",
            row.enterprise
        );
    }

    for forbidden in [
        "memory.ingest",
        "memory.page_fault",
        "memory.sync",
        "ccos.causal_intervene",
        "ccos.signal_failure",
        "shell.exec",
        "code.execute",
        "repository.modify",
        "patch.apply",
        "self.modify",
    ] {
        assert!(
            !enterprise.contains(forbidden),
            "write/forbidden capability became model-visible in DSH: {forbidden}"
        );
    }
}
