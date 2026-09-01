from pathlib import Path

p = Path("crates/ccos-enterprise-memory/src/lib.rs")
text = p.read_text()
marker = "mod context_budget;\n"
addition = """mod bundle;
pub use bundle::{
    MemoryBundleEntry, MemoryBundleError, MemoryBundleManifest, MemoryBundleVersion,
    MemoryContentDigest, MemoryProviderReference,
};

""" + marker
assert marker in text
assert "mod bundle;" not in text
p.write_text(text.replace(marker, addition, 1))
