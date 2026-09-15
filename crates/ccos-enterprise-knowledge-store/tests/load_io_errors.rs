//! Loading errors must not be reinterpreted as an empty journal.
use ccos_enterprise_knowledge_store::{KnowledgeStore as Store, StoreError, JOURNAL_FILE};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "ccos-load-knowledge-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn absent_journal_keeps_the_documented_empty_read_without_creation() {
    let dir = Directory::new();
    let loaded = Store::load(&dir.0).unwrap();
    assert!(loaded.entries.is_empty());
    assert_eq!(loaded.torn_tail, 0);
    assert!(!dir.0.join(JOURNAL_FILE).exists());
    let missing = dir.0.join("missing-parent");
    assert!(Store::load(&missing).unwrap().entries.is_empty());
    assert!(!missing.exists());
}

#[test]
fn an_existing_empty_regular_journal_is_still_valid() {
    let dir = Directory::new();
    fs::write(dir.0.join(JOURNAL_FILE), b"").unwrap();
    let loaded = Store::load(&dir.0).unwrap();
    assert!(loaded.entries.is_empty());
    assert_eq!(loaded.torn_tail, 0);
}

#[test]
fn non_directory_root_is_not_an_empty_journal() {
    let dir = Directory::new();
    let root = dir.0.join("not-a-directory");
    fs::write(&root, b"existing unrelated file").unwrap();
    let result = Store::load(&root);
    assert!(
        matches!(result, Err(StoreError::Io { ref path, ref source })
        if *path == root.join(JOURNAL_FILE) && source.kind() != std::io::ErrorKind::NotFound),
        "{result:?}"
    );
    assert_eq!(fs::read(root).unwrap(), b"existing unrelated file");
}

#[test]
fn directory_at_journal_path_is_an_io_error() {
    let dir = Directory::new();
    let path = dir.0.join(JOURNAL_FILE);
    fs::create_dir(&path).unwrap();
    assert!(
        matches!(Store::load(&dir.0), Err(StoreError::Io { path: found, .. }) if found == path)
    );
    assert!(path.is_dir());
}

#[cfg(unix)]
#[test]
fn symbolic_link_loop_is_an_error_not_empty_authority() {
    let dir = Directory::new();
    let path = dir.0.join(JOURNAL_FILE);
    std::os::unix::fs::symlink(JOURNAL_FILE, &path).unwrap();
    assert!(
        matches!(Store::load(&dir.0), Err(StoreError::Io { path: found, source })
        if found == path && source.kind() != std::io::ErrorKind::NotFound)
    );
    assert!(fs::symlink_metadata(path).unwrap().file_type().is_symlink());
}
