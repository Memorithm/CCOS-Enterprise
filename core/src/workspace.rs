//! # Real Workspace Scanner (CCOS v0.3)
//!
//! Replaces the synthetic in-memory workspace with a scanner over a real
//! directory tree. It detects added / modified / removed `.rs` files and feeds
//! **only the delta** to the [`IncrementalGraphEngine`](crate::incremental),
//! preserving the `O(Δ)` property end-to-end.
//!
//! File I/O is async (`tokio::fs`). The scanner is resilient: a file that
//! disappears mid-scan is treated as removed rather than causing an error.

use crate::incremental::IncrementalGraphEngine;
use crate::memory::MemoryGraph;
use crate::util::sha256_hex as hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use tokio::io::AsyncReadExt;

/// Hard limits for one workspace scan. They keep an untrusted tree from
/// turning discovery into an unbounded allocation or read.
pub const MAX_WORKSPACE_RUST_FILES: usize = 10_000;
pub const MAX_RUST_FILE_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_WORKSPACE_RUST_BYTES: u64 = 512 * 1024 * 1024;

#[cfg(unix)]
#[derive(Debug)]
struct WorkspaceRoot {
    canonical: PathBuf,
    dir: rustix::fd::OwnedFd,
}

#[cfg(not(unix))]
#[derive(Debug)]
struct WorkspaceRoot {
    canonical: PathBuf,
}

/// Typed error for workspace operations.
#[derive(Debug)]
pub enum WorkspaceError {
    Io(String),
    UnsafePath(String),
    LimitExceeded(String),
}

impl std::fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkspaceError::Io(e) => write!(f, "workspace I/O error: {e}"),
            WorkspaceError::UnsafePath(e) => write!(f, "unsafe workspace path: {e}"),
            WorkspaceError::LimitExceeded(e) => write!(f, "workspace limit exceeded: {e}"),
        }
    }
}

impl std::error::Error for WorkspaceError {}

impl From<std::io::Error> for WorkspaceError {
    fn from(e: std::io::Error) -> Self {
        WorkspaceError::Io(e.to_string())
    }
}

/// The set of changes detected between two scans.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceDelta {
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub removed: Vec<String>,
}

impl WorkspaceDelta {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.modified.is_empty() && self.removed.is_empty()
    }
    pub fn changed_count(&self) -> usize {
        self.added.len() + self.modified.len() + self.removed.len()
    }
}

/// Tracks the last-known content hash of every `.rs` file under `root`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkspaceScanner {
    pub root: String,
    pub files: HashMap<String, String>,
}

impl WorkspaceScanner {
    pub fn new(root: impl Into<String>) -> Self {
        Self {
            root: root.into(),
            files: HashMap::new(),
        }
    }

    /// Re-scan the workspace and return the delta versus the previous scan,
    /// updating the internal file index. Does not touch any graph.
    pub async fn scan_workspace(&mut self) -> Result<WorkspaceDelta, WorkspaceError> {
        let current = self.read_current().await?;
        let delta = Self::diff(&self.files, &current);
        self.files = current.into_iter().map(|(p, (h, _))| (p, h)).collect();
        Ok(delta)
    }

    /// Alias of [`Self::scan_workspace`] — the delta since the
    /// last scan.
    pub async fn update_delta(&mut self) -> Result<WorkspaceDelta, WorkspaceError> {
        self.scan_workspace().await
    }

    /// Scan **and** apply the delta to `graph` via the incremental engine:
    /// added/modified files are (re)parsed, removed files are evicted. Only the
    /// changed files touch the engine. Returns the applied delta.
    pub async fn sync(
        &mut self,
        engine: &mut IncrementalGraphEngine,
        graph: &mut MemoryGraph,
    ) -> Result<WorkspaceDelta, WorkspaceError> {
        let current = self.read_current().await?;
        let delta = Self::diff(&self.files, &current);

        for path in delta.added.iter().chain(delta.modified.iter()) {
            if let Some((_, content)) = current.get(path) {
                // Evict any prior version, then ingest — O(Δ): only this file.
                engine.evict_file_nodes(path, graph);
                engine.process_delta(path, None, content, graph);
            }
        }
        for path in &delta.removed {
            engine.evict_file_nodes(path, graph);
            engine.file_states.remove(path);
        }

        self.files = current.into_iter().map(|(p, (h, _))| (p, h)).collect();
        Ok(delta)
    }

    /// Poll the workspace up to `max_polls` times at `interval`, invoking
    /// `on_change` for every non-empty delta. Returns the number of change
    /// events observed. A bounded, crash-free alternative to OS file watching.
    pub async fn watch_changes<F: FnMut(&WorkspaceDelta)>(
        &mut self,
        interval: Duration,
        max_polls: usize,
        mut on_change: F,
    ) -> Result<usize, WorkspaceError> {
        let mut events = 0;
        for i in 0..max_polls {
            if i > 0 {
                tokio::time::sleep(interval).await;
            }
            let delta = self.scan_workspace().await?;
            if !delta.is_empty() {
                events += 1;
                on_change(&delta);
            }
        }
        Ok(events)
    }

    /// Read every `.rs` file under `root` into `(path -> (hash, content))`.
    /// Files that vanish mid-scan are skipped (and thus appear as removed).
    async fn read_current(&self) -> Result<HashMap<String, (String, String)>, WorkspaceError> {
        let mut current = HashMap::new();
        let Some(root) = Self::open_root(&self.root).await? else {
            return Ok(current);
        };
        #[cfg(unix)]
        let paths = {
            let directory = root.dir.try_clone().map_err(|e| {
                WorkspaceError::Io(format!("cannot clone workspace root descriptor: {e}"))
            })?;
            tokio::task::spawn_blocking(move || Self::collect_rs_unix(directory))
                .await
                .map_err(|e| WorkspaceError::Io(format!("workspace scan worker failed: {e}")))??
        };
        #[cfg(not(unix))]
        let paths: Vec<PathBuf> = Vec::new();
        let mut total_bytes = 0u64;
        for relative in paths {
            let path = root.canonical.join(&relative);
            let key = path.to_string_lossy().to_string();
            let Some(content) =
                Self::read_regular_file(&root, &relative, &path, &mut total_bytes).await?
            else {
                continue; // disappeared mid-scan: treat as absent
            };
            current.insert(key, (hash(&content), content));
        }
        Ok(current)
    }

    async fn open_root(root: &str) -> Result<Option<WorkspaceRoot>, WorkspaceError> {
        let root_path = PathBuf::from(root);
        let metadata = match tokio::fs::symlink_metadata(&root_path).await {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(WorkspaceError::UnsafePath(format!(
                "workspace root must be a real directory: {}",
                root_path.display()
            )));
        }
        let canonical = tokio::fs::canonicalize(&root_path).await?;
        let canonical_metadata = tokio::fs::symlink_metadata(&canonical).await?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            let dir = rustix::fs::open(
                &root_path,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|e| {
                WorkspaceError::UnsafePath(format!(
                    "cannot pin workspace root {}: {e}",
                    canonical.display()
                ))
            })?;
            let root_file = std::fs::File::from(dir);
            let descriptor_metadata = root_file.metadata()?;
            if descriptor_metadata.dev() != metadata.dev()
                || descriptor_metadata.ino() != metadata.ino()
                || descriptor_metadata.dev() != canonical_metadata.dev()
                || descriptor_metadata.ino() != canonical_metadata.ino()
            {
                return Err(WorkspaceError::UnsafePath(format!(
                    "workspace root changed while it was being pinned: {}",
                    canonical.display()
                )));
            }
            let dir = rustix::fd::OwnedFd::from(root_file);
            Ok(Some(WorkspaceRoot { canonical, dir }))
        }

        #[cfg(not(unix))]
        {
            let _root = WorkspaceRoot { canonical };
            Err(WorkspaceError::UnsafePath(
                "secure workspace scanning requires descriptor-relative path resolution, which is not available on this platform"
                    .into(),
            ))
        }
    }

    /// Open one file without following its final symlink, revalidate that it is
    /// a regular file confined to `root`, and read at most the configured
    /// per-file and aggregate budgets. `None` means the file vanished during
    /// the scan.
    async fn read_regular_file(
        root: &WorkspaceRoot,
        relative: &Path,
        display_path: &Path,
        total_bytes: &mut u64,
    ) -> Result<Option<String>, WorkspaceError> {
        if relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(WorkspaceError::UnsafePath(format!(
                "invalid relative Rust source path: {}",
                display_path.display()
            )));
        }

        #[cfg(unix)]
        let file = match Self::open_relative_unix(&root.dir, relative, display_path)? {
            Some(file) => tokio::fs::File::from_std(file),
            None => return Ok(None),
        };

        #[cfg(not(unix))]
        let file: tokio::fs::File = return Err(WorkspaceError::UnsafePath(
            "secure descriptor-relative workspace reads are unavailable on this platform".into(),
        ));
        let metadata = file.metadata().await?;
        if !metadata.file_type().is_file() {
            return Err(WorkspaceError::UnsafePath(format!(
                "refusing non-regular Rust source {}",
                display_path.display()
            )));
        }
        if metadata.len() > MAX_RUST_FILE_BYTES {
            return Err(WorkspaceError::LimitExceeded(format!(
                "{} is {} bytes (maximum {})",
                display_path.display(),
                metadata.len(),
                MAX_RUST_FILE_BYTES
            )));
        }
        let remaining = MAX_WORKSPACE_RUST_BYTES
            .checked_sub(*total_bytes)
            .ok_or_else(|| WorkspaceError::LimitExceeded("byte budget overflow".into()))?;
        if metadata.len() > remaining {
            return Err(WorkspaceError::LimitExceeded(format!(
                "Rust sources exceed {} bytes",
                MAX_WORKSPACE_RUST_BYTES
            )));
        }

        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_RUST_FILE_BYTES.min(remaining) + 1)
            .read_to_end(&mut bytes)
            .await?;
        if bytes.len() as u64 > MAX_RUST_FILE_BYTES {
            return Err(WorkspaceError::LimitExceeded(format!(
                "{} grew beyond {} bytes while being read",
                display_path.display(),
                MAX_RUST_FILE_BYTES
            )));
        }
        *total_bytes = total_bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| WorkspaceError::LimitExceeded("byte budget overflow".into()))?;
        if *total_bytes > MAX_WORKSPACE_RUST_BYTES {
            return Err(WorkspaceError::LimitExceeded(format!(
                "Rust sources exceed {} bytes",
                MAX_WORKSPACE_RUST_BYTES
            )));
        }
        let content = String::from_utf8(bytes).map_err(|e| {
            WorkspaceError::Io(format!(
                "{} is not valid UTF-8: {e}",
                display_path.display()
            ))
        })?;
        Ok(Some(content))
    }

    #[cfg(unix)]
    fn open_relative_unix(
        root: &rustix::fd::OwnedFd,
        relative: &Path,
        display_path: &Path,
    ) -> Result<Option<std::fs::File>, WorkspaceError> {
        let flags = rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK;

        #[cfg(any(target_os = "linux", target_os = "android"))]
        let opened = rustix::fs::openat2(
            root,
            relative,
            flags,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::BENEATH
                | rustix::fs::ResolveFlags::NO_SYMLINKS
                | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        );

        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let opened = {
            let mut directory = rustix::fs::openat(
                root,
                ".",
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            );
            let components: Vec<_> = relative.components().collect();
            for (index, component) in components.iter().enumerate() {
                let Component::Normal(name) = component else {
                    return Err(WorkspaceError::UnsafePath(format!(
                        "invalid relative Rust source path: {}",
                        display_path.display()
                    )));
                };
                let current = match directory {
                    Ok(ref current) => current,
                    Err(error) => return Self::map_anchored_open_error(error, display_path),
                };
                let component_flags = if index + 1 == components.len() {
                    flags
                } else {
                    flags | rustix::fs::OFlags::DIRECTORY
                };
                directory =
                    rustix::fs::openat(current, name, component_flags, rustix::fs::Mode::empty());
            }
            directory
        };

        match opened {
            Ok(fd) => Ok(Some(std::fs::File::from(fd))),
            Err(error) => Self::map_anchored_open_error(error, display_path),
        }
    }

    #[cfg(unix)]
    fn collect_rs_unix(root: rustix::fd::OwnedFd) -> Result<Vec<PathBuf>, WorkspaceError> {
        use std::os::unix::ffi::OsStrExt;

        let mut out = Vec::new();
        let mut stack = vec![(root, PathBuf::new())];
        while let Some((directory, relative_dir)) = stack.pop() {
            let entries = rustix::fs::Dir::read_from(&directory).map_err(|e| {
                WorkspaceError::Io(format!(
                    "cannot enumerate workspace directory {}: {e}",
                    relative_dir.display()
                ))
            })?;
            for entry in entries {
                let entry = entry.map_err(|e| {
                    WorkspaceError::Io(format!(
                        "cannot enumerate workspace directory {}: {e}",
                        relative_dir.display()
                    ))
                })?;
                let name_bytes = entry.file_name().to_bytes();
                if name_bytes == b"." || name_bytes == b".." {
                    continue;
                }
                let name = std::ffi::OsStr::from_bytes(name_bytes);
                if name_bytes.first() == Some(&b'.') || name_bytes == b"target" {
                    continue;
                }
                let relative = relative_dir.join(name);
                let file_type = entry.file_type();
                if file_type.is_symlink() {
                    if relative.extension().and_then(|e| e.to_str()) == Some("rs") {
                        return Err(WorkspaceError::UnsafePath(format!(
                            "refusing symbolic-link Rust source {}",
                            relative.display()
                        )));
                    }
                    continue;
                }
                if file_type.is_dir() {
                    let child = rustix::fs::openat(
                        &directory,
                        name,
                        rustix::fs::OFlags::RDONLY
                            | rustix::fs::OFlags::DIRECTORY
                            | rustix::fs::OFlags::NOFOLLOW
                            | rustix::fs::OFlags::CLOEXEC
                            | rustix::fs::OFlags::NONBLOCK,
                        rustix::fs::Mode::empty(),
                    )
                    .map_err(|e| {
                        WorkspaceError::UnsafePath(format!(
                            "cannot safely enter workspace directory {}: {e}",
                            relative.display()
                        ))
                    })?;
                    stack.push((child, relative));
                } else if relative.extension().and_then(|e| e.to_str()) == Some("rs") {
                    if out.len() == MAX_WORKSPACE_RUST_FILES {
                        return Err(WorkspaceError::LimitExceeded(format!(
                            "more than {MAX_WORKSPACE_RUST_FILES} Rust sources"
                        )));
                    }
                    out.push(relative);
                }
            }
        }
        out.sort();
        Ok(out)
    }

    #[cfg(unix)]
    fn map_anchored_open_error(
        error: rustix::io::Errno,
        path: &Path,
    ) -> Result<Option<std::fs::File>, WorkspaceError> {
        if error == rustix::io::Errno::NOENT {
            Ok(None)
        } else {
            Err(WorkspaceError::UnsafePath(format!(
                "cannot open {} beneath pinned workspace root: {error}",
                path.display()
            )))
        }
    }

    fn diff(
        previous: &HashMap<String, String>,
        current: &HashMap<String, (String, String)>,
    ) -> WorkspaceDelta {
        let mut delta = WorkspaceDelta::default();
        for (path, (hash, _)) in current {
            match previous.get(path) {
                None => delta.added.push(path.clone()),
                Some(old) if old != hash => delta.modified.push(path.clone()),
                _ => {}
            }
        }
        for path in previous.keys() {
            if !current.contains_key(path) {
                delta.removed.push(path.clone());
            }
        }
        delta.added.sort();
        delta.modified.sort();
        delta.removed.sort();
        delta
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "ccos_ws_{}_{}_{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[tokio::test]
    async fn scan_detects_add_modify_remove() {
        let dir = temp_dir("scan");
        let main = dir.join("main.rs");
        let lib = dir.join("lib.rs");
        let module = dir.join("module.rs");
        std::fs::write(&main, "fn main() {}").unwrap();
        std::fs::write(&lib, "pub mod module;").unwrap();
        std::fs::write(&module, "pub fn a() {}").unwrap();

        let mut scanner = WorkspaceScanner::new(dir.to_string_lossy().to_string());

        // First scan: all three are new.
        let d0 = scanner.scan_workspace().await.unwrap();
        assert_eq!(d0.added.len(), 3);
        assert!(d0.modified.is_empty() && d0.removed.is_empty());

        // Second scan, no change.
        let d1 = scanner.scan_workspace().await.unwrap();
        assert!(d1.is_empty(), "no change must produce an empty delta");

        // Modify only module.rs → only module.rs is reported modified.
        std::fs::write(&module, "pub fn a() {}\npub fn b() {}").unwrap();
        let d2 = scanner.scan_workspace().await.unwrap();
        assert_eq!(d2.modified.len(), 1);
        assert!(d2.modified[0].ends_with("module.rs"));
        assert!(d2.added.is_empty() && d2.removed.is_empty());

        // Remove lib.rs.
        std::fs::remove_file(&lib).unwrap();
        let d3 = scanner.scan_workspace().await.unwrap();
        assert_eq!(d3.removed.len(), 1);
        assert!(d3.removed[0].ends_with("lib.rs"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn sync_reparses_only_changed_file() {
        let dir = temp_dir("sync");
        std::fs::write(dir.join("main.rs"), "fn main() {}").unwrap();
        std::fs::write(dir.join("lib.rs"), "pub mod module;").unwrap();
        std::fs::write(dir.join("module.rs"), "pub fn a() {}").unwrap();

        let mut scanner = WorkspaceScanner::new(dir.to_string_lossy().to_string());
        let mut engine = IncrementalGraphEngine::new();
        let mut graph = MemoryGraph::new(0.2, 100_000);

        let d0 = scanner.sync(&mut engine, &mut graph).await.unwrap();
        assert_eq!(d0.added.len(), 3);
        let mutations_after_initial = engine.total_mutations();
        assert_eq!(mutations_after_initial, 3);

        // Modify only module.rs and re-sync.
        std::fs::write(dir.join("module.rs"), "pub fn a() {}\npub fn b() {}").unwrap();
        let d1 = scanner.sync(&mut engine, &mut graph).await.unwrap();
        assert_eq!(d1.changed_count(), 1, "only one file changed");
        assert_eq!(
            engine.total_mutations() - mutations_after_initial,
            1,
            "exactly one file must be reparsed"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn watch_and_update_delta_detect_changes() {
        let dir = temp_dir("watch");
        std::fs::write(dir.join("a.rs"), "fn a() {}").unwrap();
        let mut scanner = WorkspaceScanner::new(dir.to_string_lossy().to_string());

        // `update_delta` reports the initial files.
        let d0 = scanner.update_delta().await.unwrap();
        assert_eq!(d0.added.len(), 1);

        // Modify a file; `watch_changes` must observe it within a few polls.
        std::fs::write(dir.join("a.rs"), "fn a() {}\nfn b() {}").unwrap();
        let mut changed = 0usize;
        let events = scanner
            .watch_changes(Duration::from_millis(1), 3, |d| {
                changed += d.changed_count()
            })
            .await
            .unwrap();
        assert!(events >= 1, "watch_changes must observe the modification");
        assert!(changed >= 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn removed_file_evicts_its_nodes() {
        let dir = temp_dir("evict");
        std::fs::write(dir.join("a.rs"), "pub fn a() {}\nstruct A;").unwrap();
        std::fs::write(dir.join("b.rs"), "pub fn b() {}").unwrap();

        let mut scanner = WorkspaceScanner::new(dir.to_string_lossy().to_string());
        let mut engine = IncrementalGraphEngine::new();
        let mut graph = MemoryGraph::new(0.2, 100_000);
        scanner.sync(&mut engine, &mut graph).await.unwrap();
        let before = graph.node_count();
        assert!(before > 0);

        std::fs::remove_file(dir.join("a.rs")).unwrap();
        let d = scanner.sync(&mut engine, &mut graph).await.unwrap();
        assert_eq!(d.removed.len(), 1);
        assert!(
            graph.node_count() < before,
            "removed file's nodes must be evicted"
        );
        assert_eq!(
            graph.prune_dangling_edges(),
            0,
            "no dangling edges after removal"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_rust_symlink_outside_workspace() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir("symlink_root");
        let outside = temp_dir("symlink_outside");
        let sentinel = outside.join("sentinel.rs");
        std::fs::write(&sentinel, "pub const OUTSIDE: bool = true;").unwrap();
        symlink(&sentinel, dir.join("escaped.rs")).unwrap();

        let mut scanner = WorkspaceScanner::new(dir.to_string_lossy().to_string());
        let error = scanner.scan_workspace().await.unwrap_err();
        assert!(matches!(error, WorkspaceError::UnsafePath(_)));
        assert!(
            scanner.files.is_empty(),
            "outside source must not be indexed"
        );

        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn anchored_open_rejects_symlinked_ancestor() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir("ancestor_root");
        let outside = temp_dir("ancestor_outside");
        std::fs::write(
            outside.join("sentinel.rs"),
            "pub const OUTSIDE: bool = true;",
        )
        .unwrap();
        symlink(&outside, dir.join("swapped")).unwrap();

        let root = WorkspaceScanner::open_root(dir.to_string_lossy().as_ref())
            .await
            .unwrap()
            .unwrap();
        let relative = Path::new("swapped/sentinel.rs");
        let escaped = root.canonical.join(relative);
        let mut total = 0;
        let error = WorkspaceScanner::read_regular_file(&root, relative, &escaped, &mut total)
            .await
            .unwrap_err();
        assert!(matches!(error, WorkspaceError::UnsafePath(_)));
        assert_eq!(total, 0, "rejected source must not consume a read budget");

        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    #[tokio::test]
    async fn rejects_oversized_rust_source_before_reading_it() {
        let dir = temp_dir("oversized");
        let file = std::fs::File::create(dir.join("large.rs")).unwrap();
        file.set_len(MAX_RUST_FILE_BYTES + 1).unwrap();

        let mut scanner = WorkspaceScanner::new(dir.to_string_lossy().to_string());
        let error = scanner.scan_workspace().await.unwrap_err();
        assert!(matches!(error, WorkspaceError::LimitExceeded(_)));
        assert!(
            scanner.files.is_empty(),
            "oversized source must not be indexed"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
