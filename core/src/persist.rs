//! Kernel state persistence.
//!
//! A [`KernelSnapshot`] bundles the causal [`MemoryGraph`], the append-only
//! [`EventLog`] and the hash-chained [`DistributedEventLog`] into a single
//! self-describing JSON document so a session can be saved to disk and later
//! reloaded, verified or replayed (`ccos save` / `verify` / `replay`).

use crate::distributed_event_log::DistributedEventLog;
use crate::event_log::EventLog;
use crate::memory::MemoryGraph;
use serde::{Deserialize, Serialize};

const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelSnapshot {
    /// Crate version that wrote the snapshot (for forward-compat checks).
    pub version: String,
    pub graph: MemoryGraph,
    pub event_log: EventLog,
    pub dist_log: DistributedEventLog,
}

impl KernelSnapshot {
    pub fn new(graph: MemoryGraph, event_log: EventLog, dist_log: DistributedEventLog) -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            graph,
            event_log,
            dist_log,
        }
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Persist the snapshot to `path` as pretty JSON through the kernel's
    /// durable publication primitive: a private, exclusively-created sibling is
    /// synced, atomically renamed into place, then its parent directory is synced.
    pub fn save(&self, path: &str) -> std::io::Result<()> {
        let json = self
            .to_json()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        enforce_snapshot_size(json.len(), MAX_SNAPSHOT_BYTES)?;
        crate::util::write_durable(std::path::Path::new(path), json.as_bytes())
    }

    /// Load a snapshot previously written by [`KernelSnapshot::save`].
    pub fn load(path: &str) -> std::io::Result<Self> {
        let data = crate::bounded_file::read_regular_bounded(
            std::path::Path::new(path),
            MAX_SNAPSHOT_BYTES,
        )?;
        serde_json::from_slice(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Verify the snapshot's integrity without mutating it: both hash chains
    /// (the primary [`EventLog`] and the [`DistributedEventLog`]) must validate
    /// and the graph must hold no dangling edges. Returns the first failure as a
    /// message. This is the single integrity check shared by the load-and-verify
    /// path here and by the runtime restore in [`crate::persistence`].
    pub fn verify_integrity(&self) -> Result<(), String> {
        let dist = self.dist_log.verify_integrity();
        if !dist.valid {
            return Err(format!(
                "distributed-log chain invalid: {} error(s)",
                dist.errors.len()
            ));
        }
        let primary = self.event_log.verify_integrity();
        if !primary.valid {
            return Err(format!(
                "event-log chain invalid: {} error(s)",
                primary.errors.len()
            ));
        }
        let dangling = self.graph.dangling_edge_count();
        if dangling != 0 {
            return Err(format!("{dangling} dangling edge(s) in graph"));
        }
        Ok(())
    }

    /// Load a snapshot **and** verify its integrity ([`verify_integrity`](Self::verify_integrity)),
    /// failing with `InvalidData` if either hash chain or the graph is corrupt.
    pub fn load_verified(path: &str) -> std::io::Result<Self> {
        let snap = Self::load(path)?;
        snap.verify_integrity()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(snap)
    }
}

fn enforce_snapshot_size(size: usize, limit: usize) -> std::io::Result<()> {
    if size > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("snapshot exceeds {limit} byte limit"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_log::{EventPayload, EventType};
    use crate::memory::NodeType;

    fn empty_snapshot(version: &str) -> KernelSnapshot {
        let mut snapshot = KernelSnapshot::new(
            MemoryGraph::default(),
            EventLog::new("persist-test".into()),
            DistributedEventLog::new(),
        );
        snapshot.version = version.into();
        snapshot
    }

    #[test]
    fn writer_and_loader_share_the_snapshot_size_limit() {
        assert!(enforce_snapshot_size(8, 8).is_ok());
        let error = enforce_snapshot_size(9, 8).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_save_is_private_atomic_and_survives_crash_debris() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "ccos-snapshot-durable-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("snapshot.json");
        let path_str = path.to_str().unwrap();

        empty_snapshot("before").save(path_str).unwrap();

        // Model SIGKILL after the private sibling was written but before rename:
        // the published snapshot remains authoritative and loadable, while a
        // later save must ignore the orphan rather than exposing partial JSON.
        let orphan = dir.join("snapshot.json.tmp.crash-fragment");
        std::fs::write(&orphan, br#"{"version":"torn""#).unwrap();
        assert_eq!(KernelSnapshot::load(path_str).unwrap().version, "before");

        // Replacing a too-permissive target publishes a fresh private inode.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        empty_snapshot("after").save(path_str).unwrap();
        assert_eq!(KernelSnapshot::load(path_str).unwrap().version, "after");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read(&orphan).unwrap(), br#"{"version":"torn""#);

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn snapshot_json_roundtrip_preserves_state() {
        let mut graph = MemoryGraph::default();
        graph.upsert_node("a".into(), "A".into(), "x".into(), NodeType::Module);
        graph.upsert_node("b".into(), "B".into(), "y".into(), NodeType::Symbol);
        graph.add_edge(
            "a".into(),
            "b".into(),
            0.9,
            crate::memory::EdgeType::DependsOn,
        );

        let mut event_log = EventLog::new("persist-test".into());
        event_log.append(
            EventType::CycleStart,
            EventPayload::CycleEvent {
                cycle_number: 0,
                action: "init".into(),
            },
        );

        let mut dist_log = DistributedEventLog::new();
        dist_log.append("e0".into(), "kernel".into());

        let snap = KernelSnapshot::new(graph, event_log, dist_log);
        let json = snap.to_json().unwrap();
        let restored = KernelSnapshot::from_json(&json).unwrap();

        assert_eq!(restored.graph.node_count(), 2);
        assert_eq!(restored.graph.edge_count(), 1);
        assert_eq!(restored.event_log.event_count(), 1);
        assert!(restored.dist_log.verify_integrity().valid);
        assert_eq!(restored.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn verify_integrity_passes_clean_and_rejects_a_tampered_chain() {
        let mut graph = MemoryGraph::default();
        graph.upsert_node("a".into(), "A".into(), "x".into(), NodeType::Module);
        let mut dist_log = DistributedEventLog::new();
        dist_log.append("e0".into(), "kernel".into());
        let mut snap = KernelSnapshot::new(graph, EventLog::new("t".into()), dist_log);
        assert!(snap.verify_integrity().is_ok(), "a clean snapshot verifies");
        snap.dist_log.hash_chain[0].hash = "deadbeef".repeat(8);
        assert!(
            snap.verify_integrity().is_err(),
            "a tampered chain is rejected"
        );
    }
}
