use std::fmt;

use crate::{
    MemoryAssetId, MemoryAssetState, MemoryGraphError, MemoryInvalidationReport, MemoryLineageGraph,
};

/// Retention intent for one governed memory asset.
///
/// Time is always supplied by the caller. This contract never reads the system
/// clock, which keeps replay, audit and tests deterministic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryRetentionPolicy {
    /// No automatic expiration. Explicit governance may still invalidate the asset.
    Retain,
    /// Automatically invalidate the asset at or after this Unix timestamp.
    ExpireAt { unix_seconds: u64 },
}

/// Deterministic result of applying a retention policy at one explicit time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryRetentionOutcome {
    /// The asset remains active under the policy at the supplied time.
    Retained,
    /// The asset was already stale or invalidated, so retention performed no mutation.
    AlreadyInactive(MemoryAssetState),
    /// Expiration invalidated the asset and propagated staleness through lineage.
    Expired(MemoryInvalidationReport),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryRetentionError {
    UnknownAsset(MemoryAssetId),
    Graph(MemoryGraphError),
}

impl fmt::Display for MemoryRetentionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownAsset(id) => write!(f, "unknown memory asset: {}", id.as_str()),
            Self::Graph(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for MemoryRetentionError {}

/// Apply one asset's retention policy without consulting a wall clock.
///
/// Expiration reuses the lineage graph's invalidation path, so descendants are
/// made stale rather than silently surviving with revoked ancestry. This
/// operation does not delete semantic payload bytes; physical purge belongs to
/// the provider/storage layer after governance has recorded the invalidation.
pub fn apply_memory_retention(
    graph: &mut MemoryLineageGraph,
    asset_id: &MemoryAssetId,
    policy: MemoryRetentionPolicy,
    now_unix_seconds: u64,
) -> Result<MemoryRetentionOutcome, MemoryRetentionError> {
    let state = graph
        .state(asset_id)
        .ok_or_else(|| MemoryRetentionError::UnknownAsset(asset_id.clone()))?;

    if state != MemoryAssetState::Active {
        return Ok(MemoryRetentionOutcome::AlreadyInactive(state));
    }

    match policy {
        MemoryRetentionPolicy::Retain => Ok(MemoryRetentionOutcome::Retained),
        MemoryRetentionPolicy::ExpireAt { unix_seconds } if now_unix_seconds < unix_seconds => {
            Ok(MemoryRetentionOutcome::Retained)
        }
        MemoryRetentionPolicy::ExpireAt { .. } => graph
            .invalidate(asset_id)
            .map(MemoryRetentionOutcome::Expired)
            .map_err(MemoryRetentionError::Graph),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryAssetDescriptor, MemoryEvidenceRef, MemoryLineage, MemorySpace, MemoryStratum};

    fn id(value: &str) -> MemoryAssetId {
        MemoryAssetId::new(value).unwrap()
    }

    fn root(value: &str) -> MemoryAssetDescriptor {
        MemoryAssetDescriptor::new(
            id(value),
            MemorySpace::Tenant,
            MemoryStratum::Evidence,
            MemoryLineage::root([MemoryEvidenceRef::new(format!("audit:{value}")).unwrap()])
                .unwrap(),
        )
        .unwrap()
    }

    fn child(value: &str, parent: &str) -> MemoryAssetDescriptor {
        MemoryAssetDescriptor::new(
            id(value),
            MemorySpace::Tenant,
            MemoryStratum::Episode,
            MemoryLineage::derived([id(parent)], []).unwrap(),
        )
        .unwrap()
    }

    fn graph() -> MemoryLineageGraph {
        let mut graph = MemoryLineageGraph::new();
        graph.register(root("root")).unwrap();
        graph.register(child("child", "root")).unwrap();
        graph
    }

    #[test]
    fn retain_policy_never_auto_invalidates() {
        let mut graph = graph();
        assert_eq!(
            apply_memory_retention(&mut graph, &id("root"), MemoryRetentionPolicy::Retain, u64::MAX)
                .unwrap(),
            MemoryRetentionOutcome::Retained
        );
        assert_eq!(graph.state(&id("root")), Some(MemoryAssetState::Active));
        assert_eq!(graph.state(&id("child")), Some(MemoryAssetState::Active));
    }

    #[test]
    fn expiry_is_inclusive_at_deadline() {
        let mut graph = graph();
        let policy = MemoryRetentionPolicy::ExpireAt { unix_seconds: 100 };

        assert_eq!(
            apply_memory_retention(&mut graph, &id("root"), policy, 99).unwrap(),
            MemoryRetentionOutcome::Retained
        );
        let outcome = apply_memory_retention(&mut graph, &id("root"), policy, 100).unwrap();
        assert!(matches!(outcome, MemoryRetentionOutcome::Expired(_)));
        assert_eq!(
            graph.state(&id("root")),
            Some(MemoryAssetState::Invalidated)
        );
        assert_eq!(graph.state(&id("child")), Some(MemoryAssetState::Stale));
    }

    #[test]
    fn expiration_report_preserves_lineage_impact() {
        let mut graph = graph();
        let outcome = apply_memory_retention(
            &mut graph,
            &id("root"),
            MemoryRetentionPolicy::ExpireAt { unix_seconds: 1 },
            2,
        )
        .unwrap();
        let MemoryRetentionOutcome::Expired(report) = outcome else {
            panic!("expected expiration");
        };
        assert_eq!(report.invalidated, id("root"));
        assert_eq!(report.stale_descendants.into_iter().collect::<Vec<_>>(), vec![id("child")]);
    }

    #[test]
    fn already_inactive_asset_is_not_mutated_again() {
        let mut graph = graph();
        graph.invalidate(&id("root")).unwrap();
        assert_eq!(
            apply_memory_retention(
                &mut graph,
                &id("root"),
                MemoryRetentionPolicy::ExpireAt { unix_seconds: 1 },
                2,
            )
            .unwrap(),
            MemoryRetentionOutcome::AlreadyInactive(MemoryAssetState::Invalidated)
        );
    }

    #[test]
    fn unknown_asset_fails_closed() {
        let mut graph = MemoryLineageGraph::new();
        assert_eq!(
            apply_memory_retention(
                &mut graph,
                &id("missing"),
                MemoryRetentionPolicy::Retain,
                0,
            ),
            Err(MemoryRetentionError::UnknownAsset(id("missing")))
        );
    }
}
