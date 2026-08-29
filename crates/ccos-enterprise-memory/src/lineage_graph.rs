use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use crate::{MemoryAssetDescriptor, MemoryAssetId, MemorySpace};

/// Retrieval eligibility of one governed memory asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryAssetState {
    /// The asset and every registered ancestor are currently valid.
    Active,
    /// An ancestor was invalidated; this derived asset must be revalidated or rebuilt.
    Stale,
    /// This exact asset was explicitly invalidated.
    Invalidated,
}

/// Deterministic result of an explicit invalidation operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryInvalidationReport {
    pub invalidated: MemoryAssetId,
    pub stale_descendants: BTreeSet<MemoryAssetId>,
}

/// Validation failures for the governed lineage graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryGraphError {
    DuplicateAsset(MemoryAssetId),
    UnknownAsset(MemoryAssetId),
    UnknownParent(MemoryAssetId),
    ParentNotActive {
        parent: MemoryAssetId,
        state: MemoryAssetState,
    },
    CrossSpaceDerivation {
        parent: MemoryAssetId,
        parent_space: MemorySpace,
        child_space: MemorySpace,
    },
}

impl fmt::Display for MemoryGraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateAsset(id) => write!(f, "memory asset already registered: {}", id.as_str()),
            Self::UnknownAsset(id) => write!(f, "unknown memory asset: {}", id.as_str()),
            Self::UnknownParent(id) => write!(f, "unknown memory parent: {}", id.as_str()),
            Self::ParentNotActive { parent, state } => write!(
                f,
                "memory parent {} is not active ({state:?})",
                parent.as_str()
            ),
            Self::CrossSpaceDerivation {
                parent,
                parent_space,
                child_space,
            } => write!(
                f,
                "memory derivation would cross spaces for parent {}: {parent_space:?} -> {child_space:?}",
                parent.as_str()
            ),
        }
    }
}

impl std::error::Error for MemoryGraphError {}

/// In-memory governance index for lineage validity.
///
/// This graph contains metadata only: no semantic payloads, embeddings or
/// backend handles. Derived assets may only be registered from already-known,
/// active parents in the same [`MemorySpace`]. That fail-closed rule prevents a
/// derivation step from silently widening an asset's collaboration boundary.
/// Explicit cross-space promotion can be layered above this contract with its
/// own authorization and evidence requirements.
#[derive(Debug, Default)]
pub struct MemoryLineageGraph {
    assets: BTreeMap<MemoryAssetId, MemoryAssetDescriptor>,
    children: BTreeMap<MemoryAssetId, BTreeSet<MemoryAssetId>>,
    states: BTreeMap<MemoryAssetId, MemoryAssetState>,
}

impl MemoryLineageGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register one descriptor after validating all graph-level invariants.
    pub fn register(&mut self, descriptor: MemoryAssetDescriptor) -> Result<(), MemoryGraphError> {
        if self.assets.contains_key(&descriptor.id) {
            return Err(MemoryGraphError::DuplicateAsset(descriptor.id));
        }

        for parent_id in descriptor.lineage.parents() {
            let Some(parent) = self.assets.get(parent_id) else {
                return Err(MemoryGraphError::UnknownParent(parent_id.clone()));
            };
            let state = self
                .states
                .get(parent_id)
                .copied()
                .unwrap_or(MemoryAssetState::Active);
            if state != MemoryAssetState::Active {
                return Err(MemoryGraphError::ParentNotActive {
                    parent: parent_id.clone(),
                    state,
                });
            }
            if parent.space != descriptor.space {
                return Err(MemoryGraphError::CrossSpaceDerivation {
                    parent: parent_id.clone(),
                    parent_space: parent.space.clone(),
                    child_space: descriptor.space.clone(),
                });
            }
        }

        let id = descriptor.id.clone();
        for parent_id in descriptor.lineage.parents() {
            self.children
                .entry(parent_id.clone())
                .or_default()
                .insert(id.clone());
        }
        self.states.insert(id.clone(), MemoryAssetState::Active);
        self.assets.insert(id, descriptor);
        Ok(())
    }

    pub fn descriptor(&self, id: &MemoryAssetId) -> Option<&MemoryAssetDescriptor> {
        self.assets.get(id)
    }

    pub fn state(&self, id: &MemoryAssetId) -> Option<MemoryAssetState> {
        self.states.get(id).copied()
    }

    pub fn len(&self) -> usize {
        self.assets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.assets.is_empty()
    }

    /// Explicitly invalidate one asset and mark all of its derived descendants stale.
    ///
    /// Invalidated descendants are never downgraded back to `Stale`. The returned
    /// descendant set is sorted and deduplicated for stable audit/event payloads.
    pub fn invalidate(
        &mut self,
        id: &MemoryAssetId,
    ) -> Result<MemoryInvalidationReport, MemoryGraphError> {
        if !self.assets.contains_key(id) {
            return Err(MemoryGraphError::UnknownAsset(id.clone()));
        }
        self.states
            .insert(id.clone(), MemoryAssetState::Invalidated);

        let mut queue = VecDeque::new();
        if let Some(children) = self.children.get(id) {
            queue.extend(children.iter().cloned());
        }

        let mut stale_descendants = BTreeSet::new();
        while let Some(current) = queue.pop_front() {
            if !stale_descendants.insert(current.clone()) {
                continue;
            }
            if self.state(&current) != Some(MemoryAssetState::Invalidated) {
                self.states.insert(current.clone(), MemoryAssetState::Stale);
            }
            if let Some(children) = self.children.get(&current) {
                queue.extend(children.iter().cloned());
            }
        }

        Ok(MemoryInvalidationReport {
            invalidated: id.clone(),
            stale_descendants,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryEvidenceRef, MemoryLineage, MemoryStratum};

    fn id(value: &str) -> MemoryAssetId {
        MemoryAssetId::new(value).unwrap()
    }

    fn root(value: &str, space: MemorySpace) -> MemoryAssetDescriptor {
        MemoryAssetDescriptor::new(
            id(value),
            space,
            MemoryStratum::Evidence,
            MemoryLineage::root([MemoryEvidenceRef::new(format!("audit:{value}")).unwrap()]).unwrap(),
        )
        .unwrap()
    }

    fn derived(
        value: &str,
        space: MemorySpace,
        stratum: MemoryStratum,
        parents: impl IntoIterator<Item = MemoryAssetId>,
    ) -> MemoryAssetDescriptor {
        MemoryAssetDescriptor::new(
            id(value),
            space,
            stratum,
            MemoryLineage::derived(parents, []).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn registration_requires_known_active_parents() {
        let mut graph = MemoryLineageGraph::new();
        let child = derived(
            "episode",
            MemorySpace::Tenant,
            MemoryStratum::Episode,
            [id("missing")],
        );
        assert_eq!(
            graph.register(child),
            Err(MemoryGraphError::UnknownParent(id("missing")))
        );
    }

    #[test]
    fn derivation_cannot_silently_widen_or_change_space() {
        let mut graph = MemoryLineageGraph::new();
        let agent = MemorySpace::agent("reviewer").unwrap();
        graph.register(root("evidence", agent.clone())).unwrap();

        let promoted = derived(
            "episode",
            MemorySpace::Tenant,
            MemoryStratum::Episode,
            [id("evidence")],
        );
        assert_eq!(
            graph.register(promoted),
            Err(MemoryGraphError::CrossSpaceDerivation {
                parent: id("evidence"),
                parent_space: agent,
                child_space: MemorySpace::Tenant,
            })
        );
    }

    #[test]
    fn invalidation_propagates_staleness_transitively() {
        let mut graph = MemoryLineageGraph::new();
        let space = MemorySpace::project("ccos").unwrap();
        graph.register(root("e0", space.clone())).unwrap();
        graph
            .register(derived(
                "e1",
                space.clone(),
                MemoryStratum::Episode,
                [id("e0")],
            ))
            .unwrap();
        graph
            .register(derived(
                "e2",
                space,
                MemoryStratum::Context,
                [id("e1")],
            ))
            .unwrap();

        let report = graph.invalidate(&id("e0")).unwrap();
        assert_eq!(graph.state(&id("e0")), Some(MemoryAssetState::Invalidated));
        assert_eq!(graph.state(&id("e1")), Some(MemoryAssetState::Stale));
        assert_eq!(graph.state(&id("e2")), Some(MemoryAssetState::Stale));
        assert_eq!(report.stale_descendants, BTreeSet::from([id("e1"), id("e2")]));
    }

    #[test]
    fn stale_parent_cannot_seed_new_derived_memory() {
        let mut graph = MemoryLineageGraph::new();
        let space = MemorySpace::Tenant;
        graph.register(root("root", space.clone())).unwrap();
        graph
            .register(derived(
                "episode",
                space.clone(),
                MemoryStratum::Episode,
                [id("root")],
            ))
            .unwrap();
        graph.invalidate(&id("root")).unwrap();

        let child = derived(
            "context",
            space,
            MemoryStratum::Context,
            [id("episode")],
        );
        assert_eq!(
            graph.register(child),
            Err(MemoryGraphError::ParentNotActive {
                parent: id("episode"),
                state: MemoryAssetState::Stale,
            })
        );
    }

    #[test]
    fn later_upstream_invalidation_never_downgrades_explicit_invalidation() {
        let mut graph = MemoryLineageGraph::new();
        let space = MemorySpace::Tenant;
        graph.register(root("root", space.clone())).unwrap();
        graph
            .register(derived(
                "episode",
                space,
                MemoryStratum::Episode,
                [id("root")],
            ))
            .unwrap();

        graph.invalidate(&id("episode")).unwrap();
        graph.invalidate(&id("root")).unwrap();
        assert_eq!(
            graph.state(&id("episode")),
            Some(MemoryAssetState::Invalidated)
        );
    }
}
