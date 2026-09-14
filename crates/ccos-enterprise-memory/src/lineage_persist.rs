impl MemoryLineageGraph {
    /// Every registered asset and its current eligibility, in asset-id order.
    pub fn entries(&self) -> Vec<(MemoryAssetDescriptor, MemoryAssetState)> {
        self.assets
            .iter()
            .map(|(id, descriptor)| (descriptor.clone(), self.states[id]))
            .collect()
    }

    /// Rebuild lineage including stale and invalidated assets.
    ///
    /// Every descriptor requires exactly one explicit state. Missing, duplicate
    /// or unknown state rows are rejected: restore never defaults to `Active`.
    /// Descriptors pass through the same validating registration path as live
    /// assets. The provisional graph remains private until saved states have
    /// been checked and installed, so inactive ancestors are never published as
    /// active. Active children of inactive parents are refused, not repaired.
    pub fn restore(
        descriptors: impl IntoIterator<Item = MemoryAssetDescriptor>,
        states: impl IntoIterator<Item = (MemoryAssetId, MemoryAssetState)>,
    ) -> Result<Self, MemoryGraphError> {
        let mut graph = Self::from_active_descriptors(descriptors)?;
        let mut saved = BTreeMap::new();
        for (id, state) in states {
            if !graph.assets.contains_key(&id) {
                return Err(MemoryGraphError::UnknownAsset(id));
            }
            if saved.insert(id.clone(), state).is_some() {
                return Err(MemoryGraphError::DuplicateAssetState(id));
            }
        }
        for id in graph.assets.keys() {
            if !saved.contains_key(id) {
                return Err(MemoryGraphError::MissingAssetState(id.clone()));
            }
        }
        for (id, descriptor) in &graph.assets {
            if saved[id] != MemoryAssetState::Active {
                continue;
            }
            for parent in descriptor.lineage.parents() {
                let parent_state = saved[parent];
                if parent_state != MemoryAssetState::Active {
                    return Err(MemoryGraphError::ParentNotActive {
                        parent: parent.clone(),
                        state: parent_state,
                    });
                }
            }
        }
        graph.states = saved;
        Ok(graph)
    }
}

#[cfg(test)]
mod persistence_tests {
    use super::*;
    use crate::{MemoryError, MemoryEvidenceRef, MemoryLineage, MemoryStratum};

    fn id(value: &str) -> MemoryAssetId {
        MemoryAssetId::new(value).unwrap()
    }

    fn root() -> MemoryAssetDescriptor {
        MemoryAssetDescriptor::new(
            id("root"),
            MemorySpace::Tenant,
            MemoryStratum::Evidence,
            MemoryLineage::root([MemoryEvidenceRef::new("audit:root").unwrap()]).unwrap(),
        )
        .unwrap()
    }

    fn child() -> MemoryAssetDescriptor {
        MemoryAssetDescriptor::new(
            id("child"),
            MemorySpace::Tenant,
            MemoryStratum::Episode,
            MemoryLineage::derived([id("root")], []).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn restore_does_not_default_a_missing_state_to_active() {
        assert_eq!(
            MemoryLineageGraph::restore([root()], []),
            Err(MemoryGraphError::MissingAssetState(id("root")))
        );
    }

    #[test]
    fn restore_rejects_identical_and_conflicting_duplicate_states() {
        for second in [MemoryAssetState::Active, MemoryAssetState::Invalidated] {
            assert_eq!(
                MemoryLineageGraph::restore(
                    [root()],
                    [(id("root"), MemoryAssetState::Active), (id("root"), second)],
                ),
                Err(MemoryGraphError::DuplicateAssetState(id("root")))
            );
        }
    }

    #[test]
    fn restore_rejects_state_for_an_unknown_asset() {
        assert_eq!(
            MemoryLineageGraph::restore([], [(id("unknown"), MemoryAssetState::Active)]),
            Err(MemoryGraphError::UnknownAsset(id("unknown")))
        );
    }

    #[test]
    fn inactive_lineage_round_trips_in_reverse_descriptor_order() {
        let graph = MemoryLineageGraph::restore(
            [child(), root()],
            [
                (id("child"), MemoryAssetState::Stale),
                (id("root"), MemoryAssetState::Invalidated),
            ],
        )
        .unwrap();
        assert_eq!(graph.state(&id("root")), Some(MemoryAssetState::Invalidated));
        assert_eq!(graph.state(&id("child")), Some(MemoryAssetState::Stale));
        assert!(graph.active_descriptors().is_empty());
        let entries = graph.entries();
        let restored = MemoryLineageGraph::restore(
            entries.iter().map(|(descriptor, _)| descriptor.clone()),
            entries.iter().map(|(descriptor, state)| (descriptor.id.clone(), *state)),
        )
        .unwrap();
        assert_eq!(restored, graph);
    }

    #[test]
    fn restore_rejects_active_child_of_inactive_parent() {
        assert_eq!(
            MemoryLineageGraph::restore(
                [child(), root()],
                [
                    (id("root"), MemoryAssetState::Invalidated),
                    (id("child"), MemoryAssetState::Active),
                ],
            ),
            Err(MemoryGraphError::ParentNotActive {
                parent: id("root"),
                state: MemoryAssetState::Invalidated,
            })
        );
    }

    #[test]
    fn public_descriptor_fields_cannot_bypass_live_or_restored_validation() {
        let mut invalid = root();
        invalid.stratum = MemoryStratum::Episode;
        let expected = MemoryGraphError::InvalidDescriptor(MemoryError::DerivedMemoryRequiresParent);
        let mut graph = MemoryLineageGraph::new();
        assert_eq!(graph.register(invalid.clone()), Err(expected.clone()));
        assert!(graph.is_empty());
        assert_eq!(
            MemoryLineageGraph::restore([invalid], [(id("root"), MemoryAssetState::Active)]),
            Err(expected)
        );
    }
}
