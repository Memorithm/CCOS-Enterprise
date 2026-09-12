impl MemoryLineageGraph {
    /// Every registered asset and its current eligibility, in asset-id order.
    pub fn entries(&self) -> Vec<(MemoryAssetDescriptor, MemoryAssetState)> {
        self.assets
            .iter()
            .map(|(id, descriptor)| {
                (
                    descriptor.clone(),
                    self.state(id).unwrap_or(MemoryAssetState::Active),
                )
            })
            .collect()
    }

    /// Rebuild lineage including stale and invalidated assets.
    ///
    /// Unlike [`Self::from_active_descriptors`], parents need not be active: a
    /// persisted child of an invalidated parent must still reconstruct. An
    /// asset saved as `Active` while an ancestor is not is refused rather than
    /// silently repaired.
    pub fn restore(
        descriptors: impl IntoIterator<Item = MemoryAssetDescriptor>,
        states: impl IntoIterator<Item = (MemoryAssetId, MemoryAssetState)>,
    ) -> Result<Self, MemoryGraphError> {
        let mut pending = BTreeMap::new();
        for descriptor in descriptors {
            let id = descriptor.id.clone();
            if pending.insert(id.clone(), descriptor).is_some() {
                return Err(MemoryGraphError::DuplicateAsset(id));
            }
        }

        let mut graph = Self::new();
        while !pending.is_empty() {
            let ready: Vec<_> = pending
                .iter()
                .filter(|(_, descriptor)| {
                    descriptor
                        .lineage
                        .parents()
                        .all(|parent| graph.assets.contains_key(parent))
                })
                .map(|(id, _)| id.clone())
                .collect();
            if ready.is_empty() {
                return Err(MemoryGraphError::UnresolvedImportParents(
                    pending.keys().cloned().collect(),
                ));
            }
            for id in ready {
                let descriptor = pending
                    .remove(&id)
                    .expect("ready ids are selected from pending descriptors");
                graph.register_restored(descriptor)?;
            }
        }

        let mut saved = BTreeMap::new();
        for (id, state) in states {
            if !graph.assets.contains_key(&id) {
                return Err(MemoryGraphError::UnknownAsset(id));
            }
            saved.insert(id, state);
        }
        for id in graph.assets.keys() {
            let state = saved.get(id).copied().unwrap_or(MemoryAssetState::Active);
            graph.states.insert(id.clone(), state);
        }
        for (id, state) in &graph.states {
            if *state != MemoryAssetState::Active {
                continue;
            }
            for parent in graph.assets[id].lineage.parents() {
                let parent_state = graph
                    .states
                    .get(parent)
                    .copied()
                    .unwrap_or(MemoryAssetState::Active);
                if parent_state != MemoryAssetState::Active {
                    return Err(MemoryGraphError::ParentNotActive {
                        parent: parent.clone(),
                        state: parent_state,
                    });
                }
            }
        }
        Ok(graph)
    }

    fn register_restored(
        &mut self,
        descriptor: MemoryAssetDescriptor,
    ) -> Result<(), MemoryGraphError> {
        if self.assets.contains_key(&descriptor.id) {
            return Err(MemoryGraphError::DuplicateAsset(descriptor.id));
        }
        for parent_id in descriptor.lineage.parents() {
            let Some(parent) = self.assets.get(parent_id) else {
                return Err(MemoryGraphError::UnknownParent(parent_id.clone()));
            };
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
}
