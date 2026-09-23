//! Exhaustive provenance registry bound to one governed lineage graph.
//!
//! This is intentionally separate from trust metadata. A registry is accepted
//! only when every graph asset has exactly one validated provenance class.

use std::collections::{BTreeMap, BTreeSet};

use crate::{MemoryAssetId, MemoryLineageGraph, MemoryProvenanceClass, MemoryProvenanceError};

/// Complete origin classification for one governed lineage graph.
///
/// Presence in this registry grants no trust or authorization; it only records
/// how each asset arose and is evaluated orthogonally to existing policy gates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryProvenanceRegistry {
    classes: BTreeMap<MemoryAssetId, MemoryProvenanceClass>,
}

impl MemoryProvenanceRegistry {
    /// Build an explicit exhaustive registry for one graph.
    pub fn new(
        graph: &MemoryLineageGraph,
        rows: impl IntoIterator<Item = (MemoryAssetId, MemoryProvenanceClass)>,
    ) -> Result<Self, MemoryProvenanceRegistryError> {
        let mut classes = BTreeMap::new();
        for (id, class) in rows {
            let descriptor = graph
                .descriptor(&id)
                .ok_or_else(|| MemoryProvenanceRegistryError::UnknownAsset(id.clone()))?;
            if classes.contains_key(&id) {
                return Err(MemoryProvenanceRegistryError::DuplicateAsset(id));
            }
            class.validate_for(descriptor).map_err(|source| {
                MemoryProvenanceRegistryError::InvalidClass {
                    asset: id.clone(),
                    source,
                }
            })?;
            classes.insert(id, class);
        }

        let expected: BTreeSet<_> = graph
            .entries()
            .into_iter()
            .map(|(descriptor, _)| descriptor.id)
            .collect();
        for id in expected {
            if !classes.contains_key(&id) {
                return Err(MemoryProvenanceRegistryError::MissingAsset(id));
            }
        }
        Ok(Self { classes })
    }

    /// Conservative migration for assets created before explicit provenance.
    ///
    /// Hypothetical is never inferred.
    pub fn inferred(graph: &MemoryLineageGraph) -> Self {
        let classes = graph
            .entries()
            .into_iter()
            .map(|(descriptor, _)| {
                let class = MemoryProvenanceClass::inferred(&descriptor);
                (descriptor.id, class)
            })
            .collect();
        Self { classes }
    }

    pub fn class(&self, id: &MemoryAssetId) -> Option<MemoryProvenanceClass> {
        self.classes.get(id).copied()
    }

    pub fn entries(&self) -> impl Iterator<Item = (&MemoryAssetId, MemoryProvenanceClass)> {
        self.classes.iter().map(|(id, class)| (id, *class))
    }

    pub fn len(&self) -> usize {
        self.classes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryProvenanceRegistryError {
    UnknownAsset(MemoryAssetId),
    DuplicateAsset(MemoryAssetId),
    MissingAsset(MemoryAssetId),
    InvalidClass {
        asset: MemoryAssetId,
        source: MemoryProvenanceError,
    },
}

impl std::fmt::Display for MemoryProvenanceRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownAsset(id) => write!(f, "provenance names unknown asset {}", id.as_str()),
            Self::DuplicateAsset(id) => {
                write!(f, "duplicate provenance row for asset {}", id.as_str())
            }
            Self::MissingAsset(id) => {
                write!(f, "missing provenance row for asset {}", id.as_str())
            }
            Self::InvalidClass { asset, source } => {
                write!(
                    f,
                    "invalid provenance for asset {}: {source}",
                    asset.as_str()
                )
            }
        }
    }
}

impl std::error::Error for MemoryProvenanceRegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidClass { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MemoryAssetDescriptor, MemoryEvidenceRef, MemoryLineage, MemorySpace, MemoryStratum,
    };

    fn id(value: &str) -> MemoryAssetId {
        MemoryAssetId::new(value).unwrap()
    }

    fn graph() -> MemoryLineageGraph {
        let mut graph = MemoryLineageGraph::new();
        graph
            .register(
                MemoryAssetDescriptor::new(
                    id("source"),
                    MemorySpace::Tenant,
                    MemoryStratum::Evidence,
                    MemoryLineage::root([MemoryEvidenceRef::new("source:1").unwrap()]).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        graph
            .register(
                MemoryAssetDescriptor::new(
                    id("candidate"),
                    MemorySpace::Tenant,
                    MemoryStratum::Episode,
                    MemoryLineage::derived([id("source")], []).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        graph
    }

    #[test]
    fn inferred_registry_is_exhaustive_and_never_hypothetical() {
        let registry = MemoryProvenanceRegistry::inferred(&graph());
        assert_eq!(registry.len(), 2);
        assert_eq!(
            registry.class(&id("source")),
            Some(MemoryProvenanceClass::Observed)
        );
        assert_eq!(
            registry.class(&id("candidate")),
            Some(MemoryProvenanceClass::Derived)
        );
    }

    #[test]
    fn explicit_hypothetical_derived_asset_is_preserved() {
        let registry = MemoryProvenanceRegistry::new(
            &graph(),
            [
                (id("source"), MemoryProvenanceClass::Observed),
                (id("candidate"), MemoryProvenanceClass::Hypothetical),
            ],
        )
        .unwrap();
        assert_eq!(
            registry.class(&id("candidate")),
            Some(MemoryProvenanceClass::Hypothetical)
        );
    }

    #[test]
    fn missing_unknown_duplicate_and_invalid_rows_fail_closed() {
        let graph = graph();
        assert!(matches!(
            MemoryProvenanceRegistry::new(
                &graph,
                [(id("source"), MemoryProvenanceClass::Observed)]
            ),
            Err(MemoryProvenanceRegistryError::MissingAsset(_))
        ));
        assert!(matches!(
            MemoryProvenanceRegistry::new(
                &graph,
                [
                    (id("source"), MemoryProvenanceClass::Observed),
                    (id("candidate"), MemoryProvenanceClass::Derived),
                    (id("ghost"), MemoryProvenanceClass::Derived),
                ]
            ),
            Err(MemoryProvenanceRegistryError::UnknownAsset(_))
        ));
        assert!(matches!(
            MemoryProvenanceRegistry::new(
                &graph,
                [
                    (id("source"), MemoryProvenanceClass::Observed),
                    (id("source"), MemoryProvenanceClass::Observed),
                    (id("candidate"), MemoryProvenanceClass::Derived),
                ]
            ),
            Err(MemoryProvenanceRegistryError::DuplicateAsset(_))
        ));
        assert!(matches!(
            MemoryProvenanceRegistry::new(
                &graph,
                [
                    (id("source"), MemoryProvenanceClass::Hypothetical),
                    (id("candidate"), MemoryProvenanceClass::Derived),
                ]
            ),
            Err(MemoryProvenanceRegistryError::InvalidClass { .. })
        ));
    }
}
