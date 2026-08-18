//! Bounded deterministic graph queries over canonical Knowledge Plane state.
//!
//! This crate is a read-only view. It owns no graph database and has no mutation API.
//! External Neo4j/RDF/etc. backends can later implement rebuildable projections, while
//! this view defines graph semantics directly from the P0 canonical state.
//!
//! Historical transaction-time queries are performed by first calling
//! `KnowledgeState::replay_at` and then creating a [`GraphView`] over that snapshot.
//! This avoids inventing a second temporal index for entities inside the graph layer.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use ccos_enterprise_knowledge::{KnowledgeState, TenantKnowledge};
use ccos_enterprise_knowledge_model::{
    EntityId, EntityRecord, EvidenceId, RelationId, RelationRecord, TenantId, UnixMillis,
};

pub const KG_CONTRACT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraphLimits {
    pub max_depth: usize,
    pub max_visited: usize,
    pub max_results: usize,
}

impl Default for GraphLimits {
    fn default() -> Self {
        Self {
            max_depth: 16,
            max_visited: 10_000,
            max_results: 1_000,
        }
    }
}

impl GraphLimits {
    pub fn validate(self) -> Result<Self, GraphError> {
        if self.max_depth == 0 || self.max_visited == 0 || self.max_results == 0 {
            return Err(GraphError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphEdge {
    pub id: RelationId,
    pub from: EntityId,
    pub relation: String,
    pub to: EntityId,
    pub evidence: BTreeSet<EvidenceId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphPath {
    /// Ordered entities from source through target, inclusive.
    pub entities: Vec<EntityId>,
    /// Relation IDs in the same traversal order. `relations.len() + 1 == entities.len()`.
    pub relations: Vec<RelationId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphError {
    InvalidLimits,
    UnknownTenant,
    UnknownEntity(EntityId),
    ResultLimitExceeded { limit: usize },
    VisitLimitExceeded { limit: usize },
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => f.write_str("graph limits must all be greater than zero"),
            Self::UnknownTenant => f.write_str("tenant knowledge partition does not exist"),
            Self::UnknownEntity(id) => write!(f, "unknown entity {id}"),
            Self::ResultLimitExceeded { limit } => {
                write!(f, "graph query exceeded {limit}-result bound")
            }
            Self::VisitLimitExceeded { limit } => {
                write!(f, "graph query exceeded {limit}-visited-node bound")
            }
        }
    }
}

impl std::error::Error for GraphError {}

pub struct GraphView<'a> {
    tenant: &'a TenantKnowledge,
    valid_time: UnixMillis,
    limits: GraphLimits,
}

impl<'a> GraphView<'a> {
    pub fn new(
        state: &'a KnowledgeState,
        tenant: &TenantId,
        valid_time: UnixMillis,
        limits: GraphLimits,
    ) -> Result<Self, GraphError> {
        let tenant = state.tenant(tenant).ok_or(GraphError::UnknownTenant)?;
        Ok(Self {
            tenant,
            valid_time,
            limits: limits.validate()?,
        })
    }

    pub fn entity(&self, id: &EntityId) -> Result<&'a EntityRecord, GraphError> {
        self.tenant
            .entities
            .get(id)
            .ok_or_else(|| GraphError::UnknownEntity(id.clone()))
    }

    pub fn entity_count(&self) -> usize {
        self.tenant.entities.len()
    }

    pub fn outgoing(
        &self,
        entity: &EntityId,
        relation_filter: Option<&str>,
    ) -> Result<Vec<GraphEdge>, GraphError> {
        self.entity(entity)?;
        let mut edges: Vec<_> = self
            .tenant
            .relations
            .values()
            .filter(|record| {
                relation_visible(record, self.valid_time)
                    && &record.assertion.from == entity
                    && relation_filter.is_none_or(|name| record.assertion.relation == name)
            })
            .map(graph_edge)
            .collect();
        edges.sort_by(|left, right| {
            (&left.to, &left.relation, &left.id).cmp(&(&right.to, &right.relation, &right.id))
        });
        self.bound_results(edges)
    }

    pub fn incoming(
        &self,
        entity: &EntityId,
        relation_filter: Option<&str>,
    ) -> Result<Vec<GraphEdge>, GraphError> {
        self.entity(entity)?;
        let mut edges: Vec<_> = self
            .tenant
            .relations
            .values()
            .filter(|record| {
                relation_visible(record, self.valid_time)
                    && &record.assertion.to == entity
                    && relation_filter.is_none_or(|name| record.assertion.relation == name)
            })
            .map(graph_edge)
            .collect();
        edges.sort_by(|left, right| {
            (&left.from, &left.relation, &left.id).cmp(&(&right.from, &right.relation, &right.id))
        });
        self.bound_results(edges)
    }

    /// Deterministic breadth-first shortest path following outgoing relations only.
    pub fn shortest_path(
        &self,
        from: &EntityId,
        to: &EntityId,
        relation_filter: Option<&str>,
    ) -> Result<Option<GraphPath>, GraphError> {
        self.entity(from)?;
        self.entity(to)?;
        if from == to {
            return Ok(Some(GraphPath {
                entities: vec![from.clone()],
                relations: Vec::new(),
            }));
        }

        let mut queue = VecDeque::from([(from.clone(), 0_usize)]);
        let mut visited = BTreeSet::from([from.clone()]);
        let mut parent: BTreeMap<EntityId, (EntityId, RelationId)> = BTreeMap::new();

        while let Some((current, depth)) = queue.pop_front() {
            if depth >= self.limits.max_depth {
                continue;
            }
            for edge in self.outgoing(&current, relation_filter)? {
                if !visited.insert(edge.to.clone()) {
                    continue;
                }
                if visited.len() > self.limits.max_visited {
                    return Err(GraphError::VisitLimitExceeded {
                        limit: self.limits.max_visited,
                    });
                }
                parent.insert(edge.to.clone(), (current.clone(), edge.id.clone()));
                if &edge.to == to {
                    return Ok(Some(reconstruct_path(from, to, &parent)));
                }
                queue.push_back((edge.to, depth + 1));
            }
        }
        Ok(None)
    }

    /// All entities reachable by outgoing edges within the configured depth, excluding root.
    pub fn descendants(
        &self,
        root: &EntityId,
        relation_filter: Option<&str>,
    ) -> Result<Vec<EntityId>, GraphError> {
        self.walk(root, relation_filter, true)
    }

    /// All entities that can reach root through matching edges, within the configured depth.
    pub fn ancestors(
        &self,
        root: &EntityId,
        relation_filter: Option<&str>,
    ) -> Result<Vec<EntityId>, GraphError> {
        self.walk(root, relation_filter, false)
    }

    fn walk(
        &self,
        root: &EntityId,
        relation_filter: Option<&str>,
        outgoing: bool,
    ) -> Result<Vec<EntityId>, GraphError> {
        self.entity(root)?;
        let mut queue = VecDeque::from([(root.clone(), 0_usize)]);
        let mut visited = BTreeSet::from([root.clone()]);

        while let Some((current, depth)) = queue.pop_front() {
            if depth >= self.limits.max_depth {
                continue;
            }
            let edges = if outgoing {
                self.outgoing(&current, relation_filter)?
            } else {
                self.incoming(&current, relation_filter)?
            };
            for edge in edges {
                let next = if outgoing { edge.to } else { edge.from };
                if !visited.insert(next.clone()) {
                    continue;
                }
                if visited.len() > self.limits.max_visited {
                    return Err(GraphError::VisitLimitExceeded {
                        limit: self.limits.max_visited,
                    });
                }
                if visited.len() - 1 > self.limits.max_results {
                    return Err(GraphError::ResultLimitExceeded {
                        limit: self.limits.max_results,
                    });
                }
                queue.push_back((next, depth + 1));
            }
        }
        visited.remove(root);
        Ok(visited.into_iter().collect())
    }

    fn bound_results<T>(&self, results: Vec<T>) -> Result<Vec<T>, GraphError> {
        if results.len() > self.limits.max_results {
            Err(GraphError::ResultLimitExceeded {
                limit: self.limits.max_results,
            })
        } else {
            Ok(results)
        }
    }
}

fn relation_visible(record: &RelationRecord, valid_time: UnixMillis) -> bool {
    record.invalidated_at.is_none() && record.assertion.validity.contains(valid_time)
}

fn graph_edge(record: &RelationRecord) -> GraphEdge {
    GraphEdge {
        id: record.assertion.id.clone(),
        from: record.assertion.from.clone(),
        relation: record.assertion.relation.clone(),
        to: record.assertion.to.clone(),
        evidence: record.assertion.evidence.clone(),
    }
}

fn reconstruct_path(
    from: &EntityId,
    to: &EntityId,
    parent: &BTreeMap<EntityId, (EntityId, RelationId)>,
) -> GraphPath {
    let mut entities = vec![to.clone()];
    let mut relations = Vec::new();
    let mut cursor = to.clone();
    while &cursor != from {
        let (previous, relation) = parent
            .get(&cursor)
            .expect("every discovered non-root node has a parent");
        relations.push(relation.clone());
        entities.push(previous.clone());
        cursor = previous.clone();
    }
    entities.reverse();
    relations.reverse();
    GraphPath {
        entities,
        relations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ccos_enterprise_knowledge::{JournalEntry, KnowledgeOp};
    use ccos_enterprise_knowledge_model::{
        AssertionKind, EntityRecord, EvidenceId, EvidenceRecord, RelationAssertion, SourceId,
        SourceRecord, SourceTrust, ValidityInterval,
    };

    fn tenant() -> TenantId {
        TenantId("acme".into())
    }

    fn evidence() -> BTreeSet<EvidenceId> {
        BTreeSet::from([EvidenceId::from("evidence:1")])
    }

    fn state() -> KnowledgeState {
        let tenant = tenant();
        let mut entries = vec![
            JournalEntry::new(
                0,
                KnowledgeOp::RegisterSource(SourceRecord {
                    id: SourceId::from("source:1"),
                    tenant: tenant.clone(),
                    locator: "memory://test".into(),
                    content_hash: Some("sha256:test".into()),
                    trust: SourceTrust::Internal,
                }),
            ),
            JournalEntry::new(
                1,
                KnowledgeOp::AddEvidence(EvidenceRecord {
                    id: EvidenceId::from("evidence:1"),
                    tenant: tenant.clone(),
                    source: SourceId::from("source:1"),
                    locator: Some("bytes:0-1".into()),
                    content_hash: Some("sha256:test".into()),
                }),
            ),
        ];
        for (index, id) in ["a", "b", "c", "d"].into_iter().enumerate() {
            entries.push(JournalEntry::new(
                (index + 2) as u64,
                KnowledgeOp::AddEntity(EntityRecord {
                    id: EntityId::from(id),
                    tenant: tenant.clone(),
                    namespace: None,
                    entity_type: "node".into(),
                    label: Some(id.into()),
                    evidence: evidence(),
                    kind: AssertionKind::Observation,
                }),
            ));
        }
        let relation = |sequence: u64, id: &str, from: &str, to: &str, valid_until| {
            JournalEntry::new(
                sequence,
                KnowledgeOp::AssertRelation(RelationAssertion {
                    id: RelationId::from(id),
                    tenant: tenant.clone(),
                    from: EntityId::from(from),
                    relation: "depends_on".into(),
                    to: EntityId::from(to),
                    validity: ValidityInterval {
                        valid_from: Some(UnixMillis(0)),
                        valid_until,
                    },
                    evidence: evidence(),
                    kind: AssertionKind::Observation,
                }),
            )
        };
        entries.extend([
            relation(6, "r:a-b", "a", "b", None),
            relation(7, "r:a-c", "a", "c", None),
            relation(8, "r:b-d", "b", "d", None),
            relation(9, "r:c-d", "c", "d", Some(UnixMillis(5))),
        ]);
        KnowledgeState::replay(entries).unwrap()
    }

    #[test]
    fn outgoing_edges_are_stably_ordered_and_valid_time_filtered() {
        let state = state();
        let view =
            GraphView::new(&state, &tenant(), UnixMillis(10), GraphLimits::default()).unwrap();
        let edges = view
            .outgoing(&EntityId::from("a"), Some("depends_on"))
            .unwrap();
        assert_eq!(
            edges
                .iter()
                .map(|edge| edge.to.as_str())
                .collect::<Vec<_>>(),
            vec!["b", "c"]
        );
        assert!(view
            .outgoing(&EntityId::from("c"), None)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn shortest_path_is_deterministic_under_equal_length_choices() {
        let state = state();
        let view =
            GraphView::new(&state, &tenant(), UnixMillis(1), GraphLimits::default()).unwrap();
        let path = view
            .shortest_path(
                &EntityId::from("a"),
                &EntityId::from("d"),
                Some("depends_on"),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            path.entities
                .iter()
                .map(EntityId::as_str)
                .collect::<Vec<_>>(),
            vec!["a", "b", "d"]
        );
        assert_eq!(
            path.relations
                .iter()
                .map(RelationId::as_str)
                .collect::<Vec<_>>(),
            vec!["r:a-b", "r:b-d"]
        );
    }

    #[test]
    fn descendants_and_ancestors_are_bounded_and_sorted() {
        let state = state();
        let view =
            GraphView::new(&state, &tenant(), UnixMillis(1), GraphLimits::default()).unwrap();
        assert_eq!(
            view.descendants(&EntityId::from("a"), Some("depends_on"))
                .unwrap(),
            vec![
                EntityId::from("b"),
                EntityId::from("c"),
                EntityId::from("d")
            ]
        );
        assert_eq!(
            view.ancestors(&EntityId::from("d"), Some("depends_on"))
                .unwrap(),
            vec![
                EntityId::from("a"),
                EntityId::from("b"),
                EntityId::from("c")
            ]
        );
    }

    #[test]
    fn visit_limit_fails_closed_instead_of_truncating_graph_semantics() {
        let state = state();
        let view = GraphView::new(
            &state,
            &tenant(),
            UnixMillis(1),
            GraphLimits {
                max_depth: 16,
                max_visited: 2,
                max_results: 100,
            },
        )
        .unwrap();
        assert_eq!(
            view.descendants(&EntityId::from("a"), None),
            Err(GraphError::VisitLimitExceeded { limit: 2 })
        );
    }
}
