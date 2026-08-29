use std::collections::BTreeSet;
use std::fmt;

use ccos_enterprise_tenancy::TenantScope;

use super::{
    LoadoutMemoryQuery, MemoryError, MemoryLoadout, MemorySpace, ScopedMemoryObservation,
    SemanticMemoryProvider,
};

/// Absolute safety ceilings for one semantic-memory recall.
pub const MAX_MEMORY_RECALL_ITEMS: usize = 1_024;
pub const MAX_MEMORY_RECALL_SHORTLIST: usize = 8_192;
pub const MAX_MEMORY_RECALL_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

/// Explicit resource budget for one semantic-memory recall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRecallBudget {
    max_items: usize,
    max_shortlist: usize,
    max_payload_bytes: usize,
}

impl MemoryRecallBudget {
    pub fn new(
        max_items: usize,
        max_shortlist: usize,
        max_payload_bytes: usize,
    ) -> Result<Self, MemoryRecallBudgetError> {
        validate_limit("max_items", max_items, MAX_MEMORY_RECALL_ITEMS)?;
        validate_limit("max_shortlist", max_shortlist, MAX_MEMORY_RECALL_SHORTLIST)?;
        validate_limit(
            "max_payload_bytes",
            max_payload_bytes,
            MAX_MEMORY_RECALL_PAYLOAD_BYTES,
        )?;
        if max_shortlist < max_items {
            return Err(MemoryRecallBudgetError::ShortlistBelowItems {
                max_items,
                max_shortlist,
            });
        }
        Ok(Self {
            max_items,
            max_shortlist,
            max_payload_bytes,
        })
    }

    pub const fn max_items(self) -> usize {
        self.max_items
    }
    pub const fn max_shortlist(self) -> usize {
        self.max_shortlist
    }
    pub const fn max_payload_bytes(self) -> usize {
        self.max_payload_bytes
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BudgetedMemoryRecall<'a> {
    pub embedding: &'a [f32],
    pub loadout: &'a MemoryLoadout,
    pub budget: MemoryRecallBudget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryRecallBudgetError {
    LimitOutOfRange {
        field: &'static str,
        found: usize,
        max: usize,
    },
    ShortlistBelowItems {
        max_items: usize,
        max_shortlist: usize,
    },
    Provider(MemoryError),
    ProviderReturnedUnauthorizedSpace(MemorySpace),
    ProviderReturnedNonFiniteSimilarity,
}

impl fmt::Display for MemoryRecallBudgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitOutOfRange { field, found, max } => {
                write!(f, "memory recall {field} {found} is outside 1..={max}")
            }
            Self::ShortlistBelowItems {
                max_items,
                max_shortlist,
            } => write!(
                f,
                "memory recall shortlist {max_shortlist} is smaller than item limit {max_items}"
            ),
            Self::Provider(error) => error.fmt(f),
            Self::ProviderReturnedUnauthorizedSpace(space) => write!(
                f,
                "memory provider returned observation from non-loadout space {space:?}"
            ),
            Self::ProviderReturnedNonFiniteSimilarity => {
                write!(f, "memory provider returned non-finite similarity")
            }
        }
    }
}

impl std::error::Error for MemoryRecallBudgetError {}

pub trait SemanticMemoryProviderExt: SemanticMemoryProvider {
    fn recall_loadout_bounded(
        &self,
        scoped: TenantScope<BudgetedMemoryRecall<'_>>,
    ) -> Result<Vec<ScopedMemoryObservation>, MemoryRecallBudgetError> {
        let TenantScope { tenant, inner } = scoped;
        let allowed_spaces: BTreeSet<_> = inner.loadout.spaces().cloned().collect();
        let query = LoadoutMemoryQuery {
            embedding: inner.embedding,
            k: inner.budget.max_items,
            shortlist: inner.budget.max_shortlist,
            loadout: inner.loadout,
        };
        let observations = self
            .recall_loadout(TenantScope::new(tenant, query))
            .map_err(MemoryRecallBudgetError::Provider)?;

        let mut accepted = Vec::with_capacity(observations.len().min(inner.budget.max_items));
        let mut payload_bytes = 0usize;
        for observation in observations {
            if !allowed_spaces.contains(&observation.space) {
                return Err(MemoryRecallBudgetError::ProviderReturnedUnauthorizedSpace(
                    observation.space,
                ));
            }
            if !observation.similarity.is_finite() {
                return Err(MemoryRecallBudgetError::ProviderReturnedNonFiniteSimilarity);
            }
            if accepted.len() >= inner.budget.max_items {
                break;
            }
            let next_bytes = payload_bytes.saturating_add(observation.payload.len());
            if next_bytes > inner.budget.max_payload_bytes {
                continue;
            }
            payload_bytes = next_bytes;
            accepted.push(observation);
        }
        Ok(accepted)
    }
}

impl<T: SemanticMemoryProvider + ?Sized> SemanticMemoryProviderExt for T {}

fn validate_limit(
    field: &'static str,
    found: usize,
    max: usize,
) -> Result<(), MemoryRecallBudgetError> {
    if found == 0 || found > max {
        Err(MemoryRecallBudgetError::LimitOutOfRange { field, found, max })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{MemorySpace, ScopedMemoryWrite};
    use super::*;

    struct Provider {
        observations: Vec<ScopedMemoryObservation>,
    }

    impl SemanticMemoryProvider for Provider {
        fn insert_scoped(
            &mut self,
            _scoped: TenantScope<ScopedMemoryWrite<'_>>,
        ) -> Result<(), MemoryError> {
            Ok(())
        }
        fn recall_loadout(
            &self,
            scoped: TenantScope<LoadoutMemoryQuery<'_>>,
        ) -> Result<Vec<ScopedMemoryObservation>, MemoryError> {
            assert_eq!(scoped.inner.k, 2);
            assert_eq!(scoped.inner.shortlist, 4);
            Ok(self.observations.clone())
        }
    }

    fn budget() -> MemoryRecallBudget {
        MemoryRecallBudget::new(2, 4, 5).unwrap()
    }
    fn tenant_scope<T>(value: T) -> TenantScope<T> {
        TenantScope::new(ccos_enterprise_tenancy::TenantId("acme".into()), value)
    }

    #[test]
    fn invalid_or_inverted_limits_fail_closed() {
        assert!(matches!(
            MemoryRecallBudget::new(0, 1, 1),
            Err(MemoryRecallBudgetError::LimitOutOfRange {
                field: "max_items",
                ..
            })
        ));
        assert_eq!(
            MemoryRecallBudget::new(3, 2, 10),
            Err(MemoryRecallBudgetError::ShortlistBelowItems {
                max_items: 3,
                max_shortlist: 2
            })
        );
    }

    #[test]
    fn response_is_bounded_without_truncating_payloads() {
        let provider = Provider {
            observations: vec![
                ScopedMemoryObservation {
                    space: MemorySpace::Tenant,
                    payload: vec![1, 2, 3, 4, 5, 6],
                    similarity: 0.9,
                },
                ScopedMemoryObservation {
                    space: MemorySpace::Tenant,
                    payload: vec![7, 8, 9],
                    similarity: 0.8,
                },
                ScopedMemoryObservation {
                    space: MemorySpace::Tenant,
                    payload: vec![10, 11],
                    similarity: 0.7,
                },
                ScopedMemoryObservation {
                    space: MemorySpace::Tenant,
                    payload: vec![12],
                    similarity: 0.6,
                },
            ],
        };
        let loadout = MemoryLoadout::tenant_only();
        let result = provider
            .recall_loadout_bounded(tenant_scope(BudgetedMemoryRecall {
                embedding: &[1.0, 0.0],
                loadout: &loadout,
                budget: budget(),
            }))
            .unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].payload, vec![7, 8, 9]);
        assert_eq!(result[1].payload, vec![10, 11]);
        assert_eq!(
            result.iter().map(|item| item.payload.len()).sum::<usize>(),
            5
        );
    }

    #[test]
    fn provider_cannot_escape_the_admitted_loadout() {
        let provider = Provider {
            observations: vec![ScopedMemoryObservation {
                space: MemorySpace::team("forbidden").unwrap(),
                payload: vec![1],
                similarity: 1.0,
            }],
        };
        let loadout = MemoryLoadout::tenant_only();
        let error = provider
            .recall_loadout_bounded(tenant_scope(BudgetedMemoryRecall {
                embedding: &[1.0],
                loadout: &loadout,
                budget: budget(),
            }))
            .unwrap_err();
        assert!(
            matches!(error, MemoryRecallBudgetError::ProviderReturnedUnauthorizedSpace(MemorySpace::Team(id)) if id == "forbidden")
        );
    }

    #[test]
    fn non_finite_provider_scores_fail_closed() {
        let provider = Provider {
            observations: vec![ScopedMemoryObservation {
                space: MemorySpace::Tenant,
                payload: vec![1],
                similarity: f32::NAN,
            }],
        };
        let loadout = MemoryLoadout::tenant_only();
        assert_eq!(
            provider.recall_loadout_bounded(tenant_scope(BudgetedMemoryRecall {
                embedding: &[1.0],
                loadout: &loadout,
                budget: budget()
            })),
            Err(MemoryRecallBudgetError::ProviderReturnedNonFiniteSimilarity)
        );
    }
}
