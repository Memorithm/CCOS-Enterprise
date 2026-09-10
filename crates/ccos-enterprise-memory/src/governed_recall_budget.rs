use std::collections::BTreeSet;

use ccos_enterprise_tenancy::TenantScope;

use crate::{
    BudgetedMemoryRecall, GovernedMemoryObservation, GovernedSemanticMemoryProvider,
    LoadoutMemoryQuery, MemoryRecallBudgetError,
};

/// Bounded recall for identity-preserving governed semantic-memory providers.
///
/// The provider receives only the explicit loadout and the bounded item/shortlist
/// limits. The response is then revalidated before any lineage or trust decision:
/// an observation from a non-loadout space or with a non-finite similarity fails
/// closed, while whole payloads are admitted only inside the aggregate byte budget.
pub trait GovernedSemanticMemoryProviderExt: GovernedSemanticMemoryProvider {
    fn recall_governed_bounded(
        &self,
        scoped: TenantScope<BudgetedMemoryRecall<'_>>,
    ) -> Result<Vec<GovernedMemoryObservation>, MemoryRecallBudgetError> {
        let TenantScope { tenant, inner } = scoped;
        let allowed_spaces: BTreeSet<_> = inner.loadout.spaces().cloned().collect();
        let query = LoadoutMemoryQuery {
            embedding: inner.embedding,
            k: inner.budget.max_items(),
            shortlist: inner.budget.max_shortlist(),
            loadout: inner.loadout,
        };
        let observations = self
            .recall_governed(TenantScope::new(tenant, query))
            .map_err(MemoryRecallBudgetError::Provider)?;

        let mut accepted = Vec::with_capacity(observations.len().min(inner.budget.max_items()));
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
            if accepted.len() >= inner.budget.max_items() {
                break;
            }
            let next_bytes = payload_bytes.saturating_add(observation.payload.len());
            if next_bytes > inner.budget.max_payload_bytes() {
                continue;
            }
            payload_bytes = next_bytes;
            accepted.push(observation);
        }
        Ok(accepted)
    }
}

impl<T: GovernedSemanticMemoryProvider + ?Sized> GovernedSemanticMemoryProviderExt for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        GovernedMemoryWrite, MemoryAssetId, MemoryError, MemoryLoadout, MemoryRecallBudget,
        MemorySpace,
    };

    struct Provider {
        observations: Vec<GovernedMemoryObservation>,
    }

    impl GovernedSemanticMemoryProvider for Provider {
        fn insert_governed(
            &mut self,
            _scoped: TenantScope<GovernedMemoryWrite<'_>>,
        ) -> Result<(), MemoryError> {
            Ok(())
        }

        fn recall_governed(
            &self,
            scoped: TenantScope<LoadoutMemoryQuery<'_>>,
        ) -> Result<Vec<GovernedMemoryObservation>, MemoryError> {
            assert_eq!(scoped.inner.k, 2);
            assert_eq!(scoped.inner.shortlist, 4);
            Ok(self.observations.clone())
        }
    }

    fn observation(
        id: &str,
        space: MemorySpace,
        payload: &[u8],
        similarity: f32,
    ) -> GovernedMemoryObservation {
        GovernedMemoryObservation {
            asset_id: MemoryAssetId::new(id).unwrap(),
            space,
            payload: payload.to_vec(),
            similarity,
        }
    }

    fn scoped<'a>(
        embedding: &'a [f32],
        loadout: &'a MemoryLoadout,
    ) -> TenantScope<BudgetedMemoryRecall<'a>> {
        TenantScope::new(
            ccos_enterprise_tenancy::TenantId("acme".into()),
            BudgetedMemoryRecall {
                embedding,
                loadout,
                budget: MemoryRecallBudget::new(2, 4, 5).unwrap(),
            },
        )
    }

    #[test]
    fn governed_recall_is_bounded_without_losing_asset_identity() {
        let provider = Provider {
            observations: vec![
                observation("large", MemorySpace::Tenant, b"123456", 0.9),
                observation("kept-a", MemorySpace::Tenant, b"abc", 0.8),
                observation("kept-b", MemorySpace::Tenant, b"de", 0.7),
                observation("extra", MemorySpace::Tenant, b"x", 0.6),
            ],
        };
        let loadout = MemoryLoadout::tenant_only();
        let embedding = [1.0_f32, 0.0];
        let recalled = provider
            .recall_governed_bounded(scoped(&embedding, &loadout))
            .unwrap();
        assert_eq!(
            recalled
                .iter()
                .map(|item| item.asset_id.as_str())
                .collect::<Vec<_>>(),
            vec!["kept-a", "kept-b"]
        );
        assert_eq!(recalled.iter().map(|item| item.payload.len()).sum::<usize>(), 5);
    }

    #[test]
    fn provider_cannot_escape_the_requested_loadout() {
        let provider = Provider {
            observations: vec![observation(
                "leak",
                MemorySpace::project("other").unwrap(),
                b"x",
                1.0,
            )],
        };
        let loadout = MemoryLoadout::tenant_only();
        let embedding = [1.0_f32, 0.0];
        assert!(matches!(
            provider.recall_governed_bounded(scoped(&embedding, &loadout)),
            Err(MemoryRecallBudgetError::ProviderReturnedUnauthorizedSpace(
                MemorySpace::Project(id)
            )) if id == "other"
        ));
    }

    #[test]
    fn non_finite_similarity_fails_closed_before_governance_use() {
        let provider = Provider {
            observations: vec![observation("nan", MemorySpace::Tenant, b"x", f32::NAN)],
        };
        let loadout = MemoryLoadout::tenant_only();
        let embedding = [1.0_f32, 0.0];
        assert_eq!(
            provider.recall_governed_bounded(scoped(&embedding, &loadout)),
            Err(MemoryRecallBudgetError::ProviderReturnedNonFiniteSimilarity)
        );
    }
}
