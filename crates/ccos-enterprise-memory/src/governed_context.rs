use std::collections::BTreeMap;

use crate::{
    GovernedMemoryObservation, MemoryContextBudget, MemoryContextError, MemoryLoadoutPlan,
};

/// Structured bootstrap context whose chunks retain their governed asset identity.
///
/// Keeping `MemoryAssetId` attached after admission lets downstream audit and
/// provenance code explain exactly which memory assets entered an agent context.
#[derive(Debug, Clone, PartialEq)]
pub struct GovernedMemoryContextAssembly {
    chunks: Vec<GovernedMemoryObservation>,
    payload_bytes: usize,
}

impl GovernedMemoryContextAssembly {
    pub fn chunks(&self) -> &[GovernedMemoryObservation] {
        &self.chunks
    }

    pub fn into_chunks(self) -> Vec<GovernedMemoryObservation> {
        self.chunks
    }

    pub const fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }

    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }
}

/// Assemble a bounded bootstrap context from observations that have already
/// crossed governed recall admission.
///
/// The function deliberately does not evaluate trust itself: callers must first
/// use the governed recall gate, making the order of operations explicit. This
/// boundary then rechecks bootstrap-space admission, finite similarity, item
/// count and aggregate payload bytes while preserving `MemoryAssetId`.
pub fn assemble_governed_bootstrap_context(
    plan: &MemoryLoadoutPlan,
    observations: impl IntoIterator<Item = GovernedMemoryObservation>,
    budget: MemoryContextBudget,
) -> Result<GovernedMemoryContextAssembly, MemoryContextError> {
    let priorities: BTreeMap<_, _> = plan
        .bindings()
        .filter(|binding| binding.usage.allows_bootstrap())
        .map(|binding| (binding.space.clone(), binding.priority))
        .collect();

    let mut candidates = Vec::new();
    for (input_order, observation) in observations.into_iter().enumerate() {
        let Some(priority) = priorities.get(&observation.space).copied() else {
            return Err(MemoryContextError::ObservationOutsideBootstrapLoadout(
                observation.space,
            ));
        };
        if !observation.similarity.is_finite() {
            return Err(MemoryContextError::NonFiniteSimilarity);
        }
        candidates.push((priority, input_order, observation));
    }

    candidates.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| right.2.similarity.total_cmp(&left.2.similarity))
            .then_with(|| left.2.space.cmp(&right.2.space))
            .then_with(|| left.2.asset_id.cmp(&right.2.asset_id))
            .then_with(|| left.1.cmp(&right.1))
    });

    let mut chunks = Vec::with_capacity(candidates.len().min(budget.max_items()));
    let mut payload_bytes = 0usize;
    for (_, _, observation) in candidates {
        if chunks.len() >= budget.max_items() {
            break;
        }
        let next_bytes = payload_bytes.saturating_add(observation.payload.len());
        if next_bytes > budget.max_payload_bytes() {
            continue;
        }
        payload_bytes = next_bytes;
        chunks.push(observation);
    }

    Ok(GovernedMemoryContextAssembly {
        chunks,
        payload_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MemoryAssetId, MemoryLoadoutBinding, MemorySpace, MemoryUsageMode,
    };

    fn binding(space: MemorySpace, priority: u16, usage: MemoryUsageMode) -> MemoryLoadoutBinding {
        MemoryLoadoutBinding::new(space, priority, usage).unwrap()
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

    fn plan() -> MemoryLoadoutPlan {
        MemoryLoadoutPlan::new([
            binding(
                MemorySpace::Tenant,
                100,
                MemoryUsageMode::BootstrapAndOnDemand,
            ),
            binding(
                MemorySpace::project("ccos").unwrap(),
                80,
                MemoryUsageMode::Bootstrap,
            ),
            binding(
                MemorySpace::team("runtime").unwrap(),
                70,
                MemoryUsageMode::OnDemand,
            ),
        ])
        .unwrap()
    }

    #[test]
    fn governed_context_preserves_asset_identity() {
        let assembly = assemble_governed_bootstrap_context(
            &plan(),
            [observation(
                "asset:1",
                MemorySpace::Tenant,
                b"payload",
                0.9,
            )],
            MemoryContextBudget::new(4, 64).unwrap(),
        )
        .unwrap();
        assert_eq!(assembly.len(), 1);
        assert_eq!(assembly.chunks()[0].asset_id.as_str(), "asset:1");
        assert_eq!(assembly.chunks()[0].payload, b"payload");
    }

    #[test]
    fn on_demand_only_space_fails_closed() {
        let error = assemble_governed_bootstrap_context(
            &plan(),
            [observation(
                "asset:hidden",
                MemorySpace::team("runtime").unwrap(),
                b"hidden",
                1.0,
            )],
            MemoryContextBudget::new(4, 64).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            MemoryContextError::ObservationOutsideBootstrapLoadout(MemorySpace::Team(id))
                if id == "runtime"
        ));
    }

    #[test]
    fn priority_beats_similarity_without_becoming_authority() {
        let project = MemorySpace::project("ccos").unwrap();
        let assembly = assemble_governed_bootstrap_context(
            &plan(),
            [
                observation("project", project, b"project", 0.99),
                observation("tenant", MemorySpace::Tenant, b"tenant", 0.1),
            ],
            MemoryContextBudget::new(4, 64).unwrap(),
        )
        .unwrap();
        assert_eq!(assembly.chunks()[0].asset_id.as_str(), "tenant");
        assert_eq!(assembly.chunks()[1].asset_id.as_str(), "project");
    }

    #[test]
    fn byte_budget_skips_whole_payloads_and_preserves_ids() {
        let plan = MemoryLoadoutPlan::new([binding(
            MemorySpace::Tenant,
            1,
            MemoryUsageMode::Bootstrap,
        )])
        .unwrap();
        let assembly = assemble_governed_bootstrap_context(
            &plan,
            [
                observation("large", MemorySpace::Tenant, b"123456", 0.9),
                observation("small-a", MemorySpace::Tenant, b"abc", 0.8),
                observation("small-b", MemorySpace::Tenant, b"de", 0.7),
            ],
            MemoryContextBudget::new(3, 5).unwrap(),
        )
        .unwrap();
        assert_eq!(assembly.payload_bytes(), 5);
        assert_eq!(
            assembly
                .chunks()
                .iter()
                .map(|chunk| chunk.asset_id.as_str())
                .collect::<Vec<_>>(),
            vec!["small-a", "small-b"]
        );
    }

    #[test]
    fn non_finite_similarity_fails_closed() {
        assert_eq!(
            assemble_governed_bootstrap_context(
                &plan(),
                [observation("nan", MemorySpace::Tenant, b"x", f32::NAN)],
                MemoryContextBudget::new(1, 1).unwrap(),
            ),
            Err(MemoryContextError::NonFiniteSimilarity)
        );
    }
}
