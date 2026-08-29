use std::collections::BTreeMap;
use std::fmt;

use super::{MemoryLoadoutPlan, MemorySpace, ScopedMemoryObservation};

/// Absolute safety ceilings for bootstrap memory context assembly.
pub const MAX_MEMORY_CONTEXT_ITEMS: usize = 256;
pub const MAX_MEMORY_CONTEXT_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// Hard limits for memory that may be carried into an agent bootstrap context.
///
/// The budget is intentionally independent from provider shortlist limits. Recall
/// may inspect more candidates than the runtime is willing to carry forward as
/// context, but context assembly never widens the admitted loadout or truncates
/// an individual payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryContextBudget {
    max_items: usize,
    max_payload_bytes: usize,
}

impl MemoryContextBudget {
    pub fn new(max_items: usize, max_payload_bytes: usize) -> Result<Self, MemoryContextError> {
        validate_limit("max_items", max_items, MAX_MEMORY_CONTEXT_ITEMS)?;
        validate_limit(
            "max_payload_bytes",
            max_payload_bytes,
            MAX_MEMORY_CONTEXT_PAYLOAD_BYTES,
        )?;
        Ok(Self {
            max_items,
            max_payload_bytes,
        })
    }

    pub const fn max_items(self) -> usize {
        self.max_items
    }

    pub const fn max_payload_bytes(self) -> usize {
        self.max_payload_bytes
    }
}

/// Structured bootstrap context. Payloads remain distinct data chunks rather
/// than being concatenated into instructions or a prompt string.
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryContextAssembly {
    chunks: Vec<ScopedMemoryObservation>,
    payload_bytes: usize,
}

impl MemoryContextAssembly {
    pub fn chunks(&self) -> &[ScopedMemoryObservation] {
        &self.chunks
    }

    pub fn into_chunks(self) -> Vec<ScopedMemoryObservation> {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryContextError {
    LimitOutOfRange {
        field: &'static str,
        found: usize,
        max: usize,
    },
    ObservationOutsideBootstrapLoadout(MemorySpace),
    NonFiniteSimilarity,
}

impl fmt::Display for MemoryContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitOutOfRange { field, found, max } => {
                write!(f, "memory context {field} {found} is outside 1..={max}")
            }
            Self::ObservationOutsideBootstrapLoadout(space) => write!(
                f,
                "memory context observation came from non-bootstrap space {space:?}"
            ),
            Self::NonFiniteSimilarity => {
                write!(f, "memory context observation has non-finite similarity")
            }
        }
    }
}

impl std::error::Error for MemoryContextError {}

/// Assemble a bounded, structured bootstrap memory context from already-recalled
/// observations.
///
/// Every observation is rechecked against the plan's bootstrap bindings. Binding
/// priority determines cross-space ordering; similarity orders candidates within
/// equal-priority bindings. Neither field grants access. Oversized chunks are
/// skipped whole so byte budgets never corrupt or partially reinterpret payloads.
pub fn assemble_bootstrap_context(
    plan: &MemoryLoadoutPlan,
    observations: impl IntoIterator<Item = ScopedMemoryObservation>,
    budget: MemoryContextBudget,
) -> Result<MemoryContextAssembly, MemoryContextError> {
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
            .then_with(|| left.1.cmp(&right.1))
    });

    let mut chunks = Vec::with_capacity(candidates.len().min(budget.max_items));
    let mut payload_bytes = 0usize;
    for (_, _, observation) in candidates {
        if chunks.len() >= budget.max_items {
            break;
        }
        let next_bytes = payload_bytes.saturating_add(observation.payload.len());
        if next_bytes > budget.max_payload_bytes {
            continue;
        }
        payload_bytes = next_bytes;
        chunks.push(observation);
    }

    Ok(MemoryContextAssembly {
        chunks,
        payload_bytes,
    })
}

fn validate_limit(field: &'static str, found: usize, max: usize) -> Result<(), MemoryContextError> {
    if found == 0 || found > max {
        Err(MemoryContextError::LimitOutOfRange { field, found, max })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryLoadoutBinding, MemoryUsageMode};

    fn binding(space: MemorySpace, priority: u16, usage: MemoryUsageMode) -> MemoryLoadoutBinding {
        MemoryLoadoutBinding::new(space, priority, usage).unwrap()
    }

    fn observation(space: MemorySpace, payload: &[u8], similarity: f32) -> ScopedMemoryObservation {
        ScopedMemoryObservation {
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
    fn context_budget_is_hard_bounded() {
        assert!(matches!(
            MemoryContextBudget::new(0, 1),
            Err(MemoryContextError::LimitOutOfRange {
                field: "max_items",
                ..
            })
        ));
        assert!(matches!(
            MemoryContextBudget::new(1, MAX_MEMORY_CONTEXT_PAYLOAD_BYTES + 1),
            Err(MemoryContextError::LimitOutOfRange {
                field: "max_payload_bytes",
                ..
            })
        ));
    }

    #[test]
    fn non_bootstrap_observation_fails_closed() {
        let error = assemble_bootstrap_context(
            &plan(),
            [observation(
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
    fn binding_priority_orders_cross_space_context() {
        let project = MemorySpace::project("ccos").unwrap();
        let assembly = assemble_bootstrap_context(
            &plan(),
            [
                observation(project, b"project-high-similarity", 0.99),
                observation(MemorySpace::Tenant, b"tenant", 0.10),
            ],
            MemoryContextBudget::new(4, 128).unwrap(),
        )
        .unwrap();
        assert_eq!(assembly.chunks()[0].space, MemorySpace::Tenant);
        assert_eq!(assembly.chunks()[1].payload, b"project-high-similarity");
    }

    #[test]
    fn byte_budget_skips_whole_chunks_and_can_admit_later_smaller_chunks() {
        let assembly = assemble_bootstrap_context(
            &MemoryLoadoutPlan::new([binding(MemorySpace::Tenant, 1, MemoryUsageMode::Bootstrap)])
                .unwrap(),
            [
                observation(MemorySpace::Tenant, b"123456", 0.9),
                observation(MemorySpace::Tenant, b"abc", 0.8),
                observation(MemorySpace::Tenant, b"de", 0.7),
            ],
            MemoryContextBudget::new(3, 5).unwrap(),
        )
        .unwrap();
        assert_eq!(assembly.payload_bytes(), 5);
        assert_eq!(assembly.len(), 2);
        assert_eq!(assembly.chunks()[0].payload, b"abc");
        assert_eq!(assembly.chunks()[1].payload, b"de");
    }

    #[test]
    fn non_finite_similarity_fails_closed() {
        let error = assemble_bootstrap_context(
            &plan(),
            [observation(MemorySpace::Tenant, b"x", f32::NAN)],
            MemoryContextBudget::new(1, 1).unwrap(),
        )
        .unwrap_err();
        assert_eq!(error, MemoryContextError::NonFiniteSimilarity);
    }
}
