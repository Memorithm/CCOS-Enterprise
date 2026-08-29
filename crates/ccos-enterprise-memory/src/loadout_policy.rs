use std::collections::BTreeSet;
use std::fmt;

use super::{MemoryError, MemoryLoadout, MemorySpace};

/// Hard bound on the number of memory spaces that may be equipped at once.
///
/// Keeping the policy bounded prevents an agent configuration from silently
/// expanding into an unbounded cross-project/team retrieval surface.
pub const MAX_MEMORY_LOADOUT_BINDINGS: usize = 64;

/// How one equipped memory space may participate in an agent interaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemoryUsageMode {
    /// Eligible only for bounded bootstrap/context assembly.
    Bootstrap,
    /// Eligible only for explicit on-demand retrieval.
    OnDemand,
    /// Eligible for both bootstrap and on-demand retrieval.
    BootstrapAndOnDemand,
}

impl MemoryUsageMode {
    pub const fn allows_bootstrap(self) -> bool {
        matches!(self, Self::Bootstrap | Self::BootstrapAndOnDemand)
    }

    pub const fn allows_on_demand(self) -> bool {
        matches!(self, Self::OnDemand | Self::BootstrapAndOnDemand)
    }
}

/// One governed memory-space binding inside an agent loadout.
///
/// `priority` is an ordering hint only. It never grants access and cannot widen
/// the `MemorySpace`; authorization must already have admitted the binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryLoadoutBinding {
    pub space: MemorySpace,
    pub priority: u16,
    pub usage: MemoryUsageMode,
}

impl MemoryLoadoutBinding {
    pub fn new(
        space: MemorySpace,
        priority: u16,
        usage: MemoryUsageMode,
    ) -> Result<Self, MemoryLoadoutPlanError> {
        space.validate().map_err(MemoryLoadoutPlanError::Memory)?;
        Ok(Self {
            space,
            priority,
            usage,
        })
    }
}

/// Deterministic, bounded set of memory-space bindings for one agent/runtime.
///
/// Bindings are sorted by descending priority and then by `MemorySpace`. A space
/// may occur only once: callers must make usage intent explicit rather than
/// relying on conflict resolution between duplicate bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryLoadoutPlan {
    bindings: Vec<MemoryLoadoutBinding>,
}

impl MemoryLoadoutPlan {
    pub fn new(
        bindings: impl IntoIterator<Item = MemoryLoadoutBinding>,
    ) -> Result<Self, MemoryLoadoutPlanError> {
        let mut bindings: Vec<_> = bindings.into_iter().collect();
        if bindings.is_empty() {
            return Err(MemoryLoadoutPlanError::Empty);
        }
        if bindings.len() > MAX_MEMORY_LOADOUT_BINDINGS {
            return Err(MemoryLoadoutPlanError::TooManyBindings {
                found: bindings.len(),
                max: MAX_MEMORY_LOADOUT_BINDINGS,
            });
        }

        let mut seen = BTreeSet::new();
        for binding in &bindings {
            binding
                .space
                .validate()
                .map_err(MemoryLoadoutPlanError::Memory)?;
            if !seen.insert(binding.space.clone()) {
                return Err(MemoryLoadoutPlanError::DuplicateSpace(
                    binding.space.clone(),
                ));
            }
        }

        bindings.sort_by(|left, right| {
            right
                .priority
                .cmp(&left.priority)
                .then_with(|| left.space.cmp(&right.space))
        });
        Ok(Self { bindings })
    }

    pub fn bindings(&self) -> impl Iterator<Item = &MemoryLoadoutBinding> {
        self.bindings.iter()
    }

    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    /// Build the exact space allow-list eligible for bootstrap assembly.
    pub fn bootstrap_loadout(&self) -> Result<Option<MemoryLoadout>, MemoryLoadoutPlanError> {
        self.filtered_loadout(MemoryUsageMode::allows_bootstrap)
    }

    /// Build the exact space allow-list eligible for explicit retrieval.
    pub fn on_demand_loadout(&self) -> Result<Option<MemoryLoadout>, MemoryLoadoutPlanError> {
        self.filtered_loadout(MemoryUsageMode::allows_on_demand)
    }

    fn filtered_loadout(
        &self,
        allowed: impl Fn(MemoryUsageMode) -> bool,
    ) -> Result<Option<MemoryLoadout>, MemoryLoadoutPlanError> {
        let spaces: Vec<_> = self
            .bindings
            .iter()
            .filter(|binding| allowed(binding.usage))
            .map(|binding| binding.space.clone())
            .collect();
        if spaces.is_empty() {
            Ok(None)
        } else {
            MemoryLoadout::new(spaces)
                .map(Some)
                .map_err(MemoryLoadoutPlanError::Memory)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryLoadoutPlanError {
    Empty,
    TooManyBindings { found: usize, max: usize },
    DuplicateSpace(MemorySpace),
    Memory(MemoryError),
}

impl fmt::Display for MemoryLoadoutPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "memory loadout plan must contain at least one binding"),
            Self::TooManyBindings { found, max } => {
                write!(f, "memory loadout plan has {found} bindings; maximum is {max}")
            }
            Self::DuplicateSpace(space) => {
                write!(f, "memory loadout plan contains duplicate space {space:?}")
            }
            Self::Memory(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for MemoryLoadoutPlanError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(space: MemorySpace, priority: u16, usage: MemoryUsageMode) -> MemoryLoadoutBinding {
        MemoryLoadoutBinding::new(space, priority, usage).unwrap()
    }

    #[test]
    fn plan_is_deterministic_by_priority_then_space() {
        let project = MemorySpace::project("ccos").unwrap();
        let team = MemorySpace::team("runtime").unwrap();
        let plan = MemoryLoadoutPlan::new([
            binding(team.clone(), 10, MemoryUsageMode::OnDemand),
            binding(project.clone(), 20, MemoryUsageMode::Bootstrap),
            binding(MemorySpace::Tenant, 20, MemoryUsageMode::BootstrapAndOnDemand),
        ])
        .unwrap();

        assert_eq!(
            plan.bindings()
                .map(|binding| binding.space.clone())
                .collect::<Vec<_>>(),
            vec![MemorySpace::Tenant, project, team]
        );
    }

    #[test]
    fn duplicate_spaces_fail_closed_even_when_modes_differ() {
        let space = MemorySpace::team("runtime").unwrap();
        let result = MemoryLoadoutPlan::new([
            binding(space.clone(), 10, MemoryUsageMode::Bootstrap),
            binding(space.clone(), 20, MemoryUsageMode::OnDemand),
        ]);
        assert_eq!(result, Err(MemoryLoadoutPlanError::DuplicateSpace(space)));
    }

    #[test]
    fn malformed_raw_space_fails_at_binding_boundary() {
        let result = MemoryLoadoutBinding::new(
            MemorySpace::Agent(String::new()),
            1,
            MemoryUsageMode::OnDemand,
        );
        assert!(matches!(
            result,
            Err(MemoryLoadoutPlanError::Memory(MemoryError::InvalidMemorySpace {
                kind: "agent"
            }))
        ));
    }

    #[test]
    fn usage_modes_produce_narrow_loadouts() {
        let tenant = binding(
            MemorySpace::Tenant,
            100,
            MemoryUsageMode::BootstrapAndOnDemand,
        );
        let project_space = MemorySpace::project("ccos").unwrap();
        let team_space = MemorySpace::team("runtime").unwrap();
        let plan = MemoryLoadoutPlan::new([
            tenant,
            binding(
                project_space.clone(),
                90,
                MemoryUsageMode::Bootstrap,
            ),
            binding(team_space.clone(), 80, MemoryUsageMode::OnDemand),
        ])
        .unwrap();

        let bootstrap = plan.bootstrap_loadout().unwrap().unwrap();
        assert_eq!(
            bootstrap.spaces().cloned().collect::<Vec<_>>(),
            vec![MemorySpace::Tenant, project_space]
        );

        let on_demand = plan.on_demand_loadout().unwrap().unwrap();
        assert_eq!(
            on_demand.spaces().cloned().collect::<Vec<_>>(),
            vec![MemorySpace::Tenant, team_space]
        );
    }

    #[test]
    fn absent_usage_class_returns_none_without_scope_widening() {
        let plan = MemoryLoadoutPlan::new([binding(
            MemorySpace::Tenant,
            1,
            MemoryUsageMode::Bootstrap,
        )])
        .unwrap();
        assert!(plan.on_demand_loadout().unwrap().is_none());
    }

    #[test]
    fn binding_count_is_bounded() {
        let bindings = (0..=MAX_MEMORY_LOADOUT_BINDINGS)
            .map(|index| {
                binding(
                    MemorySpace::agent(format!("agent-{index}" )).unwrap(),
                    0,
                    MemoryUsageMode::OnDemand,
                )
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            MemoryLoadoutPlan::new(bindings),
            Err(MemoryLoadoutPlanError::TooManyBindings { found, max })
                if found == MAX_MEMORY_LOADOUT_BINDINGS + 1 && max == MAX_MEMORY_LOADOUT_BINDINGS
        ));
    }
}
