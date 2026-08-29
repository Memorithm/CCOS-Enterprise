//! Governance contract for activating experimental/research execution modes.
//!
//! This module is deliberately policy-only. It does not retrieve memory, verify
//! human approvals, select a model/kernel, execute a research feature, or treat
//! evidence as authorization. Evidence references remain observations; an
//! approval reference becomes authoritative only after the dedicated approval
//! subsystem validates it against tenant/action/artifact/expiry/revocation.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::PolicyDecision;

const MAX_ID_BYTES: usize = 256;
const MAX_EVIDENCE_REFS: usize = 64;

/// Hard resource ceilings attached to one research activation policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResearchResourceCaps {
    /// Maximum logical history items admitted by the reference research rule.
    pub max_history_items: u64,
    /// Maximum memory footprint admitted by the policy, in bytes.
    pub max_memory_bytes: u64,
    /// Maximum wall-clock budget admitted for one governed execution, in milliseconds.
    pub max_wall_time_ms: u64,
}

impl ResearchResourceCaps {
    /// Validate non-zero hard ceilings.
    pub fn new(
        max_history_items: u64,
        max_memory_bytes: u64,
        max_wall_time_ms: u64,
    ) -> Result<Self, ResearchPolicyError> {
        if max_history_items == 0 {
            return Err(ResearchPolicyError::ZeroResourceCap("max_history_items"));
        }
        if max_memory_bytes == 0 {
            return Err(ResearchPolicyError::ZeroResourceCap("max_memory_bytes"));
        }
        if max_wall_time_ms == 0 {
            return Err(ResearchPolicyError::ZeroResourceCap("max_wall_time_ms"));
        }
        Ok(Self {
            max_history_items,
            max_memory_bytes,
            max_wall_time_ms,
        })
    }
}

/// Explicit policy response when reference history would exceed its hard cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundedHistoryFallback {
    /// Fail closed rather than changing the research semantic.
    Reject,
    /// Permit an explicitly classified bounded-history approximation.
    ///
    /// This is never equivalent to the reference rule merely because a
    /// particular input happens to fit inside the bound.
    Approximation {
        /// Maximum history items retained by the approved approximation.
        max_history_items: u64,
    },
}

/// Deterministic rollback action recorded in policy before activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchRollbackRule {
    /// Disable the research semantic and do not substitute another one.
    DisableResearchSemantic,
    /// Return to one explicitly named baseline semantic/revision.
    RestoreBaseline {
        /// Stable baseline semantic identifier.
        semantic_id: String,
        /// Exact baseline semantic revision.
        revision: u32,
    },
}

/// Human-approval requirement exposed to the authoritative approval subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResearchApprovalRequirement {
    /// Canonical approval action to validate, e.g. `research.activate`.
    pub action: String,
}

/// Governed policy for one exact research semantic revision.
///
/// Evidence references are prerequisites for review/audit, not authorization.
/// [`Self::activation_decision`] therefore remains
/// [`PolicyDecision::RequireApproval`] regardless of evidence count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResearchActivationPolicy {
    /// Stable research semantic identifier.
    pub semantic_id: String,
    /// Exact semantic revision governed by this policy.
    pub semantic_revision: u32,
    /// Immutable evidence/artifact references considered by governance.
    pub evidence_refs: Vec<String>,
    /// Hard resource ceilings.
    pub resource_caps: ResearchResourceCaps,
    /// Explicit handling of history-cap exhaustion.
    pub bounded_history_fallback: BoundedHistoryFallback,
    /// Predeclared rollback behavior.
    pub rollback: ResearchRollbackRule,
    /// Approval action that must be validated by the approval subsystem.
    pub approval: ResearchApprovalRequirement,
    /// Stable audit category for activation/resource/rollback events.
    pub audit_category: String,
}

impl ResearchActivationPolicy {
    /// Construct a validated research activation policy.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        semantic_id: impl Into<String>,
        semantic_revision: u32,
        evidence_refs: Vec<String>,
        resource_caps: ResearchResourceCaps,
        bounded_history_fallback: BoundedHistoryFallback,
        rollback: ResearchRollbackRule,
        approval_action: impl Into<String>,
        audit_category: impl Into<String>,
    ) -> Result<Self, ResearchPolicyError> {
        let semantic_id = semantic_id.into();
        validate_identifier("semantic_id", &semantic_id)?;
        if semantic_revision == 0 {
            return Err(ResearchPolicyError::ZeroSemanticRevision);
        }
        if evidence_refs.is_empty() {
            return Err(ResearchPolicyError::MissingEvidence);
        }
        if evidence_refs.len() > MAX_EVIDENCE_REFS {
            return Err(ResearchPolicyError::TooManyEvidenceReferences {
                count: evidence_refs.len(),
                max: MAX_EVIDENCE_REFS,
            });
        }
        let mut unique = BTreeSet::new();
        for evidence in &evidence_refs {
            validate_identifier("evidence_ref", evidence)?;
            if !unique.insert(evidence.as_str()) {
                return Err(ResearchPolicyError::DuplicateEvidenceReference(
                    evidence.clone(),
                ));
            }
        }

        if let BoundedHistoryFallback::Approximation { max_history_items } =
            bounded_history_fallback
        {
            if max_history_items == 0 {
                return Err(ResearchPolicyError::ZeroBoundedHistoryFallback);
            }
            if max_history_items > resource_caps.max_history_items {
                return Err(ResearchPolicyError::FallbackExceedsHistoryCap {
                    fallback: max_history_items,
                    cap: resource_caps.max_history_items,
                });
            }
        }

        if let ResearchRollbackRule::RestoreBaseline {
            semantic_id,
            revision,
        } = &rollback
        {
            validate_identifier("rollback.semantic_id", semantic_id)?;
            if *revision == 0 {
                return Err(ResearchPolicyError::ZeroRollbackRevision);
            }
        }

        let approval_action = approval_action.into();
        validate_action(&approval_action)?;
        let audit_category = audit_category.into();
        validate_action(&audit_category)?;

        Ok(Self {
            semantic_id,
            semantic_revision,
            evidence_refs,
            resource_caps,
            bounded_history_fallback,
            rollback,
            approval: ResearchApprovalRequirement {
                action: approval_action,
            },
            audit_category,
        })
    }

    /// Research activation always requires authoritative human approval.
    ///
    /// Evidence, similarity scores, benchmark outcomes and policy configuration
    /// alone never produce `Allow`.
    #[must_use]
    pub const fn activation_decision(&self) -> PolicyDecision {
        PolicyDecision::RequireApproval
    }

    /// Evaluate hard resource observations without mutating policy state.
    ///
    /// A memory or wall-time excess always denies. A history excess either
    /// denies or returns an explicit bounded-approximation directive according
    /// to the predeclared fallback policy; it never truncates implicitly.
    #[must_use]
    pub const fn evaluate_resources(
        &self,
        history_items: u64,
        memory_bytes: u64,
        wall_time_ms: u64,
    ) -> ResearchResourceDecision {
        if memory_bytes > self.resource_caps.max_memory_bytes
            || wall_time_ms > self.resource_caps.max_wall_time_ms
        {
            return ResearchResourceDecision::Deny;
        }
        if history_items <= self.resource_caps.max_history_items {
            return ResearchResourceDecision::ProceedReference;
        }
        match self.bounded_history_fallback {
            BoundedHistoryFallback::Reject => ResearchResourceDecision::Deny,
            BoundedHistoryFallback::Approximation { max_history_items } => {
                ResearchResourceDecision::UseBoundedApproximation { max_history_items }
            }
        }
    }
}

/// Explicit result of resource-policy evaluation for a research run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchResourceDecision {
    /// Reference research semantics fit all hard caps.
    ProceedReference,
    /// Execute only the pre-approved bounded-history approximation.
    UseBoundedApproximation {
        /// Explicit history bound; downstream evidence must classify this as approximation.
        max_history_items: u64,
    },
    /// Reject the execution rather than weakening another resource/semantic invariant.
    Deny,
}

/// Validation errors for research activation policy declarations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResearchPolicyError {
    /// One resource ceiling was zero.
    ZeroResourceCap(&'static str),
    /// Semantic revision zero is not a valid exact revision.
    ZeroSemanticRevision,
    /// At least one evidence reference is required.
    MissingEvidence,
    /// Evidence reference count exceeds the bounded policy representation.
    TooManyEvidenceReferences { count: usize, max: usize },
    /// Evidence references must be unique.
    DuplicateEvidenceReference(String),
    /// The bounded-history fallback cannot be zero-sized.
    ZeroBoundedHistoryFallback,
    /// Bounded fallback exceeds the hard history ceiling.
    FallbackExceedsHistoryCap { fallback: u64, cap: u64 },
    /// Baseline rollback revision zero is invalid.
    ZeroRollbackRevision,
    /// A bounded identifier/reference was malformed.
    InvalidIdentifier { field: &'static str },
    /// An approval/audit action was not canonical dot-separated lowercase text.
    InvalidAction,
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), ResearchPolicyError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/')
        })
    {
        return Err(ResearchPolicyError::InvalidIdentifier { field });
    }
    Ok(())
}

fn validate_action(value: &str) -> Result<(), ResearchPolicyError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || !value.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        })
    {
        return Err(ResearchPolicyError::InvalidAction);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps() -> ResearchResourceCaps {
        ResearchResourceCaps::new(128, 1 << 20, 5_000).unwrap()
    }

    fn policy(fallback: BoundedHistoryFallback) -> ResearchActivationPolicy {
        ResearchActivationPolicy::new(
            "flat.nonlocal_history_softmax",
            1,
            vec!["evidence:sha256:abc123".into()],
            caps(),
            fallback,
            ResearchRollbackRule::RestoreBaseline {
                semantic_id: "flat.standard_softmax".into(),
                revision: 1,
            },
            "research.activate",
            "research.activation",
        )
        .unwrap()
    }

    #[test]
    fn evidence_never_authorizes_research_activation() {
        let policy = policy(BoundedHistoryFallback::Reject);
        assert_eq!(policy.activation_decision(), PolicyDecision::RequireApproval);
    }

    #[test]
    fn resources_preserve_reference_when_caps_hold() {
        let policy = policy(BoundedHistoryFallback::Reject);
        assert_eq!(
            policy.evaluate_resources(128, 1 << 20, 5_000),
            ResearchResourceDecision::ProceedReference
        );
    }

    #[test]
    fn history_excess_can_only_use_explicit_approximation() {
        let policy = policy(BoundedHistoryFallback::Approximation {
            max_history_items: 32,
        });
        assert_eq!(
            policy.evaluate_resources(129, 1_000, 10),
            ResearchResourceDecision::UseBoundedApproximation {
                max_history_items: 32
            }
        );
    }

    #[test]
    fn memory_or_time_excess_never_falls_back_semantically() {
        let policy = policy(BoundedHistoryFallback::Approximation {
            max_history_items: 32,
        });
        assert_eq!(
            policy.evaluate_resources(1, (1 << 20) + 1, 10),
            ResearchResourceDecision::Deny
        );
        assert_eq!(
            policy.evaluate_resources(1, 1_000, 5_001),
            ResearchResourceDecision::Deny
        );
    }

    #[test]
    fn invalid_or_ambiguous_policy_fails_closed() {
        assert!(matches!(
            ResearchActivationPolicy::new(
                "flat.nonlocal_history_softmax",
                1,
                vec![],
                caps(),
                BoundedHistoryFallback::Reject,
                ResearchRollbackRule::DisableResearchSemantic,
                "research.activate",
                "research.activation",
            ),
            Err(ResearchPolicyError::MissingEvidence)
        ));
        assert!(matches!(
            ResearchActivationPolicy::new(
                "flat.nonlocal_history_softmax",
                1,
                vec!["evidence:a".into()],
                caps(),
                BoundedHistoryFallback::Approximation {
                    max_history_items: 129,
                },
                ResearchRollbackRule::DisableResearchSemantic,
                "research.activate",
                "research.activation",
            ),
            Err(ResearchPolicyError::FallbackExceedsHistoryCap { .. })
        ));
    }
}
