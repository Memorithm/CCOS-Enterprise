//! Backend-neutral agent-memory contract for CCOS Enterprise.
//!
//! This crate owns the CCOS vocabulary for composing semantic-memory domains.
//! It deliberately contains no vector index, database, network transport, or
//! vendor-specific implementation. Providers receive an explicit tenant scope
//! and an explicit memory loadout for every operation.
//!
//! The contract is original to CCOS Enterprise. External memory systems may
//! inform product requirements, but their APIs, schemas, storage layouts, and
//! source code are not part of this interface.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;

use ccos_enterprise_tenancy::TenantScope;

mod bundle;
pub use bundle::{
    MemoryBundleEntry, MemoryBundleError, MemoryBundleManifest, MemoryBundleVersion,
    MemoryContentDigest, MemoryProviderReference,
};

mod context_budget;
pub use context_budget::{
    assemble_bootstrap_context, MemoryContextAssembly, MemoryContextBudget, MemoryContextError,
    MAX_MEMORY_CONTEXT_ITEMS, MAX_MEMORY_CONTEXT_PAYLOAD_BYTES,
};

mod governed_recall;
pub use governed_recall::{
    admit_governed_recall, GovernedRecallGate, GovernedRecallGateError, GovernedRecallTrustPolicy,
};

mod governed_recall_budget;
pub use governed_recall_budget::GovernedSemanticMemoryProviderExt;

mod governed_context;
pub use governed_context::{assemble_governed_bootstrap_context, GovernedMemoryContextAssembly};

mod governed_provider;
pub use governed_provider::{
    GovernedMemoryObservation, GovernedMemoryWrite, GovernedSemanticMemoryProvider,
};

mod lineage_graph;
pub use lineage_graph::{
    MemoryAssetState, MemoryGraphError, MemoryInvalidationReport, MemoryLineageGraph,
};

mod loadout_policy;
pub use loadout_policy::{
    MemoryLoadoutBinding, MemoryLoadoutPlan, MemoryLoadoutPlanError, MemoryUsageMode,
    MAX_MEMORY_LOADOUT_BINDINGS,
};

mod promotion;
pub use promotion::{evaluate_memory_promotion, MemoryPromotionCandidate, MemoryPromotionError};

mod recall_budget;
pub use recall_budget::{
    BudgetedMemoryRecall, MemoryRecallBudget, MemoryRecallBudgetError, SemanticMemoryProviderExt,
    MAX_MEMORY_RECALL_ITEMS, MAX_MEMORY_RECALL_PAYLOAD_BYTES, MAX_MEMORY_RECALL_SHORTLIST,
};

mod retention;
pub use retention::{
    apply_memory_retention, MemoryRetentionError, MemoryRetentionOutcome, MemoryRetentionPolicy,
};

mod trust;
pub use trust::{MemoryTrustError, MemoryTrustMetadata, MemoryValidationState};

mod projection;
pub use projection::{
    load_governed_memory_projection, save_governed_memory_projection, GovernedMemoryProjection,
    GovernedMemoryProjectionError, GOVERNED_MEMORY_PROJECTION_FILE,
    GOVERNED_MEMORY_PROJECTION_VERSION,
};

mod attestation;
pub use attestation::{attest_governed_context, MemoryAdmissionReason, MemoryContextAttestation};
