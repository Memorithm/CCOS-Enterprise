//! # The conformance suite's view of the product
//!
//! The composed admission path used to live here, in a `publish = false` test
//! harness that no shipped crate depended on. That was the finding, not the
//! design: `docs/ENTERPRISE_SECURITY_MODEL.md` describes a six-layer product,
//! and no shipped crate composed any two of those layers.
//!
//! It now lives in [`ccos_enterprise_runtime`], and this crate re-exports it
//! so the suite keeps guarding the **real** thing rather than a copy of it.
//! Nothing is redefined here: if a test compiles against this module, it is
//! compiled against shipped code.
//!
//! Several tests in this suite assert behaviour that is *wrong on purpose*,
//! with a comment saying so, precisely so a repair fails loudly here instead
//! of silently changing semantics. When one fails, read the comment before
//! touching the assertion.

pub use ccos_enterprise_runtime::{
    actor, request, two_tenant_deployment, AuditRecord, Call, Deployment, Outcome, Refusal,
    TenantState, DEFAULT_AUDIT_CAPACITY, DEFAULT_REPLAY_MEMORY, MAX_IDENTIFIER_BYTES,
};
