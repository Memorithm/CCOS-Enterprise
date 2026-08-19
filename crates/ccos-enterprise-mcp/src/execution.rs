//! Binary-local compatibility module for the canonical Enterprise execution journal.
//!
//! The authoritative implementation is `ccos-enterprise-execution`; the stdio
//! server keeps its existing `execution::*` module path through this re-export.

pub use ccos_enterprise_execution::*;
