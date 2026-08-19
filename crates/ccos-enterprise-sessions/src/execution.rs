//! Compatibility re-export of the shared Enterprise execution journal.
//!
//! Public paths under `ccos_enterprise_sessions::execution` stay stable while
//! MCP hosts and tenant sessions consume one crash-safe implementation.

pub use ccos_enterprise_execution::*;
