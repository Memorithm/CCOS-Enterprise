//! DeepSeek/MCP compatibility view of the shared Enterprise execution journal.
//!
//! Keep this module path stable for the stdio server and its backend wrapper;
//! the durable implementation lives in `ccos-enterprise-execution`.

pub use ccos_enterprise_execution::{
    ExecutionEvent, ExecutionJournal, JournalError, ToolRecovery, ToolRecoveryDisposition,
};
