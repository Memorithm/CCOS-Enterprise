#![forbid(unsafe_code)]

//! Evidence-backed skill crystallization for CCOS Enterprise.
//!
//! This crate does not execute skills and never calls an LLM. It converts the
//! evidence-only DeepSeek Harness L1 capture emitted by the Enterprise adapter
//! into a deterministic lifecycle that can later be surfaced through governed
//! read-only tools.
//!
//! Raw prompts, tool arguments/results, workspace paths and model output are
//! deliberately absent from the persisted skill registry. A skill contains
//! only its ordered tool names, reliability counters, lifecycle state and
//! bounded evidence identifiers.

mod parser;
mod registry;
mod store;

pub use parser::{
    parse_capture, skill_fingerprint, EpisodeObservation, ToolObservation, ToolOutcome,
    EPISODE_SCHEMA,
};
pub use registry::{
    ObserveDisposition, ObserveResult, SkillConfig, SkillRecord, SkillRegistry, SkillSnapshot,
    SkillStatus, SKILL_SNAPSHOT_SCHEMA,
};
pub use store::SkillStore;

use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum SkillError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Corrupt {
        path: PathBuf,
        detail: String,
    },
    UnsupportedSchema {
        found: u32,
    },
    InvalidCapture(String),
    InvalidConfig(String),
}

impl std::fmt::Display for SkillError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Corrupt { path, detail } => {
                write!(f, "{}: skill snapshot is corrupt: {detail}", path.display())
            }
            Self::UnsupportedSchema { found } => {
                write!(f, "unsupported skill snapshot schema {found}")
            }
            Self::InvalidCapture(detail) => write!(f, "invalid DSH L1 capture: {detail}"),
            Self::InvalidConfig(detail) => write!(f, "invalid skill config: {detail}"),
        }
    }
}

impl std::error::Error for SkillError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub(crate) fn io(path: &Path) -> impl FnOnce(std::io::Error) -> SkillError + '_ {
    move |source| SkillError::Io {
        path: path.to_path_buf(),
        source,
    }
}
