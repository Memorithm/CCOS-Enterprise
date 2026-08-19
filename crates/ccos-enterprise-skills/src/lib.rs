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
//! bounded evidence identifiers. The observational trial ledger likewise keeps
//! only skill ids plus domain-separated correlation/evidence hashes.

mod exposure;
mod observational;
mod parser;
mod registry;
mod store;
mod trial_store;
mod trials;

pub use exposure::parse_skill_exposures;
pub use observational::{summarize_observational_trials, SkillObservationalSummary};
pub use parser::{
    parse_capture, skill_fingerprint, EpisodeObservation, ToolObservation, ToolOutcome,
    EPISODE_SCHEMA,
};
pub use registry::{
    ObserveDisposition, ObserveResult, SkillConfig, SkillRecord, SkillRegistry, SkillSnapshot,
    SkillStatus, SKILL_SNAPSHOT_SCHEMA,
};
pub use store::SkillStore;
pub use trial_store::{SkillTrialStore, SKILL_TRIALS_FILE, SKILL_TRIALS_LOCK_FILE};
pub use trials::{
    trial_turn_key, ExposureResult, SkillTrialConfig, SkillTrialRecord, SkillTrialRegistry,
    SkillTrialSnapshot, SkillTrialStatus, TrialResolution, SKILL_TRIAL_SNAPSHOT_SCHEMA,
};

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
    CorruptTrial {
        path: PathBuf,
        detail: String,
    },
    UnsupportedSchema {
        found: u32,
    },
    UnsupportedTrialSchema {
        found: u32,
    },
    InvalidCapture(String),
    InvalidConfig(String),
    InvalidTrial(String),
}

impl std::fmt::Display for SkillError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Corrupt { path, detail } => {
                write!(f, "{}: skill snapshot is corrupt: {detail}", path.display())
            }
            Self::CorruptTrial { path, detail } => write!(
                f,
                "{}: skill trial snapshot is corrupt: {detail}",
                path.display()
            ),
            Self::UnsupportedSchema { found } => {
                write!(f, "unsupported skill snapshot schema {found}")
            }
            Self::UnsupportedTrialSchema { found } => {
                write!(f, "unsupported skill trial snapshot schema {found}")
            }
            Self::InvalidCapture(detail) => write!(f, "invalid DSH L1 capture: {detail}"),
            Self::InvalidConfig(detail) => write!(f, "invalid skill config: {detail}"),
            Self::InvalidTrial(detail) => write!(f, "invalid skill trial state: {detail}"),
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
