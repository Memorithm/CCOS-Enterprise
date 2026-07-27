//! # CCOS Enterprise — Observability
//!
//! Metrics, tracing and audit correlation (docs/COGNITIVE_AUDIT.md).
//! Foundation slice: a bounded, deterministic counter registry — exporters
//! (Prometheus/OTel) are wired at the gateway in later milestones.

use std::collections::BTreeMap;

/// A bounded in-memory counter set. BTreeMap keeps export order deterministic
/// (audit-friendly diffs).
#[derive(Debug, Default)]
pub struct CounterRegistry {
    counters: BTreeMap<String, u64>,
}

impl CounterRegistry {
    /// Maximum distinct series kept; beyond it, increments fold into
    /// `"overflow"` so a label explosion can never exhaust memory.
    pub const MAX_SERIES: usize = 4096;

    pub fn inc(&mut self, name: &str, by: u64) {
        if self.counters.len() >= Self::MAX_SERIES && !self.counters.contains_key(name) {
            *self.counters.entry("overflow".into()).or_default() += by;
            return;
        }
        *self.counters.entry(name.into()).or_default() += by;
    }

    pub fn get(&self, name: &str) -> u64 {
        self.counters.get(name).copied().unwrap_or(0)
    }

    pub fn series(&self) -> usize {
        self.counters.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_and_deterministic() {
        let mut r = CounterRegistry::default();
        r.inc("mcp.requests", 1);
        r.inc("mcp.requests", 2);
        assert_eq!(r.get("mcp.requests"), 3);
        for i in 0..CounterRegistry::MAX_SERIES + 10 {
            r.inc(&format!("series.{i}"), 1);
        }
        assert!(
            r.series() <= CounterRegistry::MAX_SERIES + 1,
            "overflow folded"
        );
        assert!(r.get("overflow") >= 10);
    }
}
