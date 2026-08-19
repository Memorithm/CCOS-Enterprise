//! Prometheus text exposition (v0.0.4) for the bounded counter registry.
//!
//! The registry's guarantees carry through to the wire format:
//!
//! - **validated metric names**: [`CounterRegistry::is_valid_name`] is
//!   exactly the Prometheus name grammar (dot-separated `[a-z0-9_]`
//!   segments), so every series is exposition-safe by construction — no
//!   escaping, no injection;
//! - **bounded cardinality**: the registry caps series and name bytes;
//!   the exposition is exactly as bounded as the registry;
//! - **no attacker-controlled labels**: the exposition carries no labels at
//!   all; tenant identifiers appear only in the metric *name* the product
//!   itself registers (e.g. `gateway.refused.tenant_not_owned`), never as a
//!   caller-supplied label value;
//! - **deterministic output**: same history, same bytes — the export is
//!   sorted, gapless and newline-terminated.
//!
//! The exposition format: one `# TYPE <name> counter` line followed by
//! `<name> <value>` lines in registry order. Values are u64 (Prometheus
//! counters), so there is no float formatting drift.

use crate::CounterRegistry;

/// The Prometheus metric name for a registry name. Identical by
/// construction; kept as a function so the grammar contract is stated once.
pub fn prometheus_name(registry_name: &str) -> &str {
    registry_name
}

/// Render the registry as Prometheus text exposition v0.0.4.
///
/// The out-of-band gauges (`_dropped`, `_dropped_events`, `_refused`) are
/// part of the registry's contract and are rendered as counters with their
/// reserved names, prefixed to keep the `_`-prefix semantics visible.
pub fn render_prometheus(registry: &CounterRegistry) -> String {
    let mut out = String::new();
    for (name, value) in registry.export() {
        out.push_str("# TYPE ");
        out.push_str(prometheus_name(name));
        out.push_str(" counter\n");
        out.push_str(prometheus_name(name));
        out.push(' ');
        out.push_str(&value.to_string());
        out.push('\n');
    }
    out
}

/// A health/readiness verdict derived from real durable subsystem state.
///
/// The registry's drop and refusal counters are the fail-closed signals:
/// a registry that is dropping telemetry or refusing names is not healthy,
/// whatever the request counters say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Health {
    /// Whether the registry reports no dropped increments and no refused
    /// names.
    pub ready: bool,
    pub dropped: u64,
    pub dropped_events: u64,
    pub refused: u64,
}

impl Health {
    /// Evaluate readiness from the registry's out-of-band gauges.
    pub fn from_registry(registry: &CounterRegistry) -> Self {
        let dropped = registry.dropped();
        let dropped_events = registry.dropped_events();
        let refused = registry.refused();
        Self {
            ready: dropped == 0 && dropped_events == 0 && refused == 0,
            dropped,
            dropped_events,
            refused,
        }
    }

    /// Render as Prometheus text: `ccos_health_ready 1|0` plus the three
    /// gauges. `ready` is a boolean gauge — a poisoned registry must never
    /// report healthy.
    pub fn render_prometheus(&self) -> String {
        format!(
            "# TYPE ccos_health_ready gauge\nccos_health_ready {}\n\
             # TYPE ccos_health_dropped counter\nccos_health_dropped {}\n\
             # TYPE ccos_health_dropped_events counter\nccos_health_dropped_events {}\n\
             # TYPE ccos_health_refused counter\nccos_health_refused {}\n",
            if self.ready { 1 } else { 0 },
            self.dropped,
            self.dropped_events,
            self.refused,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposition_is_deterministic_and_well_formed() {
        let mut r = CounterRegistry::default();
        r.inc("gateway.requests", 3);
        r.inc("gateway.forwarded", 1);
        r.inc("gateway.refused", 2);
        let first = render_prometheus(&r);
        let second = render_prometheus(&r);
        assert_eq!(first, second, "deterministic bytes");
        // Every line is either a TYPE line or a name value line; no blank
        // lines, no labels, no attacker-controlled strings.
        for line in first.lines() {
            if line.starts_with("# TYPE ") {
                assert!(line.ends_with(" counter"));
            } else {
                let mut parts = line.splitn(2, ' ');
                let name = parts.next().unwrap();
                let value = parts.next().expect("value");
                assert!(CounterRegistry::is_valid_name(name) || name.starts_with('_'));
                value.parse::<u64>().expect("u64 value");
            }
        }
        assert!(first.contains("gateway.requests 3"));
        assert!(first.contains("# TYPE _dropped counter"));
    }

    #[test]
    fn no_attacker_labels_anywhere() {
        let mut r = CounterRegistry::default();
        r.inc("gateway.requests", 1);
        let text = render_prometheus(&r);
        assert!(!text.contains('{'), "labels are never emitted");
        assert!(!text.contains('"'));
        assert!(!text.contains('='));
    }

    #[test]
    fn health_reflects_real_durable_state() {
        let mut r = CounterRegistry::default();
        assert_eq!(Health::from_registry(&r).ready, true);
        // A full registry that starts dropping telemetry is not ready.
        for i in 0..CounterRegistry::MAX_SERIES {
            r.inc(&format!("series.{i}"), 1);
        }
        r.inc("overflow", 1);
        let health = Health::from_registry(&r);
        assert_eq!(health.ready, false);
        assert_eq!(health.dropped, 1);
        let text = health.render_prometheus();
        assert!(text.contains("ccos_health_ready 0"));
        assert!(text.contains("ccos_health_dropped 1"));
        // A registry refusing names is also not ready.
        let mut r = CounterRegistry::default();
        r.inc("bad\nname", 1);
        assert_eq!(Health::from_registry(&r).ready, false);
    }
}
