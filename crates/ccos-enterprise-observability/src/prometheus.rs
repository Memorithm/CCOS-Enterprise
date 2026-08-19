//! Prometheus text exposition (v0.0.4) for the bounded counter registry.
//!
//! The registry deliberately uses dotted internal names such as
//! `gateway.requests`. Prometheus text exposition does **not** admit `.` in an
//! unquoted metric name, so the exporter performs a deterministic, injective
//! translation instead of assuming the two grammars are identical.
//!
//! - every exported metric is prefixed with `ccos_`;
//! - `_` is escaped as `__`;
//! - `.` is escaped as `_d_`;
//! - ASCII lowercase letters and digits are copied unchanged.
//!
//! Because every underscore in the source is doubled before the dot escape is
//! introduced, the mapping is reversible and collision-free (`a.b` and
//! `a_b` can never collapse onto one Prometheus series). The input registry
//! already bounds both cardinality and name bytes, so the expansion remains
//! bounded too.
//!
//! No labels are emitted: caller-controlled strings can never become an
//! unbounded label dimension. Output order remains the registry's deterministic
//! order and every exposition is newline-terminated.

use crate::CounterRegistry;

/// Maximum exported name bytes after escaping every source byte in the most
/// expansive form plus the `ccos_` prefix. The registry's source bound is the
/// authority; this constant documents the resulting exporter bound.
pub const MAX_PROMETHEUS_NAME_BYTES: usize =
    "ccos_".len() + CounterRegistry::MAX_NAME_BYTES * 3;

/// Translate one validated registry name into a valid, injective Prometheus
/// metric name.
///
/// The registry admits only lowercase ASCII letters, digits, `_` and `.` (with
/// a leading letter for caller-created series; reserved internal gauges begin
/// with `_`). The returned string therefore contains only `[a-z0-9_]` and
/// begins with `ccos_`, which is valid under the Prometheus metric-name grammar.
pub fn prometheus_name(registry_name: &str) -> String {
    let mut out = String::with_capacity("ccos_".len() + registry_name.len() * 2);
    out.push_str("ccos_");
    for byte in registry_name.bytes() {
        match byte {
            b'_' => out.push_str("__"),
            b'.' => out.push_str("_d_"),
            b'a'..=b'z' | b'0'..=b'9' => out.push(byte as char),
            // `CounterRegistry::export()` cannot produce another byte. Keep a
            // visible, injective fallback anyway so this helper is safe when
            // called directly in tests or future adapters.
            other => {
                use std::fmt::Write as _;
                let _ = write!(out, "_x{other:02x}_");
            }
        }
    }
    debug_assert!(out.len() <= MAX_PROMETHEUS_NAME_BYTES);
    out
}

/// Render the registry as Prometheus text exposition v0.0.4.
///
/// Every internal series name is normalized exactly once and the same value is
/// used in both its `TYPE` declaration and sample line.
pub fn render_prometheus(registry: &CounterRegistry) -> String {
    let mut out = String::new();
    for (name, value) in registry.export() {
        let metric = prometheus_name(name);
        out.push_str("# TYPE ");
        out.push_str(&metric);
        out.push_str(" counter\n");
        out.push_str(&metric);
        out.push(' ');
        out.push_str(&value.to_string());
        out.push('\n');
    }
    out
}

/// A first-stage health/readiness verdict derived from the bounded telemetry
/// registry itself.
///
/// This is intentionally **not** the aggregate Enterprise readiness contract:
/// durable stores, execution journals, approval state, backup state and other
/// subsystems have their own health signals. This type answers one narrower
/// question: is the telemetry registry itself accepting all events and names?
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
    /// Evaluate registry-local readiness from the out-of-band gauges.
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

    /// Render the registry-local readiness gauge and its three supporting
    /// counters. These fixed names already satisfy the Prometheus grammar.
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

    fn valid_prometheus_name(name: &str) -> bool {
        let mut bytes = name.bytes();
        let Some(first) = bytes.next() else {
            return false;
        };
        (first.is_ascii_alphabetic() || first == b'_' || first == b':')
            && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b':'))
    }

    #[test]
    fn name_translation_is_valid_and_injective_for_dot_and_underscore() {
        assert_eq!(prometheus_name("gateway.requests"), "ccos_gateway_d_requests");
        assert_eq!(prometheus_name("gateway_requests"), "ccos_gateway__requests");
        assert_ne!(
            prometheus_name("gateway.requests"),
            prometheus_name("gateway_requests")
        );
        for source in [
            "gateway.requests",
            "gateway.refused.tenant_not_owned",
            "a_b.c_d",
            "_dropped",
        ] {
            let exported = prometheus_name(source);
            assert!(valid_prometheus_name(&exported), "{exported:?}");
            assert!(exported.len() <= MAX_PROMETHEUS_NAME_BYTES);
        }
    }

    #[test]
    fn exposition_is_deterministic_and_well_formed() {
        let mut r = CounterRegistry::default();
        r.inc("gateway.requests", 3);
        r.inc("gateway.forwarded", 1);
        r.inc("gateway.refused", 2);
        let first = render_prometheus(&r);
        let second = render_prometheus(&r);
        assert_eq!(first, second, "deterministic bytes");
        for line in first.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let name = rest.strip_suffix(" counter").expect("counter type");
                assert!(valid_prometheus_name(name), "invalid TYPE name: {name:?}");
            } else {
                let mut parts = line.splitn(2, ' ');
                let name = parts.next().unwrap();
                let value = parts.next().expect("value");
                assert!(valid_prometheus_name(name), "invalid sample name: {name:?}");
                value.parse::<u64>().expect("u64 value");
            }
        }
        assert!(first.contains("ccos_gateway_d_requests 3"));
        assert!(first.contains("# TYPE ccos___dropped counter"));
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
    fn health_reflects_registry_state() {
        let mut r = CounterRegistry::default();
        assert!(Health::from_registry(&r).ready);
        for i in 0..CounterRegistry::MAX_SERIES {
            r.inc(&format!("series.{i}"), 1);
        }
        r.inc("overflow", 1);
        let health = Health::from_registry(&r);
        assert!(!health.ready);
        assert_eq!(health.dropped, 1);
        let text = health.render_prometheus();
        assert!(text.contains("ccos_health_ready 0"));
        assert!(text.contains("ccos_health_dropped 1"));

        let mut r = CounterRegistry::default();
        r.inc("bad\nname", 1);
        assert!(!Health::from_registry(&r).ready);
    }
}
