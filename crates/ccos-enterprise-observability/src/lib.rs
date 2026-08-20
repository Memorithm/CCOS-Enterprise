//! # CCOS Enterprise — Observability
//!
//! Metrics, tracing and audit correlation (docs/COGNITIVE_AUDIT.md).
//! Foundation slice: a bounded, deterministic counter registry — exporters
//! (Prometheus/OTel) are wired at the gateway in later milestones.
//!
//! The registry is the one bounded pool in Enterprise, and it is reachable
//! from every code path that names a metric. Three properties follow from
//! that and are enforced here rather than at the exporter:
//!
//! * **The bound is on bytes, not just on keys.** A cardinality cap alone is
//!   not a memory cap — `MAX_SERIES` names of unbounded length is unbounded
//!   memory — so names are capped at [`CounterRegistry::MAX_NAME_BYTES`] too.
//!   The retained size of a registry is `MAX_SERIES × MAX_NAME_BYTES` plus
//!   node overhead, and that product is an arithmetic fact, not a hope.
//! * **Names are validated, not merely stored.** The documented destination
//!   is a Prometheus/OTel exporter, whose text exposition format is newline-
//!   and space-delimited. A name carrying `\n`, a space or a `{` is a forged
//!   series the day that exporter exists, so the registry refuses it now —
//!   the sibling `ccos_enterprise_gateway::classify` rejects non-canonical
//!   tool names for exactly this reason.
//! * **The drop counters are out of band.** They are struct fields exported
//!   under reserved `_`-prefixed names, not map entries. No caller can reach
//!   them, because [`CounterRegistry::is_valid_name`] refuses a leading `_`.
//!   A registry whose drop counter lives in its own keyspace is a registry
//!   whose drop counter an attacker can seed, and a seeded drop counter is
//!   worse than no drop counter: it reads as health.

use std::collections::BTreeMap;

pub mod prometheus;

/// The out-of-band gauge names, in export order. Every one starts with `_`,
/// which [`CounterRegistry::is_valid_name`] refuses, so `inc` can never mint
/// or collide with them.
const DROPPED: &str = "_dropped";
const DROPPED_EVENTS: &str = "_dropped_events";
const REFUSED: &str = "_refused";

/// A bounded in-memory counter set. BTreeMap keeps export order deterministic
/// (audit-friendly diffs).
#[derive(Debug, Default)]
pub struct CounterRegistry {
    counters: BTreeMap<String, u64>,
    dropped: u64,
    dropped_events: u64,
    refused: u64,
}

impl CounterRegistry {
    /// Maximum distinct series kept. Beyond it an increment on an unseen name
    /// is dropped and counted in [`CounterRegistry::dropped`], so a label
    /// explosion can never exhaust memory.
    pub const MAX_SERIES: usize = 4096;

    /// Maximum length of a series name, in bytes.
    ///
    /// Without this the cardinality cap is not a memory cap: 4096 names of
    /// 1 MiB is 4 GiB behind a registry reporting a modest 4096 series, with
    /// no removal, eviction or reset API to release any of it. 128 bytes is
    /// well above every name the product registers (the longest,
    /// `gateway.refused.variant_not_activated`, is 38) and below anything a
    /// caller would need.
    pub const MAX_NAME_BYTES: usize = 128;

    /// How many out-of-band gauges [`CounterRegistry::export`] prepends.
    /// `export().len() == series() + GAUGES`, always.
    pub const GAUGES: usize = 3;

    /// Whether a name may become a series.
    ///
    /// Dot-separated segments of `[a-z0-9_]`, each non-empty, the whole no
    /// longer than [`CounterRegistry::MAX_NAME_BYTES`] bytes, and the first
    /// byte an ASCII lowercase letter. This is the same shape
    /// `ccos_enterprise_admin::is_canonical_action` requires of an action
    /// name, tightened by a leading-letter rule that reserves the `_` prefix
    /// for this type's own gauges.
    ///
    /// It is deliberately narrower than "valid UTF-8": everything it excludes
    /// — whitespace, control bytes, `{`, `}`, `"`, `\`, NUL, RTL overrides,
    /// homoglyphs, astral codepoints — is either an exporter injection vector
    /// or a way to mint two series a human reads as one.
    pub fn is_valid_name(name: &str) -> bool {
        name.len() <= Self::MAX_NAME_BYTES
            && name.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
            && name.split('.').all(|segment| {
                !segment.is_empty()
                    && segment
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            })
    }

    /// Add `by` to `name`, creating the series if there is room for it.
    ///
    /// Three refusal paths, each counted separately because each answers a
    /// different operator question:
    ///
    /// * the name is malformed → [`CounterRegistry::refused`] ("is something
    ///   trying to inject?");
    /// * the registry is full and the name is new → both
    ///   [`CounterRegistry::dropped`] ("is a label explosion happening?") and
    ///   [`CounterRegistry::dropped_events`] ("how much telemetry did I
    ///   lose?").
    ///
    /// The two drop counters differ on purpose. `dropped` moves by one per
    /// refused call whatever `by` was, so `inc(name, 0)` — squatting a slot at
    /// zero cost to the attacker — is still visible; `dropped_events` moves by
    /// `by`, so the conservation property (everything ever incremented is
    /// either in a series or in `dropped_events`) survives.
    pub fn inc(&mut self, name: &str, by: u64) {
        if !Self::is_valid_name(name) {
            self.refused = self.refused.saturating_add(1);
            return;
        }
        // Saturating adds: a counter pinned at `u64::MAX` is deterministic in
        // release and debug alike, where a wrapping/panicking add is neither.
        if self.counters.len() >= Self::MAX_SERIES && !self.counters.contains_key(name) {
            self.dropped = self.dropped.saturating_add(1);
            self.dropped_events = self.dropped_events.saturating_add(by);
            return;
        }
        let c = self.counters.entry(name.into()).or_default();
        *c = c.saturating_add(by);
    }

    /// The value of `name`, or 0 if it is absent. The reserved gauge names
    /// read back their gauge, so `get` and [`CounterRegistry::export`] never
    /// disagree.
    pub fn get(&self, name: &str) -> u64 {
        match name {
            DROPPED => self.dropped,
            DROPPED_EVENTS => self.dropped_events,
            REFUSED => self.refused,
            _ => self.counters.get(name).copied().unwrap_or(0),
        }
    }

    /// Distinct series held, excluding the out-of-band gauges. Never exceeds
    /// [`CounterRegistry::MAX_SERIES`].
    pub fn series(&self) -> usize {
        self.counters.len()
    }

    /// Increments refused for want of a slot, counted one per call.
    ///
    /// This is the label-explosion alarm, and it is the counter that has to
    /// survive an attacker: it cannot be seeded (no caller can name it) and
    /// it cannot be saturated in practice (it moves by exactly one per call,
    /// so pinning it takes `2^64` calls, where the value-carrying sibling
    /// below can be pinned by a single `u64::MAX`).
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// The counts those dropped increments carried. Saturates, so once it
    /// pins the conservation property stops holding — but
    /// [`CounterRegistry::dropped`] keeps counting regardless.
    pub fn dropped_events(&self) -> u64 {
        self.dropped_events
    }

    /// Increments refused because the name was not one
    /// [`CounterRegistry::is_valid_name`] would admit.
    pub fn refused(&self) -> u64 {
        self.refused
    }

    /// A deterministic snapshot for exporters (Prometheus/OTel at the gateway)
    /// and for audit diffing: name/value pairs in `BTreeMap` order, preceded
    /// by the three out-of-band gauges. Without this the registry's ordering
    /// guarantee is unobservable — nothing could read the counters back out.
    ///
    /// The gauges are always present, including at zero: `_dropped == 0` is
    /// the only honest way to say "nothing was dropped", and an absent series
    /// cannot say it. They sort first — `_` precedes every letter a valid
    /// name may start with — so the result is strictly sorted throughout.
    ///
    /// **Identical histories in identical order** produce identical
    /// snapshots. Identical histories in a *different* order do not, once a
    /// deployment crosses `MAX_SERIES`: which names win the last slots is
    /// decided by arrival order alone. That is inherent to a first-N cap and
    /// is stated here rather than papered over, because two replicas behind a
    /// load balancer will hit it.
    pub fn export(&self) -> Vec<(&str, u64)> {
        let mut out = Vec::with_capacity(self.counters.len() + Self::GAUGES);
        out.push((DROPPED, self.dropped));
        out.push((DROPPED_EVENTS, self.dropped_events));
        out.push((REFUSED, self.refused));
        out.extend(
            self.counters
                .iter()
                .map(|(name, value)| (name.as_str(), *value)),
        );
        out
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
        assert_eq!(r.series(), CounterRegistry::MAX_SERIES, "capped exactly");
        // `mcp.requests` took one of the 4096 slots, so 11 of the 4106
        // `series.*` names find none.
        assert_eq!(r.dropped(), 11, "and every drop counted");
        assert_eq!(r.dropped_events(), 11);
    }

    #[test]
    fn counters_saturate_instead_of_wrapping() {
        let mut r = CounterRegistry::default();
        r.inc("hot", u64::MAX - 1);
        r.inc("hot", 5);
        assert_eq!(r.get("hot"), u64::MAX, "pinned at MAX, never wrapped");
        r.inc("hot", 1);
        assert_eq!(r.get("hot"), u64::MAX, "stays pinned");
    }

    #[test]
    fn the_gauges_are_unreachable_from_inc() {
        let mut r = CounterRegistry::default();
        for reserved in [DROPPED, DROPPED_EVENTS, REFUSED] {
            r.inc(reserved, u64::MAX);
            assert_eq!(r.series(), 0, "{reserved} became a series");
        }
        // Nothing an attacker passed reached a gauge: `_dropped` and
        // `_dropped_events` never moved, and `_refused` moved by exactly one
        // per attempt — never by the `u64::MAX` that was offered.
        assert_eq!(r.dropped(), 0);
        assert_eq!(r.dropped_events(), 0);
        assert_eq!(r.refused(), 3, "each attempt counted once, by one");
    }

    #[test]
    fn name_validation_matches_what_the_product_registers() {
        for good in [
            "gateway.requests",
            "gateway.refused.variant_not_activated",
            "audit.dropped",
            "a",
            "s0",
        ] {
            assert!(CounterRegistry::is_valid_name(good), "{good:?} refused");
        }
        for bad in [
            "",
            "_dropped",
            "0leading",
            "Upper",
            "has space",
            "has\nnewline",
            "up{job=\"prod\"}",
            "trailing.",
            "double..dot",
            "dashed-name",
            "\u{435}yrillic",
        ] {
            assert!(!CounterRegistry::is_valid_name(bad), "{bad:?} admitted");
        }
        let long = "a".repeat(CounterRegistry::MAX_NAME_BYTES);
        assert!(CounterRegistry::is_valid_name(&long));
        assert!(!CounterRegistry::is_valid_name(&format!("{long}a")));
    }

    #[test]
    fn export_leads_with_the_gauges_and_stays_sorted() {
        let mut r = CounterRegistry::default();
        r.inc("zebra", 1);
        r.inc("alpha", 2);
        let rows = r.export();
        assert_eq!(rows.len(), r.series() + CounterRegistry::GAUGES);
        assert_eq!(
            rows.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            [DROPPED, DROPPED_EVENTS, REFUSED, "alpha", "zebra"]
        );
        assert!(rows.windows(2).all(|w| w[0].0 < w[1].0));
    }

    #[test]
    fn a_zero_valued_drop_is_still_visible() {
        let mut r = CounterRegistry::default();
        for i in 0..CounterRegistry::MAX_SERIES {
            r.inc(&format!("full.{i}"), 1);
        }
        r.inc("squatter", 0);
        assert_eq!(r.dropped(), 1, "a zero increment that was dropped shows");
        assert_eq!(r.dropped_events(), 0, "while carrying no events");
    }
}
