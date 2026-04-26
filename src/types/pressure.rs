//! System pressure measurement for compute budget propagation.
//!
//! [`SystemPressure`] carries an atomic headroom value (0.0–1.0) that can be
//! shared across threads and read lock-free. A monitor thread samples system
//! load (e.g., `/proc/loadavg`) and updates the headroom value; any code with
//! access to the shared handle can read it cheaply via an atomic load.
//!
//! # Headroom Semantics
//!
//! `SystemPressure` uses the same five-band scale as the runtime resource
//! monitor so callers see a stable public degradation signal:
//!
//! - `1.0` — normal, full headroom available
//! - `0.75` — light degradation
//! - `0.5` — moderate degradation
//! - `0.25` — heavy degradation
//! - `0.0` — emergency degradation

use std::sync::atomic::{AtomicU32, Ordering};

/// Atomic system pressure state shared via `Arc<SystemPressure>`.
///
/// Headroom is stored as a `u32` bit pattern of an `f32` and accessed with
/// relaxed atomics — good enough for advisory pressure signals where
/// occasional stale reads are acceptable.
#[derive(Debug)]
pub struct SystemPressure {
    /// Headroom stored as f32 bits (AtomicU32 for lock-free access).
    headroom_bits: AtomicU32,
}

impl SystemPressure {
    /// Create a new pressure state at full headroom (1.0).
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            headroom_bits: AtomicU32::new(1.0_f32.to_bits()),
        }
    }

    /// Create with an explicit initial headroom value.
    ///
    /// Headroom is clamped to `[0.0, 1.0]`. NaN inputs are treated as
    /// `0.0` (fully degraded — fail-safe), see [`sanitise_headroom`].
    #[must_use]
    #[inline]
    pub fn with_headroom(headroom: f32) -> Self {
        let clamped = sanitise_headroom(headroom);
        Self {
            headroom_bits: AtomicU32::new(clamped.to_bits()),
        }
    }

    /// Read the current headroom (0.0–1.0).
    ///
    /// Uses `Relaxed` ordering — reads may be slightly stale but are
    /// always valid f32 values in `[0.0, 1.0]`.
    #[must_use]
    #[inline]
    pub fn headroom(&self) -> f32 {
        f32::from_bits(self.headroom_bits.load(Ordering::Relaxed))
    }

    /// Update the headroom value.
    ///
    /// Headroom is clamped to `[0.0, 1.0]`. NaN inputs are treated as
    /// `0.0` (fully degraded — fail-safe), see [`sanitise_headroom`].
    #[inline]
    pub fn set_headroom(&self, headroom: f32) {
        let clamped = sanitise_headroom(headroom);
        self.headroom_bits
            .store(clamped.to_bits(), Ordering::Relaxed);
    }

    /// True if headroom is below the given threshold.
    #[must_use]
    #[inline]
    pub fn should_degrade(&self, threshold: f32) -> bool {
        self.headroom() < threshold
    }

    /// Degradation level (0–4) based on headroom thresholds.
    ///
    /// The cut points intentionally mirror
    /// `runtime::resource_monitor::DegradationLevel::from_headroom` so a
    /// `SystemPressure` cloned out of the resource monitor reports the same
    /// public severity band:
    ///
    /// - Level 0: headroom > 0.875 (Normal)
    /// - Level 1: headroom > 0.625 (Light)
    /// - Level 2: headroom > 0.375 (Moderate)
    /// - Level 3: headroom > 0.125 (Heavy)
    /// - Level 4: headroom <= 0.125 (Emergency)
    #[must_use]
    #[inline]
    pub fn degradation_level(&self) -> u8 {
        let h = self.headroom();
        if h > 0.875 {
            0
        } else if h > 0.625 {
            1
        } else if h > 0.375 {
            2
        } else if h > 0.125 {
            3
        } else {
            4
        }
    }

    /// Human-readable label for the current degradation level.
    #[must_use]
    #[inline]
    pub fn level_label(&self) -> &'static str {
        match self.degradation_level() {
            0 => "normal",
            1 => "light",
            2 => "moderate",
            3 => "heavy",
            _ => "emergency",
        }
    }
}

impl Default for SystemPressure {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// br-asupersync-ksvi5z — Fail-safe NaN/Inf sanitiser for headroom inputs.
///
/// `f32::clamp` propagates NaN unchanged (every NaN comparison returns
/// `false`, so the internal `min(max(x, lo), hi)` chain leaves NaN
/// alone). Once a NaN bit pattern is stored in `headroom_bits`, every
/// `should_degrade(threshold)` and `degradation_level()` returns the
/// "no degradation needed" branch — the threshold-based defence is
/// silently disabled and an attacker can DoS the runtime by feeding a
/// single NaN through any deserialisation path that lands in
/// `with_headroom` / `set_headroom`.
///
/// Treatment: NaN and ±∞ map to `0.0` — the most-degraded value. This
/// is the fail-safe interpretation: an unparseable pressure input
/// should make the runtime *more* cautious, not less. Finite-but-
/// out-of-range values clamp to `[0.0, 1.0]` as before.
#[inline]
fn sanitise_headroom(headroom: f32) -> f32 {
    if headroom.is_finite() {
        headroom.clamp(0.0, 1.0)
    } else {
        // NaN, +inf, -inf all collapse to 0.0 (fully degraded).
        0.0
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use serde_json::{Value, json};

    fn scrub_pressure_json(value: Value) -> Value {
        let mut scrubbed = value;

        if let Some(headroom) = scrubbed.pointer_mut("/headroom") {
            let formatted = headroom
                .as_f64()
                .map_or_else(|| headroom.to_string(), |value| format!("{value:.2}"));
            *headroom = Value::String(formatted);
        }

        scrubbed
    }

    #[test]
    fn new_starts_at_full_headroom() {
        let p = SystemPressure::new();
        assert!((p.headroom() - 1.0).abs() < f32::EPSILON);
        assert_eq!(p.degradation_level(), 0);
        assert_eq!(p.level_label(), "normal");
    }

    #[test]
    fn set_and_read_headroom() {
        let p = SystemPressure::new();
        p.set_headroom(0.42);
        assert!((p.headroom() - 0.42).abs() < 0.001);
    }

    #[test]
    fn headroom_clamped() {
        let p = SystemPressure::new();
        p.set_headroom(1.5);
        assert!((p.headroom() - 1.0).abs() < f32::EPSILON);
        p.set_headroom(-0.3);
        assert!(p.headroom().abs() < f32::EPSILON);
    }

    #[test]
    fn degradation_levels() {
        let p = SystemPressure::new();
        p.set_headroom(0.9);
        assert_eq!(p.degradation_level(), 0);
        p.set_headroom(0.8);
        assert_eq!(p.degradation_level(), 1);
        p.set_headroom(0.5);
        assert_eq!(p.degradation_level(), 2);
        p.set_headroom(0.25);
        assert_eq!(p.degradation_level(), 3);
        p.set_headroom(0.0);
        assert_eq!(p.degradation_level(), 4);
    }

    #[test]
    fn should_degrade_threshold() {
        let p = SystemPressure::with_headroom(0.3);
        assert!(p.should_degrade(0.5));
        assert!(!p.should_degrade(0.2));
    }

    #[test]
    fn with_headroom_constructor() {
        let p = SystemPressure::with_headroom(0.7);
        assert!((p.headroom() - 0.7).abs() < 0.001);
    }

    #[test]
    fn level_labels() {
        let p = SystemPressure::new();
        p.set_headroom(0.9);
        assert_eq!(p.level_label(), "normal");
        p.set_headroom(0.75);
        assert_eq!(p.level_label(), "light");
        p.set_headroom(0.5);
        assert_eq!(p.level_label(), "moderate");
        p.set_headroom(0.25);
        assert_eq!(p.level_label(), "heavy");
        p.set_headroom(0.0);
        assert_eq!(p.level_label(), "emergency");
    }

    #[test]
    fn pressure_json_snapshot_scrubbed() {
        let p = SystemPressure::with_headroom(0.42);

        insta::assert_json_snapshot!(
            "pressure_json_scrubbed",
            scrub_pressure_json(json!({
                "headroom": p.headroom(),
                "degradation_level": p.degradation_level(),
                "label": p.level_label(),
                "should_degrade_0_5": p.should_degrade(0.5),
            }))
        );
    }

    /// br-asupersync-ksvi5z — NaN inputs to `with_headroom` and
    /// `set_headroom` collapse to 0.0 (fully degraded). Without this,
    /// every `should_degrade(threshold)` returns false (NaN comparison)
    /// and the threshold-based defence is silently disabled.
    #[test]
    fn nan_headroom_collapses_to_fully_degraded() {
        let p = SystemPressure::with_headroom(f32::NAN);
        assert_eq!(p.headroom(), 0.0);
        assert!(p.should_degrade(0.5));
        assert!(p.should_degrade(0.0001));
        // Degradation level at 0.0 headroom is the most-severe band.
        assert_eq!(p.degradation_level(), 4);

        let p2 = SystemPressure::new();
        p2.set_headroom(f32::NAN);
        assert_eq!(p2.headroom(), 0.0);
    }

    /// br-asupersync-ksvi5z — ±∞ inputs also collapse to 0.0.
    #[test]
    fn infinite_headroom_collapses_to_fully_degraded() {
        let p_pos = SystemPressure::with_headroom(f32::INFINITY);
        assert_eq!(p_pos.headroom(), 0.0);
        let p_neg = SystemPressure::with_headroom(f32::NEG_INFINITY);
        assert_eq!(p_neg.headroom(), 0.0);
    }

    /// br-asupersync-ksvi5z — finite-but-out-of-range inputs still clamp
    /// to [0.0, 1.0] (unchanged behaviour, regression guard).
    #[test]
    fn out_of_range_finite_headroom_clamps() {
        let p_high = SystemPressure::with_headroom(2.0);
        assert_eq!(p_high.headroom(), 1.0);
        let p_low = SystemPressure::with_headroom(-0.5);
        assert_eq!(p_low.headroom(), 0.0);
    }
}
