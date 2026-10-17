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
    /// `0.0` (fully degraded — fail-safe), see `sanitise_headroom`.
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
    /// `0.0` (fully degraded — fail-safe), see `sanitise_headroom`.
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
#[path = "pressure_inline_tests.rs"]
mod tests;
