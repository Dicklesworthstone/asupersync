//! System pressure measurement for compute budget propagation.
//!
//! [`SystemPressure`] carries an atomic headroom value (0.0–1.0) that can be
//! shared across threads and read lock-free. A monitor thread samples system
//! load (e.g., `/proc/loadavg`) and updates the headroom value; any code with
//! access to the shared handle can read it cheaply via an atomic load.
//!
//! # Headroom Semantics
//!
//! - `1.0` — system is idle, full headroom available
//! - `0.5` — moderate load, background tasks may be paused
//! - `0.0` — critically overloaded, emergency degradation

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
    pub fn new() -> Self {
        Self {
            headroom_bits: AtomicU32::new(1.0_f32.to_bits()),
        }
    }

    /// Create with an explicit initial headroom value.
    ///
    /// Headroom is clamped to `[0.0, 1.0]`.
    #[must_use]
    pub fn with_headroom(headroom: f32) -> Self {
        let clamped = headroom.clamp(0.0, 1.0);
        Self {
            headroom_bits: AtomicU32::new(clamped.to_bits()),
        }
    }

    /// Read the current headroom (0.0–1.0).
    ///
    /// Uses `Relaxed` ordering — reads may be slightly stale but are
    /// always valid f32 values in `[0.0, 1.0]`.
    #[must_use]
    pub fn headroom(&self) -> f32 {
        f32::from_bits(self.headroom_bits.load(Ordering::Relaxed))
    }

    /// Update the headroom value.
    ///
    /// Headroom is clamped to `[0.0, 1.0]`.
    pub fn set_headroom(&self, headroom: f32) {
        let clamped = headroom.clamp(0.0, 1.0);
        self.headroom_bits
            .store(clamped.to_bits(), Ordering::Relaxed);
    }

    /// True if headroom is below the given threshold.
    #[must_use]
    pub fn should_degrade(&self, threshold: f32) -> bool {
        self.headroom() < threshold
    }

    /// Degradation level (0–4) based on headroom thresholds.
    ///
    /// - Level 0: headroom >= 0.5 (Normal)
    /// - Level 1: headroom >= 0.3 (Warning — background tasks paused)
    /// - Level 2: headroom >= 0.15 (Degraded — cache reduced)
    /// - Level 3: headroom >= 0.05 (Critical — writes throttled)
    /// - Level 4: headroom < 0.05 (Emergency — read-only mode)
    #[must_use]
    pub fn degradation_level(&self) -> u8 {
        let h = self.headroom();
        if h >= 0.5 {
            0
        } else if h >= 0.3 {
            1
        } else if h >= 0.15 {
            2
        } else if h >= 0.05 {
            3
        } else {
            4
        }
    }

    /// Human-readable label for the current degradation level.
    #[must_use]
    pub fn level_label(&self) -> &'static str {
        match self.degradation_level() {
            0 => "normal",
            1 => "warning",
            2 => "degraded",
            3 => "critical",
            _ => "emergency",
        }
    }
}

impl Default for SystemPressure {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        p.set_headroom(0.8);
        assert_eq!(p.degradation_level(), 0);
        p.set_headroom(0.4);
        assert_eq!(p.degradation_level(), 1);
        p.set_headroom(0.2);
        assert_eq!(p.degradation_level(), 2);
        p.set_headroom(0.1);
        assert_eq!(p.degradation_level(), 3);
        p.set_headroom(0.02);
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
        p.set_headroom(0.6);
        assert_eq!(p.level_label(), "normal");
        p.set_headroom(0.35);
        assert_eq!(p.level_label(), "warning");
        p.set_headroom(0.2);
        assert_eq!(p.level_label(), "degraded");
        p.set_headroom(0.08);
        assert_eq!(p.level_label(), "critical");
        p.set_headroom(0.01);
        assert_eq!(p.level_label(), "emergency");
    }
}
