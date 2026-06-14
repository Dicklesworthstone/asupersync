//! Lifeguard local-health-aware timing policy for the SWIM failure detector.
//!
//! Lifeguard ([Dadgar, Phillips, Currey, "Lifeguard: Local Health Awareness
//! for More Accurate Failure Detection", DSN-W 2018; arXiv:1707.00788]) layers
//! three refinements on top of the base SWIM protocol
//! ([Das, Gupta, Motivala, "SWIM: Scalable Weakly-consistent Infection-style
//! Process Group Membership Protocol", DSN 2002]) so that a *locally degraded*
//! node does not falsely accuse healthy peers:
//!
//! 1. **Local Health Multiplier (LHM / "awareness").** Each node tracks a small
//!    integer health score. Missed acks (especially when the node's own
//!    indirect probers also fail to respond) raise the score; successful probes
//!    lower it. The score scales the node's own probe/ack timeouts, so a slow
//!    or partitioned node waits proportionally longer before accusing anyone —
//!    converting "I think you are dead" into "I am probably the slow one".
//!
//! 2. **Dogpile / suspicion-timeout shrinking.** The window a member spends in
//!    `Suspect` before being declared `Dead` starts at a maximum and shrinks
//!    toward a minimum as additional *independent* nodes confirm the suspicion.
//!    One accuser waits the full window; a quorum collapses it quickly.
//!
//! 3. **Buddy-system refutation.** Handled in [`super::swim`]: a node that sees
//!    a suspicion about itself increments its incarnation and floods an `Alive`
//!    rumor that supersedes the suspicion.
//!
//! This module owns the *timing math* (items 1 and 2). It is pure arithmetic —
//! no I/O, no clock — so the whole policy is unit-testable in isolation.

/// Logical time, in milliseconds.
///
/// The protocol core is transport- and clock-free: callers advance time by
/// passing monotonically non-decreasing millisecond values to
/// [`super::swim::Swim::tick`] and friends. Production transports map a real or
/// virtual clock onto this type; the lab transport maps virtual time onto it.
pub type Millis = u64;

/// The Lifeguard Local Health Multiplier ("awareness" in HashiCorp memberlist).
///
/// `score` ranges over `0..max`, where `0` is perfect local health. A higher
/// score means the local node suspects *itself* of being degraded and therefore
/// stretches its own timeouts before accusing peers.
#[derive(Debug, Clone)]
pub struct Awareness {
    score: i32,
    max: i32,
}

impl Awareness {
    /// Creates a fresh, perfectly-healthy awareness tracker.
    ///
    /// `max` is the awareness cap (memberlist default: `8`). The score is
    /// clamped to `0..max`; a `max` below `1` is raised to `1` so the timeout
    /// multiplier is always at least `1`.
    #[must_use]
    pub fn new(max: i32) -> Self {
        Self {
            score: 0,
            max: max.max(1),
        }
    }

    /// Applies a health delta, clamping the score to `0..max`.
    ///
    /// Positive deltas degrade local health (raise the multiplier); negative
    /// deltas restore it. A perfectly-healthy node has score `0` and never
    /// drops below it; a maximally-degraded node sits at `max - 1`.
    pub fn apply_delta(&mut self, delta: i32) {
        self.score = (self.score + delta).clamp(0, self.max - 1);
    }

    /// Returns the current health score (`0` == healthy).
    #[must_use]
    pub fn score(&self) -> i32 {
        self.score
    }

    /// Returns the timeout multiplier implied by the current health.
    ///
    /// A healthy node (`score == 0`) multiplies by `1`; each point of degraded
    /// health adds one full multiple.
    #[must_use]
    pub fn multiplier(&self) -> u64 {
        (self.score as u64) + 1
    }

    /// Scales a base duration by the current local-health multiplier.
    #[must_use]
    pub fn scale(&self, base_ms: Millis) -> Millis {
        base_ms.saturating_mul(self.multiplier())
    }
}

/// Cluster-size scale factor `max(1, log10(max(1, n)))` used by the suspicion
/// timeout, matching HashiCorp memberlist's `suspicionTimeout` derivation.
///
/// Larger clusters tolerate a longer suspicion window because dissemination of
/// the confirming rumors takes proportionally longer (`O(log n)` rounds).
#[must_use]
pub fn node_scale(n: usize) -> f64 {
    let n = n.max(1) as f64;
    n.log10().max(1.0)
}

/// The minimum suspicion timeout, in milliseconds.
///
/// `min = suspicion_mult * node_scale(n) * probe_interval`. This is the floor
/// the window collapses to once enough independent confirmations arrive.
#[must_use]
pub fn min_suspicion_ms(suspicion_mult: u32, n: usize, probe_interval_ms: Millis) -> Millis {
    let raw = (suspicion_mult as f64) * node_scale(n) * (probe_interval_ms as f64);
    raw.round() as Millis
}

/// The maximum suspicion timeout, in milliseconds.
///
/// `max = suspicion_max_timeout_mult * min`. This is the window a lone accuser
/// waits before escalating `Suspect -> Dead`.
#[must_use]
pub fn max_suspicion_ms(min_ms: Millis, suspicion_max_timeout_mult: u32) -> Millis {
    min_ms.saturating_mul(suspicion_max_timeout_mult as u64)
}

/// The current suspicion timeout given the number of *independent* confirmations.
///
/// Interpolates from `max_ms` (at `confirmations == 0`) down to `min_ms` (at
/// `confirmations >= k`) along a logarithmic curve, matching memberlist's
/// `suspicion.go`:
///
/// ```text
/// frac    = ln(confirmations + 1) / ln(k + 1)         (clamped to 1.0)
/// timeout = max(min, max - (max - min) * frac)
/// ```
///
/// `k` is the desired number of confirmations (the SWIM/Lifeguard `k`,
/// defaulting to the indirect-probe count). A `k` of `0` is treated as `1`.
#[must_use]
pub fn suspicion_timeout_ms(min_ms: Millis, max_ms: Millis, confirmations: u32, k: u32) -> Millis {
    let max_ms = max_ms.max(min_ms);
    if confirmations == 0 {
        return max_ms;
    }
    let k = k.max(1);
    let frac = (f64::from(confirmations + 1)).ln() / (f64::from(k + 1)).ln();
    let frac = frac.clamp(0.0, 1.0);
    let span = (max_ms - min_ms) as f64;
    let reduction = (span * frac).round() as Millis;
    max_ms.saturating_sub(reduction).max(min_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn awareness_starts_healthy_and_clamps() {
        let mut a = Awareness::new(8);
        assert_eq!(a.score(), 0);
        assert_eq!(a.multiplier(), 1);
        assert_eq!(a.scale(500), 500);

        // Cannot go below zero.
        a.apply_delta(-5);
        assert_eq!(a.score(), 0);

        // Degrade and observe the multiplier grow.
        a.apply_delta(2);
        assert_eq!(a.score(), 2);
        assert_eq!(a.multiplier(), 3);
        assert_eq!(a.scale(500), 1500);

        // Cannot exceed max - 1.
        a.apply_delta(100);
        assert_eq!(a.score(), 7);
        assert_eq!(a.multiplier(), 8);
    }

    #[test]
    fn awareness_min_max_is_clamped_up() {
        let a = Awareness::new(0);
        assert_eq!(a.multiplier(), 1);
        let mut a = Awareness::new(-3);
        a.apply_delta(10);
        // max raised to 1 => score capped at 0.
        assert_eq!(a.score(), 0);
    }

    #[test]
    fn node_scale_floor_is_one() {
        assert!((node_scale(0) - 1.0).abs() < 1e-9);
        assert!((node_scale(1) - 1.0).abs() < 1e-9);
        assert!((node_scale(10) - 1.0).abs() < 1e-9);
        assert!((node_scale(100) - 2.0).abs() < 1e-9);
    }

    #[test]
    fn suspicion_window_shrinks_with_confirmations() {
        // Small cluster: node_scale == 1, min = 4 * 1 * 1000 = 4000ms,
        // max = 6 * 4000 = 24000ms.
        let n = 7;
        let min = min_suspicion_ms(4, n, 1000);
        let max = max_suspicion_ms(min, 6);
        assert_eq!(min, 4000);
        assert_eq!(max, 24000);

        // Zero confirmations => full window.
        assert_eq!(suspicion_timeout_ms(min, max, 0, 3), max);

        // Window is monotonically non-increasing in confirmations.
        let t1 = suspicion_timeout_ms(min, max, 1, 3);
        let t2 = suspicion_timeout_ms(min, max, 2, 3);
        let t3 = suspicion_timeout_ms(min, max, 3, 3);
        assert!(t1 < max);
        assert!(t2 < t1);
        assert!(t3 <= t2);

        // At/over k confirmations => floor.
        assert_eq!(suspicion_timeout_ms(min, max, 3, 3), min);
        assert_eq!(suspicion_timeout_ms(min, max, 10, 3), min);
    }

    #[test]
    fn suspicion_timeout_handles_degenerate_bounds() {
        // max below min is raised to min; k of 0 treated as 1.
        assert_eq!(suspicion_timeout_ms(5000, 1000, 0, 0), 5000);
        assert_eq!(suspicion_timeout_ms(5000, 1000, 5, 0), 5000);
    }
}
