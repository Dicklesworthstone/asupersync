//! Adaptive latency hedge controller.
//!
//! Uses Peak-EWMA to track tail latency distributions over time and provide
//! dynamic `hedge_delay` values that guarantee tail bounds while conserving
//! compute budget.

use crate::combinator::hedge::HedgeConfig;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

fn duration_nanos_saturating_u64(duration: Duration) -> u64 {
    let nanos = duration.as_nanos();
    if nanos > u128::from(u64::MAX) {
        u64::MAX
    } else {
        nanos as u64
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn decay_nanos(current: u64, decay_factor: f64) -> u64 {
    let decayed = (current as f64) * decay_factor;
    if !decayed.is_finite() || decayed <= 0.0 {
        0
    } else if decayed >= (u64::MAX as f64) {
        u64::MAX
    } else {
        decayed as u64
    }
}

/// Adaptive latency hedge controller based on Peak-EWMA.
///
/// Uses an asymmetric update rule to rapidly track latency spikes (peaks)
/// and slowly decay, providing a dynamic upper bound for latency hedging
/// that automatically adapts to system regime shifts.
///
/// # Alien Artifact: Regime Dynamics & Tail Risk (Family 10)
/// Static hedge delays suffer from "constants kill you". This controller uses
/// asymmetric exponential smoothing to dynamically adjust the hedge delay:
/// `H(t+1) = max(Sample, α * H(t))`
/// This mathematically guarantees that the hedge threshold instantly bounds new
/// latency spikes while smoothly settling back down when the regime recovers.
#[derive(Debug)]
pub struct PeakEwmaHedgeController {
    /// The current peak-EWMA estimate in nanoseconds.
    estimate_nanos: AtomicU64,
    /// Minimum allowed delay to prevent hedging too aggressively.
    min_delay: u64,
    /// Maximum allowed delay to bound worst-case wait.
    max_delay: u64,
    /// Decay factor α (e.g., 0.99 for slow decay). Fixed point or f64.
    decay_factor: f64,
}

impl PeakEwmaHedgeController {
    /// Create a new adaptive hedge controller.
    #[must_use]
    pub fn new(
        initial: Duration,
        min_delay: Duration,
        max_delay: Duration,
        decay_factor: f64,
    ) -> Self {
        assert!(
            decay_factor.is_finite() && decay_factor > 0.0 && decay_factor <= 1.0,
            "decay_factor must be finite and in (0, 1]"
        );
        let min_nanos = duration_nanos_saturating_u64(min_delay);
        let max_nanos = duration_nanos_saturating_u64(max_delay);
        assert!(
            min_nanos <= max_nanos,
            "min_delay must be <= max_delay"
        );
        let initial_nanos = duration_nanos_saturating_u64(initial).clamp(min_nanos, max_nanos);
        Self {
            estimate_nanos: AtomicU64::new(initial_nanos),
            min_delay: min_nanos,
            max_delay: max_nanos,
            decay_factor,
        }
    }

    /// Default configuration suitable for typical RPC hedging.
    #[must_use]
    pub fn default_rpc() -> Self {
        Self::new(
            Duration::from_millis(50),  // initial
            Duration::from_millis(10),  // min
            Duration::from_millis(500), // max
            0.99,                       // decay (slow return to normal)
        )
    }

    /// Observe the completion time of a primary request to adjust the threshold.
    pub fn observe(&self, rtt: Duration) {
        let sample = duration_nanos_saturating_u64(rtt);
        let mut current = self.estimate_nanos.load(Ordering::Acquire);
        loop {
            // Exact Peak-EWMA update: H(t+1) = max(sample, α * H(t))
            let decayed = decay_nanos(current, self.decay_factor);
            let next = sample.max(decayed);

            match self.estimate_nanos.compare_exchange_weak(
                current,
                next,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(updated) => current = updated,
            }
        }
    }

    /// Get the current dynamically calculated hedge configuration.
    #[must_use]
    pub fn current_config(&self) -> HedgeConfig {
        let mut delay_nanos = self.estimate_nanos.load(Ordering::Relaxed);

        if delay_nanos < self.min_delay {
            delay_nanos = self.min_delay;
        } else if delay_nanos > self.max_delay {
            delay_nanos = self.max_delay;
        }

        HedgeConfig::new(Duration::from_nanos(delay_nanos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adaptive_hedge_tracks_peak_instantly() {
        let controller = PeakEwmaHedgeController::default_rpc();
        // Base delay is 50ms
        assert_eq!(
            controller.current_config().hedge_delay,
            Duration::from_millis(50)
        );

        // Spike to 200ms
        controller.observe(Duration::from_millis(200));
        assert_eq!(
            controller.current_config().hedge_delay,
            Duration::from_millis(200)
        );
    }

    #[test]
    fn adaptive_hedge_decays_slowly() {
        let controller = PeakEwmaHedgeController::default_rpc();
        controller.observe(Duration::from_millis(200)); // peak

        // Small observation should trigger decay (200 * 0.99 = 198)
        controller.observe(Duration::from_millis(10));
        let delay = controller.current_config().hedge_delay.as_millis();
        assert_eq!(delay, 198);
    }

    #[test]
    fn adaptive_hedge_respects_bounds() {
        let controller = PeakEwmaHedgeController::default_rpc(); // max 500ms

        controller.observe(Duration::from_secs(1)); // Way over max
        assert_eq!(
            controller.current_config().hedge_delay,
            Duration::from_millis(500)
        );
    }

    #[test]
    fn adaptive_hedge_uses_peak_ewma_max_equation() {
        let controller = PeakEwmaHedgeController::new(
            Duration::from_millis(200),
            Duration::from_millis(1),
            Duration::from_secs(1),
            0.99,
        );

        // 0.99 * 200ms = 198ms; sample=199ms should win via max(sample, decayed).
        controller.observe(Duration::from_millis(199));
        assert_eq!(
            controller.current_config().hedge_delay,
            Duration::from_millis(199)
        );
    }

    #[test]
    fn adaptive_hedge_clamps_initial_delay() {
        let controller = PeakEwmaHedgeController::new(
            Duration::from_secs(1),
            Duration::from_millis(10),
            Duration::from_millis(50),
            0.99,
        );
        assert_eq!(
            controller.current_config().hedge_delay,
            Duration::from_millis(50)
        );
    }

    #[test]
    #[should_panic(expected = "min_delay must be <= max_delay")]
    fn adaptive_hedge_rejects_inverted_bounds() {
        let _ = PeakEwmaHedgeController::new(
            Duration::from_millis(20),
            Duration::from_millis(50),
            Duration::from_millis(10),
            0.99,
        );
    }

    #[test]
    #[should_panic(expected = "decay_factor must be finite and in (0, 1]")]
    fn adaptive_hedge_rejects_invalid_decay_factor() {
        let _ = PeakEwmaHedgeController::new(
            Duration::from_millis(20),
            Duration::from_millis(10),
            Duration::from_millis(50),
            1.5,
        );
    }

    #[test]
    fn adaptive_hedge_saturates_huge_duration_samples() {
        let controller = PeakEwmaHedgeController::new(
            Duration::from_millis(20),
            Duration::from_millis(10),
            Duration::from_millis(500),
            0.99,
        );
        controller.observe(Duration::from_secs(u64::MAX));
        // Hard clamp still applies at config projection.
        assert_eq!(
            controller.current_config().hedge_delay,
            Duration::from_millis(500)
        );
    }
}
