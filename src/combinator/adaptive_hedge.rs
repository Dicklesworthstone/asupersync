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

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
fn decay_nanos(current: u64, decay_factor: f64) -> u64 {
    // Peak-EWMA uses fractional decay; conversion through f64 is intentional.
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
        assert!(min_nanos <= max_nanos, "min_delay must be <= max_delay");
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
            // Clamp the stored atomic state itself so concurrent observers never
            // publish out-of-range values, even before projecting via HedgeConfig.
            let next = sample.max(decayed).clamp(self.min_delay, self.max_delay);

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

    /// Get the current dynamically calculated hedge delay.
    #[must_use]
    pub fn current_delay(&self) -> Duration {
        let mut delay_nanos = self.estimate_nanos.load(Ordering::Relaxed);

        if delay_nanos < self.min_delay {
            delay_nanos = self.min_delay;
        } else if delay_nanos > self.max_delay {
            delay_nanos = self.max_delay;
        }

        Duration::from_nanos(delay_nanos)
    }

    /// Get the current dynamically calculated hedge configuration.
    #[must_use]
    pub fn current_config(&self) -> HedgeConfig {
        HedgeConfig::new(self.current_delay())
    }
}

#[cfg(test)]
#[path = "adaptive_hedge_inline_tests.rs"]
mod tests;
