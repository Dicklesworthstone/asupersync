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
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn raw_estimate_nanos(controller: &PeakEwmaHedgeController) -> u64 {
        controller.estimate_nanos.load(Ordering::Relaxed)
    }

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
        assert_eq!(
            raw_estimate_nanos(&controller),
            duration_nanos_saturating_u64(Duration::from_millis(500))
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

    #[test]
    fn adaptive_hedge_clamps_raw_atomic_state_at_upper_bound() {
        let controller = PeakEwmaHedgeController::new(
            Duration::from_millis(20),
            Duration::from_millis(10),
            Duration::from_millis(50),
            0.99,
        );

        controller.observe(Duration::from_secs(1));

        assert_eq!(
            raw_estimate_nanos(&controller),
            duration_nanos_saturating_u64(Duration::from_millis(50))
        );
    }

    #[test]
    fn adaptive_hedge_clamps_raw_atomic_state_at_lower_bound_after_decay() {
        let controller = PeakEwmaHedgeController::new(
            Duration::from_millis(20),
            Duration::from_millis(10),
            Duration::from_millis(50),
            0.5,
        );

        for _ in 0..8 {
            controller.observe(Duration::ZERO);
        }

        assert_eq!(
            raw_estimate_nanos(&controller),
            duration_nanos_saturating_u64(Duration::from_millis(10))
        );
    }

    #[test]
    fn adaptive_hedge_keeps_atomic_state_bounded_under_multithreaded_observe_contention() {
        let controller = Arc::new(PeakEwmaHedgeController::new(
            Duration::from_millis(20),
            Duration::from_millis(10),
            Duration::from_millis(50),
            0.95,
        ));
        let start = Arc::new(Barrier::new(5));
        let samples = [
            Duration::ZERO,
            Duration::from_millis(5),
            Duration::from_millis(25),
            Duration::from_millis(200),
        ];

        let handles: Vec<_> = (0..4)
            .map(|thread_idx| {
                let controller = Arc::clone(&controller);
                let start = Arc::clone(&start);
                thread::spawn(move || {
                    start.wait();
                    for round in 0..512 {
                        let sample = samples[(thread_idx + round) % samples.len()];
                        controller.observe(sample);
                        let raw = raw_estimate_nanos(&controller);
                        assert!(
                            raw >= controller.min_delay && raw <= controller.max_delay,
                            "raw estimate {raw} escaped bounds [{}..={}]",
                            controller.min_delay,
                            controller.max_delay
                        );
                    }
                })
            })
            .collect();

        start.wait();
        for handle in handles {
            handle
                .join()
                .expect("observe() contention thread should not panic");
        }

        let final_raw = raw_estimate_nanos(&controller);
        assert!(
            final_raw >= controller.min_delay && final_raw <= controller.max_delay,
            "final raw estimate {final_raw} escaped bounds [{}..={}]",
            controller.min_delay,
            controller.max_delay
        );
    }

    #[test]
    fn metamorphic_replay_with_readonly_probes_is_stable() {
        let trace = [
            Duration::from_millis(80),
            Duration::from_millis(15),
            Duration::from_millis(220),
            Duration::from_millis(5),
            Duration::from_millis(120),
            Duration::ZERO,
        ];

        let baseline = PeakEwmaHedgeController::new(
            Duration::from_millis(50),
            Duration::from_millis(10),
            Duration::from_millis(500),
            0.95,
        );
        let mut baseline_delays = Vec::with_capacity(trace.len());
        for sample in trace {
            baseline.observe(sample);
            baseline_delays.push(baseline.current_config().hedge_delay);
        }

        let replayed = PeakEwmaHedgeController::new(
            Duration::from_millis(50),
            Duration::from_millis(10),
            Duration::from_millis(500),
            0.95,
        );
        let mut replayed_delays = Vec::with_capacity(trace.len());
        for sample in trace {
            let pre_probe = replayed.current_config();
            assert!(
                pre_probe.hedge_delay >= Duration::from_millis(10)
                    && pre_probe.hedge_delay <= Duration::from_millis(500),
                "readonly probe must stay within configured bounds"
            );
            replayed.observe(sample);
            let post_probe = replayed.current_config();
            replayed_delays.push(post_probe.hedge_delay);
        }

        assert_eq!(
            replayed_delays, baseline_delays,
            "interleaving readonly config probes must not perturb replayed hedge trajectory"
        );
        assert_eq!(
            raw_estimate_nanos(&replayed),
            raw_estimate_nanos(&baseline),
            "readonly probes must not perturb the final atomic hedge estimate"
        );
    }
}
