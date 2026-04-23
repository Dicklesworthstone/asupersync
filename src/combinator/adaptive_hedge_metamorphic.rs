#![allow(clippy::all)]
//! Metamorphic Testing: Adaptive Hedge Latency Calculations
//!
//! This module implements metamorphic relations for the `PeakEwmaHedgeController`,
//! verifying that its dynamic delay calculations satisfy formal mathematical
//! properties like monotonicity and geometric decay.

#![cfg(test)]

use crate::combinator::adaptive_hedge::PeakEwmaHedgeController;
use std::time::Duration;
use crate::util::det_rng::DetRng;

/// Generates a sequence of random latency observations.
fn generate_observations(seed: u64, count: usize, max_ms: u64) -> Vec<Duration> {
    let mut rng = DetRng::new(seed);
    (0..count)
        .map(|_| Duration::from_millis(rng.next_u64() % max_ms))
        .collect()
}

/// Metamorphic Relation 1: Pointwise Monotonicity
///
/// If input sequence A dominates input sequence B (i.e., A[i] >= B[i] for all i),
/// then the resulting hedge delay after observing A must be >= the delay after B,
/// assuming both start from the same initial state.
#[test]
fn metamorphic_pointwise_monotonicity() {
    let min_delay = Duration::from_millis(5);
    let max_delay = Duration::from_millis(1000);
    let initial = Duration::from_millis(50);
    let decay = 0.95;

    let base_seq = generate_observations(0x1234, 100, 200);
    
    // Create a dominating sequence by adding a positive offset to every element
    let offset = Duration::from_millis(20);
    let dominating_seq: Vec<Duration> = base_seq.iter().map(|d| *d + offset).collect();

    let controller_a = PeakEwmaHedgeController::new(initial, min_delay, max_delay, decay);
    let controller_b = PeakEwmaHedgeController::new(initial, min_delay, max_delay, decay);

    for i in 0..base_seq.len() {
        controller_a.observe(dominating_seq[i]);
        controller_b.observe(base_seq[i]);

        let delay_a = controller_a.current_config().hedge_delay;
        let delay_b = controller_b.current_config().hedge_delay;

        assert!(
            delay_a >= delay_b,
            "Monotonicity violated at step {}: delay_a={:?} < delay_b={:?}",
            i, delay_a, delay_b
        );
    }
}

/// Metamorphic Relation 2: Geometric Decay Boundedness
///
/// If we observe a massive peak `P` followed by `N` observations of `0`,
/// the resulting delay should be exactly `P * decay^N` (clamped to min_delay).
#[test]
fn metamorphic_geometric_decay() {
    let min_delay = Duration::from_millis(1);
    let max_delay = Duration::from_millis(10000);
    let initial = Duration::from_millis(10);
    let decay = 0.90;

    let controller = PeakEwmaHedgeController::new(initial, min_delay, max_delay, decay);

    // Inject peak
    let peak_ms = 1000;
    controller.observe(Duration::from_millis(peak_ms));

    let mut expected_ms = peak_ms as f64;

    for step in 1..=50 {
        // Observe near-zero (sub-millisecond) to trigger decay without overriding the peak
        controller.observe(Duration::from_nanos(1));
        
        expected_ms *= decay;
        let expected_clamped = expected_ms.max(min_delay.as_millis() as f64);
        
        let actual_ms = controller.current_config().hedge_delay.as_millis() as f64;
        
        // Allow a small epsilon for floating-point/integer truncation differences
        let diff = (actual_ms - expected_clamped).abs();
        assert!(
            diff <= 1.0,
            "Decay violated at step {}: expected roughly {}, got {} (diff: {})",
            step, expected_clamped, actual_ms, diff
        );
    }
}

/// Metamorphic Relation 3: Time-Scale Invariance (Proportionality)
///
/// If we scale all inputs and limits by a factor `K`, the resulting
/// hedge delay should be scaled by exactly `K` (modulo integer truncation).
#[test]
fn metamorphic_scale_invariance() {
    let base_min = 10;
    let base_max = 500;
    let base_initial = 50;
    let decay = 0.99;
    let scale_factor = 3;

    let controller_base = PeakEwmaHedgeController::new(
        Duration::from_millis(base_initial),
        Duration::from_millis(base_min),
        Duration::from_millis(base_max),
        decay,
    );

    let controller_scaled = PeakEwmaHedgeController::new(
        Duration::from_millis(base_initial * scale_factor),
        Duration::from_millis(base_min * scale_factor),
        Duration::from_millis(base_max * scale_factor),
        decay,
    );

    let seq = generate_observations(0x5678, 100, 200);

    for obs in seq {
        controller_base.observe(obs);
        controller_scaled.observe(obs * (scale_factor as u32));

        let delay_base = controller_base.current_config().hedge_delay.as_millis() as f64;
        let delay_scaled = controller_scaled.current_config().hedge_delay.as_millis() as f64;

        let expected_scaled = delay_base * (scale_factor as f64);
        let diff = (delay_scaled - expected_scaled).abs();

        assert!(
            diff <= 1.0,
            "Scale invariance violated: base={}, scaled={}, expected={}, diff={}",
            delay_base, delay_scaled, expected_scaled, diff
        );
    }
}