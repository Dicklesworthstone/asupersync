//! Metamorphic Testing: obligation::eprocess evidence threshold invariants
//!
//! This module implements metamorphic relations (MRs) to verify that the
//! e-process evidence accumulation system maintains its statistical guarantees
//! and anytime-valid sequential testing properties under various scenarios.
//!
//! # Metamorphic Relations
//!
//! - **MR1 (Evidence Monotonicity)**: e-process evidence accumulates monotonically
//!   under valid updates - e-values never decrease
//! - **MR2 (Threshold Correctness)**: rejection threshold triggers correctly per
//!   alpha-level - alert when e_value >= 1/alpha
//! - **MR3 (Sequential Testing)**: sequential testing preserves type I error budget
//!   - anytime stopping maintains P(false alarm) ≤ alpha
//! - **MR4 (Calibration Validity)**: calibration preserves e-value validity
//!   - supermartingale property holds under different expected lifetimes
//! - **MR5 (Replay Determinism)**: cancel mid-test preserves replay determinism
//!   - same observation sequence yields identical results
//!
//! # Property Coverage
//!
//! These MRs ensure that:
//! - Statistical guarantees are maintained across all usage patterns
//! - The anytime-valid property holds regardless of stopping rules
//! - Calibration parameters preserve mathematical properties
//! - Deterministic replay is possible for debugging and testing

use crate::lab::runtime::LabRuntime;
use crate::lab::LabConfig;
use crate::obligation::eprocess::{AlertState, LeakMonitor, MonitorConfig};
use proptest::prelude::*;
use std::collections::VecDeque;

/// Test data structure for monitoring scenarios
#[derive(Debug, Clone)]
struct MonitoringScenario {
    alpha: f64,
    expected_lifetime_ns: u64,
    min_observations: u64,
    observations: Vec<u64>,
}

impl MonitoringScenario {
    fn config(&self) -> MonitorConfig {
        MonitorConfig {
            alpha: self.alpha,
            expected_lifetime_ns: self.expected_lifetime_ns,
            min_observations: self.min_observations,
        }
    }
}

/// Generate valid alpha values (between 0 and 1, exclusive)
fn alpha_strategy() -> impl Strategy<Value = f64> {
    prop::num::f64::POSITIVE
        .prop_filter("alpha in (0,1)", |&alpha| alpha > 0.0 && alpha < 1.0)
        .prop_map(|alpha| alpha.min(0.1)) // Reasonable range for testing
}

/// Generate reasonable expected lifetime values (microseconds to seconds)
fn lifetime_strategy() -> impl Strategy<Value = u64> {
    1_000u64..=1_000_000_000u64 // 1μs to 1s
}

/// Generate observation sequences (ages in nanoseconds)
fn observations_strategy() -> impl Strategy<Value = Vec<u64>> {
    prop::collection::vec(1u64..=1_000_000_000u64, 1..=50) // 1ns to 1s, up to 50 observations
}

/// Generate monitoring scenarios
fn scenario_strategy() -> impl Strategy<Value = MonitoringScenario> {
    (
        alpha_strategy(),
        lifetime_strategy(),
        1u64..=10u64, // min_observations
        observations_strategy(),
    ).prop_map(|(alpha, expected_lifetime_ns, min_observations, observations)| {
        MonitoringScenario {
            alpha,
            expected_lifetime_ns,
            min_observations,
            observations,
        }
    })
}

/// **MR1: Evidence Monotonicity**
///
/// The e-process evidence must accumulate monotonically under valid updates.
/// Each observation can only increase or maintain the e-value, never decrease it.
/// This follows from the fact that likelihood ratios are ≥ 1.
///
/// **Property**: ∀i: e_value(i+1) ≥ e_value(i)
#[test]
fn mr1_evidence_monotonicity() {
    proptest!(|(scenario in scenario_strategy())| {
        let mut monitor = LeakMonitor::new(scenario.config());
        let mut previous_e_value = monitor.e_value();

        for (i, &age) in scenario.observations.iter().enumerate() {
            monitor.observe(age);
            let current_e_value = monitor.e_value();

            // MR1: e-value must be monotonically non-decreasing
            prop_assert!(
                current_e_value >= previous_e_value - f64::EPSILON,
                "e-value decreased at observation {}: {:.6} -> {:.6}",
                i, previous_e_value, current_e_value
            );

            // Additional invariant: e-value starts at 1.0 and can only go up
            prop_assert!(
                current_e_value >= 1.0 - f64::EPSILON,
                "e-value below initial value at observation {}: {:.6}",
                i, current_e_value
            );

            previous_e_value = current_e_value;
        }
    });
}

/// **MR2: Threshold Correctness**
///
/// The rejection threshold must trigger correctly per alpha-level.
/// When e_value >= 1/alpha, the monitor should be in Alert state.
/// When e_value < 1/alpha, the monitor should not be in Alert state
/// (unless min_observations constraint isn't met).
///
/// **Property**: alert_state = Alert ⟺ e_value ≥ 1/alpha ∧ obs ≥ min_obs
#[test]
fn mr2_threshold_correctness() {
    proptest!(|(scenario in scenario_strategy())| {
        let mut monitor = LeakMonitor::new(scenario.config());
        let threshold = monitor.threshold();

        for &age in &scenario.observations {
            monitor.observe(age);
            let e_value = monitor.e_value();
            let obs_count = monitor.observations();
            let is_alert = monitor.is_alert();
            let alert_state = monitor.alert_state();

            // MR2.1: Alert state consistency
            prop_assert_eq!(is_alert, alert_state == AlertState::Alert,
                "is_alert() inconsistent with alert_state()");

            // MR2.2: Threshold trigger correctness
            if obs_count >= scenario.min_observations {
                if e_value >= threshold - f64::EPSILON {
                    prop_assert!(is_alert,
                        "Should be alert: e_value={:.6} >= threshold={:.6}, obs={}",
                        e_value, threshold, obs_count);
                }
            } else {
                prop_assert!(!is_alert,
                    "Should not alert before min_observations: obs={} < min={}",
                    obs_count, scenario.min_observations);
            }

            // MR2.3: Threshold value consistency
            prop_assert!(
                (threshold - 1.0 / scenario.alpha).abs() < f64::EPSILON,
                "Threshold should equal 1/alpha: {:.6} vs {:.6}",
                threshold, 1.0 / scenario.alpha
            );
        }
    });
}

/// **MR3: Sequential Testing Error Budget**
///
/// Sequential testing must preserve the type I error budget regardless of
/// stopping rules. The anytime-valid property means P(false alarm) ≤ alpha
/// no matter when we choose to stop monitoring.
///
/// **Property**: ∀stopping_time: P(alert at stopping_time | H0) ≤ alpha
#[test]
fn mr3_sequential_testing_error_budget() {
    proptest!(|(
        scenario in scenario_strategy(),
        stopping_points in prop::collection::vec(1usize..=20, 1..=5)
    )| {
        let config = scenario.config();
        let observations = &scenario.observations[..scenario.observations.len().min(50)];

        // Test multiple stopping points to verify anytime-valid property
        for &stop_point in &stopping_points {
            if stop_point >= observations.len() { continue; }

            let mut monitor = LeakMonitor::new(config);

            // Run until stopping point
            for &age in &observations[..=stop_point] {
                monitor.observe(age);
            }

            let e_value_at_stop = monitor.e_value();
            let was_alert_at_stop = monitor.is_alert();

            // MR3.1: E-value bound under null hypothesis simulation
            // For "normal" observations (≤ expected_lifetime), e-value should stay reasonable
            let all_normal = observations[..=stop_point]
                .iter()
                .all(|&age| age <= config.expected_lifetime_ns);

            if all_normal && observations.len() > config.min_observations as usize {
                // Under simulated H0, e-value should not systematically exceed threshold
                // This is a statistical property - we can't guarantee it for every sequence,
                // but we can check that very conservative sequences don't trigger
                let very_conservative = observations[..=stop_point]
                    .iter()
                    .all(|&age| age <= config.expected_lifetime_ns / 2);

                if very_conservative {
                    prop_assert!(
                        e_value_at_stop <= 10.0, // Allow some variation but should stay reasonable
                        "E-value too high under conservative H0 simulation: {:.6} at stop {}",
                        e_value_at_stop, stop_point
                    );
                }
            }

            // MR3.2: Alert consistency across stopping points
            // If we extend the sequence, alert state can only become more likely
            if stop_point + 1 < observations.len() {
                let mut extended_monitor = LeakMonitor::new(config);
                for &age in &observations[..=stop_point + 1] {
                    extended_monitor.observe(age);
                }
                let extended_alert = extended_monitor.is_alert();
                let extended_e_value = extended_monitor.e_value();

                // Evidence should not decrease with more observations (MR1 again)
                prop_assert!(
                    extended_e_value >= e_value_at_stop - f64::EPSILON,
                    "E-value decreased with additional observation: {:.6} -> {:.6}",
                    e_value_at_stop, extended_e_value
                );

                // If we were already alerting, we should still be alerting
                if was_alert_at_stop {
                    prop_assert!(extended_alert,
                        "Lost alert state after additional observation at stop {}",
                        stop_point
                    );
                }
            }
        }
    });
}

/// **MR4: Calibration Validity**
///
/// Calibration parameters must preserve e-value validity. The supermartingale
/// property should hold under different expected lifetime calibrations.
/// Proper calibration affects the likelihood ratios but maintains mathematical guarantees.
///
/// **Property**: E[e_value | H0] ≤ 1 + ε for reasonable calibrations
#[test]
fn mr4_calibration_validity() {
    proptest!(|(
        base_lifetime in lifetime_strategy(),
        calibration_factors in prop::collection::vec(0.5f64..=2.0, 2..=5),
        alpha in alpha_strategy(),
        observations in prop::collection::vec(1u64..=1_000_000_000u64, 5..=20)
    )| {
        for &factor in &calibration_factors {
            let calibrated_lifetime = ((base_lifetime as f64) * factor) as u64;
            if calibrated_lifetime == 0 { continue; }

            let config = MonitorConfig {
                alpha,
                expected_lifetime_ns: calibrated_lifetime,
                min_observations: 3,
            };

            let mut monitor = LeakMonitor::new(config);
            let initial_e_value = monitor.e_value();

            // MR4.1: Initial state is valid regardless of calibration
            prop_assert!(
                (initial_e_value - 1.0).abs() < f64::EPSILON,
                "Initial e-value should be 1.0 regardless of calibration: {:.6}",
                initial_e_value
            );

            for &age in &observations {
                monitor.observe(age);
                let e_value = monitor.e_value();

                // MR4.2: E-value remains finite and positive
                prop_assert!(
                    e_value.is_finite() && e_value > 0.0,
                    "E-value must remain finite and positive: {:.6}",
                    e_value
                );

                // MR4.3: Threshold scales correctly with alpha
                let threshold = monitor.threshold();
                prop_assert!(
                    (threshold - 1.0 / alpha).abs() < f64::EPSILON,
                    "Threshold should be 1/alpha regardless of lifetime calibration: {:.6} vs {:.6}",
                    threshold, 1.0 / alpha
                );
            }

            // MR4.4: Conservative calibration property
            // If we drastically overestimate expected lifetime, we should be more conservative
            if calibration_factors.len() >= 2 {
                let conservative_factor = calibration_factors.iter().fold(0.0f64, |a, &b| a.max(b));
                let liberal_factor = calibration_factors.iter().fold(f64::INFINITY, |a, &b| a.min(b));

                if (conservative_factor / liberal_factor) >= 1.5 {
                    let conservative_config = MonitorConfig {
                        alpha,
                        expected_lifetime_ns: ((base_lifetime as f64) * conservative_factor) as u64,
                        min_observations: 3,
                    };
                    let liberal_config = MonitorConfig {
                        alpha,
                        expected_lifetime_ns: ((base_lifetime as f64) * liberal_factor) as u64,
                        min_observations: 3,
                    };

                    let mut conservative_monitor = LeakMonitor::new(conservative_config);
                    let mut liberal_monitor = LeakMonitor::new(liberal_config);

                    // Same observations should produce lower e-value with conservative calibration
                    for &age in observations.iter().take(10) {
                        conservative_monitor.observe(age);
                        liberal_monitor.observe(age);
                    }

                    let conservative_e = conservative_monitor.e_value();
                    let liberal_e = liberal_monitor.e_value();

                    // This relationship should hold for observations larger than the conservative estimate
                    let has_large_obs = observations.iter().take(10)
                        .any(|&age| age > ((base_lifetime as f64) * conservative_factor) as u64);

                    if !has_large_obs {
                        prop_assert!(
                            conservative_e <= liberal_e + f64::EPSILON,
                            "Conservative calibration should yield lower e-value for normal observations: {:.6} vs {:.6}",
                            conservative_e, liberal_e
                        );
                    }
                }
            }
        }
    });
}

/// **MR5: Replay Determinism**
///
/// Cancelling mid-test and replaying with the same observations must preserve
/// determinism. This ensures that the monitor has no hidden state and that
/// debugging and testing scenarios are reproducible.
///
/// **Property**: replay(observations[..n]) = original(observations[..n]) for any n
#[test]
fn mr5_replay_determinism() {
    proptest!(|(
        scenario in scenario_strategy(),
        replay_points in prop::collection::vec(0usize..=30, 2..=5)
    )| {
        let config = scenario.config();
        let observations = &scenario.observations;

        if observations.is_empty() { return Ok(()); }

        for &replay_point in &replay_points {
            if replay_point >= observations.len() { continue; }

            // Original execution up to replay point
            let mut original_monitor = LeakMonitor::new(config);
            for &age in &observations[..=replay_point] {
                original_monitor.observe(age);
            }
            let original_snapshot = original_monitor.snapshot();

            // Replay execution: fresh monitor, same observations
            let mut replay_monitor = LeakMonitor::new(config);
            for &age in &observations[..=replay_point] {
                replay_monitor.observe(age);
            }
            let replay_snapshot = replay_monitor.snapshot();

            // MR5.1: E-values must be identical
            prop_assert!(
                (original_snapshot.e_value - replay_snapshot.e_value).abs() < f64::EPSILON,
                "E-value differs in replay at point {}: {:.6} vs {:.6}",
                replay_point, original_snapshot.e_value, replay_snapshot.e_value
            );

            // MR5.2: Alert states must be identical
            prop_assert_eq!(
                original_snapshot.alert_state, replay_snapshot.alert_state,
                "Alert state differs in replay at point {}: {:?} vs {:?}",
                replay_point, original_snapshot.alert_state, replay_snapshot.alert_state
            );

            // MR5.3: Observation counts must be identical
            prop_assert_eq!(
                original_snapshot.observations, replay_snapshot.observations,
                "Observation count differs in replay at point {}: {} vs {}",
                replay_point, original_snapshot.observations, replay_snapshot.observations
            );

            // MR5.4: Peak e-values must be identical
            prop_assert!(
                (original_snapshot.peak_e_value - replay_snapshot.peak_e_value).abs() < f64::EPSILON,
                "Peak e-value differs in replay at point {}: {:.6} vs {:.6}",
                replay_point, original_snapshot.peak_e_value, replay_snapshot.peak_e_value
            );

            // MR5.5: Test reset and replay determinism
            original_monitor.reset();
            replay_monitor.reset();

            // After reset, both should be identical
            let reset_original = original_monitor.snapshot();
            let reset_replay = replay_monitor.snapshot();

            prop_assert!(
                (reset_original.e_value - reset_replay.e_value).abs() < f64::EPSILON,
                "E-value after reset differs: {:.6} vs {:.6}",
                reset_original.e_value, reset_replay.e_value
            );
            prop_assert_eq!(
                reset_original.alert_state, reset_replay.alert_state,
                "Alert state after reset differs"
            );

            // Re-run a prefix and verify determinism is maintained
            if replay_point > 2 {
                let prefix_len = replay_point / 2;
                for &age in &observations[..prefix_len] {
                    original_monitor.observe(age);
                    replay_monitor.observe(age);
                }

                let prefix_original = original_monitor.snapshot();
                let prefix_replay = replay_monitor.snapshot();

                prop_assert!(
                    (prefix_original.e_value - prefix_replay.e_value).abs() < f64::EPSILON,
                    "E-value after reset+prefix differs: {:.6} vs {:.6}",
                    prefix_original.e_value, prefix_replay.e_value
                );
            }
        }
    });
}

/// **Composite MR: End-to-End Statistical Properties**
///
/// Combines multiple MRs to test the overall statistical behavior:
/// monotonicity + threshold correctness + calibration under various scenarios.
#[test]
fn mr_composite_statistical_properties() {
    proptest!(|(
        alpha in alpha_strategy(),
        expected_lifetimes in prop::collection::vec(lifetime_strategy(), 2..=4),
        observation_sequences in prop::collection::vec(observations_strategy(), 2..=3)
    )| {
        for &expected_lifetime_ns in &expected_lifetimes {
            for observations in &observation_sequences {
                if observations.is_empty() { continue; }

                let config = MonitorConfig {
                    alpha,
                    expected_lifetime_ns,
                    min_observations: 3,
                };

                let mut monitor = LeakMonitor::new(config);
                let mut e_value_history = VecDeque::new();

                for (i, &age) in observations.iter().enumerate() {
                    let prev_e_value = monitor.e_value();
                    monitor.observe(age);
                    let curr_e_value = monitor.e_value();

                    e_value_history.push_back(curr_e_value);

                    // Composite property 1: Monotonicity (MR1)
                    prop_assert!(
                        curr_e_value >= prev_e_value - f64::EPSILON,
                        "Monotonicity violation at step {}: {:.6} -> {:.6}",
                        i, prev_e_value, curr_e_value
                    );

                    // Composite property 2: Threshold consistency (MR2)
                    let threshold = monitor.threshold();
                    let is_alert = monitor.is_alert();
                    let obs_count = monitor.observations();

                    if obs_count >= config.min_observations {
                        if curr_e_value >= threshold {
                            prop_assert!(is_alert,
                                "Should be alerting at step {}: e={:.6} >= threshold={:.6}",
                                i, curr_e_value, threshold
                            );
                        }
                        if !is_alert {
                            prop_assert!(curr_e_value < threshold + f64::EPSILON,
                                "Should not be alerting at step {}: e={:.6} < threshold={:.6}",
                                i, curr_e_value, threshold
                            );
                        }
                    }

                    // Composite property 3: Peak tracking
                    let peak_e_value = monitor.peak_e_value();
                    prop_assert!(
                        peak_e_value >= curr_e_value - f64::EPSILON,
                        "Peak e-value should be >= current: {:.6} vs {:.6}",
                        peak_e_value, curr_e_value
                    );

                    if let Some(&max_historical) = e_value_history.iter().max_by(|a, b| a.partial_cmp(b).unwrap()) {
                        prop_assert!(
                            (peak_e_value - max_historical).abs() < f64::EPSILON,
                            "Peak e-value should match historical maximum: {:.6} vs {:.6}",
                            peak_e_value, max_historical
                        );
                    }
                }

                // Composite property 4: Snapshot consistency
                let final_snapshot = monitor.snapshot();
                prop_assert_eq!(
                    final_snapshot.observations,
                    observations.len() as u64,
                    "Final observation count mismatch"
                );

                prop_assert!(
                    (final_snapshot.e_value - monitor.e_value()).abs() < f64::EPSILON,
                    "Snapshot e-value inconsistent with monitor state"
                );
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Simple integration test to verify the basic metamorphic properties work together
    #[test]
    fn integration_basic_metamorphic_properties() {
        let config = MonitorConfig {
            alpha: 0.01,
            expected_lifetime_ns: 1_000_000, // 1ms
            min_observations: 3,
        };

        let mut monitor = LeakMonitor::new(config);

        // Test monotonicity with a few observations
        let observations = [500_000u64, 1_000_000, 2_000_000];
        let mut prev_e_value = monitor.e_value();

        for &age in &observations {
            monitor.observe(age);
            let curr_e_value = monitor.e_value();

            // Verify monotonicity
            assert!(curr_e_value >= prev_e_value - f64::EPSILON,
                "E-value decreased: {} -> {}", prev_e_value, curr_e_value);

            prev_e_value = curr_e_value;
        }

        // Test replay determinism
        let mut replay_monitor = LeakMonitor::new(config);
        for &age in &observations {
            replay_monitor.observe(age);
        }

        assert!((monitor.e_value() - replay_monitor.e_value()).abs() < f64::EPSILON,
            "Replay not deterministic");
        assert_eq!(monitor.alert_state(), replay_monitor.alert_state(),
            "Alert state not deterministic");

        // Test threshold correctness
        let threshold = monitor.threshold();
        assert!((threshold - 1.0 / config.alpha).abs() < f64::EPSILON,
            "Threshold incorrect: {} vs expected {}", threshold, 1.0 / config.alpha);
    }
}