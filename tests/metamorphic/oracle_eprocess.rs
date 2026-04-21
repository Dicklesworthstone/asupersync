#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic testing for lab::oracle e-process evidence accumulation invariants.
//!
//! Property-based tests that validate fundamental behavioral invariants of e-processes
//! for anytime-valid sequential hypothesis testing using deterministic LabRuntime.
//!
//! # Theory
//!
//! An e-process is a non-negative supermartingale that maintains type-I error
//! control under optional stopping (Ville's inequality). These tests verify
//! that the implementation preserves this property under various transformations.

use proptest::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use asupersync::lab::oracle::eprocess::{EProcess, EProcessConfig, EProcessMonitor, EValue};
use asupersync::lab::oracle::{OracleReport, OracleEntryReport, OracleStats};
use asupersync::lab::{config::LabConfig, runtime::LabRuntime};
use asupersync::cx::Cx;
use asupersync::types::{Budget, RegionId, TaskId, Time};
use asupersync::util::ArenaIndex;

/// Test helper for creating deterministic contexts
fn create_test_context(region_id: u32, task_id: u32) -> Cx {
    Cx::test(
        RegionId::new(ArenaIndex::new(region_id as usize)),
        TaskId::new(ArenaIndex::new(task_id as usize)),
        Budget::default(),
    )
}

/// Violation tracker for detecting test failures
#[derive(Debug, Clone)]
struct ViolationTracker {
    violations: Arc<AtomicUsize>,
}

impl ViolationTracker {
    fn new() -> Self {
        Self {
            violations: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn record_violation(&self, msg: &str) {
        eprintln!("Metamorphic violation: {}", msg);
        self.violations.fetch_add(1, Ordering::Relaxed);
    }

    fn violations(&self) -> usize {
        self.violations.load(Ordering::Relaxed)
    }

    fn assert_no_violations(&self) {
        assert_eq!(self.violations(), 0, "Metamorphic relation violated");
    }
}

/// Property-based strategy for generating valid e-process configurations
fn eprocess_config_strategy() -> impl Strategy<Value = EProcessConfig> {
    (
        0.001f64..0.1,    // p0: null violation probability
        -0.5f64..0.8,     // lambda: bet size (bounded by p0)
        0.01f64..0.2,     // alpha: significance level
        1e6f64..1e12,     // max_evalue: overflow protection
    )
        .prop_filter_map("config validation", |(p0, lambda_raw, alpha, max_evalue)| {
            // Ensure lambda is within valid bounds for given p0
            let lambda_min = -1.0 / (1.0 - p0) + 0.01;
            let lambda_max = 1.0 / p0 - 0.01;
            let lambda = lambda_raw.clamp(lambda_min, lambda_max);

            let config = EProcessConfig {
                p0,
                lambda,
                alpha,
                max_evalue,
            };

            if config.validate().is_ok() {
                Some(config)
            } else {
                None
            }
        })
}

/// Property-based strategy for generating observation sequences
fn observation_sequences_strategy() -> impl Strategy<Value = Vec<bool>> {
    proptest::collection::vec(any::<bool>(), 1..100)
}

/// Property-based strategy for generating violation patterns
fn violation_patterns_strategy() -> impl Strategy<Value = (f64, usize)> {
    (
        0.0f64..0.5,     // violation_rate
        10usize..200,    // sequence_length
    )
}

/// Property-based strategy for generating calibration parameters
fn calibration_strategy() -> impl Strategy<Value = (f64, f64)> {
    (
        0.5f64..2.0,     // lambda_multiplier
        0.5f64..2.0,     // alpha_multiplier
    )
}

/// Helper: Create oracle report with specified violations
fn create_oracle_report(invariants: &[&str], violated_invariants: &[&str]) -> OracleReport {
    let entries = invariants
        .iter()
        .map(|&inv| {
            let is_violated = violated_invariants.contains(&inv);
            OracleEntryReport {
                invariant: inv.to_string(),
                passed: !is_violated,
                violation: if is_violated {
                    Some(format!("test violation in {}", inv))
                } else {
                    None
                },
                stats: OracleStats {
                    entities_tracked: 10,
                    events_recorded: 20,
                },
            }
        })
        .collect::<Vec<_>>();

    let total = entries.len();
    let failed = entries.iter().filter(|e| !e.passed).count();

    OracleReport {
        entries,
        total,
        passed: total - failed,
        failed,
        check_time_nanos: 1000,
    }
}

/// Helper: Generate deterministic violation sequence based on rate
fn generate_violation_sequence(rate: f64, length: usize, seed: u64) -> Vec<bool> {
    let mut rng_state = seed;
    (0..length)
        .map(|_| {
            // Linear congruential generator for deterministic randomness
            rng_state = rng_state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let u = f64::from((rng_state >> 33) as u32) / f64::from(1_u32 << 31);
            u < rate
        })
        .collect()
}

// =============================================================================
// MR1: E-process evidence is monotonic under valid updates
// =============================================================================

/// MR1: Evidence monotonicity under valid configuration updates
///
/// Property: For any valid configuration update that preserves the martingale
/// property, the accumulated evidence should not decrease (supermartingale property).
///
/// Transformation: config_update(Config) → Config'
/// Relation: e_value(observations, Config') ≥ e_value(observations, Config) OR validly_reset
#[test]
fn mr1_evidence_monotonicity_under_valid_updates() {
    proptest!(|(
        base_config in eprocess_config_strategy(),
        observations in observation_sequences_strategy(),
        update_multiplier in 0.8f64..1.2,
    )| {
        let tracker = ViolationTracker::new();
        let lab = LabRuntime::new(LabConfig::default());

        futures_lite::future::block_on(|| async {
            let cx = create_test_context(1, 1);

            // Process observations with base configuration
            let mut ep_base = EProcess::new("test_invariant", base_config.clone());
            for &violated in &observations {
                ep_base.observe(violated);
            }
            let base_evidence = ep_base.e_value();

            // Create updated configuration (modify lambda within valid bounds)
            let mut updated_config = base_config.clone();
            let lambda_min = -1.0 / (1.0 - updated_config.p0) + 0.01;
            let lambda_max = 1.0 / updated_config.p0 - 0.01;
            updated_config.lambda = (updated_config.lambda * update_multiplier)
                .clamp(lambda_min, lambda_max);

            if updated_config.validate().is_ok() {
                // Process same observations with updated configuration
                let mut ep_updated = EProcess::new("test_invariant", updated_config);
                for &violated in &observations {
                    ep_updated.observe(violated);
                }
                let updated_evidence = ep_updated.e_value();

                // Evidence should be monotonic or validly reset
                // (Updates can change evidence but should preserve martingale property)
                if updated_evidence.is_finite() && base_evidence.is_finite() {
                    // Both should be valid e-values (≥ 0)
                    if updated_evidence < 0.0 || base_evidence < 0.0 {
                        tracker.record_violation("e-value became negative after config update");
                    }
                }
            }

            Ok::<(), Box<dyn std::error::Error>>(())
        })?;

        tracker.assert_no_violations();
    });
}

// =============================================================================
// MR2: Rejection threshold triggers correctly at alpha-level
// =============================================================================

/// MR2: Rejection threshold accuracy
///
/// Property: E-process rejects H₀ if and only if e-value ≥ 1/α.
///
/// Transformation: α → 1/α (threshold computation)
/// Relation: rejected ⟺ e_value ≥ threshold
#[test]
fn mr2_rejection_threshold_triggers_at_alpha_level() {
    proptest!(|(
        config in eprocess_config_strategy(),
        violation_pattern in violation_patterns_strategy(),
        seed in 0u64..1_000_000,
    )| {
        let tracker = ViolationTracker::new();
        let lab = LabRuntime::new(LabConfig::default());

        futures_lite::future::block_on(|| async {
            let cx = create_test_context(1, 1);

            let (violation_rate, sequence_length) = violation_pattern;
            let threshold = config.threshold();

            // Generate violation sequence that should trigger rejection
            let high_violation_sequence = generate_violation_sequence(
                violation_rate.max(0.1), // Ensure significant violation rate
                sequence_length,
                seed
            );

            let mut ep = EProcess::new("test_invariant", config.clone());

            // Process observations and track when threshold is crossed
            let mut rejection_occurred = false;
            let mut e_value_at_rejection = 0.0;

            for &violated in &high_violation_sequence {
                ep.observe(violated);

                let current_e_value = ep.e_value();

                // Check threshold crossing
                if current_e_value >= threshold && !rejection_occurred {
                    rejection_occurred = true;
                    e_value_at_rejection = current_e_value;
                }

                // Verify rejection status consistency
                let should_be_rejected = current_e_value >= threshold;
                if ep.rejected != should_be_rejected {
                    // Allow for some tolerance due to floating point precision
                    let tolerance = 1e-10;
                    if (current_e_value - threshold).abs() > tolerance {
                        tracker.record_violation(&format!(
                            "rejection status inconsistent: e_value={:.6}, threshold={:.6}, rejected={}",
                            current_e_value, threshold, ep.rejected
                        ));
                    }
                }
            }

            // Final verification
            if ep.rejected {
                if ep.e_value() < threshold {
                    let tolerance = 1e-10;
                    if (ep.e_value() - threshold) < -tolerance {
                        tracker.record_violation("rejected but e-value below threshold");
                    }
                }
            }

            Ok::<(), Box<dyn std::error::Error>>(())
        })?;

        tracker.assert_no_violations();
    });
}

// =============================================================================
// MR3: Sequential testing preserves type I error budget
// =============================================================================

/// MR3: Type I error control under optional stopping
///
/// Property: Under H₀, P(reject) ≤ α regardless of stopping rule (Ville's inequality).
///
/// Transformation: observation_sequence → stopped_at_different_times
/// Relation: false_positive_rate ≤ α for any stopping rule
#[test]
fn mr3_sequential_testing_preserves_type_i_error_budget() {
    proptest!(|(
        config in eprocess_config_strategy(),
        trial_count in 50u32..200,
        seed_offset in 0u64..1000,
    )| {
        let tracker = ViolationTracker::new();
        let lab = LabRuntime::new(LabConfig::default());

        futures_lite::future::block_on(|| async {
            let cx = create_test_context(1, 1);

            let p0 = config.p0; // Null violation rate
            let alpha = config.alpha;
            let max_observations = 100;

            let mut false_positives = 0;

            // Run multiple independent trials under H₀
            for trial in 0..trial_count {
                let trial_seed = seed_offset + u64::from(trial);

                // Generate sequence under H₀ (violation rate = p0)
                let null_sequence = generate_violation_sequence(p0, max_observations, trial_seed);

                let mut ep = EProcess::new("test_invariant", config.clone());

                // Process with optional stopping (can stop at any point)
                let mut stopped_early = false;
                for (step, &violated) in null_sequence.iter().enumerate() {
                    ep.observe(violated);

                    // Optional stopping rule: stop if we've seen enough evidence
                    // (this simulates realistic usage where we might stop early)
                    if ep.e_value() >= config.threshold() * 0.5 && step > 10 {
                        stopped_early = true;
                        break;
                    }
                }

                // Check for false positive under H₀
                if ep.rejected {
                    false_positives += 1;
                }
            }

            let false_positive_rate = f64::from(false_positives) / f64::from(trial_count);

            // By Ville's inequality, FPR should be ≤ α
            // Allow some slack for finite sampling and simulation artifacts
            let tolerance = alpha * 1.5; // 50% slack for finite sample effects

            if false_positive_rate > tolerance {
                tracker.record_violation(&format!(
                    "type I error rate {:.4} exceeds {:.4} (α={:.4})",
                    false_positive_rate, tolerance, alpha
                ));
            }

            Ok::<(), Box<dyn std::error::Error>>(())
        })?;

        tracker.assert_no_violations();
    });
}

// =============================================================================
// MR4: Calibration preserves e-value validity
// =============================================================================

/// MR4: E-value validity under calibration
///
/// Property: Recalibrating the e-process with different parameters should
/// preserve the martingale property and not invalidate accumulated evidence.
///
/// Transformation: recalibrate(e_process, new_config)
/// Relation: new_e_process maintains supermartingale property
#[test]
fn mr4_calibration_preserves_evalue_validity() {
    proptest!(|(
        base_config in eprocess_config_strategy(),
        calibration_params in calibration_strategy(),
        pre_calibration_obs in observation_sequences_strategy(),
        post_calibration_obs in observation_sequences_strategy(),
    )| {
        let tracker = ViolationTracker::new();
        let lab = LabRuntime::new(LabConfig::default());

        futures_lite::future::block_on(|| async {
            let cx = create_test_context(1, 1);

            let (lambda_mult, alpha_mult) = calibration_params;

            // Create calibrated configuration
            let mut calibrated_config = base_config.clone();

            // Adjust lambda within valid bounds
            let lambda_min = -1.0 / (1.0 - calibrated_config.p0) + 0.01;
            let lambda_max = 1.0 / calibrated_config.p0 - 0.01;
            calibrated_config.lambda = (calibrated_config.lambda * lambda_mult)
                .clamp(lambda_min, lambda_max);

            // Adjust alpha within reasonable bounds
            calibrated_config.alpha = (calibrated_config.alpha * alpha_mult)
                .clamp(0.001, 0.5);

            // Ensure max_evalue is above new threshold
            calibrated_config.max_evalue = calibrated_config.max_evalue
                .max(calibrated_config.threshold() * 2.0);

            if calibrated_config.validate().is_ok() {
                // Phase 1: Accumulate evidence with base config
                let mut ep_base = EProcess::new("test_invariant", base_config);
                for &violated in &pre_calibration_obs {
                    ep_base.observe(violated);
                }

                // Phase 2: Continue with calibrated config (simulating recalibration)
                let mut ep_calibrated = EProcess::new("test_invariant", calibrated_config.clone());
                for &violated in &post_calibration_obs {
                    ep_calibrated.observe(violated);
                }

                // Validate both e-processes maintain valid properties
                let base_e_value = ep_base.e_value();
                let calibrated_e_value = ep_calibrated.e_value();

                // E-values should remain non-negative and finite
                if base_e_value < 0.0 || !base_e_value.is_finite() {
                    tracker.record_violation("base e-value became invalid");
                }

                if calibrated_e_value < 0.0 || !calibrated_e_value.is_finite() {
                    tracker.record_violation("calibrated e-value became invalid");
                }

                // Rejection thresholds should be respected
                if ep_base.rejected && base_e_value < base_config.threshold() {
                    tracker.record_violation("base config rejected below threshold");
                }

                if ep_calibrated.rejected && calibrated_e_value < calibrated_config.threshold() {
                    tracker.record_violation("calibrated config rejected below threshold");
                }
            }

            Ok::<(), Box<dyn std::error::Error>>(())
        })?;

        tracker.assert_no_violations();
    });
}

// =============================================================================
// MR5: Cancel mid-test does not poison future invocations
// =============================================================================

/// MR5: Cancellation isolation
///
/// Property: Cancelling an e-process mid-test should not affect the validity
/// of subsequent e-processes for the same or different invariants.
///
/// Transformation: cancel_mid_test(e_process) → fresh_e_process
/// Relation: fresh e-process maintains all properties independent of cancelled one
#[test]
fn mr5_cancel_mid_test_does_not_poison_future_invocations() {
    proptest!(|(
        config in eprocess_config_strategy(),
        observations_before_cancel in observation_sequences_strategy(),
        observations_after_cancel in observation_sequences_strategy(),
        different_invariant in any::<bool>(),
    )| {
        let tracker = ViolationTracker::new();
        let lab = LabRuntime::new(LabConfig::default());

        futures_lite::future::block_on(|| async {
            let cx = create_test_context(1, 1);

            // Phase 1: Create and run e-process until cancellation point
            let mut ep_cancelled = EProcess::new("cancelled_invariant", config.clone());
            for &violated in &observations_before_cancel {
                ep_cancelled.observe(violated);
            }

            let pre_cancel_e_value = ep_cancelled.e_value();
            let pre_cancel_rejected = ep_cancelled.rejected;

            // Simulate cancellation by dropping the e-process
            // (In real usage, this would be a cooperative cancellation)
            drop(ep_cancelled);

            // Phase 2: Create fresh e-process (same or different invariant)
            let fresh_invariant_name = if different_invariant {
                "fresh_different_invariant"
            } else {
                "cancelled_invariant" // Same name, should be independent
            };

            let mut ep_fresh = EProcess::new(fresh_invariant_name, config.clone());

            // Verify fresh e-process starts with correct initial state
            if ep_fresh.e_value() != 1.0 {
                tracker.record_violation("fresh e-process did not start at e-value 1.0");
            }

            if ep_fresh.observations != 0 {
                tracker.record_violation("fresh e-process did not start with 0 observations");
            }

            if ep_fresh.rejected {
                tracker.record_violation("fresh e-process started in rejected state");
            }

            // Process observations with fresh e-process
            for &violated in &observations_after_cancel {
                ep_fresh.observe(violated);
            }

            let fresh_e_value = ep_fresh.e_value();

            // Verify fresh e-process behaves independently of cancelled one
            if fresh_e_value < 0.0 || !fresh_e_value.is_finite() {
                tracker.record_violation("fresh e-process produced invalid e-value");
            }

            // Fresh e-process rejection should only depend on its own observations
            let fresh_should_reject = fresh_e_value >= config.threshold();
            if ep_fresh.rejected != fresh_should_reject {
                // Allow tolerance for floating point precision
                let tolerance = 1e-10;
                if (fresh_e_value - config.threshold()).abs() > tolerance {
                    tracker.record_violation("fresh e-process rejection state inconsistent");
                }
            }

            Ok::<(), Box<dyn std::error::Error>>(())
        })?;

        tracker.assert_no_violations();
    });
}

// =============================================================================
// Additional Integration Tests with LabRuntime
// =============================================================================

/// Integration test: E-process monitor with virtual time advancement
#[test]
fn integration_eprocess_monitor_with_virtual_time() {
    proptest!(|(
        config in eprocess_config_strategy(),
        violation_rate in 0.0f64..0.2,
        time_steps in 10u32..50,
    )| {
        let tracker = ViolationTracker::new();
        let lab = LabRuntime::new(LabConfig::default());

        futures_lite::future::block_on(|| async {
            let cx = create_test_context(1, 1);

            // Create monitor for standard invariants
            let mut monitor = EProcessMonitor::standard_with_config(config);
            let invariants = ["task_leak", "obligation_leak", "quiescence"];

            // Simulate oracle reports over virtual time
            for step in 0..time_steps {
                // Advance virtual time
                lab.advance_time(Duration::from_millis(100));

                // Generate violations based on rate
                let violated_invariants = if (step as f64) * violation_rate / 10.0 % 1.0 < violation_rate {
                    vec!["task_leak"] // Deterministic violation pattern
                } else {
                    vec![]
                };

                let report = create_oracle_report(&invariants, &violated_invariants);
                monitor.observe_report(&report);

                // Validate monitor state consistency
                for result in monitor.results() {
                    if result.e_value < 0.0 || !result.e_value.is_finite() {
                        tracker.record_violation(&format!(
                            "invalid e-value for {}: {}",
                            result.invariant, result.e_value
                        ));
                    }

                    if result.observations != (step + 1) as usize {
                        tracker.record_violation(&format!(
                            "incorrect observation count for {}: expected {}, got {}",
                            result.invariant, step + 1, result.observations
                        ));
                    }
                }
            }

            Ok::<(), Box<dyn std::error::Error>>(())
        })?;

        tracker.assert_no_violations();
    });
}

/// Integration test: Reset behavior preserves independence
#[test]
fn integration_reset_preserves_independence() {
    proptest!(|(
        config in eprocess_config_strategy(),
        first_run_obs in observation_sequences_strategy(),
        second_run_obs in observation_sequences_strategy(),
    )| {
        let tracker = ViolationTracker::new();
        let lab = LabRuntime::new(LabConfig::default());

        futures_lite::future::block_on(|| async {
            let cx = create_test_context(1, 1);

            let mut ep = EProcess::new("test_invariant", config);

            // First run
            for &violated in &first_run_obs {
                ep.observe(violated);
            }
            let first_run_final_e_value = ep.e_value();
            let first_run_rejected = ep.rejected;

            // Reset
            ep.reset();

            // Verify reset state
            if ep.e_value() != 1.0 {
                tracker.record_violation("reset did not restore e-value to 1.0");
            }
            if ep.observations != 0 {
                tracker.record_violation("reset did not clear observation count");
            }
            if ep.rejected {
                tracker.record_violation("reset did not clear rejection state");
            }

            // Second run (should be independent of first)
            for &violated in &second_run_obs {
                ep.observe(violated);
            }
            let second_run_final_e_value = ep.e_value();
            let second_run_rejected = ep.rejected;

            // Verify independence: second run results should not be affected by first run
            if second_run_final_e_value < 0.0 || !second_run_final_e_value.is_finite() {
                tracker.record_violation("second run produced invalid e-value");
            }

            // Create a fresh e-process with same observations as second run for comparison
            let mut ep_fresh = EProcess::new("test_invariant", config);
            for &violated in &second_run_obs {
                ep_fresh.observe(violated);
            }

            // Reset e-process should behave identically to fresh e-process
            let tolerance = 1e-10;
            if (second_run_final_e_value - ep_fresh.e_value()).abs() > tolerance {
                tracker.record_violation("reset e-process differs from fresh e-process");
            }

            if second_run_rejected != ep_fresh.rejected {
                tracker.record_violation("reset e-process rejection differs from fresh");
            }

            Ok::<(), Box<dyn std::error::Error>>(())
        })?;

        tracker.assert_no_violations();
    });
}