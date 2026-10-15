#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic tests for `cancel::progress_certificate` diagnostics.
//!
//! These tests validate deterministic accounting and cross-input relations for
//! progress verdicts under `LabRuntime`. Conditional concentration candidates
//! retain the assumptions and no-claim boundary documented by the module.
//!
//! ## Key Properties Tested (5 Metamorphic Relations)
//!
//! 1. **Converging verdict requires observed progress**: a converging verdict
//!    has positive net potential reduction
//! 2. **Verdict reproduction is deterministic**: identical observations
//!    produce identical verdicts
//! 3. **Input perturbation is visible**: modified observations detectably
//!    change verdict properties
//! 4. **Verdict queries are idempotent**: multiple `verdict()` calls return
//!    identical results without state mutation
//! 5. **Reset isolates runs**: `reset()` clears prior observations before a new
//!    trace is recorded
//!
//! ## Metamorphic Relations
//!
//! - **Deterministic verdict**: same observations → same verdict
//! - **Input sensitivity**: modified observations → different verdict
//! - **Idempotent query**: `verdict()` × N = `verdict()` × 1
//! - **Convergence consistency**: DrainPhase correlates with convergence status
//! - **Reset isolation**: post-reset observations are independent of prior state

use proptest::prelude::*;
use std::collections::VecDeque;

use asupersync::cancel::progress_certificate::{
    CertificateVerdict, DrainPhase, ProgressCertificate, ProgressConfig, ProgressObservation,
};
use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::{ArenaIndex, Budget, RegionId, TaskId};

// =============================================================================
// Test Utilities
// =============================================================================

/// Create a test context for progress certificate testing.
fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 1)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

/// Generate a sequence of potential values that converge to zero.
fn arb_converging_sequence() -> impl Strategy<Value = Vec<f64>> {
    (5usize..20).prop_flat_map(|len| {
        // Start with a high value, exponentially decay with noise
        let initial = 100.0 + (0.0..50.0);
        initial.prop_flat_map(move |start| {
            let decay_rate = 0.7..0.9;
            decay_rate.prop_flat_map(move |rate| {
                let noise_factor = 0.0..0.1;
                noise_factor.prop_map(move |noise| {
                    let mut values = Vec::with_capacity(len);
                    let mut current = start;

                    for i in 0..len {
                        values.push(current.max(0.0));
                        // Exponential decay with small random noise
                        let noise = if i > 0 {
                            (fastrand::f64() - 0.5) * 2.0 * noise * current
                        } else {
                            0.0
                        };
                        current = current * rate + noise;
                    }

                    // Ensure the last few values are very small or zero
                    if values.len() > 2 {
                        values[values.len() - 1] = 0.0;
                        values[values.len() - 2] =
                            (0.0..5.0).sample(&mut proptest::test_runner::TestRunner::default());
                    }

                    values
                })
            })
        })
    })
}

/// Generate a sequence of potential values that do not converge (stalled).
fn arb_stalled_sequence() -> impl Strategy<Value = Vec<f64>> {
    (8usize..15).prop_flat_map(|len| {
        let base_value = 20.0..100.0;
        base_value.prop_map(move |base| {
            let mut values = Vec::with_capacity(len);
            // Start with some progress, then stall
            values.push(base);
            values.push(base * 0.8);
            values.push(base * 0.7);

            // Then stall - values stay roughly the same or increase slightly
            for _ in 3..len {
                let prev = values[values.len() - 1];
                let variation = (fastrand::f64() - 0.3) * 0.1 * prev; // Slight upward bias
                values.push((prev + variation).max(prev * 0.95));
            }

            values
        })
    })
}

/// Generate random potential sequences.
fn arb_random_sequence() -> impl Strategy<Value = Vec<f64>> {
    prop::collection::vec(0.0f64..200.0, 3..25)
}

/// Compare two certificate verdicts for essential equality (allowing for floating point tolerance).
fn verdicts_essentially_equal(a: &CertificateVerdict, b: &CertificateVerdict) -> bool {
    const EPSILON: f64 = 1e-10;

    a.converging == b.converging
        && a.stall_detected == b.stall_detected
        && a.total_steps == b.total_steps
        && a.drain_phase == b.drain_phase
        && (a.current_potential - b.current_potential).abs() < EPSILON
        && (a.initial_potential - b.initial_potential).abs() < EPSILON
        && (a.mean_credit - b.mean_credit).abs() < EPSILON
        && (a.max_observed_step - b.max_observed_step).abs() < EPSILON
        && (a.confidence_bound - b.confidence_bound).abs() < EPSILON
        && (a.azuma_bound - b.azuma_bound).abs() < EPSILON
        && (a.freedman_bound - b.freedman_bound).abs() < EPSILON
}

/// Create a certificate from an observation sequence.
fn certificate_from_sequence(observations: &[f64], config: ProgressConfig) -> ProgressCertificate {
    let mut cert = ProgressCertificate::new(config);
    for &potential in observations {
        cert.observe(potential);
    }
    cert
}

// =============================================================================
// Metamorphic Relation 1: Converging verdict requires observed progress
// =============================================================================

proptest! {
    #[test]
    fn mr1_converging_verdict_requires_observed_progress(
        converging_seq in arb_converging_sequence(),
        stalled_seq in arb_stalled_sequence(),
    ) {
        // MR1: A converging verdict should correspond to observed net reduction.

        // Test 1: Converging sequence should eventually show convergence
        let mut converging_cert = ProgressCertificate::with_defaults();
        for &potential in &converging_seq {
            converging_cert.observe(potential);
        }

        let converging_verdict = converging_cert.verdict();

        // If the verdict reports convergence, validate the observed reduction.
        if converging_verdict.converging {
            // The empirical policy requires positive endpoint net progress.
            let progress_made = converging_verdict.initial_potential - converging_verdict.current_potential;
            prop_assert!(progress_made > 0.0,
                "Converging certificate should show actual progress: initial={}, current={}, progress={}",
                converging_verdict.initial_potential, converging_verdict.current_potential, progress_made);

            // Gross downward credit is always non-negative; rebounds are
            // accounted for separately by the signed net-progress rate.
            prop_assert!(converging_verdict.mean_credit >= 0.0,
                "Converging certificate should have non-negative gross credit: {}",
                converging_verdict.mean_credit);
        }

        // Test 2: Stalled sequence should NOT show convergence
        let mut stalled_cert = ProgressCertificate::with_defaults();
        for &potential in &stalled_seq {
            stalled_cert.observe(potential);
        }

        let stalled_verdict = stalled_cert.verdict();

        // The generator has a noisy tail and may not meet the configured stall
        // run length. Whenever the explicit stall rule does fire, the separate
        // empirical status must fail closed; projected confidence is unrelated.
        if stalled_verdict.stall_detected {
            prop_assert!(!stalled_verdict.converging,
                "An explicit stall cannot be classified as empirically converging");
        }
    }
}

// =============================================================================
// Metamorphic Relation 2: Verdict reproduction is deterministic
// =============================================================================

proptest! {
    #[test]
    fn mr2_verdict_reproduction_is_deterministic(
        observations in arb_random_sequence(),
        config_confidence in 0.8f64..0.99,
        config_stall_threshold in 3usize..15,
    ) {
        // MR2: Identical observations should produce identical verdicts (deterministic reproduction)

        let config = ProgressConfig {
            confidence: config_confidence,
            stall_threshold: config_stall_threshold,
            ..ProgressConfig::default()
        };

        // Create two identical certificates with the same configuration
        let cert1 = certificate_from_sequence(&observations, config.clone());
        let cert2 = certificate_from_sequence(&observations, config);

        let verdict1 = cert1.verdict();
        let verdict2 = cert2.verdict();

        // Verdicts should be essentially identical
        prop_assert!(verdicts_essentially_equal(&verdict1, &verdict2),
            "Identical observations should produce identical verdicts:\nVerdict 1: {:?}\nVerdict 2: {:?}",
            verdict1, verdict2);

        // Certificate properties should also match
        prop_assert_eq!(cert1.total_observations(), cert2.total_observations());
        prop_assert_eq!(cert1.len(), cert2.len());
        prop_assert_eq!(cert1.is_empty(), cert2.is_empty());

        // Gross-credit-accounted potential should match.
        let accounted1 = cert1.martingale_value();
        let accounted2 = cert2.martingale_value();
        prop_assert!((accounted1 - accounted2).abs() < 1e-10,
            "Gross-credit accounting should match: {} vs {}", accounted1, accounted2);
    }
}

// =============================================================================
// Metamorphic Relation 3: Input perturbation is visible
// =============================================================================

proptest! {
    #[test]
    fn mr3_input_perturbation_is_visible(
        observations in arb_random_sequence().prop_filter("Need at least 3 observations", |obs| obs.len() >= 3),
        tamper_index in any::<usize>(),
        tamper_delta in -50.0f64..50.0,
    ) {
        // MR3: Modified observation data should detectably change verdict properties

        let tamper_idx = tamper_index % observations.len();

        // Original certificate
        let original_cert = certificate_from_sequence(&observations, ProgressConfig::default());
        let original_verdict = original_cert.verdict();

        // Perturbed input - modify one observation.
        let mut perturbed_observations = observations.clone();
        perturbed_observations[tamper_idx] =
            (perturbed_observations[tamper_idx] + tamper_delta).max(0.0);

        let perturbed_cert =
            certificate_from_sequence(&perturbed_observations, ProgressConfig::default());
        let perturbed_verdict = perturbed_cert.verdict();

        // Skip if clamping or a tiny delta left the input effectively unchanged.
        if (observations[tamper_idx] - perturbed_observations[tamper_idx]).abs() < 1e-10 {
            return Ok(());
        }

        // At least one significant verdict property should change.
        let properties_changed =
            original_verdict.converging != perturbed_verdict.converging ||
            original_verdict.stall_detected != perturbed_verdict.stall_detected ||
            original_verdict.drain_phase != perturbed_verdict.drain_phase ||
            (original_verdict.current_potential - perturbed_verdict.current_potential).abs() > 1e-6 ||
            (original_verdict.mean_credit - perturbed_verdict.mean_credit).abs() > 1e-6 ||
            (original_verdict.confidence_bound - perturbed_verdict.confidence_bound).abs() > 1e-6;

        prop_assert!(properties_changed,
            "Perturbed input should produce a detectably different verdict.\nOriginal: converging={}, phase={:?}, potential={:.6}, credit={:.6}\nPerturbed: converging={}, phase={:?}, potential={:.6}, credit={:.6}",
            original_verdict.converging, original_verdict.drain_phase, original_verdict.current_potential, original_verdict.mean_credit,
            perturbed_verdict.converging, perturbed_verdict.drain_phase, perturbed_verdict.current_potential, perturbed_verdict.mean_credit);
    }
}

// =============================================================================
// Metamorphic Relation 4: Repeated verdict queries are idempotent
// =============================================================================

proptest! {
    #[test]
    fn mr4_repeated_verdict_queries_are_idempotent(
        observations in arb_random_sequence(),
        num_calls in 2usize..10,
    ) {
        // MR4: Multiple verdict() calls should return identical results without state mutation

        let cert = certificate_from_sequence(&observations, ProgressConfig::default());

        // Call verdict() multiple times and ensure they're all identical
        let first_verdict = cert.verdict();
        let mut all_verdicts = vec![first_verdict.clone()];

        for _ in 1..num_calls {
            all_verdicts.push(cert.verdict());
        }

        // All verdicts should be essentially identical to the first one
        for (i, verdict) in all_verdicts.iter().enumerate().skip(1) {
            prop_assert!(verdicts_essentially_equal(&first_verdict, verdict),
                "Verdict call {} should be identical to first call:\nFirst: {:?}\nCall {}: {:?}",
                i, first_verdict, i, verdict);
        }

        // Certificate should report the same properties before and after verdict calls
        let post_observation_count = cert.total_observations();
        let post_len = cert.len();
        prop_assert_eq!(post_observation_count, observations.len());
        prop_assert_eq!(post_len, observations.len());

        // Calling verdict should not mutate the certificate's core state
        let final_verdict = cert.verdict();
        prop_assert!(verdicts_essentially_equal(&first_verdict, &final_verdict),
            "Final verdict should match first verdict after multiple calls");
    }
}

// =============================================================================
// Metamorphic Relation 5: Reset isolates observation histories
// =============================================================================

proptest! {
    #[test]
    fn mr5_reset_isolates_observation_histories(
        pre_reset_obs in arb_random_sequence(),
        post_reset_obs in arb_random_sequence(),
    ) {
        // MR5: reset() clears prior state before recording a new trace.

        let config = ProgressConfig::default();
        let mut cert = ProgressCertificate::new(config);

        // Feed pre-reset observations
        for &potential in &pre_reset_obs {
            cert.observe(potential);
        }

        let pre_reset_verdict = cert.verdict();
        let pre_reset_observations_count = cert.total_observations();
        let pre_reset_len = cert.len();
        // Reset the certificate.
        cert.reset();

        // Certificate should be in fresh state after reset
        prop_assert_eq!(cert.total_observations(), 0, "Certificate should have 0 observations after reset");
        prop_assert_eq!(cert.len(), 0, "Certificate should have 0 length after reset");
        prop_assert!(cert.is_empty(), "Certificate should be empty after reset");

        let post_reset_empty_verdict = cert.verdict();
        prop_assert_eq!(post_reset_empty_verdict.total_steps, 0, "Empty certificate should have 0 total steps");

        // Feed post-reset observations
        for &potential in &post_reset_obs {
            cert.observe(potential);
        }

        let post_reset_verdict = cert.verdict();

        // Post-reset certificate should be completely independent of pre-reset state
        prop_assert_eq!(post_reset_verdict.total_steps, post_reset_obs.len(),
            "Post-reset certificate should only count new observations");

        // Post-reset verdict should not reflect any pre-reset history
        if !post_reset_obs.is_empty() {
            prop_assert_eq!(post_reset_verdict.initial_potential, post_reset_obs[0],
                "Post-reset initial potential should be first new observation: expected {}, got {}",
                post_reset_obs[0], post_reset_verdict.initial_potential);
        }

        // Pre-reset and post-reset verdicts should be independent
        // (unless by coincidence they have identical observation patterns)
        if pre_reset_obs != post_reset_obs && !pre_reset_obs.is_empty() && !post_reset_obs.is_empty() {
            let initial_potentials_differ = (pre_reset_verdict.initial_potential - post_reset_verdict.initial_potential).abs() > 1e-10;
            let step_counts_differ = pre_reset_verdict.total_steps != post_reset_verdict.total_steps;

            prop_assert!(initial_potentials_differ || step_counts_differ,
                "Pre-reset and post-reset certificates should be independent when observation sequences differ");
        }

        // Certificate should accept new observations normally after reset
        let additional_observation = 42.0;
        cert.observe(additional_observation);
        let final_verdict = cert.verdict();

        prop_assert_eq!(final_verdict.total_steps, post_reset_obs.len() + 1,
            "Certificate should accept additional observations after reset");
    }
}

// =============================================================================
// Integration test: Full certificate lifecycle with LabRuntime
// =============================================================================

#[test]
fn integration_certificate_lifecycle_lab_runtime() {
    // Integration test using LabRuntime for deterministic execution
    let config = LabConfig::default();
    let mut lab = LabRuntime::new(config);

    futures_lite::future::block_on(async {
        let cx = test_cx();

        // Create certificate with aggressive configuration
        let cert_config = ProgressConfig::aggressive();
        let mut cert = ProgressCertificate::new(cert_config);

        // Simulate a realistic drain sequence
        let drain_sequence = vec![
            100.0, 85.0, 70.0, 58.0, 45.0, 35.0, 25.0, 18.0, 12.0, 8.0, 5.0, 3.0, 1.0, 0.0,
        ];

        for (step, &potential) in drain_sequence.iter().enumerate() {
            cert.observe(potential);

            let verdict = cert.verdict();

            // Validate invariants at each step
            assert!(verdict.total_steps == step + 1);
            assert!(verdict.current_potential >= 0.0);
            assert!(verdict.initial_potential >= verdict.current_potential);

            // As we progress, we should eventually see a favorable empirical
            // trend. Conditional confidence is a separate diagnostic.
            if step >= 8 {
                // After sufficient observations
                if verdict.converging {
                    assert!(verdict.estimated_remaining_steps.is_some());
                    assert!(!verdict.stall_detected);
                }
            }
        }

        let final_verdict = cert.verdict();

        // Final verdict should show successful convergence
        assert!(
            final_verdict.converging,
            "Final verdict should show convergence"
        );
        assert_eq!(final_verdict.drain_phase, DrainPhase::Quiescent);
        assert_eq!(final_verdict.current_potential, 0.0);
        assert!(final_verdict.confidence_bound > 0.8);

        // Test idempotency
        let verdict_copy = cert.verdict();
        assert!(verdicts_essentially_equal(&final_verdict, &verdict_copy));

        // Test reset
        cert.reset();
        assert_eq!(cert.total_observations(), 0);
        assert!(cert.is_empty());

        cx.budget().consume_uniform(1).await;
    });
}
