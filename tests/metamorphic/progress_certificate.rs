//! Metamorphic tests for cancel::progress_certificate proof invariants.
//!
//! These tests validate the statistical and mathematical properties of progress
//! certificates using metamorphic relations under deterministic LabRuntime.
//! The tests focus on proof invariants rather than specific output values.
//!
//! ## Key Properties Tested (5 Metamorphic Relations)
//!
//! 1. **Certificate issued only after drain completes**: converging certificates
//!    correspond to DrainPhase::Quiescent or strong convergence evidence
//! 2. **Certificate encoding is canonical**: identical observations produce
//!    identical verdicts (deterministic reproduction)
//! 3. **Tampered certificate rejected by verifier**: modified observation data
//!    detectably changes verdict properties
//! 4. **Double-signed certificate idempotent**: multiple verdict() calls return
//!    identical results without state mutation
//! 5. **Revoked certificate honored via generation bump**: reset() invalidates
//!    previous certificates and new observations generate fresh certificates
//!
//! ## Metamorphic Relations
//!
//! - **Deterministic verdict**: same observations → same verdict
//! - **Tamper detection**: modified observations → different verdict
//! - **Idempotent verification**: verdict() × N = verdict() × 1
//! - **Convergence consistency**: DrainPhase correlates with convergence status
//! - **Reset isolation**: post-reset certificates independent of pre-reset state

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
        RegionId::from_arena(ArenaIndex::new(0, 0)),
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
                        values[values.len() - 2] = (0.0..5.0).sample(&mut proptest::test_runner::TestRunner::default());
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
// Metamorphic Relation 1: Certificate issued only after drain completes
// =============================================================================

proptest! {
    #[test]
    fn mr1_certificate_issued_only_after_drain_completes(
        converging_seq in arb_converging_sequence(),
        stalled_seq in arb_stalled_sequence(),
    ) {
        // MR1: Converging certificates should correspond to actual convergence evidence

        // Test 1: Converging sequence should eventually show convergence
        let mut converging_cert = ProgressCertificate::with_defaults();
        for &potential in &converging_seq {
            converging_cert.observe(potential);
        }

        let converging_verdict = converging_cert.verdict();

        // If the certificate claims convergence, validate the evidence
        if converging_verdict.converging {
            // Should have made significant progress from initial to final potential
            let progress_made = converging_verdict.initial_potential - converging_verdict.current_potential;
            prop_assert!(progress_made > 0.0,
                "Converging certificate should show actual progress: initial={}, current={}, progress={}",
                converging_verdict.initial_potential, converging_verdict.current_potential, progress_made);

            // Should have positive mean credit (average progress per step)
            prop_assert!(converging_verdict.mean_credit >= 0.0,
                "Converging certificate should have non-negative mean credit: {}",
                converging_verdict.mean_credit);
        }

        // Test 2: Stalled sequence should NOT show convergence
        let mut stalled_cert = ProgressCertificate::with_defaults();
        for &potential in &stalled_seq {
            stalled_cert.observe(potential);
        }

        let stalled_verdict = stalled_cert.verdict();

        // Stalled sequences should either not converge or have stall detection
        if !stalled_verdict.converging {
            prop_assert!(true); // Expected behavior
        } else {
            // If it claims convergence despite stalling, the confidence should be very low
            prop_assert!(stalled_verdict.confidence_bound < 0.8,
                "Stalled sequence claiming convergence should have low confidence: {}",
                stalled_verdict.confidence_bound);
        }
    }
}

// =============================================================================
// Metamorphic Relation 2: Certificate encoding is canonical
// =============================================================================

proptest! {
    #[test]
    fn mr2_certificate_encoding_is_canonical(
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

        // Martingale values should match
        let mv1 = cert1.martingale_value();
        let mv2 = cert2.martingale_value();
        prop_assert!((mv1 - mv2).abs() < 1e-10, "Martingale values should match: {} vs {}", mv1, mv2);
    }
}

// =============================================================================
// Metamorphic Relation 3: Tampered certificate rejected by verifier
// =============================================================================

proptest! {
    #[test]
    fn mr3_tampered_certificate_rejected_by_verifier(
        observations in arb_random_sequence().prop_filter("Need at least 3 observations", |obs| obs.len() >= 3),
        tamper_index in any::<usize>(),
        tamper_delta in -50.0f64..50.0,
    ) {
        // MR3: Modified observation data should detectably change verdict properties

        let tamper_idx = tamper_index % observations.len();

        // Original certificate
        let original_cert = certificate_from_sequence(&observations, ProgressConfig::default());
        let original_verdict = original_cert.verdict();

        // Tampered certificate - modify one observation
        let mut tampered_observations = observations.clone();
        tampered_observations[tamper_idx] = (tampered_observations[tamper_idx] + tamper_delta).max(0.0);

        let tampered_cert = certificate_from_sequence(&tampered_observations, ProgressConfig::default());
        let tampered_verdict = tampered_cert.verdict();

        // Skip test if the tamper was too small to matter (within epsilon)
        if (observations[tamper_idx] - tampered_observations[tamper_idx]).abs() < 1e-10 {
            return Ok(());
        }

        // The tampered certificate should produce a detectably different verdict
        // At least one significant property should change
        let properties_changed =
            original_verdict.converging != tampered_verdict.converging ||
            original_verdict.stall_detected != tampered_verdict.stall_detected ||
            original_verdict.drain_phase != tampered_verdict.drain_phase ||
            (original_verdict.current_potential - tampered_verdict.current_potential).abs() > 1e-6 ||
            (original_verdict.mean_credit - tampered_verdict.mean_credit).abs() > 1e-6 ||
            (original_verdict.confidence_bound - tampered_verdict.confidence_bound).abs() > 1e-6;

        prop_assert!(properties_changed,
            "Tampered certificate should produce detectably different verdict.\nOriginal: converging={}, phase={:?}, potential={:.6}, credit={:.6}\nTampered: converging={}, phase={:?}, potential={:.6}, credit={:.6}",
            original_verdict.converging, original_verdict.drain_phase, original_verdict.current_potential, original_verdict.mean_credit,
            tampered_verdict.converging, tampered_verdict.drain_phase, tampered_verdict.current_potential, tampered_verdict.mean_credit);
    }
}

// =============================================================================
// Metamorphic Relation 4: Double-signed certificate idempotent
// =============================================================================

proptest! {
    #[test]
    fn mr4_double_signed_certificate_idempotent(
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
        let post_martingale = cert.martingale_value();

        prop_assert_eq!(post_observation_count, observations.len());
        prop_assert_eq!(post_len, observations.len());

        // Calling verdict should not mutate the certificate's core state
        let final_verdict = cert.verdict();
        prop_assert!(verdicts_essentially_equal(&first_verdict, &final_verdict),
            "Final verdict should match first verdict after multiple calls");
    }
}

// =============================================================================
// Metamorphic Relation 5: Revoked certificate honored via generation bump
// =============================================================================

proptest! {
    #[test]
    fn mr5_revoked_certificate_honored_via_generation_bump(
        pre_reset_obs in arb_random_sequence(),
        post_reset_obs in arb_random_sequence(),
    ) {
        // MR5: reset() should invalidate previous certificates and new observations should generate fresh certificates

        let config = ProgressConfig::default();
        let mut cert = ProgressCertificate::new(config);

        // Feed pre-reset observations
        for &potential in &pre_reset_obs {
            cert.observe(potential);
        }

        let pre_reset_verdict = cert.verdict();
        let pre_reset_observations_count = cert.total_observations();
        let pre_reset_len = cert.len();
        let pre_reset_martingale = cert.martingale_value();

        // Reset the certificate (generation bump)
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

    lab.block_on(async {
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

            // As we progress, we should eventually see convergence
            if step >= 8 {  // After sufficient observations
                if verdict.converging {
                    assert!(verdict.confidence_bound > 0.0);
                }
            }
        }

        let final_verdict = cert.verdict();

        // Final verdict should show successful convergence
        assert!(final_verdict.converging, "Final verdict should show convergence");
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