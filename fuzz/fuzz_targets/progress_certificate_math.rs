#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use asupersync::cancel::progress_certificate::{
    ProgressCertificate, ProgressConfig, CertificateVerdict, DrainPhase,
    ProgressObservation, EvidenceEntry
};

/// Comprehensive fuzz target for progress certificate mathematical operations
///
/// Tests the statistical analysis and martingale theory implementations for:
/// - Configuration validation edge cases (NaN, infinity, extreme values)
/// - Certificate observation sequences with mathematical edge cases
/// - Azuma-Hoeffding and Freedman bound calculations under extreme conditions
/// - Supermartingale property verification with adversarial sequences
/// - Evidence generation and verdict computation robustness
/// - Compact/reset operations with large observation histories
/// - Phase classification accuracy under varying drain patterns
#[derive(Arbitrary, Debug)]
struct ProgressCertificateFuzz {
    /// Configuration to test, may contain edge case values
    config: ConfigFuzz,
    /// Sequence of potential observations to feed to certificate
    observations: Vec<ObservationFuzz>,
    /// Operations to perform on the certificate
    operations: Vec<CertificateOperation>,
}

/// Configuration fuzzing with mathematical edge cases
#[derive(Arbitrary, Debug)]
struct ConfigFuzz {
    /// Confidence level - test values around [0,1] boundaries and special floats
    confidence: f64,
    /// Maximum step bound - test with extreme values, NaN, infinity
    max_step_bound: f64,
    /// Stall threshold for consecutive non-decreasing steps
    stall_threshold: usize,
    /// Minimum observations before issuing verdict
    min_observations: usize,
    /// Epsilon for floating-point comparisons
    epsilon: f64,
}

/// Observation values that may trigger mathematical edge cases
#[derive(Arbitrary, Debug)]
struct ObservationFuzz {
    /// Potential value - may be NaN, infinity, very large/small, or negative
    potential: f64,
}

/// Operations to perform on the certificate during fuzzing
#[derive(Arbitrary, Debug)]
enum CertificateOperation {
    /// Observe a potential value
    Observe(f64),
    /// Compute verdict
    Verdict,
    /// Compact to keep only last N observations
    Compact(usize),
    /// Reset certificate to empty state
    Reset,
    /// Check specific mathematical properties
    CheckMartingaleProperty,
    /// Check variance calculation
    CheckVariance,
    /// Check Azuma-Hoeffding bound
    CheckAzumaBound,
    /// Check Freedman bound
    CheckFreedmanBound,
    /// Check phase classification
    CheckDrainPhase,
}

/// Maximum limits for safety during fuzzing
const MAX_OBSERVATIONS: usize = 10000;
const MAX_COMPACT_KEEP: usize = 1000;
const EXTREME_VALUE_THRESHOLD: f64 = 1e100;

fuzz_target!(|input: ProgressCertificateFuzz| {
    // Limit observation count for performance
    let observations = if input.observations.len() > MAX_OBSERVATIONS {
        &input.observations[..MAX_OBSERVATIONS]
    } else {
        &input.observations
    };

    // Test configuration creation and validation
    test_config_validation(&input.config);

    // Create certificate with potentially invalid config (should handle gracefully)
    let config = create_safe_config(&input.config);
    let mut cert = ProgressCertificate::new(config);

    // Test observation sequence
    for obs in observations {
        test_observe_potential(&mut cert, obs.potential);
    }

    // Test operations sequence
    for operation in &input.operations {
        match operation {
            CertificateOperation::Observe(potential) => {
                test_observe_potential(&mut cert, *potential);
            },
            CertificateOperation::Verdict => {
                test_verdict_computation(&cert);
            },
            CertificateOperation::Compact(keep) => {
                let safe_keep = (*keep).min(MAX_COMPACT_KEEP);
                test_compact_operation(&mut cert, safe_keep);
            },
            CertificateOperation::Reset => {
                test_reset_operation(&mut cert);
            },
            CertificateOperation::CheckMartingaleProperty => {
                test_martingale_property(&cert);
            },
            CertificateOperation::CheckVariance => {
                test_variance_calculation(&cert);
            },
            CertificateOperation::CheckAzumaBound => {
                test_azuma_bound_properties(&cert);
            },
            CertificateOperation::CheckFreedmanBound => {
                test_freedman_bound_properties(&cert);
            },
            CertificateOperation::CheckDrainPhase => {
                test_drain_phase_classification(&cert);
            },
        }
    }

    // Final comprehensive test
    test_comprehensive_properties(&cert);
});

fn test_config_validation(config_fuzz: &ConfigFuzz) {
    let config = ProgressConfig {
        confidence: config_fuzz.confidence,
        max_step_bound: config_fuzz.max_step_bound,
        stall_threshold: config_fuzz.stall_threshold,
        min_observations: config_fuzz.min_observations,
        epsilon: config_fuzz.epsilon,
    };

    // Validation should never panic, only return Result
    let validation_result = config.validate();

    // Test specific edge cases that should be rejected
    if config.confidence <= 0.0 || config.confidence >= 1.0 || !config.confidence.is_finite() {
        assert!(validation_result.is_err(), "Invalid confidence should be rejected");
    }
    if config.max_step_bound <= 0.0 || !config.max_step_bound.is_finite() {
        assert!(validation_result.is_err(), "Invalid step bound should be rejected");
    }
    if config.stall_threshold == 0 {
        assert!(validation_result.is_err(), "Zero stall threshold should be rejected");
    }
    if config.min_observations < 2 {
        assert!(validation_result.is_err(), "Min observations < 2 should be rejected");
    }
    if config.epsilon < 0.0 || !config.epsilon.is_finite() {
        assert!(validation_result.is_err(), "Invalid epsilon should be rejected");
    }

    // Test preset configurations are always valid
    assert!(ProgressConfig::default().validate().is_ok());
    assert!(ProgressConfig::aggressive().validate().is_ok());
    assert!(ProgressConfig::tolerant().validate().is_ok());
}

fn create_safe_config(config_fuzz: &ConfigFuzz) -> ProgressConfig {
    // Create a configuration that will pass validation for testing certificate operations
    let confidence = config_fuzz.confidence.clamp(0.001, 0.999);
    let max_step_bound = if config_fuzz.max_step_bound.is_finite() && config_fuzz.max_step_bound > 0.0 {
        config_fuzz.max_step_bound.clamp(0.1, 1e6)
    } else {
        100.0
    };
    let stall_threshold = config_fuzz.stall_threshold.max(1).min(1000);
    let min_observations = config_fuzz.min_observations.clamp(2, 100);
    let epsilon = if config_fuzz.epsilon.is_finite() && config_fuzz.epsilon >= 0.0 {
        config_fuzz.epsilon.clamp(1e-15, 1e-6)
    } else {
        1e-12
    };

    ProgressConfig {
        confidence,
        max_step_bound,
        stall_threshold,
        min_observations,
        epsilon,
    }
}

fn test_observe_potential(cert: &mut ProgressCertificate, potential: f64) {
    let len_before = cert.len();
    let total_before = cert.total_observations();

    // Observe should never panic, regardless of input
    cert.observe(potential);

    // Invariants that must hold after any observation
    assert_eq!(cert.len(), len_before + 1, "Length should increase by 1");
    assert_eq!(cert.total_observations(), total_before + 1, "Total count should increase by 1");

    // Potential should be non-negative (clamped internally)
    if let Some(obs) = cert.observations().last() {
        assert!(obs.potential >= 0.0, "Observed potential should be non-negative");
        assert!(obs.potential.is_finite(), "Observed potential should be finite");
        assert!(obs.delta.is_finite(), "Delta should be finite");
        assert!(obs.credit >= 0.0, "Credit should be non-negative");
        assert!(obs.credit.is_finite(), "Credit should be finite");
    }

    // Mathematical properties
    assert!(cert.total_credit() >= 0.0, "Total credit should be non-negative");
    assert!(cert.total_credit().is_finite(), "Total credit should be finite");
    assert!(cert.martingale_value().is_finite(), "Martingale value should be finite");
}

fn test_verdict_computation(cert: &ProgressCertificate) {
    // Verdict computation should never panic
    let verdict = cert.verdict();

    // All verdict fields should be valid
    assert!(verdict.confidence_bound >= 0.0 && verdict.confidence_bound <= 1.0,
           "Confidence bound should be in [0,1]");
    assert!(verdict.azuma_bound >= 0.0 && verdict.azuma_bound <= 1.0,
           "Azuma bound should be in [0,1]");
    assert!(verdict.freedman_bound >= 0.0 && verdict.freedman_bound <= 1.0,
           "Freedman bound should be in [0,1]");
    assert!(verdict.freedman_bound <= verdict.azuma_bound + 1e-12,
           "Freedman should dominate (be <= Azuma)");

    assert!(verdict.current_potential >= 0.0, "Current potential should be non-negative");
    assert!(verdict.current_potential.is_finite(), "Current potential should be finite");
    assert!(verdict.initial_potential >= 0.0, "Initial potential should be non-negative");
    assert!(verdict.initial_potential.is_finite(), "Initial potential should be finite");

    assert!(verdict.mean_credit >= 0.0, "Mean credit should be non-negative");
    assert!(verdict.mean_credit.is_finite(), "Mean credit should be finite");
    assert!(verdict.max_observed_step >= 0.0, "Max step should be non-negative");
    assert!(verdict.max_observed_step.is_finite(), "Max step should be finite");

    if let Some(remaining) = verdict.estimated_remaining_steps {
        assert!(remaining >= 0.0, "Estimated remaining should be non-negative");
        assert!(remaining.is_finite(), "Estimated remaining should be finite");
    }

    if let Some(variance) = verdict.empirical_variance {
        assert!(variance >= 0.0, "Variance should be non-negative");
        assert!(variance.is_finite(), "Variance should be finite");
    }

    // Phase should be valid
    test_drain_phase_validity(verdict.drain_phase);

    // Evidence should be valid
    for evidence in &verdict.evidence {
        assert!(evidence.step < verdict.total_steps, "Evidence step should be valid");
        assert!(evidence.potential >= 0.0, "Evidence potential should be non-negative");
        assert!(evidence.potential.is_finite(), "Evidence potential should be finite");
        assert!(evidence.bound.is_finite(), "Evidence bound should be finite");
        assert!(!evidence.description.is_empty(), "Evidence description should be non-empty");
    }
}

fn test_compact_operation(cert: &mut ProgressCertificate, keep: usize) {
    let total_before = cert.total_observations();
    let credit_before = cert.total_credit();
    let martingale_before = cert.martingale_value();
    let increase_count_before = cert.increase_count();

    cert.compact(keep);

    // Compaction should preserve statistical summaries
    assert_eq!(cert.total_observations(), total_before,
              "Total observations should be preserved");
    assert!((cert.total_credit() - credit_before).abs() < 1e-12,
           "Total credit should be preserved");
    assert!((cert.martingale_value() - martingale_before).abs() < 1e-12,
           "Martingale value should be preserved");
    assert_eq!(cert.increase_count(), increase_count_before,
              "Increase count should be preserved");

    // Length should be appropriately reduced
    if total_before > keep {
        assert_eq!(cert.len(), keep, "Should retain exactly 'keep' observations");
    } else {
        assert_eq!(cert.len(), total_before, "Should retain all observations if count <= keep");
    }
}

fn test_reset_operation(cert: &mut ProgressCertificate) {
    cert.reset();

    // All state should be cleared
    assert!(cert.is_empty(), "Certificate should be empty after reset");
    assert_eq!(cert.len(), 0, "Length should be zero");
    assert_eq!(cert.total_observations(), 0, "Total observations should be zero");
    assert!((cert.total_credit()).abs() < 1e-12, "Total credit should be zero");
    assert_eq!(cert.increase_count(), 0, "Increase count should be zero");
    assert!(cert.delta_variance().is_none(), "Variance should be None");
}

fn test_martingale_property(cert: &ProgressCertificate) {
    if cert.is_empty() {
        return;
    }

    let ratio = cert.martingale_ratio();
    assert!(ratio.is_finite(), "Martingale ratio should be finite");
    assert!(ratio >= 0.0, "Martingale ratio should be non-negative");

    // For a true supermartingale with no increases, ratio should be ≈ 1.0
    // With increases, it can exceed 1.0 but shouldn't be wildly large
    assert!(ratio <= 1000.0, "Martingale ratio should be bounded");

    let martingale_value = cert.martingale_value();
    assert!(martingale_value.is_finite(), "Martingale value should be finite");
    assert!(martingale_value >= 0.0, "Martingale value should be non-negative");
}

fn test_variance_calculation(cert: &ProgressCertificate) {
    if let Some(variance) = cert.delta_variance() {
        assert!(variance >= 0.0, "Variance should be non-negative");
        assert!(variance.is_finite(), "Variance should be finite");
    }
}

fn test_azuma_bound_properties(cert: &ProgressCertificate) {
    let verdict = cert.verdict();
    let azuma = verdict.azuma_bound;

    assert!(azuma >= 0.0 && azuma <= 1.0, "Azuma bound should be a probability");
    assert!(azuma.is_finite(), "Azuma bound should be finite");
}

fn test_freedman_bound_properties(cert: &ProgressCertificate) {
    let verdict = cert.verdict();
    let freedman = verdict.freedman_bound;
    let azuma = verdict.azuma_bound;

    assert!(freedman >= 0.0 && freedman <= 1.0, "Freedman bound should be a probability");
    assert!(freedman.is_finite(), "Freedman bound should be finite");
    assert!(freedman <= azuma + 1e-12, "Freedman should dominate Azuma");
}

fn test_drain_phase_classification(cert: &ProgressCertificate) {
    let phase = cert.drain_phase();
    test_drain_phase_validity(phase);

    // Phase classification should be consistent with verdict
    let verdict = cert.verdict();
    assert_eq!(phase, verdict.drain_phase, "Phase should be consistent");
}

fn test_drain_phase_validity(phase: DrainPhase) {
    // All drain phases should be valid enum variants
    match phase {
        DrainPhase::Warmup |
        DrainPhase::RapidDrain |
        DrainPhase::SlowTail |
        DrainPhase::Stalled |
        DrainPhase::Quiescent => {
            // Valid phase
        }
    }

    // Display should work
    let display = format!("{}", phase);
    assert!(!display.is_empty(), "Phase display should not be empty");
}

fn test_comprehensive_properties(cert: &ProgressCertificate) {
    // Test all basic properties
    assert!(cert.total_observations() >= cert.len(),
           "Total observations should be >= retained length");

    if !cert.is_empty() {
        // Test mathematical consistency
        let verdict = cert.verdict();

        // Total progress should be consistent
        let total_progress = verdict.initial_potential - verdict.current_potential;
        assert!(total_progress.is_finite(), "Total progress should be finite");

        // Mean credit calculation should be consistent
        if verdict.total_steps > 1 {
            let expected_mean = cert.total_credit() / ((verdict.total_steps - 1) as f64);
            assert!((verdict.mean_credit - expected_mean).abs() < 1e-10,
                   "Mean credit should be consistent");
        }

        // Stall detection should be consistent with increase count
        if verdict.stall_detected {
            // If stalled, should have some monotonicity pattern
            assert!(verdict.total_steps >= cert.config().stall_threshold,
                   "Stall detection requires minimum steps");
        }

        // Evidence should contain key information for significant events
        if verdict.current_potential <= cert.config().epsilon {
            let has_quiescence = verdict.evidence.iter()
                .any(|e| e.description.contains("quiescence"));
            assert!(has_quiescence, "Quiescence should be noted in evidence");
        }
    }

    // Configuration should remain valid throughout
    assert!(cert.config().validate().is_ok(),
           "Configuration should remain valid");
}

/// Test specific mathematical edge cases that might cause numerical instability
fn test_extreme_value_handling() {
    let config = ProgressConfig::default();
    let mut cert = ProgressCertificate::new(config);

    // Test with very large values
    cert.observe(1e100);
    cert.observe(5e99);
    let verdict = cert.verdict();
    assert!(verdict.azuma_bound.is_finite(), "Should handle large values");

    // Test with very small positive values
    cert.reset();
    cert.observe(1e-100);
    cert.observe(5e-101);
    let verdict = cert.verdict();
    assert!(verdict.current_potential >= 0.0, "Should handle tiny values");

    // Test sequence that might cause overflow in sum calculations
    cert.reset();
    for _ in 0..100 {
        cert.observe(1e10);
        cert.observe(5e9);
    }
    let verdict = cert.verdict();
    assert!(verdict.mean_credit.is_finite(), "Should handle large accumulations");
}